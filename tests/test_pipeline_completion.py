from __future__ import annotations

import json
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import Repo_Privacy_Guardian as rpg
from repo_privacy_guardian.scanner import AuditCancelled


@dataclass
class PipelineHarness:
    config: rpg.GuardRunConfig
    artifacts: rpg.RunArtifacts
    events: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    cancelled: bool = False
    audit_effect: Callable[[Path], rpg.RepoReport] | None = None
    fix_effect: Callable[[rpg.RepoReport], rpg.RepoReport] | None = None
    guard: object | None = None

    def run(self) -> int:
        return rpg.execute_guard_pipeline(
            config=self.config,
            artifacts=self.artifacts,
            logger=self.logs.append,
            results_dir=self.artifacts.run_dir.parent,
            cancel_callback=lambda: self.cancelled,
        )

    def outputs(self) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object], str]:
        return (
            json.loads(self.artifacts.json_path.read_text(encoding="utf-8")),
            json.loads(self.artifacts.agent_summary_path.read_text(encoding="utf-8")),
            json.loads(self.artifacts.state_path.read_text(encoding="utf-8")),
            self.artifacts.html_path.read_text(encoding="utf-8"),
        )


@pytest.fixture
def pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PipelineHarness:
    root = tmp_path / "repositories"
    (root / "ExampleRepo").mkdir(parents=True)
    policy = tmp_path / "POLICY.md"
    policy.write_text("Synthetic policy fixture", encoding="utf-8")
    config = rpg.GuardRunConfig(
        mode="cli",
        root=root,
        policy=policy,
        repos=["ExampleRepo"],
        public_only=False,
        fix=False,
        push=False,
        dry_run=True,
        redact_third_party_emails=False,
        purge_detected_secret_files=False,
        purge_all_detected_secret_files=False,
        low_confidence_email_mode="informational",
        owner_name="Owner",
        owner_emails=[],
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        max_matches=50,
    )
    harness = PipelineHarness(config, rpg.create_run_artifacts(tmp_path / "outputs"))

    class ControlledGuard:
        def __init__(self, root: Path) -> None:
            self.root = root
            self.cancel_requested: Callable[[], bool] | None = None
            harness.guard = self

        def discover_repositories(self, _filters: list[str] | None, *, public_only: bool) -> list[Path]:
            del public_only
            harness.events.append("discover")
            return [self.root / "ExampleRepo"]

        def acquire_repo_lock(self, _repo: Path) -> object:
            harness.events.append("lock")
            return self

        def release_repo_lock(self, lock: object) -> None:
            assert lock is self
            harness.events.append("unlock")

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            harness.events.append("audit")
            if harness.audit_effect is not None:
                return harness.audit_effect(repo)
            report = rpg.RepoReport(name=repo.name, path=str(repo))
            report.finalize()
            return report

        def apply_fixes(self, _repo: Path, report: rpg.RepoReport) -> rpg.RepoReport:
            harness.events.append("fix")
            # A running rewrite must never see the cooperative audit signal.
            assert self.cancel_requested is None
            if harness.fix_effect is not None:
                return harness.fix_effect(report)
            return report

    monkeypatch.setattr(rpg, "RepoPublicationGuard", ControlledGuard)
    monkeypatch.setattr(rpg, "probe_git_available", lambda: (True, None))
    return harness


def test_pipeline_completed_clean_context_agrees_across_artifacts(pipeline: PipelineHarness) -> None:
    assert pipeline.run() == rpg.EXIT_OK
    reports, summary, state, html = pipeline.outputs()
    assert len(reports) == 1
    assert summary["status"] == state["decision"] == "PASS"
    assert summary["completion"] == state["completion"] == "complete"
    assert summary["run_context"]["completed_repositories"] == state["completed_repositories"] == 1
    assert 'decision-pass\">PASS' in html
    assert pipeline.events == ["discover", "lock", "audit", "unlock"]


def test_pipeline_preflight_error_keeps_empty_results_failed(
    pipeline: PipelineHarness, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda: (False, "controlled missing Git"))
    assert pipeline.run() == rpg.EXIT_RUNTIME_ERROR
    reports, summary, state, html = pipeline.outputs()
    assert reports == []
    assert summary["status"] == state["decision"] == "FAIL"
    assert summary["decision_reason"] == state["decision_reason"] == "runtime_error"
    assert summary["exit_code"] == state["exit_code"] == 3
    assert summary["completion"] == "incomplete"
    assert state["performance"]["phases"]["preflight"] >= 0
    assert "runtime/tooling" in summary["next_action"]
    assert 'decision-fail\">FAIL' in html
    assert pipeline.events == []


@pytest.mark.parametrize("interruption", [AuditCancelled, KeyboardInterrupt])
def test_pipeline_audit_interruption_keeps_partial_evidence_and_releases_lock(
    pipeline: PipelineHarness, interruption: type[BaseException],
) -> None:
    def interrupted(_repo: Path) -> rpg.RepoReport:
        raise interruption("controlled operator cancellation")

    pipeline.audit_effect = interrupted
    assert pipeline.run() == rpg.EXIT_ABORTED
    reports, summary, state, html = pipeline.outputs()
    assert reports == []
    assert summary["status"] == state["decision"] == "REVIEW"
    assert summary["decision_reason"] == "aborted"
    assert summary["completion"] == state["completion"] == "aborted"
    assert summary["counts"]["blocking_findings"] == 0
    assert state["completed_repositories"] == 0
    assert state["total_repositories"] == 1
    assert state["performance"]["phases"]["audit"] >= 0
    assert state["performance"]["repositories"]["ExampleRepo"]["audit"] >= 0
    assert 'decision-review\">REVIEW' in html
    assert pipeline.events == ["discover", "lock", "audit", "unlock"]


def test_pipeline_late_export_failure_refreshes_guidance_once(
    pipeline: PipelineHarness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    export = tmp_path / "controlled-export.json"
    pipeline.config.report_json = str(export)
    write = rpg.write_private_text_file
    export_attempts: list[Path] = []

    def controlled_write(path: Path, text: str) -> None:
        if path == export:
            export_attempts.append(path)
            raise OSError("controlled optional export failure")
        write(path, text)

    monkeypatch.setattr(rpg, "write_private_text_file", controlled_write)
    assert pipeline.run() == rpg.EXIT_RUNTIME_ERROR
    reports, summary, state, html = pipeline.outputs()
    assert reports[0]["status"] == "PASS"
    assert summary["status"] == state["decision"] == "FAIL"
    assert summary["exit_code"] == state["exit_code"] == 3
    assert summary["decision_reason"] == "runtime_error"
    assert 'decision-fail\">FAIL' in html
    assert len(export_attempts) == 1
    assert not export.exists()
    assert state["performance"]["phases"]["report_persistence"] >= 0


def test_pipeline_remote_cleanup_failure_cannot_keep_pass_guidance(
    pipeline: PipelineHarness, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pipeline.config.github_owner = "ExampleOrg"
    clone_root = tmp_path / "repo-privacy-guardian-github-controlled"
    cleanup_calls: list[tuple[Path, str]] = []

    def cleanup(path: Path, *, required_prefix: str) -> tuple[bool, str]:
        cleanup_calls.append((path, required_prefix))
        return False, "controlled clone cleanup failure"

    monkeypatch.setattr(
        rpg,
        "prepare_github_remote_audit_repositories",
        lambda _config, _logger: ([pipeline.config.root / "ExampleRepo"], [], clone_root, None),
    )
    monkeypatch.setattr(rpg, "remove_private_temp_tree", cleanup)
    assert pipeline.run() == rpg.EXIT_RUNTIME_ERROR
    reports, summary, state, html = pipeline.outputs()
    assert reports[0]["status"] == "PASS"
    assert summary["status"] == state["decision"] == "FAIL"
    assert summary["exit_code"] == state["exit_code"] == 3
    assert 'decision-fail\">FAIL' in html
    assert cleanup_calls == [(clone_root, "repo-privacy-guardian-github-")]
    assert state["performance"]["phases"]["remote_clone_cleanup"] >= 0
    assert "discover" not in pipeline.events


def test_pipeline_final_state_failure_refreshes_remaining_guidance(
    pipeline: PipelineHarness, monkeypatch: pytest.MonkeyPatch,
) -> None:
    write = rpg.write_private_json_file

    def controlled_state_write(path: Path, payload: dict[str, object]) -> None:
        if path == pipeline.artifacts.state_path and payload.get("phase") == "finished":
            raise OSError("controlled final manifest failure")
        write(path, payload)

    monkeypatch.setattr(rpg, "write_private_json_file", controlled_state_write)
    assert pipeline.run() == rpg.EXIT_RUNTIME_ERROR
    reports, summary, state, html = pipeline.outputs()
    assert reports[0]["status"] == "PASS"
    assert summary["status"] == "FAIL"
    assert summary["exit_code"] == 3
    assert summary["decision_reason"] == "runtime_error"
    assert 'decision-fail\">FAIL' in html
    # A failed manifest remains partial; the surviving artifacts must not
    # suggest publication readiness just because policy checks passed.
    assert state["phase"] != "finished"
    assert state.get("decision") != "PASS"
    assert any("Failed to finalize run state" in line for line in pipeline.logs)


def test_pipeline_cancel_during_fix_waits_for_safe_boundary_and_requires_reaudit(
    pipeline: PipelineHarness,
) -> None:
    pipeline.config.fix = True
    pipeline.config.confirm_each_repo_fix = False

    def finish_fix(report: rpg.RepoReport) -> rpg.RepoReport:
        pipeline.cancelled = True
        report.fix_actions.append("controlled mechanical action completed")
        return report

    pipeline.fix_effect = finish_fix
    assert pipeline.run() == rpg.EXIT_ABORTED
    reports, summary, state, html = pipeline.outputs()
    assert summary["status"] == state["decision"] == "REVIEW"
    assert summary["completion"] == "aborted"
    assert reports[0]["fix_actions"] == [
        "controlled mechanical action completed",
        "re-audit skipped because the run was cancelled",
    ]
    assert reports[0]["execution_errors"] == []
    assert "re-audit" not in state["performance"]["phases"]
    assert 'decision-review\">REVIEW' in html
    assert pipeline.events == ["discover", "lock", "audit", "fix", "unlock"]
    assert callable(pipeline.guard.cancel_requested)


def test_pipeline_advisory_only_context_agrees_with_run_state(pipeline: PipelineHarness) -> None:
    def advisory(repo: Path) -> rpg.RepoReport:
        report = rpg.RepoReport(name=repo.name, path=str(repo))
        report.exfil_code_indicators = ["src/example.py:1:synthetic advisory"]
        report.finalize()
        return report

    pipeline.audit_effect = advisory
    assert pipeline.run() == rpg.EXIT_OK
    _reports, summary, state, html = pipeline.outputs()
    assert summary["status"] == state["decision"] == "REVIEW"
    assert summary["decision_reason"] == state["decision_reason"] == "advisory"
    assert summary["completion"] == state["completion"] == "complete"
    assert 'decision-review\">REVIEW' in html


def test_pipeline_cancel_after_initial_audit_skips_repair_and_keeps_aborted_guidance(
    pipeline: PipelineHarness,
) -> None:
    pipeline.config.fix = True
    pipeline.config.confirm_each_repo_fix = False

    def cancelled_after_audit(repo: Path) -> rpg.RepoReport:
        report = rpg.RepoReport(name=repo.name, path=str(repo))
        report.finalize()
        pipeline.cancelled = True
        return report

    pipeline.audit_effect = cancelled_after_audit
    assert pipeline.run() == rpg.EXIT_ABORTED
    reports, summary, state, html = pipeline.outputs()
    assert reports[0]["status"] == "PASS"
    assert reports[0]["fix_actions"] == ["repair skipped because the run was cancelled"]
    assert reports[0]["execution_errors"] == []
    assert summary["status"] == state["decision"] == "REVIEW"
    assert summary["completion"] == "aborted"
    assert 'decision-review\">REVIEW' in html
    assert pipeline.events == ["discover", "lock", "audit", "unlock"]


@pytest.mark.parametrize("gui_callback", [False, True])
def test_pipeline_console_cancel_during_repair_finishes_write_then_preserves_evidence(
    pipeline: PipelineHarness, gui_callback: bool,
) -> None:
    pipeline.config.fix = True
    pipeline.config.confirm_each_repo_fix = False
    previous_handler = signal.getsignal(signal.SIGINT)

    def complete_reviewed_write(report: rpg.RepoReport) -> rpg.RepoReport:
        handler = signal.getsignal(signal.SIGINT)
        assert callable(handler)
        handler(signal.SIGINT, None)
        handler(signal.SIGINT, None)
        report.fix_actions.append("controlled protected write finished")
        report.backups_created.append("ExampleRepo/reviewed-backup.bundle")
        return report

    pipeline.fix_effect = complete_reviewed_write
    if gui_callback:
        exit_code = pipeline.run()
    else:
        exit_code = rpg.execute_guard_pipeline(
            config=pipeline.config,
            artifacts=pipeline.artifacts,
            logger=pipeline.logs.append,
            results_dir=pipeline.artifacts.run_dir.parent,
        )
    assert exit_code == rpg.EXIT_ABORTED
    assert signal.getsignal(signal.SIGINT) is previous_handler
    reports, summary, state, html = pipeline.outputs()
    assert reports[0]["backups_created"] == ["ExampleRepo/reviewed-backup.bundle"]
    assert "controlled protected write finished" in reports[0]["fix_actions"]
    assert "re-audit skipped because the run was cancelled" in reports[0]["fix_actions"]
    assert reports[0]["execution_errors"] == []
    assert summary["completion"] == state["completion"] == "aborted"
    assert summary["status"] == state["decision"] == "REVIEW"
    assert 'decision-review\">REVIEW' in html
    assert pipeline.events == ["discover", "lock", "audit", "fix", "unlock"]


@pytest.mark.parametrize("interruption", [AuditCancelled, KeyboardInterrupt])
def test_pipeline_cancelled_reaudit_retains_completed_repair_evidence(
    pipeline: PipelineHarness, interruption: type[BaseException],
) -> None:
    pipeline.config.fix = True
    pipeline.config.confirm_each_repo_fix = False
    audit_calls = 0

    def audit_then_cancel_reaudit(repo: Path) -> rpg.RepoReport:
        nonlocal audit_calls
        audit_calls += 1
        if audit_calls == 2:
            raise interruption("controlled interrupted re-audit")
        report = rpg.RepoReport(name=repo.name, path=str(repo))
        report.finalize()
        return report

    def reviewed_fix(report: rpg.RepoReport) -> rpg.RepoReport:
        report.fix_actions.append("controlled reviewed repair finished")
        report.backups_created.append("ExampleRepo/reviewed-backup.bundle")
        return report

    pipeline.audit_effect = audit_then_cancel_reaudit
    pipeline.fix_effect = reviewed_fix
    assert pipeline.run() == rpg.EXIT_ABORTED
    reports, summary, state, html = pipeline.outputs()
    assert len(reports) == 1
    assert reports[0]["backups_created"] == ["ExampleRepo/reviewed-backup.bundle"]
    assert "controlled reviewed repair finished" in reports[0]["fix_actions"]
    assert any("re-audit incomplete" in action for action in reports[0]["fix_actions"])
    assert reports[0]["execution_errors"] == []
    assert summary["status"] == state["decision"] == "REVIEW"
    assert summary["completion"] == "aborted"
    assert state["performance"]["phases"]["fix"] >= 0
    assert state["performance"]["phases"]["re-audit"] >= 0
    assert 'decision-review\">REVIEW' in html
    assert pipeline.events == ["discover", "lock", "audit", "fix", "audit", "unlock"]


def test_gui_handoff_preserves_runtime_guidance_for_repository_errors(
    pipeline: PipelineHarness,
) -> None:
    def failed_audit(_repo: Path) -> rpg.RepoReport:
        raise RuntimeError("controlled repository audit failure")

    pipeline.audit_effect = failed_audit
    assert pipeline.run() == rpg.EXIT_POLICY_FAILED
    reports, summary, state, html = pipeline.outputs()
    assert summary["status"] == state["decision"] == "FAIL"
    assert summary["decision_reason"] == "runtime_error"
    assert 'decision-fail\">FAIL' in html
    app = object.__new__(rpg.GuiApp)
    app._gui_locale = rpg.GUI_LOCALE_DEFAULT
    app._refresh_reports_tab = lambda: None
    app._remember_last_run_artifacts(
        pipeline.artifacts,
        run_fix=False,
        exit_code=rpg.EXIT_POLICY_FAILED,
        reports_payload=reports,
    )
    counts = app._reports_summary_counts()
    assert counts["execution_errors"] == 1
    assert app._reports_next_action_key(counts, rpg.EXIT_POLICY_FAILED, True) == "next_action_error"
    handoff = app._build_agent_handoff_text()
    assert handoff is not None
    assert app._t("next_action_error") in handoff
    assert app._t("next_action_failed") not in handoff


def test_gui_latest_empty_run_uses_its_own_completion_context(
    pipeline: PipelineHarness,
) -> None:
    pipeline.artifacts.state_path.write_text(
        json.dumps({"phase": "finished", "total_repositories": 2, "completed_repositories": 0}),
        encoding="utf-8",
    )
    app = object.__new__(rpg.GuiApp)
    app._last_audit_reports_payload = [{"name": "PreviousRepo", "status": "PASS"}]
    app._gui_locale = rpg.GUI_LOCALE_DEFAULT
    app._refresh_reports_tab = lambda: None
    app._remember_last_run_artifacts(
        pipeline.artifacts, run_fix=False, exit_code=rpg.EXIT_ABORTED, reports_payload=[],
    )
    counts = app._reports_summary_counts()
    assert counts["total"] == 0
    assert app._last_run_context is not None
    assert {key: app._last_run_context[key] for key in ("phase", "total_repositories", "completed_repositories")} == {
        "phase": "finished", "total_repositories": 2, "completed_repositories": 0,
    }
    assert app._last_audit_reports_payload == [{"name": "PreviousRepo", "status": "PASS"}]
    assert app._reports_status_label(counts, rpg.EXIT_ABORTED) == "ABORTED"
    assert app._reports_next_action_key(counts, rpg.EXIT_ABORTED, True) == "next_action_error"


def test_gui_legacy_run_without_state_does_not_invent_completion(pipeline: PipelineHarness) -> None:
    app = object.__new__(rpg.GuiApp)
    app._gui_locale = rpg.GUI_LOCALE_DEFAULT
    app._refresh_reports_tab = lambda: None
    app._remember_last_run_artifacts(
        pipeline.artifacts,
        run_fix=False,
        exit_code=rpg.EXIT_OK,
        reports_payload=[{"name": "ExampleRepo", "status": "PASS"}],
    )
    counts = app._reports_summary_counts()
    assert app._last_run_context is None
    assert app._reports_status_label(counts, rpg.EXIT_OK) == "PASS/REVIEW"
    assert app._reports_next_action_key(counts, rpg.EXIT_OK, True) == "next_action_review_artifacts"


@pytest.mark.parametrize("locale", ["en", "es-419"])
def test_gui_run_state_button_opens_shared_completion_and_metrics_artifact(
    pipeline: PipelineHarness, locale: str,
) -> None:
    from repo_privacy_guardian.gui import state as gui_state

    state_payload = {
        "phase": "finished",
        "exit_code": 0,
        "completed_repositories": 1,
        "total_repositories": 1,
        "performance": {
            "repositories": {"ExampleRepo": {"scanner_tracked": 0.01}},
            "repository_counters": {"ExampleRepo": {"tracked_files": 3}},
        },
    }
    pipeline.artifacts.state_path.write_text(json.dumps(state_payload), encoding="utf-8")
    app = object.__new__(rpg.GuiApp)
    app._last_run_artifacts = pipeline.artifacts
    app._gui_locale = locale
    opened: list[Path] = []
    app._open_local_path = opened.append
    app.log = pipeline.logs.append
    state_spec = next(spec for spec in gui_state.report_artifact_action_button_specs() if spec.command_arg == "state")
    app._action_button_command(state_spec)()
    assert opened == [pipeline.artifacts.state_path]
    assert json.loads(opened[0].read_text(encoding="utf-8")) == state_payload
    assert app._t(state_spec.text_key).endswith("run_state.json")
    assert "run_state.json" in rpg.GUI_TOOLTIP_TEXT_BY_LOCALE[locale][state_spec.tooltip_key]


@pytest.mark.parametrize("after_artifacts", [False, True])
@pytest.mark.parametrize("run_fix", [False, True])
def test_gui_worker_failure_clears_prior_pass_and_invalidates_repair_authorization(
    pipeline: PipelineHarness,
    monkeypatch: pytest.MonkeyPatch,
    after_artifacts: bool,
    run_fix: bool,
) -> None:
    class Value:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class ImmediateRoot:
        def after(self, _delay: int, callback: Callable[[], None]) -> None:
            callback()

    class FailedValue:
        def get(self) -> str:
            raise RuntimeError("controlled GUI setup failure")

    app = object.__new__(rpg.GuiApp)
    app.root = ImmediateRoot()
    app._gui_locale = rpg.GUI_LOCALE_DEFAULT
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app._last_run_artifacts = rpg.create_run_artifacts(pipeline.artifacts.run_dir.parent / "previous")
    app._last_run_exit_code = rpg.EXIT_OK
    app._last_run_context = {"phase": "finished", "total_repositories": 1, "completed_repositories": 1}
    app._last_run_reports_payload = [{"name": "PreviousRepo", "status": "PASS"}]
    app._last_audit_reports_payload = list(app._last_run_reports_payload)
    app._last_audit_selection_signature = ("PreviousRepo",)
    app._repair_ready = True
    app._repair_tab_name = "Repair"
    app._audit_tab_name = "Audit"
    app.log = pipeline.logs.append
    refreshed: list[bool] = []
    lock_reasons: list[str] = []
    app._refresh_reports_tab = lambda: refreshed.append(True)
    app._set_active_flow_tab = lambda _tab: None

    def lock_repair(*, reason_key: str) -> None:
        app._repair_ready = False
        lock_reasons.append(reason_key)

    app._lock_repair_until_next_audit = lock_repair
    if after_artifacts:
        app.root_var = Value(str(pipeline.config.root))
        app.policy_var = Value(str(pipeline.config.policy))
        app.owner_emails_var = Value("")
        app.allowed_remote_owners_var = Value("")
        app.report_dir_var = Value(str(pipeline.artifacts.run_dir.parent))
        app.report_json_var = Value("")
        app.replace_text_file_var = Value("")
        app._github_owner_value = lambda: None
        app._gui_var_str = lambda _name, default: default
        # Fail while building the configuration after creating the new run.
        app.public_only_var = FailedValue()
        monkeypatch.setattr(rpg, "create_run_artifacts", lambda _directory: pipeline.artifacts)
    else:
        app.root_var = FailedValue()

    app._run_worker(["ExampleRepo"], 50, run_fix, ("ExampleRepo",))
    counts = app._reports_summary_counts()
    assert counts["total"] == 0
    assert app._last_run_reports_payload == []
    assert app._last_run_exit_code == rpg.EXIT_RUNTIME_ERROR
    assert app._last_run_context["execution_error_count"] == 1
    assert app._last_run_artifacts is (pipeline.artifacts if after_artifacts else None)
    assert app._reports_status_label(counts, app._last_run_exit_code) == "ERROR"
    if after_artifacts:
        assert app._reports_next_action_key(counts, app._last_run_exit_code, True) == "next_action_error"
    assert app._last_audit_reports_payload == []
    assert app._last_audit_selection_signature is None
    assert app._repair_ready is False
    assert app._run_in_progress is False
    assert app._active_cancel_token is None
    assert lock_reasons == ["lock_repair_run_again" if run_fix else "lock_repair_failed"]
    assert refreshed == [True]
    assert any("GUI worker failed unexpectedly" in line for line in pipeline.logs)
