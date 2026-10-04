from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

import Repo_Privacy_Guardian as rpg
from repo_privacy_guardian import agent_summary, reporting
from repo_privacy_guardian.gui import state as gui_state
from repo_privacy_guardian.run_decision import evaluate_run_decision


COMPLETE: dict[str, object] = {
    "phase": "finished",
    "total_repositories": 1,
    "completed_repositories": 1,
}


@pytest.mark.parametrize(
    ("exit_code", "context", "report_status", "category", "expected", "completion", "reason"),
    [
        (3, {"phase": "finished", "total_repositories": 1, "completed_repositories": 0}, None, None, "FAIL", "incomplete", "runtime_error"),
        (1, {"phase": "finished", "total_repositories": 2, "completed_repositories": 1}, "PASS", None, "REVIEW", "aborted", "aborted"),
        (2, COMPLETE, "PASS", None, "FAIL", "complete", "policy_failure"),
        (0, COMPLETE, "FAIL", None, "FAIL", "complete", "policy_failure"),
        (0, COMPLETE, "PASS", "exfil_code_indicators", "REVIEW", "complete", "advisory"),
        (0, COMPLETE, "PASS", "github_hardening_accepted_risks", "PASS", "complete", "complete"),
        (0, COMPLETE, "PASS", None, "PASS", "complete", "complete"),
        (0, {"phase": "finished", "total_repositories": 0, "completed_repositories": 0}, None, None, "REVIEW", "incomplete", "incomplete"),
        (0, COMPLETE, None, None, "REVIEW", "incomplete", "incomplete"),
        (0, {"phase": "finished", "total_repositories": 2, "completed_repositories": 1}, "PASS", None, "REVIEW", "incomplete", "incomplete"),
        (0, None, "PASS", None, "REVIEW", "unknown", "incomplete"),
        (None, None, "PASS", None, "REVIEW", "unknown", "incomplete"),
        (1, COMPLETE, "FAIL", None, "FAIL", "aborted", "policy_failure"),
        (0, COMPLETE, "PASS", "execution_errors", "FAIL", "complete", "runtime_error"),
    ],
)
def test_shared_run_decision_matrix(
    tmp_path: Path,
    exit_code: int | None,
    context: dict[str, object] | None,
    report_status: str | None,
    category: str | None,
    expected: str,
    completion: str,
    reason: str,
) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path / "outputs")
    reports: list[rpg.RepoReport] = []
    if report_status is not None:
        report = rpg.RepoReport(name="ExampleRepo", path="ExampleRepo", status=report_status)
        if category:
            setattr(report, category, ["synthetic reviewed signal"])
        reports.append(report)
    payload = [rpg.sanitize_report_for_export(report) for report in reports]
    summary = agent_summary.build_agent_summary(
        reports_payload=payload,
        artifacts=artifacts,
        root_path=Path("repositories"),
        policy_path=Path("POLICY.md"),
        run_settings={},
        exit_code=exit_code,
        run_context=context,
    )
    html = reporting.render_html_report(
        reports=reports,
        artifacts=artifacts,
        root_path=Path("repositories"),
        policy_path=Path("POLICY.md"),
        run_settings={},
        finished_at=datetime(2026, 10, 4),
        exit_code=exit_code,
        run_context=context,
    )
    counts = {
        "total": len(reports),
        "failed": int(report_status == "FAIL"),
        "blocking": 1 if category == "execution_errors" else 0,
        "manual": 1 if category == "exfil_code_indicators" else 0,
    }
    # Execution errors are provided by the shared run context in the GUI.
    gui_context = dict(context or {})
    if category == "execution_errors":
        gui_context["execution_error_count"] = 1
    gui_decision = gui_state.reports_run_decision(counts, exit_code, run_context=gui_context)
    assert summary["status"] == gui_decision.status == expected
    assert summary["completion"] == gui_decision.completion == completion
    assert summary["decision_reason"] == gui_decision.reason == reason
    assert f'decision-badge decision-{expected.lower()}\">{expected}</span>' in html
    assert f"<strong>Completion:</strong> {completion}" in html
    assert summary["next_action"] == gui_decision.next_action
    handoff = agent_summary.format_agent_summary_handoff(summary)
    assert f"status: {expected}" in handoff
    assert f"completion: {completion}" in handoff
    assert f"exit_code: {exit_code}" in handoff


def test_repository_status_without_bucket_entries_still_blocks(tmp_path: Path) -> None:
    summary = agent_summary.build_agent_summary(
        reports_payload=[{"name": "ExampleRepo", "status": "FAIL"}],
        artifacts=rpg.create_run_artifacts(tmp_path),
        root_path=Path("repositories"),
        policy_path=Path("POLICY.md"),
        run_settings={},
        exit_code=0,
        run_context=COMPLETE,
    )
    repositories = summary["repositories"]
    assert isinstance(repositories, list)
    assert repositories[0]["decision"] == "FAIL"
    assert summary["counts"]["blocking_findings"] == 0


@pytest.mark.parametrize(
    ("exit_code", "context", "manual", "expected_key"),
    [
        (0, COMPLETE, 0, "next_action_pass"),
        (0, COMPLETE, 1, "next_action_manual"),
        (0, None, 0, "next_action_review_artifacts"),
        (2, COMPLETE, 0, "next_action_failed"),
        (3, COMPLETE, 0, "next_action_error"),
        (1, COMPLETE, 0, "next_action_error"),
    ],
)
def test_gui_guidance_uses_shared_completion(
    exit_code: int,
    context: dict[str, object] | None,
    manual: int,
    expected_key: str,
) -> None:
    counts = {"total": 1, "failed": 0, "blocking": 0, "manual": manual}
    assert gui_state.reports_next_action_key(
        counts,
        exit_code,
        has_artifacts=True,
        exit_ok=0,
        exit_policy_failed=2,
        exit_runtime_error=3,
        exit_aborted=1,
        run_context=context,
    ) == expected_key


def test_completion_context_rejects_malformed_and_sensitive_fields() -> None:
    decision = evaluate_run_decision(
        exit_code=0,
        run_context={
            "phase": ["finished"],
            "total_repositories": True,
            "completed_repositories": -1,
            "detail": "operator-private-value",
        },
    )
    assert decision.status == "REVIEW"
    assert decision.completion == "unknown"
    assert "operator-private-value" not in json.dumps(decision.completion_context())


@pytest.mark.parametrize(
    ("context", "reason"),
    [
        ({**COMPLETE, "policy_failed": True}, "policy_failure"),
        ({**COMPLETE, "execution_error_count": 1}, "runtime_error"),
    ],
)
def test_global_failure_context_blocks_clean_counts(context: dict[str, object], reason: str) -> None:
    decision = evaluate_run_decision(exit_code=0, run_context=context)
    assert decision.status == "FAIL"
    assert decision.reason == reason


@pytest.mark.parametrize(
    ("exit_code", "context", "expected_badge", "expected_action"),
    [
        (0, COMPLETE, "PASS", "next_action_pass"),
        (0, None, "PASS/REVIEW", "next_action_review_artifacts"),
        (0, {**COMPLETE, "completed_repositories": 0}, "PASS/REVIEW", "next_action_review_artifacts"),
        (0, {**COMPLETE, "policy_failed": True}, "FAIL", "next_action_failed"),
        (0, {**COMPLETE, "execution_error_count": 1}, "ERROR", "next_action_error"),
        (3, COMPLETE, "ERROR", "next_action_error"),
        (1, COMPLETE, "ABORTED", "next_action_error"),
    ],
)
def test_gui_badge_and_guidance_share_completion(
    exit_code: int,
    context: dict[str, object] | None,
    expected_badge: str,
    expected_action: str,
) -> None:
    counts = {"total": 1, "failed": 0, "blocking": 0, "manual": 0}
    state = gui_state.reports_run_presentation_state(
        has_artifacts=True,
        counts=counts,
        exit_code=exit_code,
        run_action="Audit",
        artifact_paths_text="outputs/report.json",
        repair_summary_text="1 audited repository",
        empty_badge_text="Last run",
        empty_summary_text="No run yet",
        empty_paths_text="No artifacts",
        exit_ok=0,
        exit_policy_failed=2,
        exit_runtime_error=3,
        exit_aborted=1,
        run_context=context,
    )
    assert state.badge_text == expected_badge
    assert state.next_action_key == expected_action


def test_late_runtime_failure_refreshes_guidance_without_rewriting_exports(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path / "outputs")
    report = rpg.RepoReport(name="ExampleRepo", path="ExampleRepo")
    report.finalize()
    export_path = tmp_path / "external-export.json"
    reporting.persist_run_outputs(
        reports=[report],
        artifacts=artifacts,
        root_path=Path("repositories"),
        policy_path=Path("POLICY.md"),
        run_settings={},
        logger=lambda _message: None,
        optional_json_export=str(export_path),
        exit_code=0,
        run_context=COMPLETE,
    )
    original_report = artifacts.json_path.read_bytes()
    export_path.write_text("operator retained export", encoding="utf-8")
    reporting.refresh_run_guidance(
        reports=[report],
        artifacts=artifacts,
        root_path=Path("repositories"),
        policy_path=Path("POLICY.md"),
        run_settings={},
        logger=lambda _message: None,
        exit_code=3,
        run_context=COMPLETE,
    )
    summary = json.loads(artifacts.agent_summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "FAIL"
    assert summary["decision_reason"] == "runtime_error"
    assert "runtime/tooling" in summary["next_action"]
    assert 'decision-fail\">FAIL' in artifacts.html_path.read_text(encoding="utf-8")
    assert artifacts.json_path.read_bytes() == original_report
    assert export_path.read_text(encoding="utf-8") == "operator retained export"


def test_refresh_attempts_summary_when_html_destination_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path)
    write = rpg.write_private_text_file

    def controlled_write(path: Path, text: str) -> None:
        if path == artifacts.html_path:
            raise OSError("controlled destination failure")
        write(path, text)

    monkeypatch.setattr(rpg, "write_private_text_file", controlled_write)
    with pytest.raises(RuntimeError, match="guidance artifacts"):
        reporting.refresh_run_guidance(
            reports=[],
            artifacts=artifacts,
            root_path=Path("repositories"),
            policy_path=Path("POLICY.md"),
            run_settings={},
            logger=lambda _message: None,
            exit_code=3,
            run_context={"phase": "finished", "total_repositories": 1, "completed_repositories": 0},
        )
    summary = json.loads(artifacts.agent_summary_path.read_text(encoding="utf-8"))
    assert summary["status"] == "FAIL"


def test_persistence_keeps_report_array_and_redacts_diagnostics(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path)
    report = rpg.RepoReport(name="ExampleRepo", path="ExampleRepo")
    synthetic_user_path = "/".join(("C:", "Users", "synthetic-user"))
    report.execution_errors = [f"private@example.invalid at {synthetic_user_path}/diagnostic.log"]
    report.finalize()
    reporting.persist_run_outputs(
        reports=[report],
        artifacts=artifacts,
        root_path=Path("repositories"),
        policy_path=Path("POLICY.md"),
        run_settings={},
        logger=lambda _message: None,
        exit_code=3,
        run_context={**COMPLETE, "detail": "untrusted sensitive diagnostic"},
    )
    assert isinstance(json.loads(artifacts.json_path.read_text(encoding="utf-8")), list)
    summary = json.loads(artifacts.agent_summary_path.read_text(encoding="utf-8"))
    assert summary["schema_version"] == 1
    assert summary["status"] == "FAIL"
    for path in (artifacts.json_path, artifacts.agent_summary_path, artifacts.html_path):
        text = path.read_text(encoding="utf-8")
        assert "private@example.invalid" not in text
        assert synthetic_user_path not in text
        assert "untrusted sensitive diagnostic" not in text
