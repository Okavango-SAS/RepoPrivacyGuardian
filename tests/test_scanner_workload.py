"""Behavioral parity and cancellation checks for audit-scoped scanning."""

from dataclasses import asdict
from pathlib import Path
import subprocess

import pytest

import Repo_Privacy_Guardian as rpg
from repo_privacy_guardian.metrics import RunMetrics
from repo_privacy_guardian.scanner import AuditCancelled
from repo_privacy_guardian.execution import AuditCommandCancelled


def make_guard(root: Path, *, limit: int = 50, incident: bool = True) -> rpg.RepoPublicationGuard:
    return rpg.RepoPublicationGuard(
        root=root, policy_path=root / "POLICY.md", noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER, owner_name="Synthetic Maintainer",
        owner_emails=[], redact_third_party=False, purge_detected_secret_files=False,
        purge_all_detected_secret_files=False, low_confidence_email_mode="informational",
        push=False, dry_run=True, max_matches=limit, audit_litellm_incident=incident,
        audit_github_hardening=False, allow_non_owner_push=False,
        allowed_remote_owners=[], replace_text_file=None, logger=lambda _message: None,
    )


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    repo = tmp_path / "synthetic-repo"
    repo.mkdir()
    git(repo, "init", "--initial-branch", "main")
    git(repo, "config", "user.name", "Synthetic Maintainer")
    git(repo, "config", "user.email", rpg.DEFAULT_NOREPLY)
    generated_token = "gh" + "p_" + ("A" * 36)
    generated_path = "/" + "home" + "/synthetic-maintainer/project"
    files = {
        ".gitignore": rpg.render_ignore_baseline() + "\n",
        "app.py": (
            'contact = "person@synthetic.test"\n'
            f'token = "{generated_token}"\npath = "{generated_path}"\n'
            'requests.post("https://example.invalid/upload")\n'
        ),
        "requirements.txt": "litellm==1.82.8\nlitellm==1.0\n",
        "docs/example.md": f"token={generated_token}\ncontact=docs@synthetic.test\n",
        "tests/test_example.py": f"token={generated_token}\ncontact=fixture@synthetic.test\n",
        "data-ñ.txt": f"contact=unicode@synthetic.test\npassword=generated-value\npath={generated_path}\n",
        "removed.txt": f"contact=removed@synthetic.test\ntoken={generated_token}\n",
    }
    for name, value in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    (repo / "binary.dat").write_bytes(b"\x00\xff\x00")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "Synthetic initial corpus")
    (repo / "removed.txt").unlink()
    git(repo, "add", "-u")
    git(repo, "commit", "--quiet", "-m", "Synthetic deleted file")
    return repo


@pytest.mark.parametrize("limit", [1, 2, 50])
def test_single_tracked_pass_matches_independent_detectors(corpus: Path, limit: int, monkeypatch) -> None:
    guard = make_guard(corpus.parent, limit=limit)
    expected = {
        "secrets": guard._scan_tracked_secret_taxonomy(corpus),
        "paths": guard._scan_tracked_content(corpus, rpg.PERSONAL_PATH_RE),
        "emails": guard._scan_tracked_non_allowed_emails(corpus),
        "network": guard._scan_network_code_indicators(corpus),
    }
    assert expected["secrets"][0] and expected["secrets"][2] and expected["secrets"][3]
    assert expected["paths"] and expected["emails"] and expected["network"][0]
    previous = rpg.RepoReport(name=corpus.name, path=str(corpus))
    guard._scan_litellm_incident(corpus, previous)
    reads: list[Path] = []
    original_read = rpg.read_text_file_for_scan

    def read_once(path: Path) -> str | None:
        reads.append(path)
        return original_read(path)

    monkeypatch.setattr(rpg, "read_text_file_for_scan", read_once)
    current = rpg.RepoReport(name=corpus.name, path=str(corpus))
    guard._scan_tracked_inventory(corpus, current)
    assert len(reads) == len(set(reads))
    assert (
        current.tracked_secret_high_confidence, current.tracked_secret_low_confidence,
        current.tracked_secret_fixture_matches, current.tracked_secret_documentation_matches,
    ) == expected["secrets"]
    assert current.tracked_path_matches == expected["paths"]
    assert current.tracked_email_matches == expected["emails"]
    assert (current.exfil_code_indicators, current.reviewed_network_indicators) == expected["network"]
    for key in (
        "litellm_reference_hits", "litellm_compromised_reference_hits",
        "litellm_install_command_hits", "litellm_ioc_hits", "litellm_incident_severity",
    ):
        assert getattr(current, key) == getattr(previous, key)
    counters = guard.scanner_metrics.snapshot()["repository_counters"]
    assert counters[corpus.name]["tracked_inventory_calls"] == 1


@pytest.mark.parametrize("limit", [1, 2, 50])
def test_single_history_stream_matches_independent_scopes(corpus: Path, limit: int) -> None:
    guard = make_guard(corpus.parent, limit=limit)
    expected_secrets = guard._scan_history_secret_taxonomy(corpus)
    expected_paths = guard._scan_history_patch(corpus, rpg.PERSONAL_PATH_RE)
    expected_emails = guard._scan_history_non_allowed_emails(corpus)
    expected_files = guard._scan_history_secret_files(corpus)
    assert expected_paths and expected_emails and expected_files
    report = rpg.RepoReport(name=corpus.name, path=str(corpus))
    guard._scan_history_inventory(corpus, report)
    assert (
        report.history_secret_high_confidence, report.history_secret_low_confidence,
        report.history_secret_fixture_matches, report.history_secret_documentation_matches,
    ) == expected_secrets
    assert report.history_path_matches == expected_paths
    assert report.history_email_matches == expected_emails
    assert report.history_secret_files == expected_files
    assert guard._flush_repo_runtime_issues() == []
    assert guard.scanner_metrics.repo_counters[corpus.name]["history_patch_streams"] == 1


def test_audit_inventory_has_no_cross_audit_content_cache(corpus: Path, monkeypatch) -> None:
    guard = make_guard(corpus.parent)
    calls: list[tuple[str, ...]] = []
    original_git = guard._git

    def count_git(repo: Path, *args: str) -> rpg.CommandResult:
        calls.append(args)
        return original_git(repo, *args)

    monkeypatch.setattr(guard, "_git", count_git)
    monkeypatch.setattr(guard, "_read_text", lambda *_args: pytest.fail("eligible tracked gitignore must use its existing decode"))
    first = guard.audit_repo(corpus)
    assert calls.count(("ls-files", "-z")) == 1
    assert calls.count(("log", "--all", "--pretty=format:%ae")) == 1
    assert calls.count(("log", "--all", "--pretty=format:%ce")) == 1
    (corpus / "requirements.txt").write_text("safe-package==1.0\n", encoding="utf-8")
    second = guard.audit_repo(corpus)
    assert len(second.litellm_reference_hits) < len(first.litellm_reference_hits)
    assert calls.count(("ls-files", "-z")) == 2
    assert guard.scanner_metrics.repo_counters[corpus.name]["tracked_inventory_calls"] == 1
    assert not any("content" in key or "body" in key for key in asdict(guard.scanner_metrics))


def test_cancellation_is_cooperative_and_records_failed_phase(corpus: Path, monkeypatch) -> None:
    guard = make_guard(corpus.parent)
    cancelled = False
    original_read = rpg.read_text_file_for_scan

    def cancel_after_read(path: Path) -> str | None:
        nonlocal cancelled
        cancelled = True
        return original_read(path)

    monkeypatch.setattr(rpg, "read_text_file_for_scan", cancel_after_read)
    guard.cancel_requested = lambda: cancelled
    with pytest.raises(AuditCancelled):
        guard.audit_repo(corpus)
    assert guard._audit_active is False
    assert guard.scanner_metrics.repo_timings[corpus.name]["scanner_tracked"] >= 0
    assert guard._flush_repo_runtime_issues() == []
    # An operator stop must not interrupt active mechanical repair commands.
    assert guard._git(corpus, "status", "--short").returncode == 0


def test_public_only_discovery_propagates_cancellation_to_readonly_git(corpus: Path, monkeypatch) -> None:
    guard = make_guard(corpus.parent)
    cancelled = False
    guard.cancel_requested = lambda: cancelled

    class ControlledAdapter:
        def git(self, _repo: Path, *_args: str, cancel_requested=None) -> rpg.CommandResult:
            nonlocal cancelled
            assert cancel_requested is not None
            cancelled = True
            assert cancel_requested()
            raise AuditCommandCancelled("controlled cancellation")

    monkeypatch.setattr(guard, "_command_adapter", lambda: ControlledAdapter())
    monkeypatch.setattr(rpg, "is_public_github_remote", lambda *_args: pytest.fail("cancelled discovery must not make a network request"))
    with pytest.raises(AuditCancelled):
        guard.discover_repositories([corpus.name], public_only=True)
    assert guard._audit_active is False
    assert guard._flush_repo_runtime_issues() == []


def test_metrics_record_failure_merge_and_reject_non_numeric_data() -> None:
    scanner = RunMetrics()
    with pytest.raises(RuntimeError), scanner.measure_repo("synthetic-repo", "scanner_history"):
        raise RuntimeError("controlled failure")
    scanner.add_repo_count("synthetic-repo", "history_patch_lines", 7)
    total = RunMetrics()
    total.merge_scanner(scanner)
    snapshot = total.snapshot()
    assert snapshot["repositories"]["synthetic-repo"]["scanner_history"] >= 0
    assert snapshot["repository_counters"]["synthetic-repo"]["history_patch_lines"] == 7
    for value in (-1, True, "content"):
        with pytest.raises(ValueError):
            scanner.add_repo_count("synthetic-repo", "lines", value)
    with pytest.raises(ValueError):
        scanner.add_repo_count("synthetic-repo", "not a counter")


def test_required_metadata_errors_are_runtime_findings(tmp_path: Path, monkeypatch) -> None:
    guard = make_guard(tmp_path)
    monkeypatch.setattr(guard, "_git", lambda *_args: rpg.CommandResult(2, "", "controlled Git failure"))
    assert guard._unique_commit_metadata_values(tmp_path, "%ae") == []
    assert guard._history_file_matches(tmp_path, "D") == []
    issues = guard._flush_repo_runtime_issues()
    assert len(issues) == 2
    assert all("failed" in issue for issue in issues)
    report = rpg.RepoReport(name="synthetic-repo", path=str(tmp_path), execution_errors=issues)
    report.finalize()
    assert report.status == "FAIL"


def test_ignored_inventory_failure_cannot_disappear(corpus: Path, monkeypatch) -> None:
    guard = make_guard(corpus.parent)
    original_git = guard._git

    def fail_required_inventory(repo: Path, *args: str) -> rpg.CommandResult:
        if args == ("ls-files", "-ci", "--exclude-standard"):
            return rpg.CommandResult(2, "", "controlled inventory failure")
        return original_git(repo, *args)

    monkeypatch.setattr(guard, "_git", fail_required_inventory)
    report = guard.audit_repo(corpus)
    assert any("tracked ignored-file enumeration failed" in issue for issue in report.execution_errors)
    assert report.status == "FAIL"


def test_one_metadata_query_partitions_emails_and_identity_tokens(corpus: Path, monkeypatch) -> None:
    guard = make_guard(corpus.parent)
    fields: list[str] = []

    def metadata_values(_repo: Path, field: str) -> list[str]:
        fields.append(field)
        return [rpg.DEFAULT_NOREPLY, "malformed-identity"]

    monkeypatch.setattr(guard, "_unique_commit_metadata_values", metadata_values)
    report = guard.audit_repo(corpus)
    assert fields == ["%ae", "%ce"]
    assert report.author_emails == report.committer_emails == [rpg.DEFAULT_NOREPLY]
    assert report.author_identity_tokens == report.committer_identity_tokens == ["malformed-identity"]


@pytest.mark.parametrize("outcome", ["preview", "success", "failed_rewrite", "failed_mapping"])
def test_rewrite_always_cleans_private_mapping_files(tmp_path: Path, monkeypatch, outcome: str) -> None:
    guard = make_guard(tmp_path)
    guard.dry_run = outcome == "preview"
    report = rpg.RepoReport(name="synthetic-repo", path=str(tmp_path))
    report.secret_history_purge_paths = [".env"]
    mailmap = tmp_path / "mailmap.txt"
    replacement = tmp_path / "replacement.txt"
    mailmap.write_text("synthetic mapping\n", encoding="utf-8")
    replacement.write_text("synthetic replacement\n", encoding="utf-8")
    restored: list[dict[str, str]] = []
    remotes = {"origin": "https://example.invalid/synthetic/repo.git"}
    monkeypatch.setattr(guard, "_write_mailmap", lambda _report: mailmap)

    def make_replacement(_report: rpg.RepoReport) -> Path:
        if outcome == "failed_mapping":
            raise RuntimeError("controlled mapping failure")
        return replacement

    monkeypatch.setattr(guard, "_write_replace_text_file", make_replacement)
    monkeypatch.setattr(guard, "_save_remotes", lambda _repo: remotes)
    monkeypatch.setattr(guard, "_restore_remotes", lambda _repo, saved: restored.append(saved))
    monkeypatch.setattr(guard, "_ensure_git_filter_repo", lambda: None)

    def rewrite(*_args, **_kwargs) -> None:
        if outcome == "failed_rewrite":
            raise RuntimeError("controlled rewrite failure")
        assert outcome != "preview", "preview must not execute a rewrite"

    monkeypatch.setattr(guard, "_run_checked", rewrite)
    if outcome.startswith("failed"):
        with pytest.raises(RuntimeError, match="controlled"):
            guard._rewrite_history(tmp_path, report)
    else:
        guard._rewrite_history(tmp_path, report)
    assert not mailmap.exists()
    if outcome != "failed_mapping":
        assert not replacement.exists()
    assert restored == ([remotes] if outcome in {"success", "failed_rewrite"} else [])


@pytest.mark.parametrize("rewrite_fails", [True, False])
def test_rewrite_restore_error_preserves_primary_failure(tmp_path: Path, monkeypatch, rewrite_fails: bool) -> None:
    guard = make_guard(tmp_path)
    guard.dry_run = False
    report = rpg.RepoReport(name="synthetic-repo", path=str(tmp_path))
    report.secret_history_purge_paths = [".env"]
    monkeypatch.setattr(guard, "_write_mailmap", lambda _report: None)
    monkeypatch.setattr(guard, "_write_replace_text_file", lambda _report: None)
    monkeypatch.setattr(guard, "_save_remotes", lambda _repo: {})
    monkeypatch.setattr(guard, "_ensure_git_filter_repo", lambda: None)

    def primary_failure(*_args, **_kwargs) -> None:
        if rewrite_fails:
            raise RuntimeError("controlled rewrite failure")

    def restoration_failure(*_args, **_kwargs) -> None:
        raise RuntimeError("controlled restore failure")

    monkeypatch.setattr(guard, "_run_checked", primary_failure)
    monkeypatch.setattr(guard, "_restore_remotes", restoration_failure)
    with pytest.raises(RuntimeError, match="controlled rewrite failure" if rewrite_fails else "failed to restore Git remotes"):
        guard._rewrite_history(tmp_path, report)
    assert len(report.fix_errors) == (1 if rewrite_fails else 0)
    if rewrite_fails:
        assert "restore" in report.fix_errors[0]


def test_remote_restore_never_overwrites_an_unexpected_existing_remote(tmp_path: Path, monkeypatch) -> None:
    guard = make_guard(tmp_path)
    saved = {"origin": "https://example.invalid/expected/repo.git"}
    writes: list[tuple[str, ...]] = []

    def changed_remote(_repo: Path, *args: str) -> rpg.CommandResult:
        if args == ("remote",):
            return rpg.CommandResult(0, "origin\n", "")
        assert args == ("remote", "get-url", "origin")
        return rpg.CommandResult(0, "https://example.invalid/changed/repo.git\n", "")

    monkeypatch.setattr(guard, "_git", changed_remote)
    monkeypatch.setattr(guard, "_git_checked", lambda _repo, *args: writes.append(args))
    with pytest.raises(RuntimeError, match="manual review"):
        guard._restore_remotes(tmp_path, saved)
    assert writes == []


@pytest.mark.parametrize("listing_fails", [True, False])
def test_remote_capture_fails_closed_before_rewrite(tmp_path: Path, monkeypatch, listing_fails: bool) -> None:
    guard = make_guard(tmp_path)

    def fail_capture(_repo: Path, *args: str) -> rpg.CommandResult:
        if args == ("remote",) and not listing_fails:
            return rpg.CommandResult(0, "origin\n", "")
        return rpg.CommandResult(2, "", "controlled capture failure")

    monkeypatch.setattr(guard, "_git", fail_capture)
    with pytest.raises(RuntimeError, match="Unable to capture"):
        guard._save_remotes(tmp_path)


def test_repair_failure_restores_identity_without_push(tmp_path: Path, monkeypatch) -> None:
    guard = make_guard(tmp_path)
    guard.dry_run = False
    guard.cancel_requested = lambda: True
    report = rpg.RepoReport(name="synthetic-repo", path=str(tmp_path), clean_status="## main", fsck_ok=True)
    identity = {"user.name": "Synthetic Maintainer", "user.email": rpg.DEFAULT_NOREPLY}
    events: list[str] = []
    monkeypatch.setattr(guard, "_capture_local_identity", lambda _repo: identity)
    monkeypatch.setattr(guard, "_make_backup_bundle", lambda _repo: tmp_path / "synthetic.bundle")
    monkeypatch.setattr(guard, "_set_local_identity", lambda _repo: events.append("identity"))
    monkeypatch.setattr(guard, "_apply_secret_file_remediation", lambda *_args: events.append("secrets"))
    monkeypatch.setattr(guard, "_remove_tracked_ignored", lambda _repo: [])
    monkeypatch.setattr(guard, "_commit_if_needed", lambda *_args: "none")

    def failed_rewrite(*_args) -> None:
        events.append("rewrite")
        raise RuntimeError("controlled rewrite failure")

    def restore_identity(_repo: Path, saved: dict[str, str]) -> None:
        assert saved == identity
        events.append("restored")

    monkeypatch.setattr(guard, "_rewrite_history", failed_rewrite)
    monkeypatch.setattr(guard, "_restore_local_identity", restore_identity)
    monkeypatch.setattr(guard, "_push_if_requested", lambda *_args: pytest.fail("failed rewrite must not push"))
    guard.apply_fixes(tmp_path, report)
    assert events == ["identity", "secrets", "rewrite", "restored"]
    assert report.backups_created
    assert report.fix_errors == ["controlled rewrite failure"]


@pytest.mark.parametrize("failure_point", ["permissions", "partial_write", "cleanup"])
def test_private_mapping_creation_failure_cleans_only_its_directory(tmp_path: Path, monkeypatch, failure_point: str) -> None:
    created_dir = tmp_path / "repo-publication-guard-controlled"
    outside = tmp_path / "outside.txt"
    outside.write_text("outside must remain intact\n", encoding="utf-8")
    primary = RuntimeError("controlled creation failure")

    def make_directory(*, prefix: str) -> str:
        assert prefix == "repo-publication-guard-"
        created_dir.mkdir()
        return str(created_dir)

    def partial_write(path: Path, _content: str) -> None:
        assert path.parent == created_dir
        path.write_text("synthetic partial mapping\n", encoding="utf-8")
        (created_dir / ".mapping.tmp-controlled").write_text("synthetic partial atomic write\n", encoding="utf-8")
        raise primary

    monkeypatch.setattr(rpg.tempfile, "mkdtemp", make_directory)
    if failure_point == "permissions":
        def fail_permissions(_path: Path) -> None:
            raise primary

        monkeypatch.setattr(rpg, "ensure_private_directory", fail_permissions)
    else:
        monkeypatch.setattr(rpg, "write_private_text_file", partial_write)
    if failure_point == "cleanup":
        original_rmdir = Path.rmdir

        def refuse_cleanup(path: Path) -> None:
            if path == created_dir:
                raise OSError("controlled cleanup failure")
            original_rmdir(path)

        monkeypatch.setattr(Path, "rmdir", refuse_cleanup)
    with pytest.raises(RuntimeError) as raised:
        rpg.create_private_temp_text_file("repo-publication-guard-", "mapping.txt", "synthetic mapping")
    assert raised.value is primary
    assert outside.read_text(encoding="utf-8") == "outside must remain intact\n"
    assert created_dir.exists() == (failure_point == "cleanup")


def test_private_mapping_cleanup_refuses_a_replaced_directory(tmp_path: Path, monkeypatch) -> None:
    created_dir = tmp_path / "repo-publication-guard-controlled"
    replaced = False
    primary = RuntimeError("controlled creation failure")
    original_is_symlink = Path.is_symlink
    original_iterdir = Path.iterdir

    def make_directory(*, prefix: str) -> str:
        del prefix
        created_dir.mkdir()
        return str(created_dir)

    def simulate_replacement(_path: Path, _content: str) -> None:
        nonlocal replaced
        replaced = True
        raise primary

    def is_replaced(path: Path) -> bool:
        return (path == created_dir and replaced) or original_is_symlink(path)

    def refuse_traversal(path: Path):
        assert path != created_dir, "cleanup must not traverse a replaced directory"
        return original_iterdir(path)

    monkeypatch.setattr(rpg.tempfile, "mkdtemp", make_directory)
    monkeypatch.setattr(rpg, "write_private_text_file", simulate_replacement)
    monkeypatch.setattr(Path, "is_symlink", is_replaced)
    monkeypatch.setattr(Path, "iterdir", refuse_traversal)
    with pytest.raises(RuntimeError) as raised:
        rpg.create_private_temp_text_file("repo-publication-guard-", "mapping.txt", "synthetic mapping")
    assert raised.value is primary
    assert created_dir.exists()


@pytest.mark.parametrize("filename", ["", ".", "..", "../outside.txt"])
def test_private_mapping_creation_rejects_non_filename_inputs(tmp_path: Path, monkeypatch, filename: str) -> None:
    monkeypatch.setattr(rpg.tempfile, "mkdtemp", lambda **_kwargs: pytest.fail("invalid filename must not allocate a directory"))
    with pytest.raises(ValueError, match="single filename"):
        rpg.create_private_temp_text_file("repo-publication-guard-", filename, "synthetic mapping")
