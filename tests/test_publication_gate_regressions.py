from __future__ import annotations

import html
import json
import shutil
import subprocess
import sys
from pathlib import Path

import Repo_Privacy_Guardian as rpg


DEFAULT_BASELINE = rpg.render_ignore_baseline()
SUBPROCESS_TEST_TIMEOUT_SECONDS = 120


def _run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TEST_TIMEOUT_SECONDS,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"{cmd}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    return proc


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["git", "-C", str(repo), *args], check=check)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _fixture_secret() -> str:
    return "ghp_" + ("A" * 36)


def _fixture_win_user_path(*parts: str, user: str = "alice") -> str:
    return "\\".join(["C:", "Users", user, *parts])


def _commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


def _init_repo(
    tmp_path: Path,
    name: str,
    *,
    branch: str = "main",
    remote: str | None = None,
    user_email: str = "12345+repoowner@users.noreply.github.com",
) -> Path:
    repo = tmp_path / name
    _run(["git", "init", "-b", branch, str(repo)], check=False)
    if not (repo / ".git").exists():
        _run(["git", "init", str(repo)])
        _git(repo, "checkout", "-b", branch)
    _git(repo, "config", "user.name", "Repo Owner")
    _git(repo, "config", "user.email", user_email)
    if remote:
        _git(repo, "remote", "add", "origin", remote)
    return repo


def _make_guard(
    tmp_path: Path,
    *,
    policy_path: Path | None = None,
    low_confidence_email_mode: str = "informational",
) -> rpg.RepoPublicationGuard:
    return rpg.RepoPublicationGuard(
        root=tmp_path,
        policy_path=policy_path or (tmp_path / "POLICY.md"),
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        owner_name="Repo Owner",
        owner_emails=[],
        redact_third_party=False,
        purge_detected_secret_files=False,
        purge_all_detected_secret_files=False,
        low_confidence_email_mode=low_confidence_email_mode,
        push=False,
        dry_run=False,
        max_matches=50,
        audit_litellm_incident=False,
        audit_github_hardening=False,
        allow_non_owner_push=False,
        allowed_remote_owners=[],
        replace_text_file=None,
        logger=lambda _msg: None,
    )


def test_policy_parser_reads_english_minimum_baseline(tmp_path: Path) -> None:
    policy = tmp_path / "POLICY.md"
    policy.write_text(
        "# Policy\n\n"
        "Minimum baseline:\n\n"
        "- .venv/\n"
        "- __pycache__/\n"
        "- local-only/\n\n"
        "Check currently ignored sensitive paths:\n",
        encoding="utf-8",
    )

    guard = _make_guard(tmp_path, policy_path=policy)

    assert "local-only/" in guard.required_ignore_patterns


def test_policy_parser_keeps_negated_baseline_after_env_wildcard(tmp_path: Path) -> None:
    policy = tmp_path / "POLICY.md"
    policy.write_text(
        "# Policy\n\n"
        "Minimum baseline:\n\n"
        "- .env\n"
        "- .env.*\n"
        "- !.env.example\n\n"
        "Check currently ignored sensitive paths:\n",
        encoding="utf-8",
    )

    guard = _make_guard(tmp_path, policy_path=policy)

    assert ".env.*" in guard.required_ignore_patterns
    assert "!.env.example" in guard.required_ignore_patterns
    assert guard.required_ignore_patterns.index(".env.*") < guard.required_ignore_patterns.index("!.env.example")


def test_env_example_is_allowed_as_tracked_template_file(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "env-template")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / ".env.example", "API_BASE_URL=https://example.invalid\n")
    _write(repo / "README.md", "template repo\n")
    _commit_all(repo, "add env template")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.status == "PASS"
    assert report.tracked_but_ignored == []
    assert report.secret_file_candidates == []
    assert report.history_sensitive_added == []


def test_secret_taxonomy_keeps_low_confidence_and_safe_examples_non_blocking(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "secret-taxonomy-safe")
    generic_value = "synthetic-review-token" * 2
    high_shape_fixture = "ghp_" + ("A" * 36)
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "src" / "settings.py", f'api_key="{generic_value}"\n')
    _write(repo / "tests" / "fixtures" / "secrets.txt", f"token={high_shape_fixture}\n")
    _write(repo / "README.md", "postgres://user:pass@example.invalid/db\n")
    _commit_all(repo, "add synthetic secret taxonomy examples")

    report = _make_guard(tmp_path).audit_repo(repo)

    assert report.tracked_secret_matches == []
    assert report.history_secret_matches == []
    assert report.tracked_secret_low_confidence
    assert report.history_secret_low_confidence
    assert report.tracked_secret_fixture_matches
    assert report.history_secret_fixture_matches
    assert report.tracked_secret_documentation_matches
    assert report.history_secret_documentation_matches
    assert "secret-like patterns in tracked files" not in report.failures
    assert "secret-like patterns in history patches" not in report.failures


def test_secret_taxonomy_blocks_modern_provider_tokens_in_source(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "secret-taxonomy-high")
    provider_token = "glpat-" + ("A" * 24)
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "src" / "service.py", f'TOKEN = "{provider_token}"\n')
    _commit_all(repo, "add synthetic provider token")

    report = _make_guard(tmp_path).audit_repo(repo)

    assert report.tracked_secret_matches
    assert report.tracked_secret_high_confidence == report.tracked_secret_matches
    assert "secret-like patterns in tracked files" in report.failures


def test_git_metadata_credentialed_remote_is_blocking_and_redacted(tmp_path: Path) -> None:
    credentialed_remote = "https://svc:" + ("P" * 16) + "@github.com/example/repo.git"
    repo = _init_repo(tmp_path, "secret-taxonomy-remote", remote=credentialed_remote)
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "remote metadata\n")
    _commit_all(repo, "add readme")

    report = _make_guard(tmp_path).audit_repo(repo)
    payload = rpg.sanitize_report_for_export(report)

    assert report.git_metadata_secret_matches
    assert "secret-like patterns in git metadata" in report.failures
    assert "svc:" not in str(payload["origin_url"])
    assert rpg.REDACTED_SECRET in str(payload["origin_url"])


def test_git_metadata_generic_credential_config_is_advisory_and_redacted(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "secret-taxonomy-git-config")
    generic_secret = "synthetic-review-token" * 2
    _git(repo, "config", "credential.password", generic_secret)
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "local config metadata\n")
    _commit_all(repo, "add readme")

    report = _make_guard(tmp_path).audit_repo(repo)
    payload = rpg.sanitize_report_for_export(report)

    assert report.git_metadata_secret_matches == []
    assert report.git_metadata_secret_low_confidence
    assert "secret-like patterns in git metadata" not in report.failures
    assert generic_secret not in str(payload["git_metadata_secret_low_confidence"])
    assert rpg.REDACTED_SECRET in str(payload["git_metadata_secret_low_confidence"])


def test_private_commit_metadata_blocks_when_owner_cannot_be_inferred(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "metadata-no-origin", user_email="owner.real@privacy.dev")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "private metadata\n")
    _commit_all(repo, "private metadata commit")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.unexpected_emails
    assert report.unexpected_emails_owned_repo == report.unexpected_emails
    assert report.unexpected_emails_third_party_repo == []
    assert "unexpected commit metadata emails in owned repository" in report.failures


def test_malformed_commit_identity_token_blocks_owned_repo(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "metadata-malformed-owned", user_email="owner at privacy dot dev")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "malformed identity\n")
    _commit_all(repo, "malformed metadata commit")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.unexpected_identity_tokens == ["owner at privacy dot dev"]
    assert report.unexpected_identity_tokens_owned_repo == ["owner at privacy dot dev"]
    assert report.unexpected_identity_tokens_third_party_repo == []
    assert "unexpected commit metadata identity tokens in owned repository" in report.failures


def test_malformed_commit_identity_token_is_informational_for_third_party_repo(tmp_path: Path) -> None:
    repo = _init_repo(
        tmp_path,
        "metadata-malformed-third-party",
        remote="https://github.com/external/example.git",
        user_email="owner at privacy dot dev",
    )
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "malformed identity third-party\n")
    _commit_all(repo, "malformed metadata commit")

    guard = rpg.RepoPublicationGuard(
        root=tmp_path,
        policy_path=tmp_path / "POLICY.md",
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        owner_name="Repo Owner",
        owner_emails=[],
        redact_third_party=False,
        purge_detected_secret_files=False,
        purge_all_detected_secret_files=False,
        low_confidence_email_mode="informational",
        push=False,
        dry_run=False,
        max_matches=50,
        audit_litellm_incident=False,
        audit_github_hardening=False,
        allow_non_owner_push=False,
        allowed_remote_owners=["axeljackal"],
        replace_text_file=None,
        logger=lambda _msg: None,
    )
    report = guard.audit_repo(repo)

    assert report.unexpected_identity_tokens == ["owner at privacy dot dev"]
    assert report.unexpected_identity_tokens_owned_repo == []
    assert report.unexpected_identity_tokens_third_party_repo == ["owner at privacy dot dev"]
    assert "unexpected commit metadata identity tokens in owned repository" not in report.failures


def test_history_email_classification_keeps_readme_examples_low_confidence(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "history-low-confidence")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "Contact example: helper@privacy.dev\n")
    _commit_all(repo, "doc email example")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.tracked_email_low_confidence
    assert report.history_email_low_confidence
    assert report.history_email_high_confidence == []


def test_test_fixture_email_examples_do_not_block_release_profile(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "fixture-email-release")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(
        repo / "tests" / "test_contact_fixture.py",
        "def test_contact_fixture():\n"
        "    assert 'helper@privacy.dev'.endswith('@privacy.dev')\n",
    )
    _commit_all(repo, "test fixture email example")

    guard = _make_guard(tmp_path, low_confidence_email_mode="blocking")
    report = guard.audit_repo(repo)

    assert report.status == "PASS"
    assert report.tracked_email_fixture_matches
    assert report.history_email_fixture_matches
    assert report.tracked_email_low_confidence == []
    assert report.history_email_low_confidence == []
    assert "low-confidence email matches configured as blocking" not in report.failures


def test_dirty_worktree_blocks_publication_gate(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "dirty-repo")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "clean\n")
    _commit_all(repo, "baseline")
    _write(repo / "README.md", "clean\nmodified\n")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.status == "FAIL"
    assert "working tree is not clean" in report.failures


def test_execute_guard_pipeline_marks_fix_errors_as_failures(tmp_path: Path, monkeypatch) -> None:
    class FakeGuard:
        def __init__(self, **_kwargs) -> None:
            self.rewrite_personal_paths = False

        def discover_repositories(self, repo_filters, public_only):
            del repo_filters, public_only
            return [tmp_path / "repo-a"]

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            report = rpg.RepoReport(name=repo.name, path=str(repo))
            report.finalize()
            return report

        def apply_fixes(self, repo: Path, report: rpg.RepoReport) -> rpg.RepoReport:
            del repo
            report.fix_errors.append("push blocked: simulated failure")
            return report

    monkeypatch.setattr(rpg, "RepoPublicationGuard", FakeGuard)

    config = rpg.GuardRunConfig(
        mode="cli",
        root=tmp_path,
        policy=tmp_path / "POLICY.md",
        repos=["repo-a"],
        public_only=False,
        fix=True,
        push=False,
        dry_run=False,
        redact_third_party_emails=False,
        purge_detected_secret_files=False,
        purge_all_detected_secret_files=False,
        low_confidence_email_mode="informational",
        owner_name="Repo Owner",
        owner_emails=[],
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        max_matches=50,
        open_report=False,
        confirm_each_repo_fix=True,
        allow_non_owner_push=False,
        allowed_remote_owners=[],
        report_json=None,
    )
    artifacts = rpg.create_run_artifacts(tmp_path / "Audit_Results")
    lines: list[str] = []

    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=lines.append,
        results_dir=tmp_path / "Audit_Results",
    )

    payload = json.loads(artifacts.json_path.read_text(encoding="utf-8"))[0]
    assert exit_code == 2
    assert payload["status"] == "FAIL"
    assert "fix execution errors occurred" in payload["failures"]


def test_exfil_indicators_remain_advisory_by_default(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "exfil-advisory")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "main.py", 'import urllib.request\nurllib.request.urlopen("https://collector.example")\n')
    _commit_all(repo, "add outbound code")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)
    guidance_level, guidance_risk, _consequence, guidance_suggestion = rpg.repo_user_guidance(report)
    severity, _score, highlights = rpg.classify_repo_severity(report)

    assert report.status == "PASS"
    assert report.exfil_code_indicators
    assert guidance_level == "REVIEW"
    assert "advisory" in guidance_risk.lower()
    assert "does not change pass/fail" in guidance_suggestion.lower()
    assert severity == "OK"
    assert any("advisory" in item.lower() for item in highlights)


def test_exfil_indicator_filters_ignore_imports_and_detector_scaffolding() -> None:
    assert rpg.is_exfil_indicator_noise("import urllib.request") is True
    assert rpg.line_has_exfil_indicator("import urllib.request") is False
    assert (
        rpg.line_has_exfil_indicator(
            'r"requests\\.|httpx|aiohttp|urllib|urlopen|websockets|socket\\.|"'
        )
        is False
    )
    assert rpg.line_has_exfil_indicator('r"XMLHttpRequest"') is False
    assert rpg.line_has_exfil_indicator(
        'assert rpg.line_has_exfil_indicator(\'requests.post(endpoint, json=payload)\') is True'
    ) is False
    assert rpg.line_has_exfil_indicator('"pattern": "*requests.post*",') is False
    assert rpg.line_has_exfil_indicator('rule = {"pattern": "*requests.post*"}') is False
    assert rpg.line_has_exfil_indicator("urllib.request.Request(url)") is False


def test_exfil_indicator_keeps_active_network_sinks_and_contextual_terms() -> None:
    assert rpg.line_has_exfil_indicator('urllib.request.urlopen("https://collector.example")') is True
    assert rpg.line_has_exfil_indicator('requests.post(endpoint, json=payload)') is True
    assert rpg.line_has_exfil_indicator(
        'requests.post(endpoint, json={"pattern": "*safe*"})'
    ) is True
    assert rpg.line_has_exfil_indicator('const send = fetch("https://collector.example")') is True
    assert rpg.line_has_exfil_indicator('webhook = "https://collector.example/hooks/release"') is True
    assert rpg.line_has_exfil_indicator("analytics_enabled = True") is False


def test_exfil_indicator_audit_ignores_library_import_noise_in_repo_code(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "exfil-noise")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(
        repo / "main.py",
        (
            "import urllib.request\n"
            "EXFIL_CODE_RE = re.compile(\n"
            '    r"requests\\\\.|httpx|aiohttp|urllib|urlopen|websockets|socket\\\\.|"\n'
            ")\n"
            "parsed = urllib.request.Request(url)\n"
        ),
    )
    _commit_all(repo, "add exfil noise only")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.exfil_code_indicators == []


def test_exfil_indicator_audit_ignores_detector_meta_and_test_fixtures(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "exfil-test-meta")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(
        repo / "tests" / "test_meta.py",
        (
            "def test_meta():\n"
            "    _write(repo / 'main.py', 'import urllib.request\\nurllib.request.urlopen(\"https://collector.example\")\\n')\n"
            "    assert rpg.line_has_exfil_indicator('requests.post(endpoint, json=payload)') is True\n"
            '    rule = {"pattern": "*requests.post*"}\n'
            "    report.exfil_code_indicators = ['main.py:2:urllib.request.urlopen(\"https://collector.example\")']\n"
        ),
    )
    _commit_all(repo, "add exfil detector meta only")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.exfil_code_indicators == []


def test_persisted_artifacts_redact_sensitive_values(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path / "Audit_Results")
    logger = rpg.RunLogger(artifacts.log_path)
    secret = _fixture_secret()
    email = "owner.real@privacy.dev"
    win_path = _fixture_win_user_path("Secrets")

    report = rpg.RepoReport(name="redaction-demo", path=win_path)
    report.clean_status = f"## main\n M README.md {email} {secret} {win_path}"
    report.tracked_secret_matches = [f"app.py:1:{secret}"]
    report.tracked_email_matches = [f"README.md:1:{email}"]
    report.tracked_path_matches = [f"README.md:1:{win_path}"]
    report.exfil_code_indicators = ['main.py:2:urllib.request.urlopen("https://collector.example")']
    report.finalize()

    rpg.persist_run_outputs(
        reports=[report],
        artifacts=artifacts,
        root_path=tmp_path,
        policy_path=tmp_path / "POLICY.md",
        run_settings={"mode": "cli", "exfil_indicator_mode": rpg.EXFIL_INDICATOR_MODE},
        logger=logger,
    )

    for artifact_name in ("report.json", "report.html", "run.log"):
        content = (artifacts.run_dir / artifact_name).read_text(encoding="utf-8")
        assert secret not in content
        assert email not in content
        assert "alice" not in content
        if artifact_name == "report.json":
            assert rpg.REDACTED_SECRET in content
            assert rpg.REDACTED_EMAIL in content
        elif artifact_name == "report.html":
            assert html.escape(rpg.REDACTED_SECRET) in content
            assert html.escape(rpg.REDACTED_EMAIL) in content


def test_cli_smoke_passes_on_clean_repo(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "cli-smoke")
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "smoke\n")
    _commit_all(repo, "baseline")

    report_dir = Path.cwd() / "Audit_Results" / f"pytest-cli-smoke-{tmp_path.name}"
    shutil.rmtree(report_dir, ignore_errors=True)
    try:
        proc = _run(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "Repo_Privacy_Guardian.py"),
                "--root",
                str(tmp_path),
                "--repos",
                "cli-smoke",
                "--report-dir",
                str(report_dir),
                "--yes",
                "--no-open-report",
            ],
            check=False,
        )

        run_dirs = sorted([p for p in report_dir.iterdir() if p.is_dir()])
        payload = json.loads((run_dirs[-1] / "report.json").read_text(encoding="utf-8"))[0]
        assert proc.returncode == 0
        assert payload["status"] == "PASS"
    finally:
        shutil.rmtree(report_dir, ignore_errors=True)


def test_audit_repo_uses_upstream_head_for_non_main_branch(tmp_path: Path) -> None:
    remote = tmp_path / "branch-master-remote.git"
    _run(["git", "init", "--bare", "--initial-branch=master", str(remote)])

    repo = _init_repo(tmp_path, "branch-master", branch="master", remote=str(remote))
    _write(repo / ".gitignore", DEFAULT_BASELINE)
    _write(repo / "README.md", "tracked master branch\n")
    _commit_all(repo, "master branch commit")
    _git(repo, "push", "-u", "origin", "master")

    guard = _make_guard(tmp_path)
    report = guard.audit_repo(repo)

    assert report.branch == "master"
    assert report.origin_head == report.head
