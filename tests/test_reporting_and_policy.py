from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import types
from dataclasses import fields
from datetime import datetime
from pathlib import Path

import pytest

import Repo_Privacy_Guardian as rpg
import repo_privacy_guardian_github as rpg_github
from repo_privacy_guardian import config as config_helpers
from repo_privacy_guardian import evidence_taxonomy
from repo_privacy_guardian import execution as execution_helpers
from repo_privacy_guardian import history_parsing
from repo_privacy_guardian import remediation
from repo_privacy_guardian.github_fix_guide import build_github_hardening_fix_guide


def _fixture_secret() -> str:
    return "ghp_" + ("A" * 36)


def _fixture_aws_key() -> str:
    return "AKIA" + ("A" * 16)


def _fixture_stripe_secret() -> str:
    return "sk_live_" + ("A" * 24)


def _fixture_win_user_path(*parts: str, user: str = "alice") -> str:
    return "\\".join(["C:", "Users", user, *parts])


def _fixture_escaped_win_user_path(*parts: str, user: str = "alice") -> str:
    return _fixture_win_user_path(*parts, user=user).replace("\\", "\\\\")


def _fixture_win_user_path_slash(*parts: str, user: str = "alice") -> str:
    return "C:/" + "/".join(["Users", user, *parts])


def _fixture_unix_user_path(root: str, user: str, *parts: str) -> str:
    return "/" + "/".join([root, user, *parts])


def _fixture_repo_cli_path(user: str = "tester") -> str:
    return "c:/" + "/".join(
        [
            "Users",
            user,
            "Documents",
            "Repositorios",
            "RepoPrivacyGuardian",
            ".venv",
            "Scripts",
            "python.exe",
        ]
    )


def _make_report(name: str) -> rpg.RepoReport:
    report = rpg.RepoReport(name=name, path=f"C:/repos/{name}")
    report.origin_url = f"https://github.com/example/{name}.git"
    report.upstream_url = "-"
    report.branch = "main"
    report.head = "abc1234"
    report.origin_head = "abc1234"
    report.clean_status = "## main...origin/main"
    return report


def _make_run_config(**overrides) -> rpg.GuardRunConfig:
    repo_root = Path(__file__).resolve().parents[1]
    base = {
        "mode": "cli",
        "root": repo_root,
        "policy": repo_root / "docs" / "POLICY.md",
        "repos": ["repo-a"],
        "public_only": False,
        "fix": False,
        "push": False,
        "dry_run": False,
        "redact_third_party_emails": False,
        "purge_detected_secret_files": False,
        "purge_all_detected_secret_files": False,
        "rewrite_personal_paths": False,
        "low_confidence_email_mode": "informational",
        "owner_name": "Owner",
        "owner_emails": [],
        "noreply_email": rpg.DEFAULT_NOREPLY,
        "placeholder_email": rpg.DEFAULT_PLACEHOLDER,
        "max_matches": 50,
        "audit_github_hardening": False,
        "open_report": False,
        "confirm_each_repo_fix": True,
        "allow_non_owner_push": False,
        "allowed_remote_owners": [],
        "replace_text_file": None,
        "report_json": None,
    }
    base.update(overrides)
    return rpg.GuardRunConfig(**base)


def _make_guard(root: Path, logger=None) -> rpg.RepoPublicationGuard:
    return rpg.RepoPublicationGuard(
        root=root,
        policy_path=root / "POLICY.md",
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        owner_name="Owner",
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
        allowed_remote_owners=[],
        replace_text_file=None,
        logger=(logger or (lambda _msg: None)),
    )


def test_strict_profile_release_promotes_expected_policy() -> None:
    parser = rpg.make_parser()
    args = parser.parse_args(["--strict-profile", "release", "--audit-github-hardening"])
    config = rpg.build_cli_guard_run_config(args)

    assert config.strict_profile == "release"
    assert config.low_confidence_email_mode == "blocking"
    assert config.github_hardening_findings_blocking is True

    report = _make_report("repo-a")
    report.github_hardening_checked = True
    report.github_hardening_findings = ["Default branch protection is not enabled for main."]
    rpg.apply_report_policy_post_processing(report, config=config, suppression_rules=[])

    assert report.status == "FAIL"
    assert "GitHub hardening findings configured as blocking" in report.failures
    assert report.github_hardening_fix_guide


def test_strict_profile_release_keeps_accepted_github_hardening_risks_non_blocking() -> None:
    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--strict-profile",
            "release",
            "--audit-github-hardening",
            "--accept-github-admin-bypass",
        ]
    )
    config = rpg.build_cli_guard_run_config(args)

    report = _make_report("repo-a")
    report.github_hardening_checked = True
    report.github_hardening_accepted_risks = [
        "GitHub default branch protection: administrators can bypass branch protection. "
        "Accepted by --accept-github-admin-bypass for solo-maintainer operations."
    ]
    rpg.apply_report_policy_post_processing(report, config=config, suppression_rules=[])

    assert report.status == "PASS"
    assert report.failures == []
    assert report.github_hardening_fix_guide == []


def test_strict_profile_audit_only_rejects_writes() -> None:
    errors = rpg.strict_profiles.validate_strict_profile_runtime(
        profile="audit-only",
        fix=True,
        push=False,
    )

    assert errors == ["--strict-profile audit-only cannot be combined with --fix or --push."]


def test_suppressions_apply_only_to_allowed_manual_review_categories(tmp_path: Path) -> None:
    suppression_file = tmp_path / "suppressions.json"
    suppression_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "id": "exfil-doc-example",
                        "category": "exfil_code_indicators",
                        "pattern": "*requests.post*",
                        "reason": "Documented fixture for scanner coverage.",
                        "owner": "security",
                        "expires": "2099-01-01",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rules = rpg.load_configured_suppressions(_make_run_config(suppressions=str(suppression_file)))
    config = _make_run_config()
    report = _make_report("repo-a")
    report.exfil_code_indicators = ["tests/fixtures/exfil.py:12:requests.post(url, json=payload)"]
    report.tracked_secret_matches = [f"src/settings.py:1:{_fixture_secret()}"]

    rpg.apply_report_policy_post_processing(report, config=config, suppression_rules=rules)

    assert report.exfil_code_indicators == []
    assert report.suppressed_findings[0]["category"] == "exfil_code_indicators"
    assert report.tracked_secret_matches
    assert report.status == "FAIL"


def test_suppression_file_rejects_blocking_categories(tmp_path: Path) -> None:
    suppression_file = tmp_path / "bad-suppressions.json"
    suppression_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suppressions": [
                    {
                        "id": "bad-secret",
                        "category": "tracked_secret_matches",
                        "pattern": "*",
                        "reason": "not allowed",
                        "owner": "security",
                        "expires": "2099-01-01",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not suppressible"):
        rpg.load_configured_suppressions(_make_run_config(suppressions=str(suppression_file)))


def test_persist_run_outputs_writes_agent_summary_and_decision_first_html(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path / "Audit_Results")
    config = _make_run_config(agent_summary=True)
    report = _make_report("repo-a")
    report.exfil_code_indicators = ["src/client.py:4:requests.post(url)"]
    report.github_hardening_accepted_risks = [
        "GitHub default branch protection: administrators can bypass branch protection. "
        "Accepted by --accept-github-admin-bypass for solo-maintainer operations."
    ]
    report.finalize()

    rpg.persist_run_outputs(
        reports=[report],
        artifacts=artifacts,
        root_path=config.root,
        policy_path=config.policy,
        run_settings=rpg.build_run_settings(config, tmp_path / "Audit_Results"),
        logger=lambda _msg: None,
        exit_code=rpg.EXIT_OK,
    )

    assert artifacts.agent_summary_path is not None
    summary = json.loads(artifacts.agent_summary_path.read_text(encoding="utf-8"))
    assert summary["schema_version"] == 1
    assert summary["status"] == "REVIEW"
    assert summary["counts"]["accepted_risks"] == 1
    assert summary["repositories"][0]["accepted_risk_categories"] == {
        "github_hardening_accepted_risks": 1
    }
    assert summary["artifacts"]["report_json"] == "report.json"
    assert "Decision first" in artifacts.html_path.read_text(encoding="utf-8")


def _github_ok_repo_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "default_branch": "main",
        "visibility": "public",
        "private": False,
        "archived": False,
        "disabled": False,
        "has_issues": True,
        "has_wiki": False,
        "has_projects": False,
        "allow_auto_merge": False,
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
            "dependabot_security_updates": {"status": "enabled"},
            "dependency_graph": {"status": "enabled"},
        },
    }
    payload.update(overrides)
    return payload


def _github_ok_hardening_response(url: str) -> tuple[object | None, str] | None:
    if url.endswith("/private-vulnerability-reporting"):
        return {"enabled": True}, "http_200"
    if url.endswith("/actions/permissions"):
        return {
            "enabled": True,
            "allowed_actions": "selected",
            "sha_pinning_required": True,
        }, "http_200"
    if url.endswith("/actions/permissions/workflow"):
        return {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        }, "http_200"
    if url.endswith("/automated-security-fixes"):
        return {"enabled": True, "paused": False}, "http_200"
    if "dependabot/alerts" in url or "secret-scanning/alerts" in url:
        return [], "http_200"
    if url.endswith("/immutable-releases"):
        return {"enabled": True, "enforced_by_owner": False}, "http_200"
    if "/branches/" in url and url.endswith("/protection"):
        return {
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "require_code_owner_reviews": True,
                "dismiss_stale_reviews": True,
                "bypass_pull_request_allowances": {
                    "users": [],
                    "teams": [],
                    "apps": [],
                },
            },
            "required_conversation_resolution": {"enabled": True},
            "required_status_checks": {"strict": True, "contexts": ["ci"]},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
            "enforce_admins": {"enabled": True},
        }, "http_200"
    return None


def test_secret_content_patterns_include_specific_provider_tokens() -> None:
    samples = [
        "gho_" + ("A" * 36),
        "github_pat_" + ("A" * 80),
        "glpat-" + ("A" * 24),
        "gldt-" + ("B" * 24),
        "glrt-" + ("C" * 24),
        "glptt-" + ("D" * 24),
        "cfut_" + ("E" * 44),
        "cfat_" + ("F" * 44),
        "https://hooks.slack.com/services/T" + ("A" * 8) + "/B" + ("B" * 8) + "/" + ("C" * 24),
        "https://discord.com/api/webhooks/" + ("1" * 18) + "/" + ("A" * 48),
        "xapp-" + ("A" * 24),
        "xwfp-" + ("B" * 24),
        _fixture_stripe_secret(),
        "rk_live_" + ("A" * 24),
        "sk-proj-" + ("A" * 40),
        "sk-svcacct-" + ("B" * 40),
        "sk-ant-api03-" + ("C" * 40),
        "sk-ant-admin" + ("D" * 40),
        "SG." + ("A" * 22) + "." + ("B" * 43),
        "npm_" + ("A" * 36),
        "123456789:" + ("A" * 35),
        "M" + ("A" * 23) + "." + ("B" * 6) + "." + ("C" * 27),
        "heroku_api_key=" + ("a" * 8) + "-" + ("b" * 4) + "-" + ("c" * 4) + "-" + ("d" * 4) + "-" + ("e" * 12),
        "AccountKey=" + ("A" * 88),
        "aws_secret_access_key=" + ("A" * 40),
        "cloudflare_api_token=" + ("A" * 40),
        "datadog_api_key=" + ("a" * 32),
        "twilio_auth_token=" + ("b" * 32),
        "mailgun_api_key=key-" + ("c" * 32),
        "Authorization: Bearer " + ("A" * 32),
        "postgres://user:" + ("A" * 16) + "@db.example.invalid/app",
        "https://svc:" + ("P" * 16) + "@api.example.invalid/v1",
    ]

    for sample in samples:
        assert rpg.SECRET_CONTENT_RE.search(sample), sample


def test_secret_content_patterns_do_not_block_generic_assignments() -> None:
    generic = 'password="' + ("not-a-real-secret" * 2) + '"'
    assert rpg.SECRET_CONTENT_RE.search(generic) is None


def test_secret_taxonomy_classifies_generic_assignments_and_safe_examples() -> None:
    generic = 'api_key="' + ("synthetic-review-token" * 2) + '"'
    assert rpg.SECRET_CONTENT_RE.search(generic) is None
    assert rpg.LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE.search(generic)

    fixture_context = rpg.classify_secret_match_context(
        "tests/fixtures/secrets.txt",
        "token=ghp_" + ("A" * 36),
    )
    doc_context = rpg.classify_secret_match_context(
        "README.md",
        "postgres://user:pass@example.invalid/db",
    )
    active_context = rpg.classify_secret_match_context(
        "src/settings.py",
        "api_key=" + ("A" * 32),
    )

    assert fixture_context == "fixture"
    assert doc_context == "documentation"
    assert active_context == "active"


def test_history_parsing_extracts_diff_targets_and_patch_change_context() -> None:
    assert (
        history_parsing.parse_git_diff_target(
            "diff --git a/docs/old name.md b/docs/new name.md\n"
        )
        == "docs/new name.md"
    )
    assert history_parsing.parse_git_diff_target("diff --git malformed") is None
    assert history_parsing.extract_patch_change_context("+token=value\n") == "token=value\n"
    assert history_parsing.extract_patch_change_context("-old=value\n") == "old=value\n"
    assert history_parsing.extract_patch_change_context("+++ b/.env\n") is None
    assert history_parsing.extract_patch_change_context("--- a/.env\n") is None
    assert history_parsing.extract_patch_change_context(" context line\n") is None


def test_history_parsing_formats_findings_and_filters_active_secret_files() -> None:
    assert history_parsing.format_history_patch_match(4, "  " + ("x" * 300)) == (
        "L4:" + ("x" * 240)
    )
    assert (
        history_parsing.format_history_email_match(
            line_number=9,
            current_file=None,
            leaked_emails=[
                "owner-b@example.invalid",
                "owner-a@example.invalid",
                "owner-a@example.invalid",
            ],
            line="Contact owner-a@example.invalid and owner-b@example.invalid",
        )
        == (
            "L9:-:owner-a@example.invalid, owner-b@example.invalid:"
            "Contact owner-a@example.invalid and owner-b@example.invalid"
        )
    )
    assert (
        history_parsing.format_history_email_match(
            line_number=9,
            current_file="src/app.py",
            leaked_emails=[],
            line="no leaked email",
        )
        is None
    )

    secret_pattern = re.compile("SECRET")
    assert (
        history_parsing.active_secret_file_from_patch_change(
            current_file=".env",
            line_context="TOKEN=SECRET",
            secret_pattern=secret_pattern,
            classify_secret_match_context=lambda _path, _line: "active",
        )
        == ".env"
    )
    assert (
        history_parsing.active_secret_file_from_patch_change(
            current_file=None,
            line_context="TOKEN=SECRET",
            secret_pattern=secret_pattern,
            classify_secret_match_context=lambda _path, _line: "active",
        )
        is None
    )
    assert (
        history_parsing.active_secret_file_from_patch_change(
            current_file=".env",
            line_context="TOKEN=SAFE",
            secret_pattern=secret_pattern,
            classify_secret_match_context=lambda _path, _line: "active",
        )
        is None
    )
    assert (
        history_parsing.active_secret_file_from_patch_change(
            current_file=".env",
            line_context="TOKEN=SECRET",
            secret_pattern=secret_pattern,
            classify_secret_match_context=lambda _path, _line: "fixture",
        )
        is None
    )


def test_secret_taxonomy_aggregates_buckets_and_preserves_entry_format() -> None:
    high_pattern = re.compile("HIGH")
    low_pattern = re.compile("LOW")
    context_calls: list[tuple[str | None, str]] = []

    def classify_context(rel_path: str | None, snippet: str) -> str:
        context_calls.append((rel_path, snippet))
        if rel_path and rel_path.startswith("tests/"):
            return "fixture"
        if rel_path and rel_path.startswith("docs/"):
            return "documentation"
        return "active"

    buckets = evidence_taxonomy.SecretTaxonomyBuckets()
    assert evidence_taxonomy.append_secret_taxonomy_match(
        buckets=buckets,
        rel_path="src/settings.py",
        line_number=3,
        line="token=HIGH",
        secret_pattern=high_pattern,
        low_confidence_pattern=low_pattern,
        classify_secret_match_context=classify_context,
        max_matches=2,
        history=True,
    ) == evidence_taxonomy.SecretTaxonomyMatch("high_confidence", "L3:src/settings.py:token=HIGH")
    evidence_taxonomy.append_secret_taxonomy_match(
        buckets=buckets,
        rel_path="src/settings.py",
        line_number=4,
        line="api_key=LOW",
        secret_pattern=high_pattern,
        low_confidence_pattern=low_pattern,
        classify_secret_match_context=classify_context,
        max_matches=2,
    )
    evidence_taxonomy.append_secret_taxonomy_match(
        buckets=buckets,
        rel_path="tests/fixtures/example.env",
        line_number=5,
        line="token=HIGH",
        secret_pattern=high_pattern,
        low_confidence_pattern=low_pattern,
        classify_secret_match_context=classify_context,
        max_matches=2,
        history=True,
    )
    evidence_taxonomy.append_secret_taxonomy_match(
        buckets=buckets,
        rel_path="docs/guide.md",
        line_number=6,
        line="token=HIGH",
        secret_pattern=high_pattern,
        low_confidence_pattern=low_pattern,
        classify_secret_match_context=classify_context,
        max_matches=2,
        history=True,
    )
    assert buckets.as_tuple() == (
        ["L3:src/settings.py:token=HIGH"],
        ["src/settings.py:4:api_key=LOW"],
        ["L5:tests/fixtures/example.env:token=HIGH"],
        ["L6:docs/guide.md:token=HIGH"],
    )

    capped = evidence_taxonomy.SecretTaxonomyBuckets(high_confidence=["existing"])
    match = evidence_taxonomy.append_secret_taxonomy_match(
        buckets=capped,
        rel_path=None,
        line_number=7,
        line="HIGH" + ("x" * 300),
        secret_pattern=high_pattern,
        low_confidence_pattern=low_pattern,
        classify_secret_match_context=classify_context,
        max_matches=1,
        history=True,
    )
    assert match is not None
    assert match.entry == "L7:-:" + ("HIGH" + ("x" * 300))[:240]
    assert capped.high_confidence == ["existing"]
    assert context_calls[-1] == (None, ("HIGH" + ("x" * 300))[:240])
    assert (
        evidence_taxonomy.append_secret_taxonomy_match(
            buckets=capped,
            rel_path="src/settings.py",
            line_number=8,
            line="no secret here",
            secret_pattern=high_pattern,
            low_confidence_pattern=low_pattern,
            classify_secret_match_context=classify_context,
            max_matches=1,
        )
        is None
    )


def test_sensitive_filename_patterns_cover_env_provider_and_git_artifacts() -> None:
    sensitive_paths = [
        ".env.production",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".docker/config.json",
        ".aws/credentials",
        ".kube/config",
        "kubeconfig",
        "id_ed25519",
    ]

    for path in sensitive_paths:
        assert rpg.SENSITIVE_FILENAME_RE.search(path), path

    assert rpg.SENSITIVE_FILENAME_RE.search(".env.example") is None


def test_run_logger_writes_file_and_calls_sink(tmp_path: Path) -> None:
    seen: list[str] = []
    logger = rpg.RunLogger(tmp_path / "run.log", sink=seen.append)

    logger("line one")
    logger("line two")

    contents = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "line one" in contents
    assert "line two" in contents
    assert seen == ["line one", "line two"]


def test_run_logger_without_sink(tmp_path: Path) -> None:
    logger = rpg.RunLogger(tmp_path / "run.log")
    logger("no sink")
    assert "no sink" in (tmp_path / "run.log").read_text(encoding="utf-8")


def test_run_logger_redacts_sensitive_content(tmp_path: Path) -> None:
    seen: list[str] = []
    logger = rpg.RunLogger(tmp_path / "run.log", sink=seen.append)
    secret = _fixture_secret()
    win_path = _fixture_win_user_path("repo")
    escaped_win_path = _fixture_escaped_win_user_path("repo")

    logger(
        f"token {secret} "
        "email dev@example.com "
        f"path {win_path} "
        f"json_path {escaped_win_path}"
    )

    content = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert rpg.REDACTED_SECRET in content
    assert rpg.REDACTED_EMAIL in content
    assert "C:\\Users\\<redacted>" in content
    assert "C:\\\\Users\\\\<redacted>" in content
    assert "dev@example.com" not in content
    assert "alice" not in content
    assert all("dev@example.com" not in item for item in seen)


def test_run_logger_falls_back_when_sink_cannot_encode_text(tmp_path: Path, monkeypatch) -> None:
    seen: list[str] = []

    class DummyStdout:
        encoding = "cp1252"

    def fragile_sink(text: str) -> None:
        if "\ufeff" in text:
            raise UnicodeEncodeError("cp1252", text, 0, 1, "cannot encode")
        seen.append(text)

    monkeypatch.setattr(rpg.sys, "stdout", DummyStdout())

    logger = rpg.RunLogger(tmp_path / "run.log", sink=fragile_sink)
    logger("\ufeffprefix line")

    assert seen == ["?prefix line"]
    assert "\ufeffprefix line" in (tmp_path / "run.log").read_text(encoding="utf-8")


def test_run_logger_keeps_file_logging_when_sink_fails(tmp_path: Path) -> None:
    def broken_sink(_text: str) -> None:
        raise RuntimeError("ui sink closed")

    logger = rpg.RunLogger(tmp_path / "run.log", sink=broken_sink)
    logger("durable line")

    assert "durable line" in (tmp_path / "run.log").read_text(encoding="utf-8")


def test_write_private_text_file_fsyncs_parent_after_atomic_replace(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "nested" / "report.json"
    fsynced: list[Path] = []

    monkeypatch.setattr(rpg, "_fsync_parent_directory", fsynced.append)

    rpg.write_private_text_file(target, "{}")

    assert target.read_text(encoding="utf-8") == "{}"
    assert fsynced == [target]


def test_write_json_to_locked_fd_handles_partial_os_writes(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "lock.json"
    fd = os.open(str(target), os.O_RDWR | os.O_CREAT, 0o600)
    real_write = os.write
    write_sizes: list[int] = []

    def partial_write(raw_fd: int, data: bytes | memoryview) -> int:
        chunk_len = max(1, len(data) // 2)
        write_sizes.append(chunk_len)
        return real_write(raw_fd, bytes(data[:chunk_len]))

    monkeypatch.setattr(rpg.os, "write", partial_write)
    try:
        rpg._write_json_to_locked_fd(fd, {"payload": "x" * 200})
    finally:
        rpg._close_fd_safely(fd)

    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["payload"] == "x" * 200
    assert len(write_sizes) > 1


def test_read_text_file_for_scan_skips_symlinked_path(tmp_path: Path, monkeypatch) -> None:
    candidate = tmp_path / "tracked.txt"
    candidate.write_text("ghp_" + ("A" * 36), encoding="utf-8")

    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == candidate:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    assert rpg.read_text_file_for_scan(candidate) is None


def test_read_text_file_for_scan_skips_oversized_path(tmp_path: Path) -> None:
    candidate = tmp_path / "tracked.txt"
    candidate.write_bytes(b"a" * (rpg.MAX_TRACKED_TEXT_SCAN_BYTES + 1))

    assert rpg.read_text_file_for_scan(candidate) is None


def test_probe_command_available_handles_missing_binary() -> None:
    def missing_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        raise FileNotFoundError

    ok, error = rpg.probe_command_available("gh", runner=missing_runner)

    assert ok is False
    assert "Required executable not found: gh" in str(error)


def test_build_system_tool_install_command_prefers_supported_package_manager() -> None:
    win_cmd = rpg.build_system_tool_install_command(
        "gh",
        platform_name="win32",
        which=lambda exe: exe if exe == "winget" else None,
    )
    mac_cmd = rpg.build_system_tool_install_command(
        "git",
        platform_name="darwin",
        which=lambda exe: exe if exe == "brew" else None,
    )

    assert win_cmd == [
        "winget",
        "install",
        "--id",
        "GitHub.cli",
        "-e",
        "--source",
        "winget",
        "--accept-package-agreements",
        "--accept-source-agreements",
    ]
    assert mac_cmd == ["brew", "install", "git"]


def test_build_system_tool_install_command_bootstraps_winget_when_windows_has_no_package_manager() -> None:
    win_cmd = rpg.build_system_tool_install_command(
        "git",
        platform_name="win32",
        which=lambda _exe: None,
    )

    assert win_cmd == [
        "winget",
        "install",
        "--id",
        "Git.Git",
        "-e",
        "--source",
        "winget",
        "--accept-package-agreements",
        "--accept-source-agreements",
    ]


def test_format_install_command_and_install_missing_tooling() -> None:
    issued: list[list[str]] = []

    def fake_runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        issued.append(cmd)
        return rpg.subprocess.CompletedProcess(cmd, 0, "", "")

    checks = [
        rpg.ToolingCheck(
            name="customtkinter",
            state="missing",
            blocking=True,
            detail="missing",
            auto_install_command=["python", "-m", "pip", "install", "customtkinter>=5.2.2,<6"],
        )
    ]

    assert rpg.format_install_command(checks[0].auto_install_command) == "python -m pip install 'customtkinter>=5.2.2,<6'"
    rpg.install_missing_tooling(checks, lambda _msg: None, runner=fake_runner)
    assert issued == [["python", "-m", "pip", "install", "customtkinter>=5.2.2,<6"]]


def test_install_missing_tooling_bootstraps_winget_before_running_install(monkeypatch) -> None:
    issued: list[list[str]] = []

    def fake_runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        issued.append(cmd)
        return rpg.subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(rpg, "ensure_windows_winget_available", lambda logger, runner=fake_runner: True)

    checks = [
        rpg.ToolingCheck(
            name="github-auth",
            state="warning",
            blocking=False,
            detail="missing gh",
            auto_install_command=["winget", "install", "--id", "GitHub.cli"],
        )
    ]

    rpg.install_missing_tooling(checks, lambda _msg: None, runner=fake_runner)

    assert issued == [["winget", "install", "--id", "GitHub.cli"]]


def test_collect_auto_installable_tooling_checks_filters_ready_and_non_blocking() -> None:
    checks = [
        rpg.ToolingCheck(name="git", state="ready", blocking=True, detail="ok"),
        rpg.ToolingCheck(
            name="customtkinter",
            state="missing",
            blocking=True,
            detail="missing",
            auto_install_command=["python", "-m", "pip", "install", "customtkinter"],
        ),
        rpg.ToolingCheck(
            name="gh",
            state="warning",
            blocking=False,
            detail="warn",
            auto_install_command=["winget", "install", "--id", "GitHub.cli"],
        ),
    ]

    blocking_only = rpg.collect_auto_installable_tooling_checks(checks, blocking_only=True)
    all_installable = rpg.collect_auto_installable_tooling_checks(checks, blocking_only=False)

    assert [check.name for check in blocking_only] == ["customtkinter"]
    assert [check.name for check in all_installable] == ["customtkinter", "gh"]


def test_probe_windows_winget_bootstrap_available_requires_powershell() -> None:
    ok, detail = rpg.probe_windows_winget_bootstrap_available(
        platform_name="win32",
        which=lambda _exe: None,
    )

    assert ok is False
    assert "PowerShell" in str(detail)


def test_probe_windows_winget_bootstrap_available_success_and_failure_paths() -> None:
    ok, detail = rpg.probe_windows_winget_bootstrap_available(
        platform_name="win32",
        which=lambda exe: exe if exe == "powershell" else None,
        runner=lambda *args, **kwargs: rpg.subprocess.CompletedProcess(args[0], 0, "", ""),
    )
    assert ok is True
    assert detail is None

    ok, detail = rpg.probe_windows_winget_bootstrap_available(
        platform_name="win32",
        which=lambda exe: exe if exe == "powershell" else None,
        runner=lambda *args, **kwargs: rpg.subprocess.CompletedProcess(args[0], 1, "", "missing cmdlet"),
    )
    assert ok is False
    assert detail == "missing cmdlet"


def test_build_winget_bootstrap_command_variants() -> None:
    assert rpg.build_winget_bootstrap_command(platform_name="linux") is None
    assert rpg.build_winget_bootstrap_command(platform_name="win32", which=lambda _exe: None) is None

    command = rpg.build_winget_bootstrap_command(
        platform_name="win32",
        which=lambda exe: exe if exe == "powershell" else None,
    )

    assert command is not None
    assert command[0] == "powershell"
    assert rpg.WINGET_BOOTSTRAP_URL in command[-1]
    assert rpg.WINGET_PACKAGE_FAMILY_NAME in command[-1]


def test_build_windows_winget_tooling_check_reports_bootstrap_path(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_command_available", lambda executable, **kwargs: (False, f"{executable} missing"))
    monkeypatch.setattr(rpg, "probe_windows_winget_bootstrap_available", lambda **kwargs: (True, None))
    monkeypatch.setattr(
        rpg,
        "build_winget_bootstrap_command",
        lambda **kwargs: ["powershell", "-NoProfile", "-Command", "bootstrap-winget"],
    )

    check = rpg.build_windows_winget_tooling_check(platform_name="win32")

    assert check is not None
    assert check.name == "winget"
    assert check.state == "warning"
    assert check.auto_install_command == ["powershell", "-NoProfile", "-Command", "bootstrap-winget"]
    assert rpg.WINGET_BOOTSTRAP_URL in str(check.install_hint)


def test_ensure_windows_winget_available_paths(monkeypatch) -> None:
    messages: list[str] = []
    monkeypatch.setattr(rpg.sys, "platform", "win32")

    probe_states = iter(
        [
            (False, "missing"),
            (True, None),
        ]
    )
    monkeypatch.setattr(rpg, "probe_command_available", lambda executable, runner=None: next(probe_states))
    monkeypatch.setattr(
        rpg,
        "build_winget_bootstrap_command",
        lambda: ["powershell", "-NoProfile", "-Command", "bootstrap-winget"],
    )

    ok = rpg.ensure_windows_winget_available(
        messages.append,
        runner=lambda *args, **kwargs: rpg.subprocess.CompletedProcess(args[0], 0, "", ""),
    )

    assert ok is True
    assert any("bootstrap completed" in message for message in messages)

    messages.clear()
    monkeypatch.setattr(rpg, "probe_command_available", lambda executable, runner=None: (False, "missing"))
    monkeypatch.setattr(rpg, "build_winget_bootstrap_command", lambda: None)
    ok = rpg.ensure_windows_winget_available(messages.append)
    assert ok is False
    assert any(rpg.WINGET_BOOTSTRAP_URL in message for message in messages)

    messages.clear()
    monkeypatch.setattr(
        rpg,
        "build_winget_bootstrap_command",
        lambda: ["powershell", "-NoProfile", "-Command", "bootstrap-winget"],
    )
    ok = rpg.ensure_windows_winget_available(
        messages.append,
        runner=lambda *args, **kwargs: rpg.subprocess.CompletedProcess(args[0], 1, "", "boom"),
    )
    assert ok is False
    assert any("boom" in message for message in messages)


def test_prompt_gui_tooling_install_accepts_with_tk_popup(monkeypatch) -> None:
    events: list[str] = []

    class DummyRoot:
        def withdraw(self) -> None:
            events.append("withdraw")

        def attributes(self, name: str, value: object) -> None:
            events.append(f"attributes:{name}={value}")

        def destroy(self) -> None:
            events.append("destroy")

    fake_messagebox = types.SimpleNamespace(
        askyesno=lambda title, message, parent=None: events.append(f"prompt:{title}") or ("customtkinter" in message and parent is not None)
    )
    fake_tk = types.SimpleNamespace(
        Tk=lambda: DummyRoot(),
        TclError=RuntimeError,
        messagebox=fake_messagebox,
    )

    monkeypatch.setattr(rpg, "has_desktop_display", lambda: True)
    monkeypatch.setitem(sys.modules, "tkinter", fake_tk)

    checks = [
        rpg.ToolingCheck(
            name="customtkinter",
            state="missing",
            blocking=True,
            detail="GUI dependency customtkinter is not installed.",
            auto_install_command=["python", "-m", "pip", "install", "customtkinter"],
        )
    ]

    accepted = rpg.prompt_gui_tooling_install(checks, lambda _msg: None)

    assert accepted is True
    assert events == [
        "withdraw",
        "attributes:-topmost=True",
        "prompt:Install Missing GUI Tooling",
        "destroy",
    ]


def test_prompt_gui_tooling_install_returns_none_without_promptable_tools(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "has_desktop_display", lambda: True)

    checks = [
        rpg.ToolingCheck(name="git", state="missing", blocking=True, detail="missing"),
        rpg.ToolingCheck(name="customtkinter", state="ready", blocking=True, detail="ready"),
    ]

    assert rpg.prompt_gui_tooling_install(checks, lambda _msg: None) is None


def test_prompt_gui_tooling_install_supports_optional_non_blocking_prompts(monkeypatch) -> None:
    events: list[str] = []

    class DummyRoot:
        def withdraw(self) -> None:
            events.append("withdraw")

        def attributes(self, name: str, value: object) -> None:
            events.append(f"attributes:{name}={value}")

        def destroy(self) -> None:
            events.append("destroy")

    fake_messagebox = types.SimpleNamespace(
        askyesno=lambda title, message, parent=None: events.append(message) or True
    )
    fake_tk = types.SimpleNamespace(
        Tk=lambda: DummyRoot(),
        TclError=RuntimeError,
        messagebox=fake_messagebox,
    )

    monkeypatch.setattr(rpg, "has_desktop_display", lambda: True)
    monkeypatch.setitem(sys.modules, "tkinter", fake_tk)

    checks = [
        rpg.ToolingCheck(
            name="github-auth",
            state="warning",
            blocking=False,
            detail="missing gh",
            auto_install_command=["winget", "install", "--id", "GitHub.cli"],
        )
    ]

    accepted = rpg.prompt_gui_tooling_install(
        checks,
        lambda _msg: None,
        blocking_only=False,
        title="Install GitHub Tooling",
        confirm_question="Install or repair that tooling now?",
    )

    assert accepted is True
    assert any("Install or repair that tooling now?" in item for item in events)


def test_build_github_optional_tooling_checks_include_winget_when_needed(monkeypatch) -> None:
    monkeypatch.setattr(
        rpg,
        "build_windows_winget_tooling_check",
        lambda: rpg.ToolingCheck(name="winget", state="warning", blocking=False, detail="missing", auto_install_command=["powershell", "-NoProfile", "-Command", "bootstrap-winget"]),
    )
    monkeypatch.setattr(
        rpg,
        "build_github_tooling_check",
        lambda: rpg.ToolingCheck(name="github-auth", state="warning", blocking=False, detail="missing gh", auto_install_command=["winget", "install", "--id", "GitHub.cli"]),
    )

    checks = rpg.build_github_optional_tooling_checks()

    assert [check.name for check in checks] == ["winget", "github-auth"]


def test_build_github_optional_tooling_checks_skip_winget_when_github_auth_is_already_ready(monkeypatch) -> None:
    monkeypatch.setattr(
        rpg,
        "build_windows_winget_tooling_check",
        lambda: (_ for _ in ()).throw(AssertionError("winget should not be checked")),
    )
    monkeypatch.setattr(
        rpg,
        "build_github_tooling_check",
        lambda: rpg.ToolingCheck(
            name="github-auth",
            state="ready",
            blocking=False,
            detail="token available",
        ),
    )

    checks = rpg.build_github_optional_tooling_checks()

    assert [check.name for check in checks] == ["github-auth"]


def test_summarize_tooling_checks_counts_blocking_and_warnings() -> None:
    messages: list[str] = []
    checks = [
        rpg.ToolingCheck(name="git", state="ready", blocking=True, detail="ok"),
        rpg.ToolingCheck(name="gh", state="warning", blocking=False, detail="warn", install_hint="gh auth login"),
        rpg.ToolingCheck(name="tk", state="missing", blocking=True, detail="missing"),
    ]

    blocking, warnings = rpg.summarize_tooling_checks(checks, messages.append, include_ready=False)

    assert blocking == 1
    assert warnings == 1
    assert all("git" not in msg for msg in messages)
    assert any("gh auth login" in msg for msg in messages)


def test_summarize_tooling_checks_omits_install_hint_for_ready_entries() -> None:
    messages: list[str] = []
    checks = [
        rpg.ToolingCheck(
            name="git",
            state="ready",
            blocking=True,
            detail="ok",
            install_hint="winget install --id Git.Git -e --source winget",
        ),
    ]

    blocking, warnings = rpg.summarize_tooling_checks(checks, messages.append, include_ready=True)

    assert blocking == 0
    assert warnings == 0
    assert messages == ["[TOOLING] git: READY - ok"]


def test_repo_report_finalize_builds_failures() -> None:
    report = _make_report("repo-a")
    report.unexpected_emails = ["private@example.com"]
    report.tracked_secret_matches = [f"secret.txt:1:{_fixture_aws_key()}"]

    report.finalize()

    assert report.status == "FAIL"
    assert "unexpected commit metadata emails in owned repository" in report.failures
    assert "secret-like patterns in tracked files" in report.failures


def test_repo_report_finalize_blocks_unexpected_identity_tokens() -> None:
    report = _make_report("repo-identity-token")
    report.unexpected_identity_tokens = ["owner at privacy dot dev"]

    report.finalize()

    assert report.status == "FAIL"
    assert "unexpected commit metadata identity tokens in owned repository" in report.failures


def test_repo_report_finalize_with_low_confidence_blocking() -> None:
    report = _make_report("repo-blocking")
    report.low_confidence_email_mode = "blocking"
    report.tracked_email_low_confidence = ["tests/a.py:1:redacted-contributor@example.invalid:assert foo"]

    report.finalize()
    sev, _, highlights = rpg.classify_repo_severity(report)

    assert report.status == "FAIL"
    assert sev == "MEDIUM"
    assert "low-confidence email matches configured as blocking" in report.failures
    assert "Low-confidence email findings are configured as blocking" in highlights


def test_classify_repo_severity_informational_low_confidence_highlight() -> None:
    report = _make_report("repo-info")
    report.low_confidence_email_mode = "informational"
    report.email_confidence_evaluated = True
    report.history_email_low_confidence = ["L1:redacted-contributor@example.invalid:+ assert foo('redacted-contributor@example.invalid')"]
    report.email_ownership_evaluated = True
    report.unexpected_emails_third_party_repo = ["third@example.com"]
    report.finalize()

    sev, _, highlights = rpg.classify_repo_severity(report)

    assert sev == "OK"
    assert "Low-confidence email findings are informational" in highlights
    assert "Unexpected commit metadata emails in third-party repositories (informational)" in highlights


def test_repo_report_finalize_pass_state() -> None:
    report = _make_report("repo-pass")
    report.finalize()
    assert report.status == "PASS"
    assert report.failures == []


def test_create_run_artifacts_handles_collision(tmp_path: Path, monkeypatch) -> None:
    class FixedDateTime:
        @classmethod
        def now(cls) -> datetime:
            return datetime(2026, 4, 7, 12, 0, 0)

    monkeypatch.setattr(rpg, "datetime", FixedDateTime)

    base = tmp_path / "Audit_Results"
    base.mkdir()
    (base / "20260407-120000").mkdir()

    artifacts = rpg.create_run_artifacts(base)

    assert artifacts.run_dir.name == "20260407-120000-01"
    assert artifacts.json_path.name == "report.json"
    assert artifacts.log_path.name == "run.log"
    assert artifacts.html_path.name == "report.html"
    assert artifacts.state_path.name == "run_state.json"


def test_create_run_artifacts_fails_after_collision_budget(tmp_path: Path) -> None:
    def fixed_now() -> datetime:
        return datetime(2026, 4, 7, 12, 0, 0)

    base = tmp_path / "Audit_Results"
    base.mkdir()
    (base / "20260407-120000").mkdir()
    (base / "20260407-120000-01").mkdir()

    with pytest.raises(RuntimeError, match="Unable to create unique run artifacts directory after 2 attempts"):
        rpg.artifact_helpers.create_run_artifacts(
            base,
            ensure_private_directory=rpg.ensure_private_directory,
            path_has_existing_symlink_ancestor=rpg._path_has_existing_symlink_ancestor,
            apply_private_permissions=rpg._apply_private_permissions,
            run_state_filename=rpg.RUN_STATE_FILENAME,
            now_factory=fixed_now,
            max_collision_attempts=2,
        )


def test_audit_results_cleanup_plan_keeps_newest_runs_and_skips_non_runs(tmp_path: Path) -> None:
    base = tmp_path / "Audit_Results"
    base.mkdir()
    for name in ("20260516-120000", "20260517-120000", "20260518-120000"):
        (base / name).mkdir()
    (base / "notes").mkdir()
    (base / "20260518-120000.txt").write_text("not a run directory", encoding="utf-8")

    plan = rpg.build_audit_results_cleanup_plan(base, keep_runs=2)

    assert plan.discovered_count == 3
    assert [path.name for path in plan.kept_run_dirs] == ["20260518-120000", "20260517-120000"]
    assert [path.name for path in plan.removable_run_dirs] == ["20260516-120000"]
    assert sorted(Path(item).name for item in plan.skipped_entries) == ["20260518-120000.txt", "notes"]


def test_audit_results_cleanup_supports_dry_run_then_delete(tmp_path: Path) -> None:
    base = tmp_path / "Audit_Results"
    base.mkdir()
    old_run = base / "20260517-120000"
    new_run = base / "20260518-120000"
    old_run.mkdir()
    new_run.mkdir()

    plan = rpg.build_audit_results_cleanup_plan(base, keep_runs=1)

    dry_run_result = rpg.clean_audit_results(plan, dry_run=True)
    assert dry_run_result.success is True
    assert dry_run_result.deleted_run_dirs == ()
    assert old_run.exists()
    assert new_run.exists()

    delete_result = rpg.clean_audit_results(plan, dry_run=False)
    assert delete_result.success is True
    assert [path.name for path in delete_result.deleted_run_dirs] == ["20260517-120000"]
    assert not old_run.exists()
    assert new_run.exists()


def test_audit_results_cleanup_refuses_non_run_delete_targets(tmp_path: Path) -> None:
    base = tmp_path / "Audit_Results"
    base.mkdir()
    notes_dir = base / "notes"
    notes_dir.mkdir()
    plan = rpg.AuditResultsCleanupPlan(
        base_dir=base,
        keep_runs=0,
        kept_run_dirs=(),
        removable_run_dirs=(notes_dir,),
        skipped_entries=(),
    )

    result = rpg.clean_audit_results(plan, dry_run=False)

    assert result.success is False
    assert notes_dir.exists()
    assert result.failed_deletions
    assert "refusing to remove non-run artifact directory" in result.failed_deletions[0]


def test_audit_results_cleanup_rejects_negative_keep_count(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="keep_runs must be greater than or equal to zero"):
        rpg.build_audit_results_cleanup_plan(tmp_path / "Audit_Results", keep_runs=-1)


def test_run_state_tracker_persists_phase_updates(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path / "Audit_Results")
    config = _make_run_config(root=tmp_path, policy=tmp_path / "POLICY.md")

    tracker = rpg.RunStateTracker(artifacts.state_path, artifacts=artifacts, config=config)
    tracker.update(phase="auditing", current_repository="repo-a", total_repositories=1)

    payload = json.loads(artifacts.state_path.read_text(encoding="utf-8"))
    assert payload["status"] == "running"
    assert payload["phase"] == "auditing"
    assert payload["current_repository"] == "repo-a"
    assert payload["total_repositories"] == 1


def test_process_exists_rejects_invalid_pid_without_liveness_probe(monkeypatch) -> None:
    calls: list[tuple[int, int]] = []

    monkeypatch.setattr(rpg.os, "kill", lambda pid, sig: calls.append((pid, sig)))

    assert rpg.process_exists(-1) is False
    assert rpg.process_exists(0) is False
    assert calls == []


def test_subprocess_and_locking_helpers_cover_non_interactive_defaults(tmp_path: Path) -> None:
    assert rpg.subprocess_stdin() == subprocess.DEVNULL
    assert rpg.subprocess_stdin("y\n") == subprocess.PIPE
    assert rpg.streaming_popen_kwargs()["start_new_session"] is True

    rpg._close_fd_safely(None)

    fd, raw_path = os.open(str(tmp_path / "lock.json"), os.O_RDWR | os.O_CREAT, 0o600), tmp_path / "lock.json"
    try:
        os.write(fd, b"{not-json")
        os.fsync(fd)
        assert rpg._read_json_from_locked_fd(fd) is None
    finally:
        rpg._close_fd_safely(fd)
        raw_path.unlink(missing_ok=True)


def test_process_exists_windows_error_code_paths(monkeypatch) -> None:
    import ctypes

    class DummyKernel:
        def OpenProcess(self, _access, _inherit, _pid):
            return 0

    monkeypatch.setattr(rpg.os, "name", "nt", raising=False)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: DummyKernel(), raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 87, raising=False)
    assert rpg.process_exists(1234) is False

    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    assert rpg.process_exists(1234) is True


def test_process_exists_posix_signal_paths(monkeypatch) -> None:
    monkeypatch.setattr(rpg.os, "name", "posix", raising=False)
    monkeypatch.setattr(
        rpg.os,
        "kill",
        lambda _pid, _signal: (_ for _ in ()).throw(ProcessLookupError()),
    )
    assert rpg.process_exists(1234) is False

    monkeypatch.setattr(
        rpg.os,
        "kill",
        lambda _pid, _signal: (_ for _ in ()).throw(PermissionError()),
    )
    assert rpg.process_exists(1234) is True

    monkeypatch.setattr(
        rpg.os,
        "kill",
        lambda _pid, _signal: (_ for _ in ()).throw(OSError()),
    )
    assert rpg.process_exists(1234) is None

    monkeypatch.setattr(rpg.os, "kill", lambda _pid, _signal: None)
    assert rpg.process_exists(1234) is True


def test_repo_execution_lock_blocks_overlap_across_processes(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo-a"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(rpg, "REPO_LOCK_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(rpg, "REPO_LOCK_RETRY_SECONDS", 0.0)

    child_script = """
import sys
import time
from pathlib import Path
import Repo_Privacy_Guardian as rpg

repo = Path(sys.argv[1])
guard = rpg.RepoPublicationGuard(
    root=repo.parent,
    policy_path=repo.parent / "POLICY.md",
    noreply_email=rpg.DEFAULT_NOREPLY,
    placeholder_email=rpg.DEFAULT_PLACEHOLDER,
    owner_name="Owner",
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
    allowed_remote_owners=[],
    replace_text_file=None,
    logger=lambda _msg: None,
)
lock = guard.acquire_repo_lock(repo)
print("acquired", flush=True)
time.sleep(2)
guard.release_repo_lock(lock)
"""
    proc = subprocess.Popen(
        [sys.executable, "-c", child_script, str(repo)],
        cwd=str(Path(__file__).resolve().parents[1]),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().strip() == "acquired"
        guard = _make_guard(tmp_path)
        with pytest.raises(RuntimeError, match="repository execution lock is busy"):
            guard.acquire_repo_lock(repo)
        stdout, stderr = proc.communicate(timeout=10)
        assert proc.returncode == 0, stderr or stdout
        repo_lock = guard.acquire_repo_lock(repo)
        guard.release_repo_lock(repo_lock)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=10)


def test_repo_execution_lock_reuses_existing_metadata_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo-a"
    git_dir = repo / ".git"
    git_dir.mkdir(parents=True)
    lock_path = git_dir / rpg.REPO_LOCK_FILENAME
    rpg.write_private_json_file(
        lock_path,
        {
            "owner_token": "old-holder",
            "acquired_at": "2000-01-01T00:00:00",
        },
    )
    guard = _make_guard(tmp_path)

    repo_lock = guard.acquire_repo_lock(repo)
    try:
        payload = rpg._read_json_from_locked_fd(repo_lock.lock_fd)
        assert payload is not None
        assert payload["owner_token"] == repo_lock.owner_token
        assert payload["lock_kind"] == "os-advisory-file-lock"
    finally:
        guard.release_repo_lock(repo_lock)

    released_payload = json.loads(lock_path.read_text(encoding="utf-8"))
    assert released_payload["status"] == "released"
    assert released_payload["previous_owner_token"] == repo_lock.owner_token


def test_release_repo_lock_owner_change_still_releases_os_lock(tmp_path: Path) -> None:
    repo = tmp_path / "repo-a"
    git_dir = repo / ".git"
    git_dir.mkdir(parents=True)
    messages: list[str] = []
    guard = _make_guard(tmp_path, logger=messages.append)

    repo_lock = guard.acquire_repo_lock(repo)
    rpg._write_json_to_locked_fd(repo_lock.lock_fd, {"owner_token": "other-holder"})
    guard.release_repo_lock(repo_lock)

    assert any("owner changed before release" in message for message in messages)

    next_lock = guard.acquire_repo_lock(repo)
    guard.release_repo_lock(next_lock)


def test_audit_repo_records_tracked_file_enumeration_failures(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo-a"
    repo.mkdir(parents=True)

    guard = rpg.RepoPublicationGuard(
        root=tmp_path,
        policy_path=tmp_path / "POLICY.md",
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        owner_name="Owner",
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
        allowed_remote_owners=[],
        replace_text_file=None,
        logger=lambda _msg: None,
    )

    def wrapped_git(target_repo: Path, *args: str) -> rpg.CommandResult:
        assert target_repo == repo
        responses = {
            ("remote", "get-url", "origin"): rpg.CommandResult(
                0,
                "https://github.com/example/repo-a.git",
                "",
            ),
            ("remote", "get-url", "upstream"): rpg.CommandResult(1, "", ""),
            ("branch", "--show-current"): rpg.CommandResult(0, "main", ""),
            ("rev-parse", "--short", "HEAD"): rpg.CommandResult(0, "abc1234", ""),
            (
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{upstream}",
            ): rpg.CommandResult(1, "", ""),
            ("status", "--short", "--branch"): rpg.CommandResult(0, "## main...origin/main", ""),
            ("fsck", "--full"): rpg.CommandResult(0, "", ""),
            ("log", "--all", "--pretty=format:%ae"): rpg.CommandResult(
                0,
                "12345+repoowner@users.noreply.github.com\n",
                "",
            ),
            ("log", "--all", "--pretty=format:%ce"): rpg.CommandResult(
                0,
                "12345+repoowner@users.noreply.github.com\n",
                "",
            ),
            ("ls-files", "-z"): rpg.CommandResult(1, "", "fatal: simulated ls-files failure"),
            ("ls-files", "-ci", "--exclude-standard"): rpg.CommandResult(0, "", ""),
            (
                "config",
                "--local",
                "--get-regexp",
                r"^(http\..*\.extraheader|url\..*\.insteadOf|credential\..*)",
            ): rpg.CommandResult(1, "", ""),
            ("log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:"): rpg.CommandResult(
                0,
                "",
                "",
            ),
            ("log", "--all", "--diff-filter=D", "--name-only", "--pretty=format:"): rpg.CommandResult(
                0,
                "",
                "",
            ),
        }
        try:
            return responses[args]
        except KeyError as exc:
            raise AssertionError(f"unexpected git call: {args}") from exc

    monkeypatch.setattr(guard, "_git", wrapped_git)
    monkeypatch.setattr(guard, "_scan_history_patch", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(guard, "_scan_history_non_allowed_emails", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(guard, "_scan_history_secret_files", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(guard, "_history_file_matches", lambda *_args, **_kwargs: [])

    report = guard.audit_repo(repo)

    assert report.status == "FAIL"
    assert any("tracked-file enumeration failed" in issue for issue in report.execution_errors)
    assert "repository execution errors occurred" in report.failures


def test_enforce_results_dir_variants(tmp_path: Path) -> None:
    resolved, forced = rpg.enforce_results_dir(None)
    assert resolved == rpg.DEFAULT_RESULTS_DIR.resolve()
    assert forced is False

    resolved, forced = rpg.enforce_results_dir(rpg.DEFAULT_RESULTS_DIR)
    assert resolved == rpg.DEFAULT_RESULTS_DIR.resolve()
    assert forced is False

    inside = rpg.DEFAULT_RESULTS_DIR / "nested"
    resolved, forced = rpg.enforce_results_dir(inside)
    assert resolved == inside.resolve()
    assert forced is False

    outside = tmp_path / "outside"
    resolved, forced = rpg.enforce_results_dir(outside)
    assert resolved == rpg.DEFAULT_RESULTS_DIR.resolve()
    assert forced is True


def test_enforce_results_dir_preserves_symlinked_requested_path_for_artifact_refusal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    report_dir = tmp_path / "Audit_Results" / "linked-results"
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == report_dir:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    resolved, forced = rpg.enforce_results_dir(report_dir)

    assert resolved == report_dir
    assert forced is False


def test_enforce_results_dir_preserves_symlinked_default_for_artifact_refusal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    default_dir = tmp_path / "Audit_Results"
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == default_dir:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(rpg, "default_results_dir", lambda: default_dir)
    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    resolved, forced = rpg.enforce_results_dir(None)

    assert resolved == default_dir
    assert forced is False


def test_resolve_optional_json_export_path_variants(tmp_path: Path) -> None:
    assert rpg.resolve_optional_json_export_path(None, "report.json") is None

    as_dir = tmp_path / "as_dir"
    path = rpg.resolve_optional_json_export_path(str(as_dir) + "/", "report.json")
    assert path == as_dir / "report.json"

    as_folder_name = tmp_path / "folder_name"
    path = rpg.resolve_optional_json_export_path(str(as_folder_name), "report.json")
    assert path == as_folder_name / "report.json"

    as_file = tmp_path / "custom" / "report.json"
    path = rpg.resolve_optional_json_export_path(str(as_file), "ignored.json")
    assert path == as_file


def test_identity_and_remote_owner_helpers() -> None:
    assert rpg.infer_github_username_from_noreply("12345+octocat@users.noreply.github.com") == "octocat"
    assert rpg.infer_github_username_from_noreply("noreply@github.com") is None

    assert rpg.parse_github_remote_owner("") is None
    assert rpg.parse_github_remote_owner("https://github.com/example/repo.git") == "example"
    assert rpg.parse_github_remote_owner("https://github.com/example/repo.name.git") == "example"
    assert rpg.parse_github_remote_owner("redacted-contributor@example.invalid:example/repo.git") == "example"
    assert rpg.parse_github_remote_owner("redacted-contributor@example.invalid:example/.github.git") == "example"
    assert rpg.parse_github_remote_owner("https://example.com/github.com/example/repo.git") is None
    assert rpg.parse_github_remote_owner("https://gitlab.com/example/repo.git") is None


def test_repo_display_name_handles_named_and_current_root_paths(tmp_path: Path, monkeypatch) -> None:
    named_repo = tmp_path / "repo-a"
    assert rpg.repo_display_name(named_repo) == "repo-a"

    monkeypatch.chdir(tmp_path)
    assert rpg.repo_display_name(Path(".")) == tmp_path.name


def test_parse_github_remote_slug_helper() -> None:
    assert rpg.parse_github_remote_slug("https://github.com/example/repo.git") == ("example", "repo")
    assert rpg.parse_github_remote_slug("git@github.com:example/repo.git") == ("example", "repo")
    assert rpg.parse_github_remote_slug("ssh://git@github.com/example/repo.git") == (
        "example",
        "repo",
    )
    assert rpg.parse_github_remote_slug("https://github.com/example/repo.name.git") == (
        "example",
        "repo.name",
    )
    assert rpg.parse_github_remote_slug("git@github.com:example/.github.git") == (
        "example",
        ".github",
    )
    assert rpg.parse_github_remote_slug("github.com/example/repo.git/") == ("example", "repo")
    assert rpg.parse_github_remote_slug("https://github.com/example/repo.git?ref=main") == (
        "example",
        "repo",
    )
    assert rpg.parse_github_remote_slug("https://github.com/example/repo%2Fextra.git") is None
    assert rpg.parse_github_remote_slug("https://github.com/owner%20space/repo.git") is None
    assert rpg.parse_github_remote_slug("https://example.com/github.com/example/repo.git") is None
    assert rpg.parse_github_remote_slug("https://github.com/example/repo/tree/main") is None
    assert rpg.parse_github_remote_slug("https://gitlab.com/example/repo.git") is None


def test_github_repo_api_url_quotes_path_components() -> None:
    assert rpg.github_repo_api_url("example", "repo.name") == "https://api.github.com/repos/example/repo.name"
    assert (
        rpg.github_repo_api_url("owner space", ".github")
        == "https://api.github.com/repos/owner%20space/.github"
    )


def test_validate_outbound_https_url_allows_only_expected_hosts() -> None:
    assert (
        rpg.validate_outbound_https_url(
            "https://api.github.com/repos/example/repo",
            {"api.github.com"},
        )
        == "https://api.github.com/repos/example/repo"
    )

    with pytest.raises(ValueError, match="only HTTPS URLs are allowed"):
        rpg.validate_outbound_https_url("http://api.github.com/repos/example/repo", {"api.github.com"})

    with pytest.raises(ValueError, match="not in the allowlist"):
        rpg.validate_outbound_https_url("https://example.com/repos/example/repo", {"api.github.com"})


def test_read_github_cli_token_uses_bounded_non_interactive_probe() -> None:
    captured: dict[str, object] = {}

    def fake_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0, stdout="gh-token\n", stderr="")

    token, status = rpg_github.read_github_cli_token(runner=fake_runner)

    assert token == "gh-token"
    assert status == "ready"
    assert captured["cmd"] == ["gh", "auth", "token"]
    assert captured["stdin"] == subprocess.DEVNULL
    assert captured["timeout"] == rpg_github.GITHUB_CLI_AUTH_TIMEOUT_SECONDS


def test_read_github_cli_token_timeout_is_non_fatal() -> None:
    def hanging_runner(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))

    token, status = rpg_github.read_github_cli_token(runner=hanging_runner)

    assert token is None
    assert status == "timeout"


def test_is_public_github_remote_maps_visibility_and_http_failures(monkeypatch) -> None:
    class DummyResponse:
        def __init__(self, payload: dict[str, object], *, status: int = 200) -> None:
            self._payload = payload
            self.status = status

        def read(self) -> bytes:
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self) -> "DummyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            del exc_type, exc, tb
            return False

    captured_urls: list[str] = []

    def private_response(request, timeout=8):  # type: ignore[no-untyped-def]
        del timeout
        captured_urls.append(request.full_url)
        return DummyResponse({"private": True})

    monkeypatch.setattr(rpg.urllib.request, "urlopen", private_response)
    assert rpg.is_public_github_remote("https://github.com/example/private-repo.git") == (
        False,
        "private",
    )
    assert rpg.is_public_github_remote("https://github.com/example/repo.name.git") == (
        False,
        "private",
    )
    assert captured_urls[-1] == "https://api.github.com/repos/example/repo.name"

    def forbidden(request, timeout=8):  # type: ignore[no-untyped-def]
        del request, timeout
        raise rpg.urllib.error.HTTPError(
            "https://api.github.com/repos/example/private-repo",
            403,
            "forbidden",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(rpg.urllib.request, "urlopen", forbidden)
    assert rpg.is_public_github_remote("https://github.com/example/private-repo.git") == (
        None,
        "forbidden_or_rate_limited",
    )


def test_github_api_helpers_map_empty_payloads_and_transport_failures(monkeypatch) -> None:
    class EmptyResponse:
        status = 204

        def read(self) -> bytes:
            return b""

        def __enter__(self) -> "EmptyResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            del exc_type, exc, tb
            return False

    monkeypatch.setattr(
        rpg.urllib.request,
        "urlopen",
        lambda request, timeout=8: EmptyResponse(),  # type: ignore[no-untyped-def]
    )
    assert rpg.github_api_get_json("https://api.github.com/repos/example/repo") == ({}, "http_204")
    assert rpg.github_api_probe_enabled("https://api.github.com/repos/example/repo/vulnerability-alerts") == (
        True,
        "http_204",
    )

    def timed_out(request, timeout=8):  # type: ignore[no-untyped-def]
        del request, timeout
        raise TimeoutError("network timed out")

    monkeypatch.setattr(rpg.urllib.request, "urlopen", timed_out)
    assert rpg.github_api_get_json("https://api.github.com/repos/example/repo") == (
        None,
        "request_failed",
    )
    assert rpg.github_api_probe_enabled("https://api.github.com/repos/example/repo/vulnerability-alerts") == (
        None,
        "request_failed",
    )


def test_fetch_github_owner_repositories_filters_pages_forks_private_and_names() -> None:
    seen_tokens: list[str | None] = []

    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        seen_tokens.append(token)
        parsed = rpg.urllib.parse.urlparse(url)
        page = int(rpg.urllib.parse.parse_qs(parsed.query)["page"][0])
        assert parsed.path == "/" + "users" + "/acme/repos"
        if page == 1:
            return (
                [
                    {
                        "name": "app",
                        "full_name": "acme/app",
                        "clone_url": "https://github.com/acme/app.git",
                        "html_url": "https://github.com/acme/app",
                        "private": False,
                        "fork": False,
                    },
                    {
                        "name": "forked",
                        "full_name": "acme/forked",
                        "clone_url": "https://github.com/acme/forked.git",
                        "html_url": "https://github.com/acme/forked",
                        "private": False,
                        "fork": True,
                    },
                    {
                        "name": "private-app",
                        "full_name": "acme/private-app",
                        "clone_url": "https://github.com/acme/private-app.git",
                        "html_url": "https://github.com/acme/private-app",
                        "private": True,
                        "fork": False,
                    },
                ],
                "http_200",
            )
        return ([], "http_200")

    repos, warnings = rpg_github.fetch_github_owner_repositories(
        "acme",
        token="token-from-env",
        include_forks=False,
        public_only=True,
        repo_names=["app", "private-app", "forked"],
        json_getter=fake_get_json,
    )

    assert warnings == []
    assert [repo.full_name for repo in repos] == ["acme/app"]
    assert seen_tokens == ["token-from-env", "token-from-env"]


def test_fetch_github_owner_repositories_falls_back_to_org_endpoint() -> None:
    paths: list[str] = []

    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        del token
        parsed = rpg.urllib.parse.urlparse(url)
        page = int(rpg.urllib.parse.parse_qs(parsed.query)["page"][0])
        paths.append(parsed.path)
        if parsed.path.startswith("/users/"):
            return (None, "http_404")
        if page > 1:
            return ([], "http_200")
        return (
            [
                {
                    "name": "service",
                    "full_name": "acme-org/service",
                    "clone_url": "https://github.com/acme-org/service.git",
                    "html_url": "https://github.com/acme-org/service",
                    "private": False,
                    "fork": False,
                }
            ],
            "http_200",
        )

    repos, warnings = rpg_github.fetch_github_owner_repositories(
        "acme-org",
        json_getter=fake_get_json,
    )

    assert warnings == []
    assert [repo.full_name for repo in repos] == ["acme-org/service"]
    assert paths[0] == "/" + "users" + "/acme-org/repos"
    assert paths[1] == "/orgs/acme-org/repos"


def test_fetch_github_owner_repositories_fails_closed_on_page_limit() -> None:
    seen_pages: list[int] = []

    def endless_pages(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        del token
        parsed = rpg.urllib.parse.urlparse(url)
        page = int(rpg.urllib.parse.parse_qs(parsed.query)["page"][0])
        seen_pages.append(page)
        return (
            [
                {
                    "name": f"repo-{page}",
                    "full_name": f"acme/repo-{page}",
                    "clone_url": f"https://github.com/acme/repo-{page}.git",
                    "html_url": f"https://github.com/acme/repo-{page}",
                    "private": False,
                    "fork": False,
                }
            ],
            "http_200",
        )

    repos, warnings = rpg_github.fetch_github_owner_repositories(
        "acme",
        json_getter=endless_pages,
    )

    assert repos == []
    assert len(seen_pages) == rpg_github.GITHUB_REPOS_MAX_PAGES
    assert any("page limit" in warning for warning in warnings)


def test_resolve_github_hardening_token_prefers_tool_specific_env() -> None:
    env = {
        "GH_TOKEN": "gh-token",
        "GITHUB_TOKEN": "github-token",
        "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN": "guardian-token",
    }

    assert rpg.resolve_github_hardening_token(env) == "guardian-token"


def test_resolve_github_hardening_token_falls_back_to_github_cli(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "read_github_cli_token", lambda runner=None: ("gh-cli-token", "ready"))

    assert rpg.resolve_github_hardening_token({}) == "gh-cli-token"


def test_github_helper_module_audit_resolves_token_by_default(tmp_path: Path, monkeypatch) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("* @owner\n", encoding="utf-8")
    seen_tokens: list[str | None] = []

    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        seen_tokens.append(token)
        response = _github_ok_hardening_response(url)
        if response is not None:
            return response
        return _github_ok_repo_payload(), "http_200"

    monkeypatch.setattr(
        rpg_github,
        "resolve_github_hardening_token",
        lambda env=None, runner=None, read_cli_token=None: "gh-admin-token",
    )

    findings, warnings = rpg_github.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/repo.git",
        token=None,
        json_getter=fake_get_json,
        probe_enabled=lambda url, token=None: (True, "http_204"),
    )

    assert findings == []
    assert warnings == []
    assert seen_tokens
    assert all(token == "gh-admin-token" for token in seen_tokens)


def test_build_cli_tooling_checks_warns_when_rewrite_tooling_missing(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda runner=None: (True, None))
    monkeypatch.setattr(rpg, "probe_git_filter_repo_available", lambda: False)

    checks = rpg.build_cli_tooling_checks(_make_run_config(fix=True))

    rewrite_check = next(check for check in checks if check.name == "git-filter-repo")
    assert rewrite_check.state == "warning"
    assert "Rewrite-based remediations may fail" in rewrite_check.detail
    assert rewrite_check.auto_install_command == [
        rpg.sys.executable,
        "-m",
        "pip",
        "install",
        *rpg.REMEDIATION_INSTALL_PACKAGES,
    ]


def test_build_cli_tooling_checks_skip_winget_when_not_relevant(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda runner=None: (True, None))
    monkeypatch.setattr(
        rpg,
        "build_system_tool_install_command",
        lambda tool_name, platform_name=None, which=None: [
            "winget",
            "install",
            "--id",
            "Git.Git",
            "-e",
            "--source",
            "winget",
        ],
    )
    monkeypatch.setattr(
        rpg,
        "build_windows_winget_tooling_check",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("winget should not be checked")),
    )

    checks = rpg.build_cli_tooling_checks(_make_run_config())

    assert [check.name for check in checks] == ["git"]


def test_build_cli_tooling_checks_include_winget_once_when_git_and_github_need_it(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda runner=None: (False, "missing git"))
    monkeypatch.setattr(
        rpg,
        "build_system_tool_install_command",
        lambda tool_name, platform_name=None, which=None: [
            "winget",
            "install",
            "--id",
            "Git.Git" if tool_name == "git" else "GitHub.cli",
            "-e",
            "--source",
            "winget",
        ],
    )
    monkeypatch.setattr(
        rpg,
        "build_windows_winget_tooling_check",
        lambda **kwargs: rpg.ToolingCheck(
            name="winget",
            state="warning",
            blocking=False,
            detail="missing winget",
            auto_install_command=["powershell", "-NoProfile", "-Command", "bootstrap-winget"],
        ),
    )
    monkeypatch.setattr(
        rpg,
        "build_github_tooling_check",
        lambda: rpg.ToolingCheck(
            name="github-auth",
            state="warning",
            blocking=False,
            detail="missing gh",
            auto_install_command=["winget", "install", "--id", "GitHub.cli"],
        ),
    )

    checks = rpg.build_cli_tooling_checks(_make_run_config(audit_github_hardening=True))

    assert [check.name for check in checks] == ["winget", "git", "github-auth"]


def test_build_cli_tooling_checks_include_github_auth_for_remote_owner_without_rewrite(
    monkeypatch,
) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda runner=None: (True, None))
    monkeypatch.setattr(
        rpg,
        "probe_git_filter_repo_available",
        lambda: (_ for _ in ()).throw(AssertionError("rewrite tooling should not be checked")),
    )
    monkeypatch.setattr(
        rpg,
        "build_github_tooling_check",
        lambda: rpg.ToolingCheck(
            name="github-auth",
            state="warning",
            blocking=False,
            detail="missing gh auth",
            install_hint="gh auth login",
        ),
    )

    checks = rpg.build_cli_tooling_checks(_make_run_config(github_owner="acme", fix=False))

    assert [check.name for check in checks] == ["git", "github-auth"]
    assert checks[-1].install_hint == "gh auth login"


def test_build_github_tooling_check_warns_when_no_token_or_gh(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "resolve_github_hardening_token", lambda env=None, runner=None: None)
    monkeypatch.setattr(rpg, "probe_command_available", lambda executable, version_args=("--version",), runner=None: (False, "missing"))
    monkeypatch.setattr(
        rpg,
        "build_system_tool_install_command",
        lambda tool_name, platform_name=None, which=None: [
            "winget",
            "install",
            "--id",
            "GitHub.cli",
            "-e",
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ],
    )

    check = rpg.build_github_tooling_check()

    assert check.state == "warning"
    assert "GitHub hardening audit will be partial" in check.detail
    assert check.auto_install_command == [
        "winget",
        "install",
        "--id",
        "GitHub.cli",
        "-e",
        "--source",
        "winget",
        "--accept-package-agreements",
        "--accept-source-agreements",
    ]


def test_build_github_tooling_check_uses_authenticated_github_cli(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "resolve_github_hardening_token", lambda env=None, runner=None: None)
    monkeypatch.setattr(
        rpg,
        "probe_command_available",
        lambda executable, version_args=("--version",), runner=None: (True, None),
    )
    monkeypatch.setattr(rpg, "read_github_cli_token", lambda runner=None: ("gh-cli-token", "ready"))

    check = rpg.build_github_tooling_check()

    assert check.state == "ready"
    assert "authenticated GitHub CLI token" in check.detail


def test_build_gui_tooling_checks_reports_missing_python_gui_bits(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda runner=None: (True, None))
    monkeypatch.setattr(rpg, "has_desktop_display", lambda platform_name=None, env=None: True)
    monkeypatch.setattr(
        rpg,
        "probe_python_module_available",
        lambda module_name: module_name == "tkinter",
    )

    checks = rpg.build_gui_tooling_checks()

    tkinter_check = next(check for check in checks if check.name == "tkinter")
    customtkinter_check = next(check for check in checks if check.name == "customtkinter")
    tkinterdnd2_check = next(check for check in checks if check.name == "tkinterdnd2")
    assert tkinter_check.state == "ready"
    assert customtkinter_check.state == "missing"
    assert customtkinter_check.auto_install_command == [
        rpg.sys.executable,
        "-m",
        "pip",
        "install",
        *rpg.GUI_INSTALL_PACKAGES,
    ]
    assert tkinterdnd2_check.state == "missing"
    assert tkinterdnd2_check.blocking is False
    assert tkinterdnd2_check.auto_install_command == [
        rpg.sys.executable,
        "-m",
        "pip",
        "install",
        *rpg.GUI_DRAG_DROP_INSTALL_PACKAGES,
    ]


def test_build_gui_tooling_checks_reports_optional_drag_drop_ready(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda runner=None: (True, None))
    monkeypatch.setattr(rpg, "has_desktop_display", lambda platform_name=None, env=None: True)
    monkeypatch.setattr(
        rpg,
        "probe_python_module_available",
        lambda module_name: module_name in {"tkinter", "customtkinter", "tkinterdnd2"},
    )

    checks = rpg.build_gui_tooling_checks()

    tkinterdnd2_check = next(check for check in checks if check.name == "tkinterdnd2")
    assert tkinterdnd2_check.state == "ready"
    assert tkinterdnd2_check.blocking is False
    assert tkinterdnd2_check.auto_install_command is None


def test_build_gui_tooling_checks_skip_winget_when_git_is_ready(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda runner=None: (True, None))
    monkeypatch.setattr(
        rpg,
        "build_system_tool_install_command",
        lambda tool_name, platform_name=None, which=None: ["winget", "install", "--id", "Git.Git"],
    )
    monkeypatch.setattr(rpg, "has_desktop_display", lambda platform_name=None, env=None: True)
    monkeypatch.setattr(rpg, "probe_python_module_available", lambda module_name: True)
    monkeypatch.setattr(
        rpg,
        "build_windows_winget_tooling_check",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("winget should not be checked")),
    )

    checks = rpg.build_gui_tooling_checks()

    assert [check.name for check in checks] == ["git", "desktop-session", "tkinter", "customtkinter", "tkinterdnd2"]


def test_audit_github_release_hardening_warns_when_admin_checks_are_skipped(tmp_path: Path, monkeypatch) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("* @owner\n", encoding="utf-8")
    seen_urls: list[str] = []
    seen_tokens: list[str | None] = []

    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        seen_urls.append(url)
        seen_tokens.append(token)
        if url.endswith("/private-vulnerability-reporting"):
            return {"enabled": True}, "http_200"
        return _github_ok_repo_payload(security_and_analysis=None), "http_200"

    monkeypatch.setattr(rpg, "github_api_get_json", fake_get_json)

    findings, warnings = rpg.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/repo.git",
        token="",
    )

    assert findings == []
    assert any("Token-gated GitHub hardening checks were skipped" in item for item in warnings)
    assert any("Unauthenticated coverage is limited" in item for item in warnings)
    assert all(token == "" for token in seen_tokens)
    assert any(url.endswith("/private-vulnerability-reporting") for url in seen_urls)
    assert not any("/branches/" in url for url in seen_urls)
    assert not any("/actions/permissions" in url for url in seen_urls)
    assert not any("/secret-scanning/alerts" in url for url in seen_urls)
    assert not any("/dependabot/alerts" in url for url in seen_urls)


def test_audit_github_release_hardening_reports_missing_controls(tmp_path: Path, monkeypatch) -> None:
    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        assert token == "gh-admin-token"
        if url.endswith("/actions/permissions"):
            return ({"enabled": False, "allowed_actions": "all", "sha_pinning_required": False}, "http_200")
        if url.endswith("/actions/permissions/workflow"):
            return (
                {
                    "default_workflow_permissions": "write",
                    "can_approve_pull_request_reviews": True,
                },
                "http_200",
            )
        if url.endswith("/automated-security-fixes"):
            return ({"enabled": False, "paused": False}, "http_200")
        if "dependabot/alerts" in url:
            return (
                [
                    {
                        "number": 1,
                        "state": "open",
                        "dependency": {"package": {"name": "private-package-name"}},
                    }
                ],
                "http_200",
            )
        if "secret-scanning/alerts" in url:
            return ([{"number": 2, "state": "open", "secret": "raw-secret-value"}], "http_200")
        if url.endswith("/immutable-releases"):
            return (None, "http_404")
        if url.endswith("/private-vulnerability-reporting"):
            return ({"enabled": False}, "http_200")
        if url.endswith("/branches/main/protection"):
            return (
                {
                    "required_pull_request_reviews": {
                        "required_approving_review_count": 0,
                        "require_code_owner_reviews": False,
                        "dismiss_stale_reviews": False,
                        "bypass_pull_request_allowances": {
                            "users": [{"login": "release-admin"}],
                            "teams": [],
                            "apps": [],
                        },
                    },
                    "required_conversation_resolution": {"enabled": False},
                    "required_status_checks": None,
                    "allow_force_pushes": {"enabled": True},
                    "allow_deletions": {"enabled": True},
                    "enforce_admins": {"enabled": False},
                },
                "http_200",
            )
        return (
            _github_ok_repo_payload(
                visibility="private",
                private=True,
                archived=True,
                disabled=True,
                has_issues=False,
                has_wiki=True,
                has_projects=True,
                allow_auto_merge=True,
                security_and_analysis={
                    "secret_scanning": {"status": "disabled"},
                    "secret_scanning_push_protection": {"status": "disabled"},
                    "dependabot_security_updates": {"status": "disabled"},
                    "dependency_graph": {"status": "disabled"},
                },
            ),
            "http_200",
        )

    monkeypatch.setattr(rpg, "github_api_get_json", fake_get_json)
    monkeypatch.setattr(
        rpg,
        "github_api_probe_enabled",
        lambda url, token=None: (False, "http_404"),
    )

    findings, warnings = rpg.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/repo.git",
        token="gh-admin-token",
    )

    assert warnings == []
    assert any(".github/CODEOWNERS is missing" in item for item in findings)
    assert any("repository is private" in item for item in findings)
    assert any("repository is archived" in item for item in findings)
    assert any("repository is disabled" in item for item in findings)
    assert any("issues are disabled" in item for item in findings)
    assert any("wiki is enabled" in item for item in findings)
    assert any("projects are enabled" in item for item in findings)
    assert any("auto-merge is enabled" in item for item in findings)
    assert any("secret scanning status is disabled" in item for item in findings)
    assert any("secret scanning push protection status is disabled" in item for item in findings)
    assert any("Dependabot security updates status is disabled" in item for item in findings)
    assert any("dependency graph status is disabled" in item for item in findings)
    assert any("private vulnerability reporting is not enabled" in item for item in findings)
    assert any("approving review is not required" in item for item in findings)
    assert any("code owner reviews are not required" in item for item in findings)
    assert any("stale reviews are not dismissed" in item for item in findings)
    assert any("bypass allowances are configured" in item for item in findings)
    assert any("conversation resolution is not required" in item for item in findings)
    assert any("required status checks are not configured" in item for item in findings)
    assert any("force pushes are allowed" in item for item in findings)
    assert any("branch deletion is allowed" in item for item in findings)
    assert any("administrators can bypass branch protection" in item for item in findings)
    assert any("Actions are disabled" in item for item in findings)
    assert any("all external actions are allowed" in item for item in findings)
    assert any("SHA pinning is not required" in item for item in findings)
    assert any("workflow permissions are broader than read-only" in item for item in findings)
    assert any("allow PR approval" in item for item in findings)
    assert any("vulnerability alerts are disabled" in item for item in findings)
    assert any("automated security fixes are disabled or paused" in item for item in findings)
    assert any("Dependabot alerts" in item and "open alert" in item for item in findings)
    assert any("secret scanning alerts" in item and "open alert" in item for item in findings)
    assert any("immutable releases are not enabled" in item for item in findings)
    assert not any("raw-secret-value" in item for item in findings)
    assert not any("private-package-name" in item for item in findings)


def test_github_hardening_metadata_classifier_is_pure_and_reports_findings() -> None:
    classification = rpg_github.classify_github_repository_metadata(
        _github_ok_repo_payload(
            visibility="private",
            private=True,
            archived=True,
            disabled=True,
            has_issues=False,
            has_wiki=True,
            has_projects=True,
            allow_auto_merge=True,
            security_and_analysis={
                "secret_scanning": {"status": "disabled"},
                "secret_scanning_push_protection": {"status": "disabled"},
                "dependabot_security_updates": {"status": "disabled"},
                "dependency_graph": {"status": "disabled"},
            },
        ),
        "http_200",
        resolved_token="gh-admin-token",
    )

    assert classification.warnings == ()
    assert any("repository is private" in item for item in classification.findings)
    assert any("repository is archived" in item for item in classification.findings)
    assert any("repository is disabled" in item for item in classification.findings)
    assert any("issues are disabled" in item for item in classification.findings)
    assert any("wiki is enabled" in item for item in classification.findings)
    assert any("projects are enabled" in item for item in classification.findings)
    assert any("auto-merge is enabled" in item for item in classification.findings)
    assert any("secret scanning status is disabled" in item for item in classification.findings)
    assert any("secret scanning push protection status is disabled" in item for item in classification.findings)
    assert any("Dependabot security updates status is disabled" in item for item in classification.findings)
    assert any("dependency graph status is disabled" in item for item in classification.findings)


def test_github_hardening_branch_protection_classifier_splits_accepted_risks() -> None:
    payload = {
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "require_code_owner_reviews": True,
            "dismiss_stale_reviews": True,
            "bypass_pull_request_allowances": {
                "users": [],
                "teams": [],
                "apps": [],
            },
        },
        "required_conversation_resolution": {"enabled": True},
        "required_status_checks": {
            "strict": True,
            "contexts": [
                "CLI smoke + release contract (automatic, ubuntu-latest, py3.13)",
                "stale required context",
            ],
        },
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "enforce_admins": {"enabled": False},
    }

    strict_classification = rpg_github.classify_github_default_branch_protection(
        payload,
        "http_200",
        accept_admin_bypass=False,
        local_workflows_present=True,
        automatic_workflow_check_names=[
            "CLI smoke + release contract (automatic, ubuntu-latest, py3.13)"
        ],
    )
    accepted_classification = rpg_github.classify_github_default_branch_protection(
        payload,
        "http_200",
        accept_admin_bypass=True,
        local_workflows_present=True,
        automatic_workflow_check_names=[
            "CLI smoke + release contract (automatic, ubuntu-latest, py3.13)"
        ],
    )

    assert any(
        "administrators can bypass branch protection" in item
        for item in strict_classification.findings
    )
    assert strict_classification.accepted_risks == ()
    assert not any(
        "administrators can bypass branch protection" in item
        for item in accepted_classification.findings
    )
    assert any(
        "administrators can bypass branch protection" in item
        for item in accepted_classification.accepted_risks
    )
    assert any(
        "contexts not produced by local automatic workflows" in item
        for item in accepted_classification.findings
    )
    assert any("stale required context" in item for item in accepted_classification.findings)


def test_github_hardening_classification_merge_and_normalization_redacts_values() -> None:
    private_path = "C:" + "\\Users\\operator\\repo"
    redacted_path = "C:" + "\\Users\\<redacted>"
    raw = rpg_github.merge_github_hardening_classifications(
        rpg_github.GitHubHardeningClassification(
            findings=(
                f"  GitHub finding leaked {private_path} and ghp_" + ("A" * 36),
                "",
            ),
            warnings=("GitHub warning for dev@example.com",),
        ),
        rpg_github.GitHubHardeningClassification(
            findings=(f"GitHub finding leaked {private_path} and ghp_" + ("A" * 36),),
            accepted_risks=("Accepted risk for dev@example.com",),
        ),
    )

    normalized = rpg_github.normalize_github_hardening_classification(
        raw,
        lambda items: rpg.normalize_text_values([rpg.redact_sensitive_text(item) for item in items]),
    )

    assert len(normalized.findings) == 1
    assert rpg.REDACTED_SECRET in normalized.findings[0]
    assert redacted_path in normalized.findings[0]
    assert normalized.warnings == ("GitHub warning for <redacted-email>",)
    assert normalized.accepted_risks == ("Accepted risk for <redacted-email>",)


def test_audit_github_release_hardening_accepts_admin_bypass_for_solo_maintainer(
    tmp_path: Path,
    monkeypatch,
) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("* @owner\n", encoding="utf-8")

    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        assert token == "gh-admin-token"
        response = _github_ok_hardening_response(url)
        if response is not None:
            payload, reason = response
            if isinstance(payload, dict) and url.endswith("/branches/main/protection"):
                payload = dict(payload)
                payload["enforce_admins"] = {"enabled": False}
            return payload, reason
        return _github_ok_repo_payload(), "http_200"

    monkeypatch.setattr(rpg, "github_api_get_json", fake_get_json)
    monkeypatch.setattr(rpg, "github_api_probe_enabled", lambda url, token=None: (True, "http_204"))

    strict_findings, strict_warnings = rpg.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/repo.git",
        token="gh-admin-token",
    )
    accepted_risks: list[str] = []
    accepted_findings, accepted_warnings = rpg.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/repo.git",
        token="gh-admin-token",
        accept_admin_bypass=True,
        accepted_risks=accepted_risks,
    )

    assert strict_warnings == []
    assert any("administrators can bypass branch protection" in item for item in strict_findings)
    assert accepted_findings == []
    assert accepted_warnings == []
    assert any("administrators can bypass branch protection" in item for item in accepted_risks)
    assert any("--accept-github-admin-bypass" in item for item in accepted_risks)


def test_github_hardening_fix_guide_names_protected_branch_baseline() -> None:
    guide = build_github_hardening_fix_guide(
        findings=[
            "GitHub default branch protection is not enabled.",
            "GitHub security and analysis: secret scanning status is disabled.",
        ],
        warnings=[],
    )

    joined = "\n".join(guide)
    assert "strict required status checks from current automatic CI" in joined
    assert "code-owner review when CODEOWNERS exists" in joined
    assert "admin enforcement" in joined
    assert "force-push/deletion disabled" in joined


def test_audit_github_release_hardening_reports_stale_required_status_checks(tmp_path: Path, monkeypatch) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("* @owner\n", encoding="utf-8")
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: ci\n\n"
        "on:\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      extended_checks:\n"
        "        type: boolean\n\n"
        "jobs:\n"
        "  smoke:\n"
        "    name: CLI smoke + release contract (automatic, ubuntu-latest, py3.13)\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: python scripts/check_release_contract.py\n"
        "  test:\n"
        "    if: ${{ github.event_name == 'workflow_dispatch' && inputs.extended_checks }}\n"
        "    name: CLI / pytest (manual, ubuntu-latest, py3.13)\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: python -m pytest\n",
        encoding="utf-8",
    )

    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        assert token == "gh-admin-token"
        response = _github_ok_hardening_response(url)
        if response is not None and not ("/branches/" in url and url.endswith("/protection")):
            return response
        if url.endswith("/branches/main/protection"):
            return (
                {
                    "required_pull_request_reviews": {
                        "required_approving_review_count": 1,
                        "require_code_owner_reviews": True,
                        "dismiss_stale_reviews": True,
                        "bypass_pull_request_allowances": {
                            "users": [],
                            "teams": [],
                            "apps": [],
                        },
                    },
                    "required_conversation_resolution": {"enabled": True},
                    "required_status_checks": {
                        "strict": True,
                        "contexts": [
                            "CLI / pytest (ubuntu-latest, py3.10)",
                            "Package smoke (ubuntu-latest, py3.13)",
                        ],
                    },
                    "allow_force_pushes": {"enabled": False},
                    "allow_deletions": {"enabled": False},
                    "enforce_admins": {"enabled": True},
                },
                "http_200",
            )
        return _github_ok_repo_payload(), "http_200"

    monkeypatch.setattr(rpg, "github_api_get_json", fake_get_json)
    monkeypatch.setattr(rpg, "github_api_probe_enabled", lambda url, token=None: (True, "http_204"))

    findings, warnings = rpg.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/repo.git",
        token="gh-admin-token",
    )

    assert warnings == []
    assert any("contexts not produced by local automatic workflows" in item for item in findings)
    assert any("CLI / pytest (ubuntu-latest, py3.10)" in item for item in findings)
    assert any("Package smoke (ubuntu-latest, py3.13)" in item for item in findings)


def test_audit_github_release_hardening_uses_resolved_token_for_repo_metadata(tmp_path: Path, monkeypatch) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("* @owner\n", encoding="utf-8")

    seen_tokens: list[str | None] = []

    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        seen_tokens.append(token)
        response = _github_ok_hardening_response(url)
        if response is not None:
            return response
        return _github_ok_repo_payload(), "http_200"

    monkeypatch.setattr(rpg, "resolve_github_hardening_token", lambda env=None, runner=None: "gh-admin-token")
    monkeypatch.setattr(rpg, "github_api_get_json", fake_get_json)
    monkeypatch.setattr(rpg, "github_api_probe_enabled", lambda url, token=None: (True, "http_204"))

    findings, warnings = rpg.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/private-repo.git",
        token=None,
    )

    assert findings == []
    assert warnings == []
    assert seen_tokens
    assert all(token == "gh-admin-token" for token in seen_tokens)


def test_discover_repositories_public_only_filters_private_and_non_github(tmp_path: Path, monkeypatch) -> None:
    public_repo = tmp_path / "repo-a-public"
    private_repo = tmp_path / "repo-b-private"
    non_gh_repo = tmp_path / "repo-c-non-github"
    for repo in (public_repo, private_repo, non_gh_repo):
        (repo / ".git").mkdir(parents=True)

    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.root = tmp_path
    guard.log = lambda _msg: None

    origin_map = {
        public_repo.name: "https://github.com/example/public-repo.git",
        private_repo.name: "https://github.com/example/private-repo.git",
        non_gh_repo.name: "https://gitlab.com/example/other-repo.git",
    }

    def fake_git(repo: Path, *args: str) -> rpg.CommandResult:
        assert args == ("remote", "get-url", "origin")
        return rpg.CommandResult(0, origin_map[repo.name], "")

    guard._git = fake_git

    visibility_map = {
        "https://github.com/example/public-repo.git": (True, "public"),
        "https://github.com/example/private-repo.git": (False, "private"),
        "https://gitlab.com/example/other-repo.git": (None, "not_github"),
    }
    monkeypatch.setattr(rpg, "is_public_github_remote", lambda remote: visibility_map[remote])

    discovered = guard.discover_repositories(repo_filters=None, public_only=True)
    assert [repo.name for repo in discovered] == ["repo-a-public"]


def test_discover_repositories_public_only_includes_current_root(tmp_path: Path, monkeypatch) -> None:
    current_root_repo = tmp_path
    child_repo = tmp_path / "repo-a-public"
    for repo in (current_root_repo, child_repo):
        (repo / ".git").mkdir(parents=True, exist_ok=True)

    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.root = tmp_path
    guard.log = lambda _msg: None

    origin_map = {
        str(current_root_repo): "https://github.com/example/current-root.git",
        str(child_repo): "https://github.com/example/repo-a-public.git",
    }

    def fake_git(repo: Path, *args: str) -> rpg.CommandResult:
        assert args == ("remote", "get-url", "origin")
        return rpg.CommandResult(0, origin_map[str(repo)], "")

    guard._git = fake_git

    visibility_map = {
        "https://github.com/example/current-root.git": (True, "public"),
        "https://github.com/example/repo-a-public.git": (True, "public"),
    }
    monkeypatch.setattr(rpg, "is_public_github_remote", lambda remote: visibility_map[remote])

    discovered = guard.discover_repositories(repo_filters=None, public_only=True)
    assert discovered == [current_root_repo, child_repo]


def test_is_relevant_email_candidate_filters_noise_domains() -> None:
    assert rpg.is_relevant_email_candidate("") is False
    assert rpg.is_relevant_email_candidate("not-an-email") is False
    assert rpg.is_relevant_email_candidate("@corp.com") is False
    assert rpg.is_relevant_email_candidate("user@") is False
    assert rpg.is_relevant_email_candidate("user@localhost") is False
    assert rpg.is_relevant_email_candidate("user@intranet") is False
    assert rpg.is_relevant_email_candidate("user@example.com") is False
    assert rpg.is_relevant_email_candidate("user@corp.local") is False
    assert rpg.is_relevant_email_candidate("user@corp.invalid") is False
    assert rpg.is_relevant_email_candidate("user@corp.example") is False
    assert rpg.is_relevant_email_candidate("user@10.0.0.1") is False
    assert rpg.is_relevant_email_candidate("user@corp.c") is False
    assert rpg.is_relevant_email_candidate("user@corp.c0") is False
    assert rpg.is_relevant_email_candidate("git@github.com") is False
    assert rpg.is_relevant_email_candidate("git@ssh.github.com") is False
    assert rpg.is_relevant_email_candidate("git@gitlab.com") is False
    assert rpg.is_relevant_email_candidate("git@bitbucket.org") is False
    assert rpg.is_relevant_email_candidate("hg@bitbucket.org") is False
    assert rpg.is_relevant_email_candidate("git@ssh.dev.azure.com") is False
    assert rpg.is_relevant_email_candidate("git@" + "corp.com") is True
    assert rpg.is_relevant_email_candidate("redacted-contributor@example.invalid") is True


def test_email_match_confidence_helpers_and_ownership_split() -> None:
    tracked = [
        "tests/auth/test_login.py:12:redacted-contributor@example.invalid:assert login('redacted-contributor@example.invalid')",
        "src/auth/service.py:22:redacted-contributor@example.invalid:admin_email = 'redacted-contributor@example.invalid'",
    ]
    history = [
        "L22:redacted-contributor@example.invalid:+ expect(user.email).toBe('redacted-contributor@example.invalid')",
        "L48:redacted-contributor@example.invalid:+ SUPPORT_EMAIL = 'redacted-contributor@example.invalid'",
    ]

    tracked_high, tracked_low = rpg.split_email_matches_by_confidence(tracked)
    history_high, history_low = rpg.split_email_matches_by_confidence(history)
    tracked_taxonomy_high, tracked_taxonomy_low, tracked_fixtures = (
        rpg.split_email_matches_by_taxonomy(tracked)
    )
    history_taxonomy_high, history_taxonomy_low, history_fixtures = (
        rpg.split_email_matches_by_taxonomy(history)
    )

    assert tracked_high == [tracked[1]]
    assert tracked_low == [tracked[0]]
    assert history_high == [history[1]]
    assert history_low == [history[0]]
    assert tracked_taxonomy_high == [tracked[1]]
    assert tracked_taxonomy_low == []
    assert tracked_fixtures == [tracked[0]]
    assert history_taxonomy_high == [history[1]]
    assert history_taxonomy_low == []
    assert history_fixtures == [history[0]]

    owned, third_party = rpg.split_unexpected_emails_by_origin_ownership(
        ["redacted-contributor@example.invalid"],
        "https://github.com/example/repo.git",
        {"example"},
    )
    assert owned == ["redacted-contributor@example.invalid"]
    assert third_party == []

    owned, third_party = rpg.split_unexpected_emails_by_origin_ownership(
        ["redacted-contributor@example.invalid"],
        "https://github.com/other/repo.git",
        {"example"},
    )
    assert owned == []
    assert third_party == ["redacted-contributor@example.invalid"]


def test_email_match_context_edge_cases_and_empty_ownership_split() -> None:
    assert rpg.extract_email_match_context("") == (None, "")
    assert rpg.extract_email_match_context("src/module.py:12") == ("src/module.py", "12")
    assert rpg.extract_email_match_context("no-colon") == (None, "no-colon")

    assert rpg.is_low_confidence_email_context("README.md", "contact") is True
    assert rpg.classify_email_match_context("README.md", "contact") == "low_confidence"
    assert rpg.is_low_confidence_email_context(None, "assert user.email") is True
    assert rpg.classify_email_match_context(None, "assert user.email") == "fixture"
    assert rpg.is_low_confidence_email_context("src/service.py", "prod_email = 'redacted-contributor@example.invalid'") is False

    owned, third_party = rpg.split_unexpected_emails_by_origin_ownership([], None, {"example"})
    assert owned == []
    assert third_party == []


def test_redact_sensitive_text_and_sanitize_export_payload() -> None:
    secret = _fixture_secret()
    low_confidence_secret = "api_key=" + ("synthetic-review-token" * 2)
    credentialed_url = "https://svc:" + ("P" * 16) + "@api.example.invalid/v1"
    win_path = _fixture_win_user_path("Documents", "repo")
    escaped_win_path = _fixture_escaped_win_user_path("Documents", "repo")
    unix_user_path = _fixture_unix_user_path("Users", "bob", "repo")
    unix_home_path = _fixture_unix_user_path("home", "carol", ".ssh")
    sample = (
        f"token {secret} "
        f"generic {low_confidence_secret} "
        f"url {credentialed_url} "
        "email dev@example.com "
        f"path {win_path} "
        f"json_path {escaped_win_path} "
        "profile AppData\\Roaming\\Code "
        "json_profile AppData\\\\Roaming\\\\Code "
        f"unix {unix_user_path} {unix_home_path}"
    )
    redacted = rpg.redact_sensitive_text(sample)

    assert rpg.REDACTED_SECRET in redacted
    assert "synthetic-review-token" not in redacted
    assert "svc:" not in redacted
    assert rpg.REDACTED_EMAIL in redacted
    assert "C:\\Users\\<redacted>" in redacted
    assert "C:\\\\Users\\\\<redacted>" in redacted
    assert "AppData\\<redacted>" in redacted
    assert "AppData\\\\<redacted>" in redacted
    assert "/Users/<redacted>" in redacted
    assert "/home/<redacted>" in redacted

    report = _make_report("repo-a")
    report.path = _fixture_win_user_path_slash("repo-a")
    report.origin_url = credentialed_url
    report.clean_status = "author dev@example.com"
    report.author_emails = ["dev@example.com"]
    report.committer_emails = ["ops@example.com"]
    report.author_identity_tokens = ["owner at privacy dot dev"]
    report.committer_identity_tokens = ["12345"]
    report.unexpected_emails = ["redacted-contributor@example.invalid"]
    report.unexpected_emails_owned_repo = ["redacted-contributor@example.invalid"]
    report.unexpected_emails_third_party_repo = ["redacted-contributor@example.invalid"]
    report.unexpected_identity_tokens = ["owner at privacy dot dev", "12345"]
    report.unexpected_identity_tokens_owned_repo = ["owner at privacy dot dev"]
    report.unexpected_identity_tokens_third_party_repo = ["12345"]
    report.tracked_secret_matches = [f"secret.txt:1:{secret}"]
    report.tracked_secret_high_confidence = [f"secret.txt:1:{secret}"]
    report.tracked_secret_low_confidence = [f"settings.py:1:{low_confidence_secret}"]
    report.tracked_secret_fixture_matches = [f"tests/fixtures/secrets.txt:1:{secret}"]
    report.tracked_secret_documentation_matches = [
        "README.md:1:postgres://user:pass@example.invalid/db"
    ]
    report.tracked_path_matches = [f"file.txt:1:{_fixture_win_user_path_slash('Documents')}"]
    report.tracked_email_matches = ["file.txt:2:dev@example.com"]
    report.tracked_email_high_confidence = ["src/main.py:2:dev@example.com"]
    report.tracked_email_low_confidence = ["tests/test_main.py:2:dev@example.com"]
    report.tracked_email_fixture_matches = ["tests/test_fixture.py:2:dev@example.com"]
    report.history_email_matches = ["L1:dev@example.com:+ email = 'dev@example.com'"]
    report.history_secret_low_confidence = [f"L1:src/settings.py:{low_confidence_secret}"]
    report.git_metadata_secret_matches = [f"origin_url:{credentialed_url}"]
    report.history_email_high_confidence = ["L1:dev@example.com:+ email = 'dev@example.com'"]
    report.history_email_low_confidence = ["L2:dev@example.com:+ assert foo('dev@example.com')"]
    report.history_email_fixture_matches = ["L3:tests/test_fixture.py:dev@example.com:+ assert foo('dev@example.com')"]
    report.reviewed_network_indicators = [
        "repo_privacy_guardian/github.py:1:with urllib.request.urlopen(request, timeout=8) as response:"
    ]
    report.github_hardening_findings = ["GitHub repository hardening: .github/CODEOWNERS is missing."]
    report.github_hardening_warnings = ["GitHub default branch protection could not be audited (http_403)."]
    report.github_hardening_accepted_risks = [
        "GitHub default branch protection: administrators can bypass branch protection. Accepted by --accept-github-admin-bypass for solo-maintainer operations."
    ]
    report.fix_actions = ["replace dev@example.com"]
    payload = rpg.sanitize_report_for_export(report)

    assert payload["path"] == "C:/Users/<redacted>/repo-a"
    assert payload["origin_url"] == rpg.REDACTED_SECRET
    assert payload["author_emails"] == [rpg.REDACTED_EMAIL]
    assert payload["committer_emails"] == [rpg.REDACTED_EMAIL]
    assert payload["author_identity_tokens"] == [rpg.REDACTED_IDENTITY_TOKEN]
    assert payload["committer_identity_tokens"] == [rpg.REDACTED_IDENTITY_TOKEN]
    assert payload["unexpected_emails"] == [rpg.REDACTED_EMAIL]
    assert payload["unexpected_emails_owned_repo"] == [rpg.REDACTED_EMAIL]
    assert payload["unexpected_emails_third_party_repo"] == [rpg.REDACTED_EMAIL]
    assert payload["unexpected_identity_tokens"] == [
        rpg.REDACTED_IDENTITY_TOKEN,
        rpg.REDACTED_IDENTITY_TOKEN,
    ]
    assert payload["unexpected_identity_tokens_owned_repo"] == [rpg.REDACTED_IDENTITY_TOKEN]
    assert payload["unexpected_identity_tokens_third_party_repo"] == [rpg.REDACTED_IDENTITY_TOKEN]
    assert rpg.REDACTED_SECRET in payload["tracked_secret_matches"][0]
    assert rpg.REDACTED_SECRET in payload["tracked_secret_high_confidence"][0]
    assert rpg.REDACTED_SECRET in payload["tracked_secret_low_confidence"][0]
    assert rpg.REDACTED_SECRET in payload["tracked_secret_fixture_matches"][0]
    assert rpg.REDACTED_SECRET in payload["tracked_secret_documentation_matches"][0]
    assert rpg.REDACTED_SECRET in payload["history_secret_low_confidence"][0]
    assert rpg.REDACTED_SECRET in payload["git_metadata_secret_matches"][0]
    assert rpg.REDACTED_EMAIL in payload["tracked_email_matches"][0]
    assert rpg.REDACTED_EMAIL in payload["tracked_email_high_confidence"][0]
    assert rpg.REDACTED_EMAIL in payload["tracked_email_low_confidence"][0]
    assert rpg.REDACTED_EMAIL in payload["tracked_email_fixture_matches"][0]
    assert rpg.REDACTED_EMAIL in payload["history_email_high_confidence"][0]
    assert rpg.REDACTED_EMAIL in payload["history_email_low_confidence"][0]
    assert rpg.REDACTED_EMAIL in payload["history_email_fixture_matches"][0]
    assert payload["reviewed_network_indicators"] == report.reviewed_network_indicators
    assert payload["github_hardening_findings"] == [
        "GitHub repository hardening: .github/CODEOWNERS is missing."
    ]
    assert payload["github_hardening_warnings"] == [
        "GitHub default branch protection could not be audited (http_403)."
    ]
    assert payload["github_hardening_accepted_risks"] == report.github_hardening_accepted_risks
    assert rpg.REDACTED_EMAIL in payload["fix_actions"][0]


def test_sanitize_report_for_export_redacts_edge_surfaces() -> None:
    secret = _fixture_secret()
    low_confidence_secret = "api_key=" + ("synthetic-review-token" * 2)
    email = "private.ops@example.com"
    user = "reportedgeuser"
    win_path = _fixture_win_user_path("Repos", "repo-a", user=user)
    slash_path = _fixture_win_user_path_slash("Repos", "repo-a", user=user)
    unix_path = _fixture_unix_user_path("home", user, "repo-a")
    raw_line = f"src/app.py:1:{secret} {low_confidence_secret} {email} {win_path} {unix_path}"

    report = _make_report(f"repo-{email}-{secret}")
    report.path = slash_path
    report.origin_url = f"https://{email}:{secret}@github.com/example/repo-a.git"
    report.upstream_url = f"file:///{slash_path}"
    report.branch = f"feature/{email}"
    report.head = secret
    report.origin_head = secret
    report.clean_status = f"## main\n M {win_path}\n?? {email}\n"
    report.author_emails = [email]
    report.committer_emails = [email]
    report.author_identity_tokens = ["owner at privacy dot dev"]
    report.committer_identity_tokens = ["12345"]
    report.unexpected_emails = [email]
    report.unexpected_emails_owned_repo = [email]
    report.unexpected_emails_third_party_repo = [email]
    report.unexpected_identity_tokens = ["owner at privacy dot dev"]
    report.unexpected_identity_tokens_owned_repo = ["owner at privacy dot dev"]
    report.unexpected_identity_tokens_third_party_repo = ["owner at privacy dot dev"]
    report.tracked_secret_matches = [raw_line]
    report.tracked_secret_high_confidence = [raw_line]
    report.tracked_secret_low_confidence = [raw_line]
    report.tracked_secret_fixture_matches = [raw_line]
    report.tracked_secret_documentation_matches = [raw_line]
    report.tracked_path_matches = [raw_line]
    report.tracked_email_matches = [raw_line]
    report.tracked_email_high_confidence = [raw_line]
    report.tracked_email_low_confidence = [raw_line]
    report.tracked_email_fixture_matches = [raw_line]
    report.tracked_secret_files = [raw_line]
    report.history_secret_matches = [raw_line]
    report.history_secret_high_confidence = [raw_line]
    report.history_secret_low_confidence = [raw_line]
    report.history_secret_fixture_matches = [raw_line]
    report.history_secret_documentation_matches = [raw_line]
    report.history_path_matches = [raw_line]
    report.history_email_matches = [raw_line]
    report.history_email_high_confidence = [raw_line]
    report.history_email_low_confidence = [raw_line]
    report.history_email_fixture_matches = [raw_line]
    report.history_secret_files = [raw_line]
    report.git_metadata_secret_matches = [raw_line]
    report.git_metadata_secret_low_confidence = [raw_line]
    report.history_sensitive_added = [raw_line]
    report.history_sensitive_deleted = [raw_line]
    report.secret_file_candidates = [raw_line]
    report.secret_file_autopurge_candidates = [raw_line]
    report.secret_file_manual_review_candidates = [raw_line]
    report.secret_history_purge_paths = [raw_line]
    report.tracked_but_ignored = [raw_line]
    report.gitignore_missing_patterns = [raw_line]
    report.exfil_code_indicators = [raw_line]
    report.reviewed_network_indicators = [raw_line]
    report.github_hardening_findings = [raw_line]
    report.github_hardening_warnings = [raw_line]
    report.github_hardening_accepted_risks = [raw_line]
    report.github_hardening_fix_guide = [raw_line]
    report.suppressed_findings = [{"category": "manual", "finding": raw_line}]
    report.litellm_reference_hits = [raw_line]
    report.litellm_compromised_reference_hits = [raw_line]
    report.litellm_install_command_hits = [raw_line]
    report.litellm_ioc_hits = [raw_line]
    report.backups_created = [raw_line]
    report.fix_actions = [raw_line]
    report.fix_errors = [raw_line]
    report.execution_errors = [raw_line]
    report.fsck_output = [raw_line]
    report.failures = [raw_line]

    payload = rpg.sanitize_report_for_export(report)
    serialized = json.dumps(payload, sort_keys=True)

    for raw in (secret, "synthetic-review-token", email, user):
        assert raw not in serialized
    assert rpg.REDACTED_SECRET in serialized
    assert rpg.REDACTED_EMAIL in serialized
    assert "C:/Users/<redacted>" in serialized
    assert "/home/<redacted>" in serialized


def test_extract_personal_path_literals_filters_regex_scaffolding() -> None:
    regex_snippet = (
        'PERSONAL_PATH_RE = re.compile(r"C:\\\\Users\\\\|/Users/|/home/|AppData\\\\|Documents\\\\")'
    )
    assert rpg.extract_personal_path_literals(regex_snippet) == []

    repo_cli_path = _fixture_repo_cli_path()
    concrete = f"AGENTS.MD:24:- {repo_cli_path}"
    assert rpg.extract_personal_path_literals(concrete) == [repo_cli_path]

    escaped_path = _fixture_escaped_win_user_path("AppData", "Roaming", "Code")
    escaped = f'path="{escaped_path}"'
    assert rpg.extract_personal_path_literals(escaped) == [
        escaped_path
    ]


def test_build_fix_preflight_summary_branches() -> None:
    assert rpg.build_fix_preflight_summary(_make_run_config(fix=False), [Path("C:/repos/repo-a")]) == []

    config_no_allowlist = _make_run_config(fix=True, push=True, allow_non_owner_push=False)
    lines_no_allowlist = rpg.build_fix_preflight_summary(config_no_allowlist, [Path("C:/repos/repo-a")])
    assert any("push owner check active" in line for line in lines_no_allowlist)
    assert any("low-confidence email mode: informational" in line for line in lines_no_allowlist)

    config_with_allowlist = _make_run_config(
        fix=True,
        push=True,
        low_confidence_email_mode="blocking",
        allowed_remote_owners=["example", "example", "owner"],
    )
    lines_with_allowlist = rpg.build_fix_preflight_summary(
        config_with_allowlist,
        [Path("C:/repos/repo-a")],
    )
    assert any("allowed remote owners: example, owner" in line for line in lines_with_allowlist)
    assert any("low-confidence email mode: blocking" in line for line in lines_with_allowlist)


def test_commit_if_needed_state_values(tmp_path: Path) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    calls: list[tuple[str, ...]] = []

    def fake_git(_repo: Path, *_args: str) -> rpg.CommandResult:
        return rpg.CommandResult(0, " M file.txt\n", "")

    def fake_git_checked(_repo: Path, *args: str) -> rpg.CommandResult:
        calls.append(args)
        return rpg.CommandResult(0, "", "")

    guard._git = fake_git
    guard._git_checked = fake_git_checked

    guard.dry_run = True
    assert guard._commit_if_needed(tmp_path, "msg") == "preview"
    assert calls == []

    guard.dry_run = False
    assert guard._commit_if_needed(tmp_path, "msg") == "committed"
    assert calls == [("add", "-A"), ("commit", "-m", "msg")]

    guard._git = lambda _repo, *_args: rpg.CommandResult(0, "", "")
    assert guard._commit_if_needed(tmp_path, "msg") == "none"


def test_write_replace_text_file_includes_personal_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.owner_emails = set()
    guard.noreply_email = rpg.DEFAULT_NOREPLY
    guard.placeholder_email = rpg.DEFAULT_PLACEHOLDER
    guard.redact_third_party = False
    guard.rewrite_personal_paths = True
    guard._is_allowed_email = lambda _email: False

    monkeypatch.setattr(rpg.tempfile, "mkdtemp", lambda prefix: str(tmp_path))

    report = _make_report("repo-paths")
    repo_cli_path = _fixture_repo_cli_path()
    report.tracked_path_matches = [f"AGENTS.MD:24:- {repo_cli_path}"]

    replace_file = guard._write_replace_text_file(report)

    assert replace_file == tmp_path / "replace-text.txt"
    contents = replace_file.read_text(encoding="utf-8")
    assert (
        f"literal:{repo_cli_path}==>"
        f"{rpg.REDACTED_PATH}"
    ) in contents


def test_write_replace_text_file_skips_personal_paths_when_disabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.owner_emails = set()
    guard.noreply_email = rpg.DEFAULT_NOREPLY
    guard.placeholder_email = rpg.DEFAULT_PLACEHOLDER
    guard.redact_third_party = False
    guard.rewrite_personal_paths = False
    guard._is_allowed_email = lambda _email: False

    monkeypatch.setattr(rpg.tempfile, "mkdtemp", lambda prefix: str(tmp_path))

    report = _make_report("repo-paths")
    report.tracked_path_matches = [f"AGENTS.MD:24:- {_fixture_repo_cli_path()}"]

    replace_file = guard._write_replace_text_file(report)

    assert replace_file is None
    assert any("rewrite-personal-paths" in item for item in report.fix_actions)


def test_write_replace_text_file_merges_explicit_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.owner_emails = set()
    guard.noreply_email = rpg.DEFAULT_NOREPLY
    guard.placeholder_email = rpg.DEFAULT_PLACEHOLDER
    guard.redact_third_party = False
    guard.rewrite_personal_paths = False
    guard._is_allowed_email = lambda _email: False

    explicit = tmp_path / "explicit-replace.txt"
    explicit.write_text(
        "# operator-provided mapping\nliteral:fixture-token==>redacted-fixture-token\n",
        encoding="utf-8",
    )
    guard.replace_text_file = str(explicit)

    monkeypatch.setattr(rpg.tempfile, "mkdtemp", lambda prefix: str(tmp_path))

    report = _make_report("repo-explicit-replace")
    replace_file = guard._write_replace_text_file(report)

    assert replace_file == tmp_path / "replace-text.txt"
    contents = replace_file.read_text(encoding="utf-8")
    assert "literal:fixture-token==>redacted-fixture-token" in contents
    assert any("merged explicit replace-text mappings" in item for item in report.fix_actions)


def test_write_replace_text_file_accepts_utf8_bom_explicit_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.owner_emails = set()
    guard.noreply_email = rpg.DEFAULT_NOREPLY
    guard.placeholder_email = rpg.DEFAULT_PLACEHOLDER
    guard.redact_third_party = False
    guard.rewrite_personal_paths = False
    guard._is_allowed_email = lambda _email: False

    explicit = tmp_path / "explicit-replace-bom.txt"
    explicit.write_text(
        "literal:fixture-token==>redacted-fixture-token\n",
        encoding="utf-8-sig",
    )
    guard.replace_text_file = str(explicit)

    monkeypatch.setattr(rpg.tempfile, "mkdtemp", lambda prefix: str(tmp_path))

    report = _make_report("repo-explicit-replace-bom")
    replace_file = guard._write_replace_text_file(report)

    contents = replace_file.read_text(encoding="utf-8")
    assert contents.splitlines()[0] == "literal:fixture-token==>redacted-fixture-token"


def test_remediation_replace_text_plan_combines_rules(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit-replace-bom.txt"
    explicit.write_text(
        "# operator-provided mapping\n"
        "literal:fixture-token==>redacted-fixture-token\n"
        "literal:fixture-token==>redacted-fixture-token\n",
        encoding="utf-8-sig",
    )
    explicit_rules = remediation.load_explicit_replace_text_rules(explicit)

    report = _make_report("repo-replace-plan")
    repo_cli_path = _fixture_repo_cli_path()
    report.tracked_email_matches = [
        "README.md:1:owner@privacy.dev contributor@outside.dev allowed@safe.dev"
    ]
    report.tracked_path_matches = [f"AGENTS.MD:24:- {repo_cli_path}"]

    plan = remediation.build_replace_text_plan(
        report,
        email_pattern=rpg.EMAIL_RE,
        is_relevant_email_candidate=rpg.is_relevant_email_candidate,
        is_allowed_email=lambda email: email == "allowed@safe.dev",
        owner_emails={"owner@privacy.dev"},
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        redact_third_party=True,
        rewrite_personal_paths=True,
        extract_personal_path_literals=rpg.extract_personal_path_literals,
        redacted_path=rpg.REDACTED_PATH,
        explicit_replace_lines=explicit_rules.lines,
        explicit_replace_source=explicit_rules.path,
    )

    assert f"literal:{repo_cli_path}==>{rpg.REDACTED_PATH}" in plan.lines
    assert f"literal:owner@privacy.dev==>{rpg.DEFAULT_NOREPLY}" in plan.lines
    assert f"literal:contributor@outside.dev==>{rpg.DEFAULT_PLACEHOLDER}" in plan.lines
    assert not any("allowed@safe.dev" in line for line in plan.lines)
    assert plan.lines.count("literal:fixture-token==>redacted-fixture-token") == 1
    assert any("merged explicit replace-text mappings" in item for item in plan.fix_actions)


def test_remediation_history_rewrite_plan_builds_purge_args_and_preview() -> None:
    report = _make_report("repo-rewrite-plan")
    report.secret_history_purge_paths = ["z.env", "a.env", "a.env"]
    report.history_sensitive_added = ["L1:.env:+API_KEY=value"]

    plan = remediation.build_history_rewrite_plan(
        report,
        mailmap_enabled=False,
        replace_text_enabled=True,
    )

    assert plan.do_rewrite is True
    assert plan.needs_history_purge is True
    assert plan.purge_paths == ("a.env", "z.env")
    assert plan.filter_repo_purge_args() == [
        "--path",
        "a.env",
        "--path",
        "z.env",
        "--path-regex",
        remediation.SENSITIVE_FILENAME_PURGE_REGEX,
        "--invert-paths",
    ]
    assert "[dry-run] replace-text enabled: True" in plan.dry_run_actions()
    assert "[dry-run] purge paths preview: a.env, z.env" in plan.dry_run_actions()
    assert "[dry-run] sensitive filename signal purge regex enabled" in plan.dry_run_actions()

    empty_plan = remediation.build_history_rewrite_plan(
        _make_report("repo-no-rewrite"),
        mailmap_enabled=False,
        replace_text_enabled=False,
    )
    assert empty_plan.do_rewrite is False
    assert empty_plan.filter_repo_purge_args() == []


def test_remediation_builds_git_filter_repo_command() -> None:
    report = _make_report("repo-filter-command")
    report.secret_history_purge_paths = ["z.env", "a.env", "a.env"]
    report.history_sensitive_deleted = ["L1:.env:-API_KEY=value"]
    plan = remediation.build_history_rewrite_plan(
        report,
        mailmap_enabled=True,
        replace_text_enabled=True,
    )

    cmd = remediation.build_git_filter_repo_command(
        python_executable="python",
        mailmap=Path("mailmap.txt"),
        replace_text=Path("replace-text.txt"),
        rewrite_plan=plan,
    )

    assert cmd == [
        "python",
        "-m",
        "git_filter_repo",
        "--force",
        "--mailmap",
        "mailmap.txt",
        "--replace-text",
        "replace-text.txt",
        "--path",
        "a.env",
        "--path",
        "z.env",
        "--path-regex",
        remediation.SENSITIVE_FILENAME_PURGE_REGEX,
        "--invert-paths",
    ]


def test_append_gitignore_lines_rejects_symlinked_target(tmp_path: Path, monkeypatch) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.pyc\n", encoding="utf-8")

    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == gitignore:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    with pytest.raises(RuntimeError, match="symlinked \\.gitignore"):
        guard._append_gitignore_lines(tmp_path, ["secrets.env"], "header")


def test_rewrite_history_auto_confirms_git_filter_repo_continuation(tmp_path: Path) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.dry_run = False
    guard.replace_text_file = None
    guard.rewrite_personal_paths = False
    guard.owner_name = "Owner"
    guard.owner_emails = {"owner@example.com"}
    guard.noreply_email = rpg.DEFAULT_NOREPLY
    guard.placeholder_email = rpg.DEFAULT_PLACEHOLDER
    guard.redact_third_party = False
    guard._is_allowed_email = lambda _email: False
    guard._ensure_git_filter_repo = lambda: None
    guard._save_remotes = lambda _repo: {"origin": "https://example.test/repo.git"}
    guard._restore_remotes = lambda _repo, _remotes: None

    captured: dict[str, object] = {}

    def fake_run_checked(
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> rpg.CommandResult:
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["input_text"] = input_text
        return rpg.CommandResult(0, "", "")

    guard._run_checked = fake_run_checked

    report = _make_report("rewrite-history")
    report.author_emails = ["owner@example.com"]
    report.committer_emails = []

    guard._rewrite_history(tmp_path, report)

    assert captured["cwd"] == tmp_path
    assert captured["input_text"] == "y\n"
    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    assert cmd[:4] == [sys.executable, "-m", "git_filter_repo", "--force"]
    assert "--mailmap" in cmd
    mailmap_path = Path(cmd[cmd.index("--mailmap") + 1])
    assert mailmap_path.exists() is False
    assert "history rewritten with git-filter-repo" in report.fix_actions


def test_write_mailmap_maps_owned_identity_tokens_to_noreply() -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.owner_name = "Owner"
    guard.owner_emails = {"owner@example.com"}
    guard.noreply_email = "12345+owner@users.noreply.github.com"
    guard.placeholder_email = rpg.DEFAULT_PLACEHOLDER
    guard.redact_third_party = True

    report = _make_report("mailmap-token")
    report.author_emails = ["owner@example.com"]
    report.unexpected_identity_tokens = ["owner at privacy dot dev", "12345"]
    report.unexpected_identity_tokens_owned_repo = ["owner at privacy dot dev"]
    report.unexpected_identity_tokens_third_party_repo = ["12345"]
    report.email_ownership_evaluated = True

    mailmap = guard._write_mailmap(report)

    assert mailmap is not None
    try:
        content = mailmap.read_text(encoding="utf-8")
        assert "Owner <12345+owner@users.noreply.github.com> <owner@example.com>" in content
        assert "Owner <12345+owner@users.noreply.github.com> <owner at privacy dot dev>" in content
        assert f"Redacted Contributor <{rpg.DEFAULT_PLACEHOLDER}> <12345>" in content
    finally:
        rpg.cleanup_private_temp_text_file(mailmap)


def test_classify_repo_severity_all_levels() -> None:
    high = _make_report("high")
    high.tracked_secret_matches = ["a"]
    high.finalize()
    assert rpg.classify_repo_severity(high)[0] == "HIGH"

    medium = _make_report("medium")
    medium.unexpected_emails = ["private@example.com"]
    medium.finalize()
    assert rpg.classify_repo_severity(medium)[0] == "MEDIUM"

    medium_tokens = _make_report("medium-tokens")
    medium_tokens.unexpected_identity_tokens = ["owner at privacy dot dev"]
    medium_tokens.finalize()
    sev, _, highlights = rpg.classify_repo_severity(medium_tokens)
    assert sev == "MEDIUM"
    assert "Malformed commit metadata identity tokens found in owned repository" in highlights

    medium_paths = _make_report("medium-paths")
    medium_paths.tracked_path_matches = [f"README.md:1:{_fixture_win_user_path_slash(user='example')}"]
    medium_paths.tracked_but_ignored = [".env"]
    medium_paths.finalize()
    sev, _, highlights = rpg.classify_repo_severity(medium_paths)
    assert sev == "MEDIUM"
    assert "Personal/local path leakage detected" in highlights
    assert "Ignored files are still tracked" in highlights

    low = _make_report("low")
    low.status = "FAIL"
    low.failures = ["custom failure"]
    sev, _, highlights = rpg.classify_repo_severity(low)
    assert sev == "LOW"
    assert highlights

    info = _make_report("info")
    info.email_ownership_evaluated = True
    info.unexpected_emails_third_party_repo = ["third@example.com"]
    info.email_confidence_evaluated = True
    info.history_email_high_confidence = ["L10:redacted-contributor@example.invalid:+ email = 'redacted-contributor@example.invalid'"]
    info.finalize()
    sev, _, highlights = rpg.classify_repo_severity(info)
    assert sev == "MEDIUM"
    assert "High-confidence non-owner email addresses found" in highlights
    assert any("third-party repositories" in item for item in highlights)

    ok = _make_report("ok")
    ok.finalize()
    assert rpg.classify_repo_severity(ok)[0] == "OK"


def test_email_remediation_decision_variants() -> None:
    skip = _make_report("skip")
    status, message = rpg.email_remediation_decision(skip)
    assert status == "SKIP"
    assert "No commit identity remediation action" in message

    review = _make_report("review")
    review.email_ownership_evaluated = True
    review.unexpected_emails_third_party_repo = ["third@example.com"]
    status, message = rpg.email_remediation_decision(review)
    assert status == "REVIEW"
    assert "Informational commit-identity findings" in message

    recommended = _make_report("recommended")
    recommended.email_confidence_evaluated = True
    recommended.history_email_high_confidence = ["L1:redacted-contributor@example.invalid:+ email = 'redacted-contributor@example.invalid'"]
    status, message = rpg.email_remediation_decision(recommended)
    assert status == "RECOMMENDED"
    assert "Authorize commit identity remediation" in message

    malformed = _make_report("malformed")
    malformed.unexpected_identity_tokens = ["owner at privacy dot dev"]
    status, message = rpg.email_remediation_decision(malformed)
    assert status == "RECOMMENDED"
    assert "malformed metadata findings" in message

    blocking_only = _make_report("blocking")
    blocking_only.low_confidence_email_mode = "blocking"
    blocking_only.email_confidence_evaluated = True
    blocking_only.history_email_low_confidence = ["L1:redacted-contributor@example.invalid:+ assert foo('redacted-contributor@example.invalid')"]
    status, message = rpg.email_remediation_decision(blocking_only)
    assert status == "RECOMMENDED"
    assert "Blocking mode active" in message


def test_repo_user_guidance_variants() -> None:
    secret_risk = _make_report("secret-risk")
    secret_risk.tracked_secret_matches = [f"secret.txt:1:{_fixture_aws_key()}"]
    level, risk, consequence, suggestion = rpg.repo_user_guidance(secret_risk)
    assert level == "IMMEDIATE"
    assert "secret indicators" in risk.lower()
    assert "credential leakage" in consequence.lower()
    assert "authorize secret purge" in suggestion.lower()

    email_risk = _make_report("email-risk")
    email_risk.email_ownership_evaluated = True
    email_risk.unexpected_emails_owned_repo = ["redacted-contributor@example.invalid"]
    level, risk, consequence, suggestion = rpg.repo_user_guidance(email_risk)
    assert level == "PRIORITY"
    assert "commit identity values" in risk.lower()
    assert "identity exposure" in consequence.lower()
    assert "authorize commit identity remediation" in suggestion.lower()

    path_risk = _make_report("path-risk")
    path_risk.tracked_path_matches = [f"README.md:1:{_fixture_win_user_path_slash(user='dev')}"]
    level, risk, consequence, suggestion = rpg.repo_user_guidance(path_risk)
    assert level == "PRIORITY"
    assert "local/personal paths" in risk.lower()
    assert "host/user structure disclosure" in consequence.lower()

    review_only = _make_report("review-only")
    review_only.email_confidence_evaluated = True
    review_only.history_email_low_confidence = ["L1:redacted-contributor@example.invalid:+ assert foo('redacted-contributor@example.invalid')"]
    level, risk, consequence, suggestion = rpg.repo_user_guidance(review_only)
    assert level == "REVIEW"
    assert "commit identity findings" in risk.lower()
    assert "alert fatigue" in consequence.lower()

    github_review = _make_report("github-review")
    github_review.github_hardening_findings = [
        "GitHub default branch protection is not enabled."
    ]
    level, risk, consequence, suggestion = rpg.repo_user_guidance(github_review)
    assert level == "REVIEW"
    assert "github repository settings" in risk.lower()
    assert "review/security controls" in consequence.lower()
    assert "--audit-github-hardening" in suggestion

    github_accepted = _make_report("github-accepted")
    github_accepted.github_hardening_accepted_risks = [
        "GitHub default branch protection: administrators can bypass branch protection. Accepted by --accept-github-admin-bypass for solo-maintainer operations."
    ]
    level, risk, consequence, suggestion = rpg.repo_user_guidance(github_accepted)
    assert level == "SKIP"
    assert "no relevant privacy risk" in risk.lower()

    skip = _make_report("skip")
    level, risk, consequence, suggestion = rpg.repo_user_guidance(skip)
    assert level == "SKIP"
    assert "no relevant privacy risk" in risk.lower()
    assert "none expected" in consequence.lower()
    assert "no remediation action required" in suggestion.lower()


def test_render_html_report_with_high_and_samples(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path)

    high = _make_report("critical-repo")
    high.tracked_secret_matches = [f"secret{i}" for i in range(10)]
    high.history_secret_matches = [f"hsecret{i}" for i in range(9)]
    high.secret_file_candidates = [f"secret/path/{i}.env" for i in range(10)]
    high.unexpected_emails = ["private@example.com"]
    high.history_sensitive_added = [".env"]
    high.gitignore_missing_patterns = ["sessions/*"]
    high.finalize()

    low = _make_report("minor-repo")
    low.gitignore_missing_patterns = [".mypy_cache/"]
    low.finalize()

    html_doc = rpg.render_html_report(
        reports=[high, low],
        artifacts=artifacts,
        root_path=Path("C:/repos"),
        policy_path=Path("C:/repos/RepoPrivacyGuardian/docs/POLICY.md"),
        run_settings={"mode": "cli", "dry_run": "False"},
        finished_at=datetime(2026, 4, 7, 12, 5, 0),
    )

    assert "Repository Privacy Audit Report" in html_doc
    assert "High severity focus" in html_doc
    assert "critical-repo" in html_doc
    assert "Showing 8 of" in html_doc
    assert "sev-high" in html_doc
    assert "Failure reason frequency" in html_doc
    assert "Unexpected emails (owned repo)" in html_doc
    assert "User guidance" in html_doc
    assert "Possible consequence:" in html_doc


def test_render_html_report_redacts_edge_surfaces(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path)
    secret = _fixture_secret()
    low_confidence_secret = "api_key=" + ("synthetic-review-token" * 2)
    email = "private.ops@example.com"
    user = "htmledgeuser"
    win_path = _fixture_win_user_path("Repos", "repo-a", user=user)
    slash_path = _fixture_win_user_path_slash("Repos", "repo-a", user=user)
    raw_line = f"src/app.py:1:{secret} {low_confidence_secret} {email} {win_path}"
    artifacts.run_dir = Path(_fixture_win_user_path("Audit_Results", artifacts.run_id, user=user))

    report = _make_report(f"repo-{email}-{secret}")
    report.path = slash_path
    report.origin_url = f"https://{email}:{secret}@github.com/example/repo-a.git"
    report.upstream_url = f"file:///{slash_path}"
    report.tracked_secret_matches = [raw_line]
    report.history_secret_matches = [raw_line]
    report.tracked_secret_low_confidence = [raw_line]
    report.history_secret_low_confidence = [raw_line]
    report.git_metadata_secret_matches = [raw_line]
    report.git_metadata_secret_low_confidence = [raw_line]
    report.secret_file_candidates = [raw_line]
    report.tracked_path_matches = [raw_line]
    report.history_path_matches = [raw_line]
    report.tracked_email_matches = [raw_line]
    report.history_email_matches = [raw_line]
    report.unexpected_emails = [email]
    report.unexpected_identity_tokens = ["owner at privacy dot dev"]
    report.exfil_code_indicators = [raw_line]
    report.reviewed_network_indicators = [raw_line]
    report.github_hardening_findings = [raw_line]
    report.github_hardening_warnings = [raw_line]
    report.github_hardening_accepted_risks = [raw_line]
    report.github_hardening_fix_guide = [raw_line]
    report.suppressed_findings = [{"category": "manual", "finding": raw_line}]
    report.litellm_reference_hits = [raw_line]
    report.litellm_ioc_hits = [raw_line]
    report.execution_errors = [raw_line]
    report.fix_errors = [raw_line]
    report.failures = [raw_line]
    report.status = "FAIL"

    html_doc = rpg.render_html_report(
        reports=[report],
        artifacts=artifacts,
        root_path=Path(win_path),
        policy_path=Path(_fixture_win_user_path("Repos", "repo-a", "docs", "POLICY.md", user=user)),
        run_settings={
            "operator": email,
            "workspace": win_path,
            "token": secret,
            "low_confidence": low_confidence_secret,
        },
        finished_at=datetime(2026, 4, 7, 12, 7, 0),
        optional_supply_chain_payload={
            "severity": "HIGH",
            "critical_evidence": [raw_line],
            "high_evidence": [raw_line],
            "medium_evidence": [raw_line],
            "python_probes": [
                {
                    "python": win_path,
                    "installed": True,
                    "version": email,
                    "location": f"{win_path}\\site-packages\\{secret}",
                }
            ],
        },
    )

    for raw in (secret, "synthetic-review-token", email, user):
        assert raw not in html_doc
    assert "&lt;redacted-secret&gt;" in html_doc
    assert "&lt;redacted-email&gt;" in html_doc
    assert "C:\\Users\\&lt;redacted&gt;" in html_doc
    assert "C:/Users/&lt;redacted&gt;" in html_doc


def test_render_html_report_with_no_failures(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path)
    passed = _make_report("clean-repo")
    passed.finalize()

    html_doc = rpg.render_html_report(
        reports=[passed],
        artifacts=artifacts,
        root_path=Path("C:/repos"),
        policy_path=Path("C:/repos/RepoPrivacyGuardian/docs/POLICY.md"),
        run_settings={"mode": "cli"},
        finished_at=datetime(2026, 4, 7, 12, 1, 0),
    )

    assert "No HIGH severity repositories in this run." in html_doc
    assert "No failure reasons recorded." in html_doc


def test_persist_run_outputs_writes_json_log_html_and_optional_export(tmp_path: Path) -> None:
    artifacts = rpg.create_run_artifacts(tmp_path)
    logger = rpg.RunLogger(artifacts.log_path)

    report = _make_report("demo")
    report.gitignore_missing_patterns = ["sessions/*"]
    report.finalize()

    extra_dir = tmp_path / "extra_json"
    rpg.persist_run_outputs(
        reports=[report],
        artifacts=artifacts,
        root_path=Path("C:/repos"),
        policy_path=Path("C:/repos/RepoPrivacyGuardian/docs/POLICY.md"),
        run_settings={"mode": "cli", "fix": "False"},
        logger=logger,
        optional_json_export=str(extra_dir),
    )

    assert artifacts.json_path.exists()
    assert artifacts.log_path.exists()
    assert artifacts.html_path.exists()

    data = json.loads(artifacts.json_path.read_text(encoding="utf-8"))
    assert data[0]["name"] == "demo"

    html_doc = artifacts.html_path.read_text(encoding="utf-8")
    assert "Repository details" in html_doc
    assert "demo" in html_doc

    extra_export = extra_dir / artifacts.json_path.name
    assert extra_export.exists()


def test_make_parser_defaults_and_flags() -> None:
    parser = rpg.make_parser()
    args = parser.parse_args([])

    assert Path(args.policy) == rpg.DEFAULT_POLICY
    assert Path(args.report_dir) == rpg.DEFAULT_RESULTS_DIR
    assert args.replace_text_file is None
    assert args.fix is False
    assert args.rewrite_personal_paths is False
    assert args.public_only == rpg.GUI_DEFAULT_PUBLIC_ONLY
    assert args.low_confidence_email_mode == "informational"
    assert args.github_owner is None
    assert args.github_include_forks is False
    assert args.github_fast is False
    assert args.github_jobs == 4
    assert args.accept_github_admin_bypass is False

    args = parser.parse_args(["--fix", "--purge-all-detected-secret-files"])
    assert args.fix is True
    assert args.purge_all_detected_secret_files is True

    args = parser.parse_args(["--rewrite-personal-paths"])
    assert args.rewrite_personal_paths is True

    args = parser.parse_args(["--low-confidence-email-mode", "blocking"])
    assert args.low_confidence_email_mode == "blocking"

    args = parser.parse_args(["--replace-text-file", "ops/replace-text.txt"])
    assert args.replace_text_file == "ops/replace-text.txt"

    args = parser.parse_args(["--github-owner", "acme", "--github-include-forks", "--github-fast", "--github-jobs", "2"])
    assert args.github_owner == "acme"
    assert args.github_include_forks is True
    assert args.github_fast is True
    assert args.github_jobs == 2

    args = parser.parse_args(["--audit-github-hardening", "--accept-github-admin-bypass"])
    assert args.audit_github_hardening is True
    assert args.accept_github_admin_bypass is True


def test_config_parser_matches_public_parser_help_and_defaults() -> None:
    parser = config_helpers.make_parser(
        default_root=rpg.default_root_dir(),
        default_policy=rpg.DEFAULT_POLICY,
        default_results_dir=rpg.DEFAULT_RESULTS_DIR,
        default_noreply=rpg.DEFAULT_NOREPLY,
        default_placeholder=rpg.DEFAULT_PLACEHOLDER,
        public_only_default=rpg.GUI_DEFAULT_PUBLIC_ONLY,
    )

    assert parser.format_help() == rpg.make_parser().format_help()

    args = parser.parse_args(["--public-only", "--no-open-report"])
    assert args.public_only is True
    assert args.open_report is False
    assert args.no_open_report is True


def test_make_parser_rejects_non_positive_max_matches() -> None:
    parser = rpg.make_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--max-matches", "0"])
    with pytest.raises(SystemExit):
        parser.parse_args(["--github-jobs", "0"])


def test_should_launch_gui_requires_explicit_flag() -> None:
    parser = rpg.make_parser()

    args_default = parser.parse_args([])
    assert rpg.should_launch_gui(args_default) is False

    args_gui = parser.parse_args(["--gui"])
    assert rpg.should_launch_gui(args_gui) is True

    args_cli = parser.parse_args(["--dry-run"])
    assert rpg.should_launch_gui(args_cli) is False


def test_parse_positive_int_validation() -> None:
    assert rpg.parse_positive_int("5") == 5
    with pytest.raises(Exception):
        rpg.parse_positive_int("0")
    with pytest.raises(Exception):
        rpg.parse_positive_int("not-an-int")


def test_normalize_github_jobs_bounds_parallel_clone_workers() -> None:
    assert rpg.normalize_github_jobs(0) == 1
    assert rpg.normalize_github_jobs(4) == 4
    assert rpg.normalize_github_jobs(10_000) == rpg.MAX_GITHUB_CLONE_JOBS


def test_build_run_settings_parity_keys() -> None:
    cli = _make_run_config(mode="cli", report_json="C:/tmp/export.json")
    gui = _make_run_config(mode="gui", report_json=None, low_confidence_email_mode="blocking")

    cli_settings = rpg.build_run_settings(cli, Path("C:/repos/Audit_Results"))
    gui_settings = rpg.build_run_settings(gui, Path("C:/repos/Audit_Results"))

    assert set(cli_settings.keys()) == set(gui_settings.keys())
    assert cli_settings["mode"] == "cli"
    assert gui_settings["mode"] == "gui"
    assert cli_settings["low_confidence_email_mode"] == "informational"
    assert gui_settings["low_confidence_email_mode"] == "blocking"


def test_normalize_repo_filters_matches_cli_default_behavior() -> None:
    assert rpg.normalize_repo_filters(["repo-a"]) == ["repo-a"]
    assert rpg.normalize_repo_filters([]) is None


def test_validate_repository_root_variants(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert rpg.validate_repository_root(missing) == f"Root folder does not exist: {missing}"

    file_path = tmp_path / "not-a-directory.txt"
    file_path.write_text("content", encoding="utf-8")
    assert rpg.validate_repository_root(file_path) == f"Root path is not a directory: {file_path}"

    assert rpg.validate_repository_root(tmp_path) is None


def test_discover_repository_targets_includes_current_root_and_children(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    child_repo = tmp_path / "repo-a"
    (child_repo / ".git").mkdir(parents=True)
    (tmp_path / "docs").mkdir()

    repos, skipped, root_error = rpg.discover_repository_targets(tmp_path, repo_filters=None)

    assert root_error is None
    assert skipped == []
    assert repos == [tmp_path, child_repo]


def test_discover_repository_targets_tracks_skipped_filters(tmp_path: Path) -> None:
    repo = tmp_path / "repo-a"
    (repo / ".git").mkdir(parents=True)

    repos, skipped, root_error = rpg.discover_repository_targets(
        tmp_path,
        repo_filters=["repo-a", "missing-repo"],
    )

    assert root_error is None
    assert repos == [repo]
    assert skipped == [str(tmp_path / "missing-repo")]


def test_discover_repository_targets_deduplicates_equivalent_filters(tmp_path: Path) -> None:
    repo = tmp_path / "repo-a"
    (repo / ".git").mkdir(parents=True)

    repos, skipped, root_error = rpg.discover_repository_targets(
        tmp_path,
        repo_filters=["repo-a", str(repo), "repo-a"],
    )

    assert root_error is None
    assert skipped == []
    assert repos == [repo]


def test_discover_repository_targets_does_not_auto_follow_symlinked_children(
    tmp_path: Path,
    monkeypatch,
) -> None:
    real_repo = tmp_path / "repo-a"
    linked_repo = tmp_path / "linked-repo"
    (real_repo / ".git").mkdir(parents=True)
    (linked_repo / ".git").mkdir(parents=True)
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == linked_repo:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    repos, skipped, root_error = rpg.discover_repository_targets(tmp_path, repo_filters=None)

    assert root_error is None
    assert skipped == []
    assert repos == [real_repo]


def test_discover_repository_targets_accepts_explicit_symlinked_child_filter(
    tmp_path: Path,
    monkeypatch,
) -> None:
    real_repo = tmp_path / "repo-a"
    linked_repo = tmp_path / "linked-repo"
    (real_repo / ".git").mkdir(parents=True)
    (linked_repo / ".git").mkdir(parents=True)
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == linked_repo:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    repos, skipped, root_error = rpg.discover_repository_targets(
        tmp_path,
        repo_filters=["linked-repo"],
    )

    assert root_error is None
    assert skipped == []
    assert repos == [linked_repo]


def test_discover_repository_targets_deduplicates_explicit_filters_by_resolved_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    real_repo = tmp_path / "repo-a"
    linked_repo = tmp_path / "linked-repo"
    (real_repo / ".git").mkdir(parents=True)
    (linked_repo / ".git").mkdir(parents=True)
    original_resolve = Path.resolve

    def fake_resolve(self: Path, *args, **kwargs) -> Path:  # type: ignore[no-untyped-def]
        if self == linked_repo:
            return real_repo
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    repos, skipped, root_error = rpg.discover_repository_targets(
        tmp_path,
        repo_filters=["linked-repo", "repo-a"],
    )

    assert root_error is None
    assert skipped == []
    assert repos == [linked_repo]


def test_describe_no_target_resolution_mentions_public_only_for_filtered_targets(
    tmp_path: Path,
) -> None:
    error, guidance = rpg.describe_no_target_resolution(
        root=tmp_path,
        repo_filters=["repo-a", "repo-b"],
        public_only=True,
    )

    assert "after applying --public-only: repo-a, repo-b" in error
    assert "publicly accessible on GitHub" in guidance


def test_normalize_csv_values_and_text_values_helpers() -> None:
    assert rpg.normalize_csv_values("") == []
    assert rpg.normalize_csv_values(" alice@example.com, bob@example.com , alice@example.com ,, ") == [
        "alice@example.com",
        "bob@example.com",
    ]
    assert rpg.normalize_text_values(["  one  ", "", "two", "one"]) == ["one", "two"]


def test_config_helpers_are_public_compatibility_reexports() -> None:
    assert rpg.parse_positive_int is config_helpers.parse_positive_int
    assert rpg.normalize_github_jobs is config_helpers.normalize_github_jobs
    assert rpg.normalize_repo_filters is config_helpers.normalize_repo_filters
    assert rpg.normalize_csv_values is config_helpers.normalize_csv_values
    assert rpg.normalize_text_values is config_helpers.normalize_text_values
    assert rpg.MAX_GITHUB_CLONE_JOBS == config_helpers.MAX_GITHUB_CLONE_JOBS


def test_build_guard_run_config_normalizes_and_infers_owner() -> None:
    config = rpg.build_guard_run_config(
        mode="cli",
        root=Path("C:/repos"),
        policy=Path("C:/repos/docs/POLICY.md"),
        repos=["repo-a"],
        public_only=False,
        fix=True,
        push=True,
        dry_run=True,
        redact_third_party_emails=True,
        purge_detected_secret_files=True,
        purge_all_detected_secret_files=False,
        rewrite_personal_paths=True,
        low_confidence_email_mode="informational",
        owner_name="Owner",
        owner_emails=["dev@example.com", " dev@example.com "],
        noreply_email="12345+octocat@users.noreply.github.com",
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        max_matches=50,
        audit_github_hardening=True,
        accept_github_admin_bypass=True,
        open_report=False,
        confirm_each_repo_fix=False,
        allow_non_owner_push=False,
        allowed_remote_owners=["axeljackal", "axeljackal"],
        replace_text_file="ops/replace-text.txt",
        report_json=None,
        github_owner=" acme ",
        github_include_forks=True,
        github_fast=True,
        github_jobs=0,
    )

    assert config.owner_emails == ["dev@example.com"]
    assert config.allowed_remote_owners == ["axeljackal", "octocat"]
    assert config.replace_text_file == "ops/replace-text.txt"
    assert config.audit_github_hardening is True
    assert config.accept_github_admin_bypass is True
    assert config.open_report is False
    assert config.confirm_each_repo_fix is False
    assert config.github_owner == "acme"
    assert config.github_include_forks is True
    assert config.github_fast is True
    assert config.github_jobs == 1


def test_config_module_builds_normalized_guard_config_kwargs() -> None:
    config = config_helpers.build_guard_run_config(
        config_factory=dict,
        mode="cli",
        root=Path("C:/repos"),
        policy=Path("C:/repos/docs/POLICY.md"),
        repos=["repo-a"],
        public_only=False,
        fix=True,
        push=True,
        dry_run=True,
        redact_third_party_emails=True,
        purge_detected_secret_files=True,
        purge_all_detected_secret_files=False,
        rewrite_personal_paths=True,
        low_confidence_email_mode="informational",
        owner_name="Owner",
        owner_emails=["dev@example.com", " dev@example.com "],
        noreply_email="12345+octocat@users.noreply.github.com",
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        max_matches=50,
        audit_github_hardening=True,
        accept_github_admin_bypass=True,
        open_report=False,
        confirm_each_repo_fix=False,
        allow_non_owner_push=False,
        allowed_remote_owners=["axeljackal", "axeljackal"],
        replace_text_file="ops/replace-text.txt",
        report_json=None,
        github_owner=" acme ",
        github_include_forks=True,
        github_fast=True,
        github_jobs=0,
        suppressions=" suppressions.json ",
    )

    assert config["owner_emails"] == ["dev@example.com"]
    assert config["allowed_remote_owners"] == ["axeljackal", "octocat"]
    assert config["github_owner"] == "acme"
    assert config["accept_github_admin_bypass"] is True
    assert config["github_jobs"] == 1
    assert config["suppressions"] == "suppressions.json"


def test_config_module_builds_cli_guard_config_kwargs() -> None:
    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--root",
            "C:/repos",
            "--repos",
            "repo-a",
            "--fix",
            "--dry-run",
            "--rewrite-personal-paths",
            "--owner-email",
            "dev@example.com",
            "--noreply-email",
            "12345+octocat@users.noreply.github.com",
            "--allow-remote-owner",
            "axeljackal",
            "--replace-text-file",
            "ops/replace-text.txt",
            "--github-owner",
            "acme",
            "--github-jobs",
            "2",
            "--audit-github-hardening",
            "--accept-github-admin-bypass",
            "--agent-summary",
            "--strict-profile",
            "release",
            "--suppressions",
            "suppressions.json",
            "--no-confirm-each-repo",
        ]
    )

    config = config_helpers.build_cli_guard_run_config(args, config_factory=dict)

    assert config["mode"] == "cli"
    assert config["root"] == Path("C:/repos")
    assert config["repos"] == ["repo-a"]
    assert config["fix"] is True
    assert config["dry_run"] is True
    assert config["rewrite_personal_paths"] is True
    assert config["owner_emails"] == ["dev@example.com"]
    assert config["allowed_remote_owners"] == ["axeljackal", "octocat"]
    assert config["replace_text_file"] == "ops/replace-text.txt"
    assert config["github_owner"] == "acme"
    assert config["github_jobs"] == 2
    assert config["agent_summary"] is True
    assert config["accept_github_admin_bypass"] is True
    assert config["confirm_each_repo_fix"] is False
    assert config["strict_profile"] == "release"
    assert config["low_confidence_email_mode"] == "blocking"
    assert config["github_hardening_findings_blocking"] is True
    assert config["suppressions"] == "suppressions.json"


def test_build_guard_run_config_parity_cli_gui_same_inputs() -> None:
    kwargs = dict(
        root=Path("C:/repos"),
        policy=Path("C:/repos/docs/POLICY.md"),
        repos=["repo-a", "repo-b"],
        public_only=True,
        fix=True,
        push=True,
        dry_run=False,
        redact_third_party_emails=True,
        purge_detected_secret_files=True,
        purge_all_detected_secret_files=False,
        rewrite_personal_paths=True,
        low_confidence_email_mode="blocking",
        owner_name="Owner",
        owner_emails=["dev@example.com"],
        noreply_email="12345+octocat@users.noreply.github.com",
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        max_matches=75,
        audit_litellm_incident=True,
        audit_github_hardening=True,
        accept_github_admin_bypass=True,
        open_report=True,
        confirm_each_repo_fix=True,
        allow_non_owner_push=False,
        allowed_remote_owners=["axeljackal"],
        replace_text_file="ops/replace-text.txt",
        report_json="C:/repos/Audit_Results/export.json",
        github_owner="acme",
        github_include_forks=True,
        github_fast=True,
        github_jobs=3,
    )
    cli_config = rpg.build_guard_run_config(mode="cli", **kwargs)
    gui_config = rpg.build_guard_run_config(mode="gui", **kwargs)

    assert cli_config.mode == "cli"
    assert gui_config.mode == "gui"

    for field in fields(rpg.GuardRunConfig):
        if field.name == "mode":
            continue
        assert getattr(cli_config, field.name) == getattr(gui_config, field.name)


def test_execute_guard_pipeline_purge_all_implies_detected(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}
    messages: list[str] = []

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            self.purge_detected_secret_files = purge_detected_secret_files

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            report = _make_report(repo.name)
            report.finalize()
            return report

    def fake_persist(
        reports,
        artifacts,
        root_path,
        policy_path,
        run_settings,
        logger,
        optional_json_export=None,
    ) -> None:
        captured["reports"] = reports
        captured["run_settings"] = run_settings

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", fake_persist)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(
        purge_all_detected_secret_files=True,
        purge_detected_secret_files=False,
        repos=None,
    )
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == 0
    assert any("implies --purge-detected-secret-files" in msg for msg in messages)
    assert captured["run_settings"]["purge_detected_secret_files"] == "True"


def test_execute_guard_pipeline_rejects_remote_github_fix_mode(tmp_path: Path, monkeypatch) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            raise AssertionError("local discovery should not run for rejected remote mode")

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    exit_code = rpg.execute_guard_pipeline(
        config=_make_run_config(github_owner="acme", fix=True),
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == rpg.EXIT_RUNTIME_ERROR
    assert any("--github-owner is audit-only" in msg for msg in messages)
    assert any("[SUMMARY] ERROR 0/0" in msg for msg in messages)


def test_execute_guard_pipeline_remote_github_audit_cleans_temp_clones(
    tmp_path: Path,
    monkeypatch,
) -> None:
    temp_root = tmp_path / "repo-privacy-guardian-github-test"
    repo = temp_root / "repo-a"
    captured: dict[str, object] = {}

    def fake_prepare(config, logger):  # type: ignore[no-untyped-def]
        del config, logger
        (repo / ".git").mkdir(parents=True)
        return [repo], [], temp_root, None

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def audit_repo(self, repo_path: Path) -> rpg.RepoReport:
            report = _make_report(repo_path.name)
            report.path = str(repo_path)
            report.finalize()
            return report

    def fake_persist(
        reports,
        artifacts,
        root_path,
        policy_path,
        run_settings,
        logger,
        optional_json_export=None,
    ) -> None:
        del artifacts, root_path, policy_path, logger, optional_json_export
        captured["reports"] = reports
        captured["run_settings"] = run_settings

    monkeypatch.setattr(rpg, "prepare_github_remote_audit_repositories", fake_prepare)
    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", fake_persist)

    artifacts = rpg.create_run_artifacts(tmp_path / "Audit_Results")
    exit_code = rpg.execute_guard_pipeline(
        config=_make_run_config(github_owner="acme", repos=["repo-a"]),
        artifacts=artifacts,
        logger=lambda _msg: None,
        results_dir=tmp_path / "Audit_Results",
    )

    assert exit_code == rpg.EXIT_OK
    assert temp_root.exists() is False
    assert captured["run_settings"]["github_owner"] == "acme"
    assert [report.name for report in captured["reports"]] == ["repo-a"]


def test_clone_github_remote_repository_public_fast_uses_git(tmp_path: Path) -> None:
    remote = rpg_github.GitHubRemoteRepository(
        name="repo-a",
        full_name="acme/repo-a",
        clone_url="https://github.com/acme/repo-a.git",
        html_url="https://github.com/acme/repo-a",
        private=False,
        fork=False,
    )
    captured: dict[str, object] = {}

    class DummyProc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        destination = Path(cmd[-1])
        (destination / ".git").mkdir(parents=True)
        return DummyProc()

    result = rpg.clone_github_remote_repository(
        remote,
        tmp_path,
        fast=True,
        runner=fake_runner,
    )

    assert result.error is None
    assert captured["cmd"][:4] == ["git", "clone", "--quiet", "--depth"]
    assert captured["cmd"][4] == "1"
    assert captured["cmd"][5] == remote.clone_url
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL


def test_remove_private_temp_tree_removes_readonly_git_files(tmp_path: Path) -> None:
    temp_root = tmp_path / "repo-privacy-guardian-github-test"
    pack_dir = temp_root / "repo-a" / ".git" / "objects" / "pack"
    pack_dir.mkdir(parents=True)
    pack_file = pack_dir / "pack-test.idx"
    pack_file.write_text("pack", encoding="utf-8")
    pack_file.chmod(0o400)

    removed, error = rpg.remove_private_temp_tree(
        temp_root,
        required_prefix="repo-privacy-guardian-github-",
    )

    assert removed is True
    assert error is None
    assert temp_root.exists() is False


def test_remove_private_temp_tree_retries_transient_cleanup_error(tmp_path: Path, monkeypatch) -> None:
    temp_root = tmp_path / "repo-privacy-guardian-github-test"
    temp_root.mkdir()
    (temp_root / "artifact.txt").write_text("payload", encoding="utf-8")
    real_rmtree = shutil.rmtree
    attempts = {"count": 0}

    def flaky_rmtree(path, onerror=None):  # type: ignore[no-untyped-def]
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise PermissionError("locked")
        return real_rmtree(path, onerror=onerror)

    monkeypatch.setattr(rpg.shutil, "rmtree", flaky_rmtree)
    monkeypatch.setattr(rpg.time, "sleep", lambda _seconds: None)

    removed, error = rpg.remove_private_temp_tree(
        temp_root,
        required_prefix="repo-privacy-guardian-github-",
    )

    assert removed is True
    assert error is None
    assert attempts["count"] == 2


def test_remove_private_temp_tree_refuses_unexpected_prefix(tmp_path: Path) -> None:
    temp_root = tmp_path / "not-rpg-temp"
    temp_root.mkdir()

    removed, error = rpg.remove_private_temp_tree(
        temp_root,
        required_prefix="repo-privacy-guardian-github-",
    )

    assert removed is False
    assert "refusing to remove unexpected temporary directory path" in str(error)
    assert temp_root.exists() is True


def test_remove_private_temp_tree_refuses_symlinked_ancestor(tmp_path: Path, monkeypatch) -> None:
    linked_parent = tmp_path / "linked-parent"
    temp_root = linked_parent / "repo-privacy-guardian-github-test"
    temp_root.mkdir(parents=True)
    (temp_root / "artifact.txt").write_text("payload", encoding="utf-8")
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == linked_parent:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    removed, error = rpg.remove_private_temp_tree(
        temp_root,
        required_prefix="repo-privacy-guardian-github-",
    )

    assert removed is False
    assert "symlinked path component" in str(error)
    assert temp_root.exists() is True
    assert (temp_root / "artifact.txt").exists()


def test_clone_github_remote_repository_private_requires_gh(tmp_path: Path) -> None:
    remote = rpg_github.GitHubRemoteRepository(
        name="private-repo",
        full_name="acme/private-repo",
        clone_url="https://github.com/acme/private-repo.git",
        html_url="https://github.com/acme/private-repo",
        private=True,
        fork=False,
    )

    def missing_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        del args, kwargs
        raise FileNotFoundError()

    result = rpg.clone_github_remote_repository(
        remote,
        tmp_path,
        fast=True,
        runner=missing_runner,
    )

    assert result.error is not None
    assert "gh unavailable" in result.error
    assert "authenticated GitHub CLI" in result.error


def test_build_github_clone_failure_report_marks_failure(tmp_path: Path) -> None:
    remote = rpg_github.GitHubRemoteRepository(
        name="repo-a",
        full_name="acme/repo-a",
        clone_url="https://github.com/acme/repo-a.git",
        html_url="https://github.com/acme/repo-a",
        private=False,
        fork=False,
    )
    result = rpg.GitHubCloneResult(remote=remote, path=tmp_path / "repo-a", error="clone failed")

    report = rpg.build_github_clone_failure_report(result)

    assert report.status == "FAIL"
    assert report.origin_url == remote.html_url
    assert any("GitHub remote clone failed" in item for item in report.execution_errors)


def test_execute_guard_pipeline_logs_blocking_email_policy(tmp_path: Path, monkeypatch) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            pass

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            report = _make_report(repo.name)
            report.finalize()
            return report

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(low_confidence_email_mode="blocking", repos=None)
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == 0
    assert any("low-confidence findings are blocking" in msg for msg in messages)


def test_execute_guard_pipeline_confirmation_abort(tmp_path: Path, monkeypatch) -> None:
    messages: list[str] = []
    instances: list[object] = []

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            self.audit_calls = 0
            instances.append(self)

        def discover_repositories(self, repo_filters, public_only: bool):
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path):
            self.audit_calls += 1
            raise AssertionError("audit_repo should not run when confirmation is denied")

        def apply_fixes(self, repo: Path, report):
            raise AssertionError("apply_fixes should not run when confirmation is denied")

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(fix=True, push=True)
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
        require_confirmation=True,
        confirm_callback=lambda: False,
    )

    assert exit_code == 1
    assert any("Run aborted by user confirmation gate." in msg for msg in messages)
    assert any("[SUMMARY] ABORTED 0/0" in msg for msg in messages)
    assert instances[0].audit_calls == 0
    state_payload = json.loads(artifacts.state_path.read_text(encoding="utf-8"))
    assert state_payload["status"] == "aborted"
    assert state_payload["exit_code"] == 1


def test_execute_guard_pipeline_cancel_callback_stops_before_next_repository(
    tmp_path: Path,
    monkeypatch,
) -> None:
    messages: list[str] = []
    audited: list[str] = []

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            return [Path("C:/repos/repo-a"), Path("C:/repos/repo-b")]

        def acquire_repo_lock(self, repo: Path):
            del repo
            return None

        def release_repo_lock(self, repo_lock) -> None:
            del repo_lock

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            audited.append(repo.name)
            report = _make_report(repo.name)
            report.finalize()
            return report

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    exit_code = rpg.execute_guard_pipeline(
        config=_make_run_config(repos=None),
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
        cancel_callback=lambda: len(audited) >= 1,
    )

    assert exit_code == 1
    assert audited == ["repo-a"]
    assert any("[SUMMARY] ABORTED 1/2" in msg for msg in messages)
    assert not any("[SUMMARY] PASS 1/1" in msg for msg in messages)
    state_payload = json.loads(artifacts.state_path.read_text(encoding="utf-8"))
    assert state_payload["status"] == "aborted"
    assert state_payload["completed_repositories"] == 1
    assert state_payload["total_repositories"] == 2


def test_execute_guard_pipeline_cancel_after_last_repo_keeps_final_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    messages: list[str] = []
    audited: list[str] = []

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            return [Path("C:/repos/repo-a")]

        def acquire_repo_lock(self, repo: Path):
            del repo
            return None

        def release_repo_lock(self, repo_lock) -> None:
            del repo_lock

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            audited.append(repo.name)
            report = _make_report(repo.name)
            report.finalize()
            return report

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    exit_code = rpg.execute_guard_pipeline(
        config=_make_run_config(repos=None),
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
        cancel_callback=lambda: len(audited) >= 1,
    )

    assert exit_code == 0
    assert audited == ["repo-a"]
    assert any("[SUMMARY] PASS 1/1" in msg for msg in messages)
    assert not any("[SUMMARY] ABORTED 1/1" in msg for msg in messages)
    state_payload = json.loads(artifacts.state_path.read_text(encoding="utf-8"))
    assert state_payload["status"] == "completed"
    assert state_payload["completed_repositories"] == 1
    assert state_payload["total_repositories"] == 1


def test_execute_guard_pipeline_fix_reaudit_flow(tmp_path: Path, monkeypatch) -> None:
    printed: list[rpg.RepoReport] = []
    captured: dict[str, object] = {}
    instances: list[object] = []

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            self.audit_calls = 0
            instances.append(self)

        def discover_repositories(self, repo_filters, public_only: bool):
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            self.audit_calls += 1
            report = _make_report("repo-a")
            report.finalize()
            return report

        def apply_fixes(self, repo: Path, report: rpg.RepoReport) -> rpg.RepoReport:
            fixed = _make_report("repo-a")
            fixed.backups_created = ["backup.bundle"]
            fixed.fix_actions = ["fixed"]
            fixed.fix_errors = []
            return fixed

    def fake_persist(
        reports,
        artifacts,
        root_path,
        policy_path,
        run_settings,
        logger,
        optional_json_export=None,
    ) -> None:
        captured["reports"] = reports
        captured["run_settings"] = run_settings

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", fake_persist)
    monkeypatch.setattr(rpg, "print_report", lambda report, logger: printed.append(report))

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(fix=True, push=False)
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=lambda _msg: None,
        results_dir=tmp_path,
    )

    assert exit_code == 0
    assert instances[0].audit_calls == 2
    assert len(printed) == 1
    assert printed[0].fix_actions == ["fixed"]
    assert captured["reports"][0].backups_created == ["backup.bundle"]


def test_execute_guard_pipeline_per_repo_confirmation_skip(tmp_path: Path, monkeypatch) -> None:
    printed: list[rpg.RepoReport] = []

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            pass

        def discover_repositories(self, repo_filters, public_only: bool):
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            report = _make_report("repo-a")
            report.finalize()
            return report

        def apply_fixes(self, repo: Path, report: rpg.RepoReport) -> rpg.RepoReport:
            raise AssertionError("apply_fixes should not run when per-repository confirmation is denied")

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)
    monkeypatch.setattr(rpg, "print_report", lambda report, logger: printed.append(report))

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(fix=True, push=False, confirm_each_repo_fix=True)
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=lambda _msg: None,
        results_dir=tmp_path,
        confirm_repo_fix_callback=lambda _repo, _index, _total: False,
    )

    assert exit_code == 0
    assert len(printed) == 1
    assert printed[0].fix_actions == ["fix skipped by per-repository confirmation gate"]


def test_execute_guard_pipeline_handles_runtime_error(tmp_path: Path, monkeypatch) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            pass

        def discover_repositories(self, repo_filters, public_only: bool):
            raise RuntimeError("boom")

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config()
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == 3
    assert any("Unhandled runtime error: boom" in msg for msg in messages)


def test_execute_guard_pipeline_isolates_repo_execution_failures(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            pass

        def discover_repositories(self, repo_filters, public_only: bool):
            return [Path("C:/repos/repo-a"), Path("C:/repos/repo-b")]

        def acquire_repo_lock(self, repo: Path):
            return None

        def release_repo_lock(self, repo_lock) -> None:
            del repo_lock

        def audit_repo(self, repo: Path):
            if repo.name == "repo-a":
                raise RuntimeError("simulated audit failure")
            report = _make_report(repo.name)
            report.finalize()
            return report

    def fake_persist(
        reports,
        artifacts,
        root_path,
        policy_path,
        run_settings,
        logger,
        optional_json_export=None,
        optional_supply_chain_payload=None,
    ) -> None:
        del artifacts, root_path, policy_path, run_settings, logger, optional_json_export, optional_supply_chain_payload
        captured["reports"] = reports

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", fake_persist)

    artifacts = rpg.create_run_artifacts(tmp_path)
    exit_code = rpg.execute_guard_pipeline(
        config=_make_run_config(),
        artifacts=artifacts,
        logger=lambda _msg: None,
        results_dir=tmp_path,
    )

    assert exit_code == 2
    reports = captured["reports"]
    assert len(reports) == 2
    assert reports[0].status == "FAIL"
    assert reports[0].execution_errors == ["simulated audit failure"]
    assert reports[1].status == "PASS"


def test_execute_guard_pipeline_writes_fail_summary_and_run_state(tmp_path: Path, monkeypatch) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            pass

        def discover_repositories(self, repo_filters, public_only: bool):
            return [Path("C:/repos/repo-a")]

        def acquire_repo_lock(self, repo: Path):
            return None

        def release_repo_lock(self, repo_lock) -> None:
            del repo_lock

        def audit_repo(self, repo: Path):
            report = _make_report(repo.name)
            report.tracked_path_matches = [f"README.md:1:{_fixture_win_user_path_slash('private')}"]
            report.finalize()
            return report

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    exit_code = rpg.execute_guard_pipeline(
        config=_make_run_config(),
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    state_payload = json.loads(artifacts.state_path.read_text(encoding="utf-8"))

    assert exit_code == 2
    assert any("[SUMMARY] FAIL 1/1" in msg for msg in messages)
    assert state_payload["status"] == "failed"
    assert state_payload["phase"] == "finished"
    assert state_payload["exit_code"] == 2
    assert state_payload["fail_count"] == 1


def test_apply_fixes_restores_local_identity_even_on_failure(tmp_path: Path, monkeypatch) -> None:
    restored: list[dict[str, str | None]] = []

    guard = rpg.RepoPublicationGuard(
        root=tmp_path,
        policy_path=tmp_path / "POLICY.md",
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        owner_name="Owner",
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
        allowed_remote_owners=[],
        replace_text_file=None,
        logger=lambda _msg: None,
    )
    monkeypatch.setattr(guard, "_capture_local_identity", lambda repo: {"user.name": "Previous", "user.email": "123+old@users.noreply.github.com"})
    monkeypatch.setattr(guard, "_restore_local_identity", lambda repo, original_identity: restored.append(original_identity))
    monkeypatch.setattr(guard, "_make_backup_bundle", lambda repo: repo / "backup.bundle")
    monkeypatch.setattr(guard, "_set_local_identity", lambda repo: None)
    monkeypatch.setattr(guard, "_apply_secret_file_remediation", lambda repo, report: None)
    monkeypatch.setattr(guard, "_remove_tracked_ignored", lambda repo: [])
    monkeypatch.setattr(guard, "_commit_if_needed", lambda repo, message: "none")
    monkeypatch.setattr(guard, "_push_if_requested", lambda repo, report: None)
    monkeypatch.setattr(guard, "_rewrite_history", lambda repo, report: (_ for _ in ()).throw(RuntimeError("rewrite failed")))

    report = _make_report("repo-a")
    guard.apply_fixes(tmp_path / "repo-a", report)

    assert restored == [{"user.name": "Previous", "user.email": "123+old@users.noreply.github.com"}]
    assert any("rewrite failed" in error for error in report.fix_errors)
    assert "restored local git identity" in report.fix_actions


def test_validate_fix_preconditions_blocks_dirty_fsck_and_execution_errors() -> None:
    report = _make_report("repo-a")
    report.clean_status = "## main...origin/main\n M README.md"
    report.fsck_ok = False
    report.execution_errors = ["history patch scan timed out after 300s"]

    issues = rpg.validate_fix_preconditions(report)

    assert any("working tree is not clean" in issue for issue in issues)
    assert any("git fsck failed" in issue for issue in issues)
    assert any("audit completed with execution errors" in issue for issue in issues)


def test_validate_fix_preconditions_clean_repo_is_empty() -> None:
    report = _make_report("repo-a")
    assert rpg.validate_fix_preconditions(report) == []


def test_policy_helpers_are_public_compatibility_reexports() -> None:
    from repo_privacy_guardian import policy
    from repo_privacy_guardian import reporting

    assert rpg.validate_fix_preconditions is policy.validate_fix_preconditions
    assert rpg.repo_user_guidance is policy.repo_user_guidance
    assert rpg.classify_repo_severity is policy.classify_repo_severity
    assert rpg.classify_litellm_incident_severity is policy.classify_litellm_incident_severity
    assert reporting.validate_fix_preconditions is policy.validate_fix_preconditions
    assert reporting.repo_user_guidance is policy.repo_user_guidance


def test_repo_has_dirty_worktree_variants() -> None:
    assert rpg.repo_has_dirty_worktree("## main...origin/main") is False
    assert rpg.repo_has_dirty_worktree("## main...origin/main\n M README.md") is True
    assert rpg.repo_has_dirty_worktree(None) is False


def test_apply_fixes_refuses_when_fix_preconditions_fail(tmp_path: Path, monkeypatch) -> None:
    guard = rpg.RepoPublicationGuard(
        root=tmp_path,
        policy_path=tmp_path / "POLICY.md",
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        owner_name="Owner",
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
        allowed_remote_owners=[],
        replace_text_file=None,
        logger=lambda _msg: None,
    )
    monkeypatch.setattr(
        guard,
        "_make_backup_bundle",
        lambda repo: (_ for _ in ()).throw(AssertionError("fix should abort before mutating the repo")),
    )

    report = _make_report("repo-a")
    report.clean_status = "## main...origin/main\n M README.md"

    result = guard.apply_fixes(tmp_path / "repo-a", report)

    assert result is report
    assert any("working tree is not clean" in error for error in report.fix_errors)
    assert report.backups_created == []


def test_run_git_command_reports_timeout(monkeypatch) -> None:
    def timed_out(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise rpg.subprocess.TimeoutExpired(args[0], timeout=1)

    monkeypatch.setattr(rpg.subprocess, "run", timed_out)

    result = rpg.run_git_command(["status"])

    assert result.returncode == 124
    assert "timed out" in result.stderr


def test_is_github_noreply_email_variants() -> None:
    assert rpg.is_github_noreply_email("noreply@github.com") is True
    assert rpg.is_github_noreply_email("12345+user@users.noreply.github.com") is True
    assert rpg.is_github_noreply_email("   ") is False
    assert rpg.is_github_noreply_email("user@example.com") is False


def test_run_git_command_mocked_subprocess(monkeypatch) -> None:
    class DummyProc:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    calls: dict[str, object] = {}

    def fake_run(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return DummyProc()

    monkeypatch.setattr(rpg.subprocess, "run", fake_run)

    result = rpg.run_git_command(["config", "--global", "user.name", "Owner"], Path("C:/repos"))

    assert result.returncode == 0
    assert result.stdout == "ok"
    assert calls["args"][0][:2] == ["git", "config"]
    assert calls["kwargs"]["cwd"] == str(Path("C:/repos"))
    assert calls["kwargs"]["stdin"] == subprocess.DEVNULL


def test_execution_adapter_preserves_cwd_input_and_timeout_contract() -> None:
    class DummyProc:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    calls: list[dict[str, object]] = []

    def fake_runner(cmd: list[str], **kwargs) -> DummyProc:
        calls.append({"cmd": cmd, "kwargs": dict(kwargs)})
        return DummyProc()

    adapter = execution_helpers.GitSubprocessAdapter(
        timeout_seconds=7,
        result_factory=rpg.CommandResult,
        missing_executable_message=lambda executable: f"missing {executable}",
        stdin_selector=rpg.subprocess_stdin,
        remediation_install_packages=("git-filter-repo>=2.45,<3",),
        python_executable="python",
        runner=fake_runner,
    )

    result = adapter.run(["tool", "arg"], cwd=Path("C:/repos/demo"), input_text="y\n")

    assert result == rpg.CommandResult(0, "ok\n", "")
    assert calls[0]["cmd"] == ["tool", "arg"]
    kwargs = calls[0]["kwargs"]
    assert kwargs["cwd"] == str(Path("C:/repos/demo"))
    assert kwargs["input"] == "y\n"
    assert kwargs["stdin"] == subprocess.PIPE
    assert kwargs["timeout"] == 7
    assert kwargs["capture_output"] is True
    assert kwargs["encoding"] == "utf-8"


def test_execution_adapter_reports_start_timeout_and_checked_errors() -> None:
    adapter = execution_helpers.GitSubprocessAdapter(
        timeout_seconds=3,
        result_factory=rpg.CommandResult,
        missing_executable_message=lambda executable: f"missing {executable}",
        stdin_selector=rpg.subprocess_stdin,
        remediation_install_packages=("git-filter-repo>=2.45,<3",),
        python_executable="python",
        runner=lambda _cmd, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )

    assert adapter.run(["missing-tool"]).stderr == "missing missing-tool"

    timeout_adapter = execution_helpers.GitSubprocessAdapter(
        timeout_seconds=3,
        result_factory=rpg.CommandResult,
        missing_executable_message=lambda executable: f"missing {executable}",
        stdin_selector=rpg.subprocess_stdin,
        remediation_install_packages=("git-filter-repo>=2.45,<3",),
        python_executable="python",
        runner=lambda cmd, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd, timeout=3)
        ),
    )

    timeout_result = timeout_adapter.run(["tool", "arg"])
    assert timeout_result.returncode == 124
    assert "Command timed out after 3s: tool arg" in timeout_result.stderr

    crash_adapter = execution_helpers.GitSubprocessAdapter(
        timeout_seconds=3,
        result_factory=rpg.CommandResult,
        missing_executable_message=lambda executable: f"missing {executable}",
        stdin_selector=rpg.subprocess_stdin,
        remediation_install_packages=("git-filter-repo>=2.45,<3",),
        python_executable="python",
        runner=lambda _cmd, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    crash_result = crash_adapter.run(["tool"])
    assert crash_result.returncode == 1
    assert "Unable to execute tool: boom" in crash_result.stderr

    failing_adapter = execution_helpers.GitSubprocessAdapter(
        timeout_seconds=3,
        result_factory=rpg.CommandResult,
        missing_executable_message=lambda executable: f"missing {executable}",
        stdin_selector=rpg.subprocess_stdin,
        remediation_install_packages=("git-filter-repo>=2.45,<3",),
        python_executable="python",
        runner=lambda _cmd, **_kwargs: rpg.CommandResult(9, "out", "err"),
    )

    with pytest.raises(RuntimeError, match=r"Command failed \(9\): tool arg"):
        failing_adapter.run_checked(["tool", "arg"])


def test_guard_git_wrappers_delegate_to_execution_adapter(monkeypatch, tmp_path: Path) -> None:
    class DummyProc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    calls: list[list[str]] = []

    def fake_runner(cmd: list[str], **_kwargs) -> DummyProc:
        calls.append(cmd)
        return DummyProc()

    monkeypatch.setattr(rpg.subprocess, "run", fake_runner)
    guard = _make_guard(tmp_path)

    assert guard._git(Path("C:/repos/demo"), "status").stdout == "ok"
    assert guard._git_checked(Path("C:/repos/demo"), "config", "user.name").stdout == "ok"
    assert calls == [
        ["git", "-C", str(Path("C:/repos/demo")), "status"],
        ["git", "-C", str(Path("C:/repos/demo")), "config", "user.name"],
    ]


def test_guard_ensure_git_filter_repo_preserves_error_contract(
    monkeypatch,
    tmp_path: Path,
) -> None:
    class DummyProc:
        returncode = 1
        stdout = ""
        stderr = "missing module"

    calls: list[list[str]] = []

    def fake_runner(cmd: list[str], **_kwargs) -> DummyProc:
        calls.append(cmd)
        return DummyProc()

    monkeypatch.setattr(rpg.subprocess, "run", fake_runner)
    guard = _make_guard(tmp_path)

    with pytest.raises(RuntimeError) as exc_info:
        guard._ensure_git_filter_repo()

    assert calls == [[sys.executable, "-m", "git_filter_repo", "--help"]]
    message = str(exc_info.value)
    assert "git-filter-repo is required" in message
    assert "pip install git-filter-repo" in message
    assert "Details: missing module" in message

    class SuccessProc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(rpg.subprocess, "run", lambda _cmd, **_kwargs: SuccessProc())
    _make_guard(tmp_path)._ensure_git_filter_repo()


def test_streaming_adapter_starts_git_history_patch_and_finalizes(tmp_path: Path) -> None:
    class DummyStream:
        def __init__(self, payload: str = "") -> None:
            self.payload = payload
            self.closed = False

        def read(self) -> str:
            return self.payload

        def close(self) -> None:
            self.closed = True

    class DummyProc:
        def __init__(self) -> None:
            self.stdout = DummyStream()
            self.stderr = DummyStream("fatal: nope")
            self.returncode: int | None = 0

        def wait(self, timeout=None):
            del timeout
            return self.returncode

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def kill(self) -> None:
            self.returncode = -9

    captured: dict[str, object] = {}
    proc = DummyProc()

    def fake_popen(cmd: list[str], **kwargs) -> DummyProc:
        captured["cmd"] = cmd
        captured["kwargs"] = dict(kwargs)
        return proc

    adapter = execution_helpers.GitStreamingAdapter(
        timeout_seconds=11,
        popen_kwargs_factory=lambda: {"stdin": subprocess.DEVNULL, "start_new_session": True},
        popen_factory=fake_popen,
    )

    started = adapter.start_git_history_patch(tmp_path)
    assert started is proc
    assert captured["cmd"] == [
        "git",
        "-C",
        str(tmp_path),
        "log",
        "--all",
        "-p",
        "--no-color",
        "--pretty=format:",
    ]
    kwargs = captured["kwargs"]
    assert kwargs["stdout"] == subprocess.PIPE
    assert kwargs["stderr"] == subprocess.PIPE
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["start_new_session"] is True
    assert kwargs["encoding"] == "utf-8"

    returncode, stderr_text = adapter.finalize(proc)

    assert returncode == 0
    assert stderr_text == "fatal: nope"
    assert proc.stdout.closed is True
    assert proc.stderr.closed is True


def test_streaming_adapter_timeout_terminates_then_kills() -> None:
    class DummyStream:
        def read(self) -> str:
            return ""

        def close(self) -> None:
            return None

    class DummyProc:
        def __init__(self) -> None:
            self.stdout = DummyStream()
            self.stderr = DummyStream()
            self.returncode: int | None = None
            self.terminated = False
            self.killed = False

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(["git"], timeout=timeout)

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True
            raise RuntimeError("cannot terminate")

        def kill(self) -> None:
            self.killed = True

    proc = DummyProc()
    adapter = execution_helpers.GitStreamingAdapter(
        timeout_seconds=1,
        popen_kwargs_factory=lambda: {},
        popen_factory=lambda *_args, **_kwargs: proc,
    )

    returncode, stderr_text = adapter.finalize(proc)

    assert returncode is None
    assert stderr_text == ""
    assert proc.terminated is True
    assert proc.killed is True


def test_guard_run_uses_non_interactive_stdin(monkeypatch, tmp_path: Path) -> None:
    class DummyProc:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    captured: list[dict[str, object]] = []

    def fake_run(*args, **kwargs):
        del args
        captured.append(dict(kwargs))
        return DummyProc()

    monkeypatch.setattr(rpg.subprocess, "run", fake_run)
    guard = _make_guard(tmp_path)

    guard._run(["git", "--version"])
    guard._run(["git", "--version"], input_text="y\n")

    assert captured[0]["stdin"] == subprocess.DEVNULL
    assert captured[0]["input"] is None
    assert captured[1]["stdin"] == subprocess.PIPE
    assert captured[1]["input"] == "y\n"


def test_rewrite_history_dry_run_does_not_execute_git_filter_repo(tmp_path: Path) -> None:
    guard = object.__new__(rpg.RepoPublicationGuard)
    guard.dry_run = True
    guard.replace_text_file = None
    guard.rewrite_personal_paths = False
    guard.owner_name = "Owner"
    guard.owner_emails = set()
    guard.noreply_email = rpg.DEFAULT_NOREPLY
    guard.placeholder_email = rpg.DEFAULT_PLACEHOLDER
    guard.redact_third_party = False
    guard._is_allowed_email = lambda _email: False
    guard._save_remotes = lambda _repo: {"origin": "https://example.test/repo.git"}
    guard._ensure_git_filter_repo = lambda: (_ for _ in ()).throw(
        AssertionError("dry-run must not require git-filter-repo")
    )
    guard._run_checked = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("dry-run must not execute git-filter-repo")
    )

    report = _make_report("rewrite-dry-run")
    report.secret_history_purge_paths = [".env"]

    guard._rewrite_history(tmp_path, report)

    assert "[dry-run] history rewrite would run" in report.fix_actions
    assert "[dry-run] purge paths preview: .env" in report.fix_actions


def test_history_patch_scan_starts_stream_process_isolated(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo-a"
    repo.mkdir()
    captured: dict[str, object] = {}

    class DummyStream:
        def __iter__(self):
            return iter(())

        def read(self) -> str:
            return ""

        def close(self) -> None:
            return None

    class DummyProc:
        def __init__(self) -> None:
            self.stdout = DummyStream()
            self.stderr = DummyStream()
            self.returncode = 0

        def wait(self, timeout=None) -> None:
            del timeout
            self.returncode = 0

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def kill(self) -> None:
            self.returncode = 0

    def fake_popen(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return DummyProc()

    monkeypatch.setattr(rpg.subprocess, "Popen", fake_popen)
    guard = _make_guard(tmp_path)

    assert guard._scan_history_patch(repo, rpg.SECRET_CONTENT_RE) == []
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL
    assert captured["kwargs"]["start_new_session"] is True


def test_history_patch_scan_records_stderr_on_nonzero_exit(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo-a"
    repo.mkdir()

    class DummyStream:
        def __init__(self, lines: list[str] | None = None, stderr: str = "") -> None:
            self.lines = lines or []
            self.stderr = stderr

        def __iter__(self):
            return iter(self.lines)

        def read(self) -> str:
            return self.stderr

        def close(self) -> None:
            return None

    class DummyProc:
        def __init__(self) -> None:
            self.stdout = DummyStream([])
            self.stderr = DummyStream(stderr="fatal: bad revision")
            self.returncode = 2

        def wait(self, timeout=None):
            del timeout
            return self.returncode

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(rpg.subprocess, "Popen", lambda *_args, **_kwargs: DummyProc())
    guard = _make_guard(tmp_path)

    assert guard._scan_history_patch(repo, rpg.SECRET_CONTENT_RE) == []
    assert guard._flush_repo_runtime_issues() == [
        "history patch scan failed with exit code 2: fatal: bad revision"
    ]


def test_history_patch_scan_terminates_after_max_matches(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo-a"
    repo.mkdir()

    class DummyStream:
        def __iter__(self):
            return iter([f"+token={_fixture_secret()}\n", f"+other={_fixture_aws_key()}\n"])

        def read(self) -> str:
            return ""

        def close(self) -> None:
            return None

    class DummyProc:
        def __init__(self) -> None:
            self.stdout = DummyStream()
            self.stderr = DummyStream()
            self.returncode: int | None = None
            self.terminated = False

        def wait(self, timeout=None):
            del timeout
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True
            self.returncode = 0

        def kill(self) -> None:
            self.returncode = -9

    proc = DummyProc()
    monkeypatch.setattr(rpg.subprocess, "Popen", lambda *_args, **_kwargs: proc)
    guard = _make_guard(tmp_path)
    guard.max_matches = 1

    matches = guard._scan_history_patch(repo, rpg.SECRET_CONTENT_RE)

    assert len(matches) == 1
    assert matches[0].startswith("L1:+token=")
    assert proc.terminated is True
    assert guard._flush_repo_runtime_issues() == []


def test_history_secret_taxonomy_scan_preserves_bucket_parity(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo-a"
    repo.mkdir()
    low_confidence_secret = "synthetic-review-token" * 2

    class DummyStream:
        def __init__(self, lines: list[str] | None = None, stderr: str = "") -> None:
            self.lines = lines or []
            self.stderr = stderr

        def __iter__(self):
            return iter(self.lines)

        def read(self) -> str:
            return self.stderr

        def close(self) -> None:
            return None

    class DummyProc:
        def __init__(self) -> None:
            self.stdout = DummyStream(
                [
                    "diff --git a/src/settings.py b/src/settings.py\n",
                    "+++ b/src/settings.py\n",
                    f"+token={_fixture_aws_key()}\n",
                    f"+api_key={low_confidence_secret}\n",
                    " context should not scan AKIAAAAAAAAAAAAAAAA\n",
                    "diff --git a/tests/fixtures/example.env b/tests/fixtures/example.env\n",
                    f"+token={_fixture_secret()}\n",
                    "diff --git a/docs/guide.md b/docs/guide.md\n",
                    f"+token={_fixture_secret()}\n",
                    "--- a/docs/guide.md\n",
                ]
            )
            self.stderr = DummyStream()
            self.returncode: int | None = None

        def wait(self, timeout=None):
            del timeout
            self.returncode = 0
            return self.returncode

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            self.returncode = 0

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr(rpg.subprocess, "Popen", lambda *_args, **_kwargs: DummyProc())
    guard = _make_guard(tmp_path)

    high_confidence, low_confidence, fixtures, documentation = guard._scan_history_secret_taxonomy(repo)

    assert high_confidence == [f"L3:src/settings.py:token={_fixture_aws_key()}"]
    assert low_confidence == [f"L4:src/settings.py:api_key={low_confidence_secret}"]
    assert fixtures == [f"L7:tests/fixtures/example.env:token={_fixture_secret()}"]
    assert documentation == [f"L9:docs/guide.md:token={_fixture_secret()}"]
    assert guard._flush_repo_runtime_issues() == []


def test_validate_git_identity_inputs() -> None:
    assert "git user.name is required." in rpg.validate_git_identity_inputs("", "")
    assert "git user.email is required." in rpg.validate_git_identity_inputs("Owner", "")
    assert (
        "git user.email must be a valid email address."
        in rpg.validate_git_identity_inputs("Owner", "invalid-email")
    )
    assert (
        "git user.email should be a GitHub noreply address "
        "(for example: <id+username>@users.noreply.github.com)."
        in rpg.validate_git_identity_inputs("Owner", "owner@example.com")
    )
    assert rpg.validate_git_identity_inputs("Owner", "12345+owner@users.noreply.github.com") == []


def test_apply_git_identity_config_global_success_mocked() -> None:
    calls: list[tuple[list[str], Path | None]] = []

    def fake_runner(args: list[str], cwd: Path | None) -> rpg.CommandResult:
        calls.append((args, cwd))
        return rpg.CommandResult(0, "", "")

    ok, msg = rpg.apply_git_identity_config(
        scope="global",
        user_name="Owner",
        user_email="123+owner@users.noreply.github.com",
        git_runner=fake_runner,
    )

    assert ok is True
    assert "Applied GLOBAL git identity" in msg
    assert calls == [
        (["config", "--global", "user.name", "Owner"], None),
        (["config", "--global", "user.email", "123+owner@users.noreply.github.com"], None),
    ]


def test_apply_git_identity_config_local_errors() -> None:
    ok, msg = rpg.apply_git_identity_config(
        scope="global",
        user_name="",
        user_email="",
    )
    assert ok is False
    assert "git user.name is required." in msg

    ok, msg = rpg.apply_git_identity_config(
        scope="local",
        user_name="Owner",
        user_email="123+owner@users.noreply.github.com",
        repo_path=None,
    )
    assert ok is False
    assert "requires a target repository path" in msg

    ok, msg = rpg.apply_git_identity_config(
        scope="workspace",
        user_name="Owner",
        user_email="123+owner@users.noreply.github.com",
    )
    assert ok is False
    assert "Unsupported git config scope" in msg


def test_apply_git_identity_config_command_failure() -> None:
    repo = Path("C:/repos/repo-a")
    calls: list[tuple[list[str], Path | None]] = []

    def fake_runner(args: list[str], cwd: Path | None) -> rpg.CommandResult:
        calls.append((args, cwd))
        if args[2] == "user.email":
            return rpg.CommandResult(1, "", "permission denied")
        return rpg.CommandResult(0, "", "")

    ok, msg = rpg.apply_git_identity_config(
        scope="local",
        user_name="Owner",
        user_email="123+owner@users.noreply.github.com",
        repo_path=repo,
        git_runner=fake_runner,
    )

    assert ok is False
    assert "Failed to set user.email (local): permission denied" in msg
    assert calls[0] == (["config", "--local", "user.name", "Owner"], repo)
    assert calls[1] == (
        ["config", "--local", "user.email", "123+owner@users.noreply.github.com"],
        repo,
    )


def test_read_git_identity_config_without_repo_mocked() -> None:
    calls: list[tuple[list[str], Path | None]] = []

    def fake_runner(args: list[str], cwd: Path | None) -> rpg.CommandResult:
        calls.append((args, cwd))
        if args[-1] == "user.name":
            return rpg.CommandResult(0, "Owner", "")
        return rpg.CommandResult(0, "123+owner@users.noreply.github.com", "")

    values = rpg.read_git_identity_config(repo_path=None, git_runner=fake_runner)

    assert values["global.user.name"] == "Owner"
    assert values["global.user.email"] == "123+owner@users.noreply.github.com"
    assert values["local.user.name"].startswith("(n/a")
    assert len(calls) == 2


def test_read_git_identity_config_with_repo_and_error_state() -> None:
    repo = Path("C:/repos/repo-a")
    calls: list[tuple[list[str], Path | None]] = []
    responses = [
        rpg.CommandResult(0, "Global Owner", ""),
        rpg.CommandResult(0, "123+global@users.noreply.github.com", ""),
        rpg.CommandResult(0, "Local Owner", ""),
        rpg.CommandResult(1, "", "fatal: config error"),
        rpg.CommandResult(0, "Effective Owner", ""),
        rpg.CommandResult(0, "123+effective@users.noreply.github.com", ""),
    ]

    def fake_runner(args: list[str], cwd: Path | None) -> rpg.CommandResult:
        calls.append((args, cwd))
        return responses[len(calls) - 1]

    values = rpg.read_git_identity_config(repo_path=repo, git_runner=fake_runner)

    assert values["local.user.name"] == "Local Owner"
    assert values["local.user.email"] == "(error: fatal: config error)"
    assert values["effective.user.name"] == "Effective Owner"
    assert values["effective.user.email"] == "123+effective@users.noreply.github.com"
    assert calls[2][1] == repo
    assert calls[3][1] == repo


def test_read_git_config_value_without_detail_returns_not_set() -> None:
    value = rpg._read_git_config_value(
        key="user.name",
        scope_args=["--local"],
        repo_path=Path("C:/repos/repo-a"),
        git_runner=lambda _args, _cwd: rpg.CommandResult(1, "", ""),
    )
    assert value == "(not set)"


def test_format_git_identity_status_contains_all_sections() -> None:
    values = {
        "global.user.name": "A",
        "global.user.email": "B",
        "local.user.name": "C",
        "local.user.email": "D",
        "effective.user.name": "E",
        "effective.user.email": "F",
    }
    text = rpg.format_git_identity_status(values, Path("C:/repos/repo-a"))

    assert "Git identity status" in text
    assert f"Repository context: {Path('C:/repos/repo-a')}" in text
    assert "Global user.name: A" in text
    assert "Effective user.email: F" in text


def test_open_github_email_settings_mocked() -> None:
    opened_urls: list[str] = []

    def ok_opener(url: str) -> bool:
        opened_urls.append(url)
        return True

    ok, msg = rpg.open_github_email_settings(opener=ok_opener)
    assert ok is True
    assert rpg.GITHUB_EMAIL_SETTINGS_URL in opened_urls
    assert "Opened" in msg

    ok, msg = rpg.open_github_email_settings(opener=lambda _url: False)
    assert ok is False
    assert "could not open" in msg

    def bad_opener(_url: str) -> bool:
        raise RuntimeError("browser unavailable")

    ok, msg = rpg.open_github_email_settings(opener=bad_opener)
    assert ok is False
    assert "browser unavailable" in msg


def test_resolve_identity_repo_path_variants(tmp_path: Path) -> None:
    root_repo = tmp_path / "root-repo"
    root_repo.mkdir()
    (root_repo / ".git").mkdir()

    nested = tmp_path / "workspace"
    nested.mkdir()
    child = nested / "repo-a"
    child.mkdir()
    (child / ".git").mkdir()

    path, error = rpg.resolve_identity_repo_path(root_repo, [])
    assert path == root_repo
    assert error is None

    path, error = rpg.resolve_identity_repo_path(nested, ["repo-a"])
    assert path == child
    assert error is None

    path, error = rpg.resolve_identity_repo_path(nested, ["repo-a", "repo-b"])
    assert path is None
    assert "Select exactly one repository" in error

    path, error = rpg.resolve_identity_repo_path(nested, ["missing-repo"])
    assert path is None
    assert "not a git repository" in error

    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    path, error = rpg.resolve_identity_repo_path(empty_root, [])
    assert path is None
    assert "Select one repository first" in error


def test_execute_guard_pipeline_gui_mode_no_regression(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            pass

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            report = _make_report(repo.name)
            report.finalize()
            return report

    def fake_persist(
        reports,
        artifacts,
        root_path,
        policy_path,
        run_settings,
        logger,
        optional_json_export=None,
    ) -> None:
        captured["run_settings"] = run_settings
        captured["reports"] = reports

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", fake_persist)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(mode="gui", repos=None, low_confidence_email_mode="blocking")
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=lambda _msg: None,
        results_dir=tmp_path,
    )

    assert exit_code == 0
    assert captured["run_settings"]["mode"] == "gui"
    assert captured["run_settings"]["low_confidence_email_mode"] == "blocking"
    assert len(captured["reports"]) == 1
    assert captured["reports"][0].name == "repo-a"


def test_execute_guard_pipeline_all_repos_when_filters_none(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    class DummyGuard:
        def __init__(
            self,
            root: Path,
            policy_path: Path,
            noreply_email: str,
            placeholder_email: str,
            owner_name: str,
            owner_emails: list[str],
            redact_third_party: bool,
            purge_detected_secret_files: bool,
            purge_all_detected_secret_files: bool,
            low_confidence_email_mode: str,
            push: bool,
            dry_run: bool,
            max_matches: int,
            allow_non_owner_push: bool,
            allowed_remote_owners: list[str],
            logger,
        ) -> None:
            pass

        def discover_repositories(self, repo_filters, public_only: bool):
            captured["repo_filters"] = repo_filters
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path) -> rpg.RepoReport:
            report = _make_report(repo.name)
            report.finalize()
            return report

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(mode="gui", repos=None)
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=lambda _msg: None,
        results_dir=tmp_path,
    )

    assert exit_code == 0
    assert captured["repo_filters"] is None


def test_execute_guard_pipeline_invalid_root_reports_clean_error(tmp_path: Path, monkeypatch) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def discover_repositories(self, repo_filters, public_only: bool):
            raise AssertionError("discover_repositories should not run when root is invalid")

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(mode="cli", root=tmp_path / "missing-root")
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == 3
    assert any("Root folder does not exist" in msg for msg in messages)
    assert any("[SUMMARY] ERROR 0/0" in msg for msg in messages)
    assert not any("Unhandled runtime error" in msg for msg in messages)


def test_execute_guard_pipeline_errors_when_requested_filters_match_no_repos(
    tmp_path: Path,
    monkeypatch,
) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            return []

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(mode="cli", repos=["missing-repo"])
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == 3
    assert any("No target repositories matched the requested filters: missing-repo" in msg for msg in messages)
    assert any("[SUMMARY] ERROR 0/0" in msg for msg in messages)
    assert not any("[SUMMARY] PASS 0/0" in msg for msg in messages)


def test_execute_guard_pipeline_errors_when_root_contains_no_git_repositories(
    tmp_path: Path,
    monkeypatch,
) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters, public_only
            return []

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(mode="cli", root=tmp_path, repos=None)
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == 3
    assert any(f"No git repositories were found under Root: {tmp_path}" in msg for msg in messages)
    assert any("point --root at an existing git checkout" in msg for msg in messages)
    assert any("[SUMMARY] ERROR 0/0" in msg for msg in messages)
    assert not any("[SUMMARY] PASS 0/0" in msg for msg in messages)


def test_execute_guard_pipeline_errors_when_public_only_excludes_everything(
    tmp_path: Path,
    monkeypatch,
) -> None:
    messages: list[str] = []

    class DummyGuard:
        def __init__(self, **kwargs) -> None:
            del kwargs

        def discover_repositories(self, repo_filters, public_only: bool):
            del repo_filters
            assert public_only is True
            return []

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(mode="cli", root=tmp_path, repos=None, public_only=True)
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=messages.append,
        results_dir=tmp_path,
    )

    assert exit_code == 3
    assert any(f"No public GitHub repositories matched under Root: {tmp_path}" in msg for msg in messages)
    assert any("remove --public-only" in msg for msg in messages)
    assert any("[SUMMARY] ERROR 0/0" in msg for msg in messages)
    assert not any("[SUMMARY] PASS 0/0" in msg for msg in messages)
