from __future__ import annotations

import json
import sys
import types
from datetime import datetime
from pathlib import Path

import pytest

import Repo_Privacy_Guardian as rpg


def _fixture_secret() -> str:
    return "ghp_" + ("A" * 36)


def _fixture_aws_key() -> str:
    return "AKIA" + ("A" * 16)


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
    base = {
        "mode": "cli",
        "root": Path("C:/repos"),
        "policy": Path("C:/repos/docs/POLICY.md"),
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


def test_repo_report_finalize_builds_failures() -> None:
    report = _make_report("repo-a")
    report.unexpected_emails = ["private@example.com"]
    report.tracked_secret_matches = [f"secret.txt:1:{_fixture_aws_key()}"]

    report.finalize()

    assert report.status == "FAIL"
    assert "unexpected commit metadata emails in owned repository" in report.failures
    assert "secret-like patterns in tracked files" in report.failures


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
    assert rpg.parse_github_remote_owner("redacted-contributor@example.invalid:example/repo.git") == "example"
    assert rpg.parse_github_remote_owner("https://gitlab.com/example/repo.git") is None


def test_parse_github_remote_slug_helper() -> None:
    assert rpg.parse_github_remote_slug("https://github.com/example/repo.git") == ("example", "repo")
    assert rpg.parse_github_remote_slug("git@github.com:example/repo.git") == ("example", "repo")
    assert rpg.parse_github_remote_slug("https://gitlab.com/example/repo.git") is None


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
    assert tkinter_check.state == "ready"
    assert customtkinter_check.state == "missing"
    assert customtkinter_check.auto_install_command == [
        rpg.sys.executable,
        "-m",
        "pip",
        "install",
        *rpg.GUI_INSTALL_PACKAGES,
    ]


def test_audit_github_release_hardening_warns_when_admin_checks_are_skipped(tmp_path: Path, monkeypatch) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("* @owner\n", encoding="utf-8")

    monkeypatch.setattr(
        rpg,
        "github_api_get_json",
        lambda url, token=None: ({"default_branch": "main", "has_wiki": False, "has_projects": False}, "http_200"),
    )

    findings, warnings = rpg.audit_github_release_hardening(
        repo=tmp_path,
        remote_url="https://github.com/example/repo.git",
        token="",
    )

    assert findings == []
    assert any("Admin-only GitHub hardening checks were skipped" in item for item in warnings)


def test_audit_github_release_hardening_reports_missing_controls(tmp_path: Path, monkeypatch) -> None:
    def fake_get_json(url: str, token: str | None = None):  # type: ignore[no-untyped-def]
        assert token == "gh-admin-token"
        if url.endswith("/actions/permissions"):
            return ({"allowed_actions": "all", "sha_pinning_required": False}, "http_200")
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
        if url.endswith("/branches/main/protection"):
            return (
                {
                    "required_pull_request_reviews": {
                        "required_approving_review_count": 0,
                        "require_code_owner_reviews": False,
                        "dismiss_stale_reviews": False,
                    },
                    "required_conversation_resolution": {"enabled": False},
                    "required_status_checks": None,
                    "allow_force_pushes": {"enabled": True},
                    "allow_deletions": {"enabled": True},
                },
                "http_200",
            )
        return (
            {
                "default_branch": "main",
                "has_wiki": True,
                "has_projects": True,
                "allow_auto_merge": True,
            },
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
    assert any("wiki is enabled" in item for item in findings)
    assert any("projects are enabled" in item for item in findings)
    assert any("auto-merge is enabled" in item for item in findings)
    assert any("approving review is not required" in item for item in findings)
    assert any("code owner reviews are not required" in item for item in findings)
    assert any("stale reviews are not dismissed" in item for item in findings)
    assert any("conversation resolution is not required" in item for item in findings)
    assert any("required status checks are not configured" in item for item in findings)
    assert any("force pushes are allowed" in item for item in findings)
    assert any("branch deletion is allowed" in item for item in findings)
    assert any("all external actions are allowed" in item for item in findings)
    assert any("SHA pinning is not required" in item for item in findings)
    assert any("workflow permissions are broader than read-only" in item for item in findings)
    assert any("allow PR approval" in item for item in findings)
    assert any("vulnerability alerts are disabled" in item for item in findings)
    assert any("automated security fixes are disabled or paused" in item for item in findings)


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

    assert tracked_high == [tracked[1]]
    assert tracked_low == [tracked[0]]
    assert history_high == [history[1]]
    assert history_low == [history[0]]

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
    assert rpg.is_low_confidence_email_context(None, "assert user.email") is True
    assert rpg.is_low_confidence_email_context("src/service.py", "prod_email = 'redacted-contributor@example.invalid'") is False

    owned, third_party = rpg.split_unexpected_emails_by_origin_ownership([], None, {"example"})
    assert owned == []
    assert third_party == []


def test_redact_sensitive_text_and_sanitize_export_payload() -> None:
    secret = _fixture_secret()
    win_path = _fixture_win_user_path("Documents", "repo")
    escaped_win_path = _fixture_escaped_win_user_path("Documents", "repo")
    unix_user_path = _fixture_unix_user_path("Users", "bob", "repo")
    unix_home_path = _fixture_unix_user_path("home", "carol", ".ssh")
    sample = (
        f"token {secret} "
        "email dev@example.com "
        f"path {win_path} "
        f"json_path {escaped_win_path} "
        "profile AppData\\Roaming\\Code "
        "json_profile AppData\\\\Roaming\\\\Code "
        f"unix {unix_user_path} {unix_home_path}"
    )
    redacted = rpg.redact_sensitive_text(sample)

    assert rpg.REDACTED_SECRET in redacted
    assert rpg.REDACTED_EMAIL in redacted
    assert "C:\\Users\\<redacted>" in redacted
    assert "C:\\\\Users\\\\<redacted>" in redacted
    assert "AppData\\<redacted>" in redacted
    assert "AppData\\\\<redacted>" in redacted
    assert "/Users/<redacted>" in redacted
    assert "/home/<redacted>" in redacted

    report = _make_report("repo-a")
    report.path = _fixture_win_user_path_slash("repo-a")
    report.clean_status = "author dev@example.com"
    report.author_emails = ["dev@example.com"]
    report.committer_emails = ["ops@example.com"]
    report.unexpected_emails = ["redacted-contributor@example.invalid"]
    report.unexpected_emails_owned_repo = ["redacted-contributor@example.invalid"]
    report.unexpected_emails_third_party_repo = ["redacted-contributor@example.invalid"]
    report.tracked_secret_matches = [f"secret.txt:1:{secret}"]
    report.tracked_path_matches = [f"file.txt:1:{_fixture_win_user_path_slash('Documents')}"]
    report.tracked_email_matches = ["file.txt:2:dev@example.com"]
    report.tracked_email_high_confidence = ["src/main.py:2:dev@example.com"]
    report.tracked_email_low_confidence = ["tests/test_main.py:2:dev@example.com"]
    report.history_email_matches = ["L1:dev@example.com:+ email = 'dev@example.com'"]
    report.history_email_high_confidence = ["L1:dev@example.com:+ email = 'dev@example.com'"]
    report.history_email_low_confidence = ["L2:dev@example.com:+ assert foo('dev@example.com')"]
    report.github_hardening_findings = ["GitHub repository hardening: .github/CODEOWNERS is missing."]
    report.github_hardening_warnings = ["GitHub default branch protection could not be audited (http_403)."]
    report.fix_actions = ["replace dev@example.com"]
    payload = rpg.sanitize_report_for_export(report)

    assert payload["path"] == "C:/Users/<redacted>/repo-a"
    assert payload["author_emails"] == [rpg.REDACTED_EMAIL]
    assert payload["committer_emails"] == [rpg.REDACTED_EMAIL]
    assert payload["unexpected_emails"] == [rpg.REDACTED_EMAIL]
    assert payload["unexpected_emails_owned_repo"] == [rpg.REDACTED_EMAIL]
    assert payload["unexpected_emails_third_party_repo"] == [rpg.REDACTED_EMAIL]
    assert rpg.REDACTED_SECRET in payload["tracked_secret_matches"][0]
    assert rpg.REDACTED_EMAIL in payload["tracked_email_matches"][0]
    assert rpg.REDACTED_EMAIL in payload["tracked_email_high_confidence"][0]
    assert rpg.REDACTED_EMAIL in payload["tracked_email_low_confidence"][0]
    assert rpg.REDACTED_EMAIL in payload["history_email_high_confidence"][0]
    assert rpg.REDACTED_EMAIL in payload["history_email_low_confidence"][0]
    assert payload["github_hardening_findings"] == [
        "GitHub repository hardening: .github/CODEOWNERS is missing."
    ]
    assert payload["github_hardening_warnings"] == [
        "GitHub default branch protection could not be audited (http_403)."
    ]
    assert rpg.REDACTED_EMAIL in payload["fix_actions"][0]


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
    assert "--mailmap" in captured["cmd"]
    assert "history rewritten with git-filter-repo" in report.fix_actions


def test_classify_repo_severity_all_levels() -> None:
    high = _make_report("high")
    high.tracked_secret_matches = ["a"]
    high.finalize()
    assert rpg.classify_repo_severity(high)[0] == "HIGH"

    medium = _make_report("medium")
    medium.unexpected_emails = ["private@example.com"]
    medium.finalize()
    assert rpg.classify_repo_severity(medium)[0] == "MEDIUM"

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
    assert "No email remediation action" in message

    review = _make_report("review")
    review.email_ownership_evaluated = True
    review.unexpected_emails_third_party_repo = ["third@example.com"]
    status, message = rpg.email_remediation_decision(review)
    assert status == "REVIEW"
    assert "Informational email findings" in message

    recommended = _make_report("recommended")
    recommended.email_confidence_evaluated = True
    recommended.history_email_high_confidence = ["L1:redacted-contributor@example.invalid:+ email = 'redacted-contributor@example.invalid'"]
    status, message = rpg.email_remediation_decision(recommended)
    assert status == "RECOMMENDED"
    assert "Authorize email remediation" in message

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
    assert "non-owner emails" in risk.lower()
    assert "identity exposure" in consequence.lower()
    assert "authorize email remediation" in suggestion.lower()

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
    assert "informational/noisy" in risk.lower()
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

    args = parser.parse_args(["--fix", "--purge-all-detected-secret-files"])
    assert args.fix is True
    assert args.purge_all_detected_secret_files is True

    args = parser.parse_args(["--rewrite-personal-paths"])
    assert args.rewrite_personal_paths is True

    args = parser.parse_args(["--low-confidence-email-mode", "blocking"])
    assert args.low_confidence_email_mode == "blocking"

    args = parser.parse_args(["--replace-text-file", "ops/replace-text.txt"])
    assert args.replace_text_file == "ops/replace-text.txt"


def test_make_parser_rejects_non_positive_max_matches() -> None:
    parser = rpg.make_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--max-matches", "0"])


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


def test_normalize_csv_values_and_text_values_helpers() -> None:
    assert rpg.normalize_csv_values("") == []
    assert rpg.normalize_csv_values(" alice@example.com, bob@example.com , alice@example.com ,, ") == [
        "alice@example.com",
        "bob@example.com",
    ]
    assert rpg.normalize_text_values(["  one  ", "", "two", "one"]) == ["one", "two"]


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
        open_report=False,
        confirm_each_repo_fix=False,
        allow_non_owner_push=False,
        allowed_remote_owners=["axeljackal", "axeljackal"],
        replace_text_file="ops/replace-text.txt",
        report_json=None,
    )

    assert config.owner_emails == ["dev@example.com"]
    assert config.allowed_remote_owners == ["axeljackal", "octocat"]
    assert config.replace_text_file == "ops/replace-text.txt"
    assert config.audit_github_hardening is True
    assert config.open_report is False
    assert config.confirm_each_repo_fix is False


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
        audit_github_hardening=True,
        open_report=True,
        confirm_each_repo_fix=True,
        allow_non_owner_push=False,
        allowed_remote_owners=["axeljackal"],
        replace_text_file="ops/replace-text.txt",
        report_json="C:/repos/Audit_Results/export.json",
    )
    cli_config = rpg.build_guard_run_config(mode="cli", **kwargs)
    gui_config = rpg.build_guard_run_config(mode="gui", **kwargs)

    assert cli_config.mode == "cli"
    assert gui_config.mode == "gui"

    same_fields = [
        "root",
        "policy",
        "repos",
        "public_only",
        "fix",
        "push",
        "dry_run",
        "redact_third_party_emails",
        "purge_detected_secret_files",
        "purge_all_detected_secret_files",
        "rewrite_personal_paths",
        "low_confidence_email_mode",
        "owner_name",
        "owner_emails",
        "noreply_email",
        "placeholder_email",
        "max_matches",
        "audit_github_hardening",
        "open_report",
        "confirm_each_repo_fix",
        "allow_non_owner_push",
        "allowed_remote_owners",
        "replace_text_file",
        "report_json",
    ]
    for field in same_fields:
        assert getattr(cli_config, field) == getattr(gui_config, field)


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
            return []

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
            return []

    monkeypatch.setattr(rpg, "RepoPublicationGuard", DummyGuard)
    monkeypatch.setattr(rpg, "persist_run_outputs", lambda *args, **kwargs: None)

    artifacts = rpg.create_run_artifacts(tmp_path)
    config = _make_run_config(low_confidence_email_mode="blocking")
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
    assert instances[0].audit_calls == 0


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
            return [Path("C:/repos/repo-a")]

        def audit_repo(self, repo: Path):
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
            return []

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
    config = _make_run_config(mode="gui", repos=["repo-a"], low_confidence_email_mode="blocking")
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=lambda _msg: None,
        results_dir=tmp_path,
    )

    assert exit_code == 0
    assert captured["run_settings"]["mode"] == "gui"
    assert captured["run_settings"]["low_confidence_email_mode"] == "blocking"
    assert captured["reports"] == []


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
            return []

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
