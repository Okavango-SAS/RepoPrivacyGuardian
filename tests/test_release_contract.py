from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import Repo_Privacy_Guardian as rpg


def _load_support_module(module_name: str, relative_path: str):
    module_path = Path(__file__).resolve().parents[1] / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_should_launch_gui_requires_explicit_flag() -> None:
    parser = rpg.make_parser()

    args_default = parser.parse_args([])
    assert rpg.should_launch_gui(args_default) is False

    args_gui = parser.parse_args(["--gui"])
    assert rpg.should_launch_gui(args_gui) is True


def test_main_without_args_prints_help_and_does_not_launch_gui(
    monkeypatch,
    capsys,
) -> None:
    launch_calls: list[bool] = []
    cli_calls: list[bool] = []

    monkeypatch.setattr(rpg, "launch_gui", lambda: launch_calls.append(True) or 0)
    monkeypatch.setattr(rpg, "run_cli", lambda _args: cli_calls.append(True) or 0)

    exit_code = rpg.main([])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "usage:" in captured.out
    assert not launch_calls
    assert not cli_calls


def test_parser_help_mentions_common_cli_flow() -> None:
    help_text = rpg.make_parser().format_help()

    assert "Common CLI flow:" in help_text
    assert "repo-privacy-guardian --check-tooling" in help_text
    assert "repo-privacy-guardian --gui" in help_text


def test_render_ignore_baseline_keeps_env_example_exception_after_env_wildcard() -> None:
    baseline = rpg.render_ignore_baseline().splitlines()

    assert ".env.*" in baseline
    assert "!.env.example" in baseline
    assert baseline.index(".env.*") < baseline.index("!.env.example")


def test_main_gui_runtime_error_reports_clean_message(monkeypatch, capsys) -> None:
    monkeypatch.setattr(rpg, "GuiApp", lambda: (_ for _ in ()).throw(RuntimeError("GUI mode requires a desktop session")))

    exit_code = rpg.launch_gui()
    captured = capsys.readouterr()

    assert exit_code == 3
    assert "desktop session" in captured.err


def test_launch_gui_success_runs_app(monkeypatch) -> None:
    calls: list[str] = []

    class DummyApp:
        def run(self) -> None:
            calls.append("run")

    monkeypatch.setattr(rpg, "GuiApp", DummyApp)

    assert rpg.launch_gui() == 0
    assert calls == ["run"]


def test_launch_gui_prompts_and_installs_missing_tools(monkeypatch) -> None:
    calls: list[str] = []
    checks_by_round = [
        [rpg.ToolingCheck(name="customtkinter", state="missing", blocking=True, detail="missing", auto_install_command=["python", "-m", "pip", "install", "customtkinter"])],
        [rpg.ToolingCheck(name="customtkinter", state="ready", blocking=True, detail="ready")],
    ]

    class DummyApp:
        def run(self) -> None:
            calls.append("run")

    monkeypatch.setattr(rpg, "GuiApp", DummyApp)
    monkeypatch.setattr(
        rpg,
        "build_gui_tooling_checks",
        lambda: checks_by_round.pop(0),
    )
    monkeypatch.setattr(rpg, "prompt_gui_tooling_install", lambda checks, logger: True)
    monkeypatch.setattr(rpg, "install_missing_tooling", lambda checks, logger: calls.append("install"))

    assert rpg.launch_gui() == 0
    assert calls == ["install", "run"]


def test_launch_gui_declined_install_keeps_missing_status(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        rpg,
        "build_gui_tooling_checks",
        lambda: [rpg.ToolingCheck(name="customtkinter", state="missing", blocking=True, detail="missing", auto_install_command=["python", "-m", "pip", "install", "customtkinter"])],
    )
    monkeypatch.setattr(rpg, "prompt_gui_tooling_install", lambda checks, logger: False)
    monkeypatch.setattr(rpg, "install_missing_tooling", lambda checks, logger: (_ for _ in ()).throw(AssertionError("should not install")))

    exit_code = rpg.launch_gui()
    captured = capsys.readouterr()

    assert exit_code == 3
    assert "GUI tooling is not ready" in captured.err


def test_gui_github_hardening_toggle_offers_optional_install(monkeypatch) -> None:
    class DummyVar:
        def __init__(self, value: bool) -> None:
            self.value = value

        def get(self) -> bool:
            return self.value

    notices: list[tuple[str, str]] = []
    install_calls: list[str] = []
    checks_by_round = [
        [
            rpg.ToolingCheck(
                name="winget",
                state="warning",
                blocking=False,
                detail="missing winget",
                auto_install_command=["powershell", "-NoProfile", "-Command", "bootstrap-winget"],
            ),
            rpg.ToolingCheck(
                name="github-auth",
                state="warning",
                blocking=False,
                detail="missing gh",
                auto_install_command=["winget", "install", "--id", "GitHub.cli"],
            ),
        ],
        [
            rpg.ToolingCheck(
                name="github-auth",
                state="warning",
                blocking=False,
                detail="gh installed but unauthenticated",
            ),
        ],
    ]

    app = object.__new__(rpg.GuiApp)
    app.audit_github_hardening_var = DummyVar(True)
    app.log = lambda _msg: None
    app.messagebox = type("MessageBox", (), {"showinfo": lambda self, title, message: notices.append((title, message))})()

    monkeypatch.setattr(rpg, "build_github_optional_tooling_checks", lambda: checks_by_round.pop(0))
    monkeypatch.setattr(rpg, "prompt_gui_tooling_install", lambda *args, **kwargs: True)
    monkeypatch.setattr(rpg, "install_missing_tooling", lambda checks, logger: install_calls.append(",".join(check.name for check in checks)))

    app._on_audit_github_hardening_toggled()

    assert install_calls == ["winget,github-auth"]
    assert notices
    assert "Authentication Still Needed" in notices[0][0]
    assert "gh auth login" in notices[0][1]


def test_missing_executable_message_variants() -> None:
    assert "Git executable not found" in rpg._missing_executable_message("git")
    assert "python3" in rpg._missing_executable_message("python3")


def test_probe_git_available_diagnostics() -> None:
    class OkProc:
        returncode = 0
        stdout = "git version 2.48.0"
        stderr = ""

    ok, error = rpg.probe_git_available(
        runner=lambda *args, **kwargs: OkProc()  # type: ignore[return-value]
    )
    assert ok is True
    assert error is None

    class BadProc:
        returncode = 1
        stdout = ""
        stderr = "permission denied"

    ok, error = rpg.probe_git_available(
        runner=lambda *args, **kwargs: BadProc()  # type: ignore[return-value]
    )
    assert ok is False
    assert "permission denied" in str(error)

    def missing_git(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise FileNotFoundError

    ok, error = rpg.probe_git_available(runner=missing_git)
    assert ok is False
    assert "Git executable not found" in str(error)


def test_run_git_command_handles_missing_git(monkeypatch) -> None:
    def missing_git(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise FileNotFoundError

    monkeypatch.setattr(rpg.subprocess, "run", missing_git)
    result = rpg.run_git_command(["status"])

    assert result.returncode == 127
    assert "Git executable not found" in result.stderr


def test_run_cli_does_not_open_report_by_default(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_execute_guard_pipeline(*, config, artifacts, logger, results_dir, **kwargs):  # type: ignore[no-untyped-def]
        del artifacts, logger, results_dir
        captured["config"] = config
        cancel_callback = kwargs.get("cancel_callback")
        captured["cancel_requested"] = bool(cancel_callback and cancel_callback())
        return 0

    monkeypatch.setattr(rpg, "execute_guard_pipeline", fake_execute_guard_pipeline)

    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--root",
            str(tmp_path),
            "--repos",
            "repo-a",
            "--report-dir",
            str(rpg.DEFAULT_RESULTS_DIR / "pytest-release-contract"),
        ]
    )
    exit_code = rpg.run_cli(args)

    assert exit_code == 0
    assert captured["config"].open_report is False


def test_run_cli_open_report_is_opt_in(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_execute_guard_pipeline(*, config, artifacts, logger, results_dir, **kwargs):  # type: ignore[no-untyped-def]
        del artifacts, logger, results_dir
        captured["config"] = config
        cancel_callback = kwargs.get("cancel_callback")
        captured["cancel_requested"] = bool(cancel_callback and cancel_callback())
        return 0

    monkeypatch.setattr(rpg, "execute_guard_pipeline", fake_execute_guard_pipeline)

    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--root",
            str(tmp_path),
            "--repos",
            "repo-a",
            "--report-dir",
            str(rpg.DEFAULT_RESULTS_DIR / "pytest-release-contract"),
            "--open-report",
        ]
    )
    exit_code = rpg.run_cli(args)

    assert exit_code == 0
    assert captured["config"].open_report is True


def test_run_cli_passes_audit_github_hardening_flag_to_config(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_execute_guard_pipeline(*, config, artifacts, logger, results_dir, **kwargs):  # type: ignore[no-untyped-def]
        del artifacts, logger, results_dir
        captured["config"] = config
        cancel_callback = kwargs.get("cancel_callback")
        captured["cancel_requested"] = bool(cancel_callback and cancel_callback())
        return 0

    monkeypatch.setattr(rpg, "execute_guard_pipeline", fake_execute_guard_pipeline)

    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--root",
            str(tmp_path),
            "--repos",
            "repo-a",
            "--audit-github-hardening",
        ]
    )
    exit_code = rpg.run_cli(args)

    assert exit_code == 0
    assert captured["config"].audit_github_hardening is True


def test_run_cli_check_tooling_returns_blocking_exit_without_running_pipeline(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        rpg,
        "build_cli_tooling_checks",
        lambda config: [
            rpg.ToolingCheck(
                name="git",
                state="missing",
                blocking=True,
                detail="Git executable not found.",
            )
        ],
    )
    monkeypatch.setattr(
        rpg,
        "execute_guard_pipeline",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("pipeline should not run")),
    )

    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--root",
            str(tmp_path),
            "--check-tooling",
        ]
    )

    assert rpg.run_cli(args) == 2


def test_run_cli_check_tooling_attempts_auto_install(tmp_path: Path, monkeypatch) -> None:
    installed: list[list[str]] = []

    def fake_build_checks(config):  # type: ignore[no-untyped-def]
        del config
        return [
            rpg.ToolingCheck(
                name="gh",
                state="warning",
                blocking=False,
                detail="Install gh.",
                auto_install_command=[
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
        ]

    monkeypatch.setattr(rpg, "build_cli_tooling_checks", fake_build_checks)
    monkeypatch.setattr(
        rpg,
        "install_missing_tooling",
        lambda checks, logger, runner=None: installed.extend(
            [check.auto_install_command for check in checks if check.auto_install_command]
        ),
    )

    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--root",
            str(tmp_path),
            "--check-tooling",
            "--install-missing-tools",
        ]
    )

    assert rpg.run_cli(args) == 0
    assert installed == [[
        "winget",
        "install",
        "--id",
        "GitHub.cli",
        "-e",
        "--source",
        "winget",
        "--accept-package-agreements",
        "--accept-source-agreements",
    ]]


def test_launch_gui_check_tooling_only_returns_missing_status(monkeypatch) -> None:
    monkeypatch.setattr(
        rpg,
        "build_gui_tooling_checks",
        lambda: [rpg.ToolingCheck(name="customtkinter", state="missing", blocking=True, detail="missing")],
    )

    assert rpg.launch_gui(check_tooling_only=True, install_missing_tools=False) == 2


def test_execute_guard_pipeline_returns_error_when_git_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rpg, "probe_git_available", lambda: (False, "Git executable not found."))
    messages: list[str] = []

    config = rpg.GuardRunConfig(
        mode="cli",
        root=tmp_path,
        policy=tmp_path / "POLICY.md",
        repos=["repo-a"],
        public_only=False,
        fix=False,
        push=False,
        dry_run=False,
        redact_third_party_emails=False,
        purge_detected_secret_files=False,
        purge_all_detected_secret_files=False,
        rewrite_personal_paths=False,
        low_confidence_email_mode="informational",
        owner_name="Owner",
        owner_emails=[],
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        max_matches=50,
        open_report=False,
        confirm_each_repo_fix=True,
        allow_non_owner_push=False,
        allowed_remote_owners=[],
        replace_text_file=None,
        report_json=None,
    )

    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=rpg.create_run_artifacts(tmp_path / "Audit_Results"),
        logger=messages.append,
        results_dir=tmp_path / "Audit_Results",
    )

    assert exit_code == 3
    assert any("Git executable not found" in msg for msg in messages)


def test_has_desktop_display_detects_headless_linux() -> None:
    assert rpg.has_desktop_display(platform_name="linux", env={}) is False
    assert rpg.has_desktop_display(platform_name="linux", env={"DISPLAY": ":0"}) is True


def test_has_desktop_display_treats_macos_as_desktop_capable() -> None:
    assert rpg.has_desktop_display(platform_name="darwin", env={}) is True


def test_load_gui_runtime_requires_display(monkeypatch) -> None:
    monkeypatch.setattr(rpg, "has_desktop_display", lambda: False)

    with pytest.raises(RuntimeError, match="headless environments"):
        rpg.load_gui_runtime()


def test_module_import_does_not_require_gui_dependencies() -> None:
    proc = subprocess.run(
        [sys.executable, "-c", "import Repo_Privacy_Guardian; print('ok')"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert proc.returncode == 0
    assert "ok" in proc.stdout


def test_module_wrapper_runs_help_without_launching_gui() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "Repo_Privacy_Guardian"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert proc.returncode == 0
    assert "usage:" in proc.stdout


def test_checkout_conftest_bootstraps_repo_root_for_imports(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import importlib.util, pathlib; "
                f"repo_root = pathlib.Path(r'{repo_root}'); "
                "conftest_path = repo_root / 'tests' / 'conftest.py'; "
                "spec = importlib.util.spec_from_file_location('checkout_conftest', conftest_path); "
                "module = importlib.util.module_from_spec(spec); "
                "assert spec is not None and spec.loader is not None; "
                "spec.loader.exec_module(module); "
                "import Repo_Privacy_Guardian; "
                "print('ok')"
            ),
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "ok" in proc.stdout


def test_release_readiness_script_exposes_help() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/release_readiness.py", "--help"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert proc.returncode == 0
    assert "release-readiness checks" in proc.stdout
    assert "--skip-self-audit" in proc.stdout


def test_release_smoke_cli_resolves_direct_script_without_installed_entrypoint(tmp_path: Path) -> None:
    smoke_cli = _load_support_module("release_smoke_cli_support", "tests/release_smoke_cli.py")
    repo_root = Path(__file__).resolve().parents[1]

    command = smoke_cli.resolve_cli_command(
        repo_root=repo_root,
        scripts_dir=tmp_path,
        which=lambda _name: None,
    )

    assert command == [sys.executable, str(repo_root / "Repo_Privacy_Guardian.py")]


def test_release_smoke_gui_bootstrap_adds_repo_root_only_once() -> None:
    smoke_gui = _load_support_module("release_smoke_gui_support", "tests/release_smoke_gui.py")
    script_path = Path(__file__).resolve().parents[1] / "tests" / "release_smoke_gui.py"
    path_list = ["sentinel"]

    repo_root = smoke_gui.bootstrap_repo_root(script_path=script_path, path_list=path_list)
    smoke_gui.bootstrap_repo_root(script_path=script_path, path_list=path_list)

    assert path_list[0] == str(repo_root)
    assert path_list.count(str(repo_root)) == 1


def test_discover_python_executables_includes_posix_virtualenv(tmp_path: Path) -> None:
    repo = tmp_path / "repo-a"
    (repo / ".git").mkdir(parents=True)
    posix_python = repo / ".venv" / "bin" / "python"
    posix_python.parent.mkdir(parents=True)
    posix_python.write_text("#!/usr/bin/env python\n", encoding="utf-8")

    discovered = rpg.discover_python_executables_for_supply_chain(tmp_path, ["repo-a"])

    assert posix_python.resolve() in discovered


def test_gui_run_worker_passes_replace_text_file_for_repair(tmp_path: Path, monkeypatch) -> None:
    class DummyVar:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

    class DummyRoot:
        def after(self, _delay, callback):
            callback()

    captured: dict[str, object] = {}

    def fake_execute_guard_pipeline(*, config, artifacts, logger, results_dir, **kwargs):  # type: ignore[no-untyped-def]
        del artifacts, logger, results_dir
        captured["config"] = config
        cancel_callback = kwargs.get("cancel_callback")
        captured["cancel_requested"] = bool(cancel_callback and cancel_callback())
        return 0

    monkeypatch.setattr(rpg, "execute_guard_pipeline", fake_execute_guard_pipeline)

    policy = tmp_path / "POLICY.md"
    policy.write_text("# Policy\n", encoding="utf-8")

    app = object.__new__(rpg.GuiApp)
    app.root = DummyRoot()
    app.root_var = DummyVar(str(tmp_path))
    app.policy_var = DummyVar(str(policy))
    app.owner_emails_var = DummyVar("")
    app.allowed_remote_owners_var = DummyVar("")
    app.report_dir_var = DummyVar(str(tmp_path / "Audit_Results"))
    app.report_json_var = DummyVar("")
    app.replace_text_file_var = DummyVar("ops/replace-text.txt")
    app.public_only_var = DummyVar(False)
    app.github_owner_var = DummyVar("")
    app.github_repo_filters_var = DummyVar("")
    app.github_include_forks_var = DummyVar(False)
    app.github_fast_var = DummyVar(False)
    app.github_jobs_var = DummyVar("4")
    app.push_var = DummyVar(False)
    app.redact_var = DummyVar(False)
    app.rewrite_personal_paths_var = DummyVar(False)
    app.purge_detected_secret_files_var = DummyVar(False)
    app.purge_all_detected_secret_files_var = DummyVar(False)
    app.dry_run_var = DummyVar(False)
    app.low_confidence_blocking_var = DummyVar(False)
    app.audit_litellm_incident_var = DummyVar(False)
    app.audit_github_hardening_var = DummyVar(True)
    app.open_report_var = DummyVar(True)
    app.confirm_each_repo_fix_var = DummyVar(True)
    app.allow_non_owner_push_var = DummyVar(False)
    app.owner_name_var = DummyVar("Owner")
    app.noreply_var = DummyVar(rpg.DEFAULT_NOREPLY)
    app.placeholder_var = DummyVar(rpg.DEFAULT_PLACEHOLDER)
    app.max_matches_var = DummyVar("50")
    app._active_cancel_token = rpg.CancellationToken()
    app._active_cancel_token.request_cancel()
    app.log = lambda _msg: None
    app._on_gui_run_finished = lambda *args, **kwargs: None

    app._run_worker(["repo-a"], 50, True, ("repo-a",))

    assert captured["config"].replace_text_file == "ops/replace-text.txt"
    assert captured["config"].audit_github_hardening is True
    assert captured["config"].github_owner is None
    assert captured["cancel_requested"] is True


def test_gui_run_worker_passes_github_owner_remote_audit_options(tmp_path: Path, monkeypatch) -> None:
    class DummyVar:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

    class DummyRoot:
        def after(self, _delay, callback):
            callback()

    captured: dict[str, object] = {}

    def fake_execute_guard_pipeline(*, config, artifacts, logger, results_dir, **kwargs):  # type: ignore[no-untyped-def]
        del artifacts, logger, results_dir, kwargs
        captured["config"] = config
        return 0

    monkeypatch.setattr(rpg, "execute_guard_pipeline", fake_execute_guard_pipeline)

    policy = tmp_path / "POLICY.md"
    policy.write_text("# Policy\n", encoding="utf-8")

    app = object.__new__(rpg.GuiApp)
    app.root = DummyRoot()
    app.root_var = DummyVar(str(tmp_path))
    app.policy_var = DummyVar(str(policy))
    app.owner_emails_var = DummyVar("")
    app.allowed_remote_owners_var = DummyVar("")
    app.report_dir_var = DummyVar(str(tmp_path / "Audit_Results"))
    app.report_json_var = DummyVar("")
    app.replace_text_file_var = DummyVar("ops/replace-text.txt")
    app.public_only_var = DummyVar(True)
    app.github_owner_var = DummyVar("Acme")
    app.github_repo_filters_var = DummyVar("api, worker")
    app.github_include_forks_var = DummyVar(True)
    app.github_fast_var = DummyVar(True)
    app.github_jobs_var = DummyVar("3")
    app.push_var = DummyVar(True)
    app.redact_var = DummyVar(False)
    app.rewrite_personal_paths_var = DummyVar(True)
    app.purge_detected_secret_files_var = DummyVar(True)
    app.purge_all_detected_secret_files_var = DummyVar(True)
    app.dry_run_var = DummyVar(True)
    app.low_confidence_blocking_var = DummyVar(False)
    app.audit_litellm_incident_var = DummyVar(False)
    app.audit_github_hardening_var = DummyVar(False)
    app.open_report_var = DummyVar(False)
    app.confirm_each_repo_fix_var = DummyVar(True)
    app.allow_non_owner_push_var = DummyVar(True)
    app.owner_name_var = DummyVar("Owner")
    app.noreply_var = DummyVar(rpg.DEFAULT_NOREPLY)
    app.placeholder_var = DummyVar(rpg.DEFAULT_PLACEHOLDER)
    app.max_matches_var = DummyVar("50")
    app._active_cancel_token = None
    app.log = lambda _msg: None
    app._on_gui_run_finished = lambda *args, **kwargs: None

    app._run_worker(["api", "worker"], 50, False, ("github-owner", "acme", "api", "worker"))

    config = captured["config"]
    assert config.github_owner == "Acme"
    assert config.github_include_forks is True
    assert config.github_fast is True
    assert config.github_jobs == 3
    assert config.repos == ["api", "worker"]
    assert config.public_only is True
    assert config.fix is False
    assert config.push is False
    assert config.replace_text_file is None
    assert config.rewrite_personal_paths is False


def test_gui_cancel_run_clicked_marks_token_and_logs() -> None:
    logged: list[str] = []
    states: list[str] = []

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app.log = logged.append
    app._update_run_buttons_state = lambda: states.append("updated")

    app.cancel_run_clicked()

    assert app._active_cancel_token.is_cancelled() is True
    assert states == ["updated"]
    assert any("Cancellation requested" in msg for msg in logged)


def test_update_run_buttons_state_disables_refresh_button_while_run_is_active() -> None:
    class DummyWidget:
        def __init__(self) -> None:
            self.kwargs: dict[str, str] = {}

        def configure(self, **kwargs) -> None:
            self.kwargs.update(kwargs)

    class DummyListbox:
        def __init__(self) -> None:
            self.state = "normal"

        def configure(self, **kwargs) -> None:
            if "state" in kwargs:
                self.state = kwargs["state"]

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app._repo_items = [("repo-a", "repo-a")]
    app._audit_button = DummyWidget()
    app._cancel_button = DummyWidget()
    app._refresh_button = DummyWidget()
    app._select_all_button = DummyWidget()
    app._clear_selection_button = DummyWidget()
    app._repair_button = None
    app.repo_list = DummyListbox()

    app._update_run_buttons_state()

    assert app._audit_button.kwargs["state"] == "disabled"
    assert app._cancel_button.kwargs["text"] == "Stop After Current Step"
    assert app._cancel_button.kwargs["state"] == "normal"
    assert app._refresh_button.kwargs["state"] == "disabled"
    assert app._select_all_button.kwargs["state"] == "disabled"
    assert app._clear_selection_button.kwargs["state"] == "disabled"
    assert app.repo_list.state == "disabled"


def test_update_run_buttons_state_allows_remote_github_audit_without_local_repos() -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class DummyWidget:
        def __init__(self) -> None:
            self.kwargs: dict[str, str] = {}

        def configure(self, **kwargs) -> None:
            self.kwargs.update(kwargs)

    class DummyListbox:
        def __init__(self) -> None:
            self.state = "normal"

        def configure(self, **kwargs) -> None:
            if "state" in kwargs:
                self.state = kwargs["state"]

    app = object.__new__(rpg.GuiApp)
    app.github_owner_var = DummyVar("acme")
    app.github_repo_filters_var = DummyVar("")
    app._run_in_progress = False
    app._active_cancel_token = None
    app._repo_items = []
    app._audit_button = DummyWidget()
    app._cancel_button = DummyWidget()
    app._refresh_button = DummyWidget()
    app._select_all_button = DummyWidget()
    app._clear_selection_button = DummyWidget()
    app._repair_button = None
    app.repo_list = DummyListbox()

    app._update_run_buttons_state()

    assert app._audit_button.kwargs["text"] == "Run Audit"
    assert app._audit_button.kwargs["state"] == "normal"
    assert app.repo_list.state == "disabled"


def test_gui_run_clicked_ignores_invalid_github_jobs_when_remote_owner_is_empty(monkeypatch) -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class DummyListbox:
        def curselection(self) -> tuple[int]:
            return (0,)

    class DummyMessageBox:
        def __init__(self) -> None:
            self.warnings: list[tuple[str, str]] = []

        def showinfo(self, title: str, message: str) -> None:
            self.warnings.append((title, message))

        def showwarning(self, title: str, message: str) -> None:
            self.warnings.append((title, message))

        def askyesno(self, _title: str, _message: str) -> bool:
            return False

    started: dict[str, object] = {}

    class DummyThread:
        def __init__(self, *, target, args, daemon):  # type: ignore[no-untyped-def]
            started["target"] = target
            started["args"] = args
            started["daemon"] = daemon

        def start(self) -> None:
            started["started"] = True

    monkeypatch.setattr(rpg.threading, "Thread", DummyThread)

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = False
    app._audit_tab_name = "1. Audit"
    app._repair_tab_name = "2. Repair"
    app._set_active_flow_tab = lambda tab: started.setdefault("tab", tab)
    app.github_owner_var = DummyVar("")
    app.github_repo_filters_var = DummyVar("")
    app.github_jobs_var = DummyVar("not-a-number")
    app.max_matches_var = DummyVar("50")
    app._repo_items = [("RepoPrivacyGuardian", "RepoPrivacyGuardian")]
    app.repo_list = DummyListbox()
    app.messagebox = DummyMessageBox()
    app._lock_repair_until_next_audit = lambda reason: started.setdefault("lock", reason)
    app._update_run_buttons_state = lambda: started.setdefault("buttons", True)
    app._run_worker = lambda *args: None

    app.run_clicked(False)

    assert app.messagebox.warnings == []
    assert app._run_in_progress is True
    assert started["args"] == (["RepoPrivacyGuardian"], 50, False, ("RepoPrivacyGuardian",))
    assert started["started"] is True


def test_update_run_buttons_state_reflects_pending_stop_request() -> None:
    class DummyWidget:
        def __init__(self) -> None:
            self.kwargs: dict[str, str] = {}

        def configure(self, **kwargs) -> None:
            self.kwargs.update(kwargs)

    class DummyListbox:
        def __init__(self) -> None:
            self.state = "normal"

        def configure(self, **kwargs) -> None:
            if "state" in kwargs:
                self.state = kwargs["state"]

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app._active_cancel_token.request_cancel()
    app._repo_items = [("repo-a", "repo-a")]
    app._audit_button = DummyWidget()
    app._cancel_button = DummyWidget()
    app._refresh_button = DummyWidget()
    app._select_all_button = DummyWidget()
    app._clear_selection_button = DummyWidget()
    app._repair_button = None
    app.repo_list = DummyListbox()

    app._update_run_buttons_state()

    assert app._cancel_button.kwargs["text"] == "Stopping after current step..."
    assert app._cancel_button.kwargs["state"] == "disabled"


def test_gui_header_flow_strip_hides_on_compact_layout() -> None:
    class DummyStrip:
        def __init__(self) -> None:
            self.actions: list[str] = []

        def grid(self) -> None:
            self.actions.append("grid")

        def grid_remove(self) -> None:
            self.actions.append("grid_remove")

    strip = DummyStrip()
    app = object.__new__(rpg.GuiApp)
    app._workflow_strip = strip
    app._workflow_strip_visible = True

    app._apply_header_flow_layout(compact=True)

    assert app._workflow_strip_visible is False
    assert strip.actions == ["grid_remove"]

    app._apply_header_flow_layout(compact=False)

    assert app._workflow_strip_visible is True
    assert strip.actions == ["grid_remove", "grid"]


def test_gui_advanced_identity_settings_are_collapsible() -> None:
    class DummyWidget:
        def __init__(self) -> None:
            self.actions: list[str] = []
            self.kwargs: dict[str, object] = {}

        def configure(self, **kwargs: object) -> None:
            self.kwargs.update(kwargs)

        def grid(self, **kwargs: object) -> None:
            self.actions.append("grid")
            self.kwargs.update(kwargs)

        def grid_configure(self, **kwargs: object) -> None:
            self.actions.append("grid_configure")
            self.kwargs.update(kwargs)

        def grid_remove(self) -> None:
            self.actions.append("grid_remove")

        def grid_columnconfigure(self, *_args: object, **_kwargs: object) -> None:
            self.actions.append("grid_columnconfigure")

    top_row = DummyWidget()
    settings_card = DummyWidget()
    profile_card = DummyWidget()
    identity_card = DummyWidget()
    toggle_button = DummyWidget()
    hint_label = DummyWidget()

    app = object.__new__(rpg.GuiApp)
    app._advanced_identity_visible = True
    app._advanced_identity_toggle_button = toggle_button
    app._advanced_identity_hint_label = hint_label
    app._identity_card = identity_card
    app._top_row = top_row
    app._settings_card = settings_card
    app._profile_card = profile_card
    app._compact_top_layout = False

    app._set_advanced_identity_visibility(False)

    assert app._advanced_identity_visible is False
    assert toggle_button.kwargs["text"] == "Show advanced identity settings"
    assert "normal audit-only path" in str(hint_label.kwargs["text"])
    assert identity_card.actions == ["grid_remove"]
    assert profile_card.actions == ["grid_remove"]
    assert settings_card.kwargs["columnspan"] == 2

    app._toggle_advanced_identity_settings()

    assert app._advanced_identity_visible is True
    assert toggle_button.kwargs["text"] == "Hide advanced identity settings"
    assert "visible" in str(hint_label.kwargs["text"])
    assert identity_card.actions[-1] == "grid"
    assert profile_card.actions[-1] == "grid_configure"


def test_on_gui_run_finished_keeps_repair_locked_after_aborted_audit() -> None:
    seen: list[tuple[str, str]] = []

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app._lock_repair_until_next_audit = lambda reason: seen.append(("lock", reason))
    app._set_active_flow_tab = lambda tab: seen.append(("tab", tab))
    app._start_repair_cooldown = lambda reports_payload, selection_signature: seen.append(  # type: ignore[assignment]
        ("cooldown", str((reports_payload, selection_signature)))
    )
    app.log = lambda message: seen.append(("log", message))
    app._audit_tab_name = "1. Audit"
    app._repair_tab_name = "2. Repair"

    app._on_gui_run_finished(False, ("repo-a",), [], rpg.EXIT_ABORTED)

    assert app._run_in_progress is False
    assert app._active_cancel_token is None
    assert ("lock", "Repair (audit cancelled)") in seen
    assert ("tab", "1. Audit") in seen
    assert any(item == ("log", "[INFO] Flow: audit cancelled. Run Audit again when you are ready to continue.") for item in seen)
    assert not any(kind == "cooldown" for kind, _value in seen)


def test_on_gui_run_finished_keeps_repair_locked_after_remote_github_audit() -> None:
    seen: list[tuple[str, str]] = []

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app._lock_repair_until_next_audit = lambda reason: seen.append(("lock", reason))
    app._set_active_flow_tab = lambda tab: seen.append(("tab", tab))
    app._start_repair_cooldown = lambda reports_payload, selection_signature: seen.append(  # type: ignore[assignment]
        ("cooldown", str((reports_payload, selection_signature)))
    )
    app.log = lambda message: seen.append(("log", message))
    app._audit_tab_name = "1. Audit"
    app._repair_tab_name = "2. Repair"

    app._on_gui_run_finished(False, ("github-owner", "acme"), [{"name": "repo-a"}], rpg.EXIT_OK)

    assert app._run_in_progress is False
    assert app._active_cancel_token is None
    assert ("lock", "Repair (remote audit is audit-only)") in seen
    assert ("tab", "1. Audit") in seen
    assert any("remote audit mode is audit-only" in value.lower() for kind, value in seen if kind == "log")
    assert not any(kind == "cooldown" for kind, _value in seen)


def test_gui_remote_selection_signature_includes_owner_and_filters() -> None:
    app = object.__new__(rpg.GuiApp)

    signature = app._run_selection_signature(["worker", "api"], github_owner="Acme")

    assert signature == ("github-owner", "acme", "api", "worker")


def test_choose_gui_font_family_prefers_available_candidates() -> None:
    picked = rpg.choose_gui_font_family(
        ("SF Pro Text", "Helvetica Neue", "Arial"),
        {"Arial", "Courier New"},
    )

    assert picked == "Arial"


def test_choose_gui_font_family_falls_back_to_first_candidate() -> None:
    picked = rpg.choose_gui_font_family(("Inter", "Noto Sans"), {"Menlo", "Courier"})
    assert picked == "Inter"


def test_gui_lock_default_text_is_english() -> None:
    app = object.__new__(rpg.GuiApp)
    app._repair_cooldown_after_id = None
    app._repair_ready = True
    app._repair_cooldown_remaining = 5
    app._repair_button_text = ""
    app._set_repair_tab_visual_lock = lambda *_args, **_kwargs: None
    app._update_run_buttons_state = lambda: None

    app._lock_repair_until_next_audit()

    assert app._repair_button_text == "Repair (run audit first)"


def test_refresh_repos_includes_current_root_and_autoselects_single_repo(tmp_path: Path) -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class DummyListbox:
        def __init__(self) -> None:
            self.items: list[str] = []
            self.selected: set[int] = set()

        def delete(self, _start, _end) -> None:
            self.items = []
            self.selected.clear()

        def insert(self, _index, value: str) -> None:
            self.items.append(value)

        def selection_set(self, index: int) -> None:
            self.selected.add(index)

        def curselection(self) -> tuple[int, ...]:
            return tuple(sorted(self.selected))

    class DummyLabel:
        def __init__(self) -> None:
            self.text = ""
            self.kwargs: dict[str, str] = {}

        def configure(self, **kwargs) -> None:
            self.kwargs.update(kwargs)
            if "text" in kwargs:
                self.text = kwargs["text"]

        def place(self, **kwargs) -> None:
            self.kwargs.update(kwargs)

        def place_forget(self) -> None:
            self.kwargs["hidden"] = "1"

    root_repo = tmp_path / "repo-a"
    (root_repo / ".git").mkdir(parents=True)

    app = object.__new__(rpg.GuiApp)
    app.root_var = DummyVar(str(root_repo))
    app.repo_list = DummyListbox()
    app._repo_items = []
    app._repo_summary_label = DummyLabel()
    app._repo_empty_state = DummyLabel()

    app.refresh_repos()

    assert app.repo_list.items == [f"{root_repo.name} (Current Root)"]
    assert app._selected_repo_names() == ["."]
    assert "Current Root is available in the list." in app._repo_summary_label.text


def test_refresh_repos_invalid_root_surfaces_empty_state_and_disables_audit(tmp_path: Path) -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class DummyListbox:
        def __init__(self) -> None:
            self.items: list[str] = []
            self.selected: set[int] = set()
            self.state = "normal"

        def delete(self, _start, _end) -> None:
            self.items = []
            self.selected.clear()

        def insert(self, _index, value: str) -> None:
            self.items.append(value)

        def selection_set(self, index: int) -> None:
            self.selected.add(index)

        def curselection(self) -> tuple[int, ...]:
            return tuple(sorted(self.selected))

        def configure(self, **kwargs) -> None:
            if "state" in kwargs:
                self.state = kwargs["state"]

    class DummyWidget:
        def __init__(self) -> None:
            self.text = ""
            self.kwargs: dict[str, str] = {}

        def configure(self, **kwargs) -> None:
            self.kwargs.update(kwargs)
            if "text" in kwargs:
                self.text = kwargs["text"]

        def place(self, **kwargs) -> None:
            self.kwargs.update(kwargs)

        def place_forget(self) -> None:
            self.kwargs["hidden"] = "1"

        def lift(self) -> None:
            self.kwargs["lifted"] = "1"

    missing_root = tmp_path / "missing-root"

    app = object.__new__(rpg.GuiApp)
    app.root_var = DummyVar(str(missing_root))
    app.repo_list = DummyListbox()
    app._repo_items = []
    app._repo_summary_label = DummyWidget()
    app._repo_empty_state = DummyWidget()
    app._repo_empty_state_title_label = DummyWidget()
    app._repo_empty_state_body_label = DummyWidget()
    app._repo_empty_state_hint_label = DummyWidget()
    app._audit_button = DummyWidget()
    app._select_all_button = DummyWidget()
    app._clear_selection_button = DummyWidget()
    app._refresh_button = DummyWidget()
    app._repair_button = None
    app._run_in_progress = False

    app.refresh_repos()

    assert "Root folder not found" in app._repo_summary_label.text
    assert app._repo_empty_state_title_label.text == "Root folder not found"
    assert app._repo_empty_state_body_label.text.startswith("The selected Root folder does not exist.")
    assert app._audit_button.kwargs["text"] == "Audit unavailable"
    assert app._audit_button.kwargs["state"] == "disabled"
    assert app._select_all_button.kwargs["state"] == "disabled"
    assert app._clear_selection_button.kwargs["state"] == "disabled"
    assert app._refresh_button.kwargs["state"] == "normal"
    assert app.repo_list.state == "disabled"


def test_refresh_repos_is_ignored_while_run_is_in_progress(tmp_path: Path) -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class DummyListbox:
        def __init__(self) -> None:
            self.items: list[str] = ["existing"]
            self.deleted = 0

        def delete(self, _start, _end) -> None:
            self.deleted += 1
            self.items = []

        def curselection(self) -> tuple[int, ...]:
            return ()

    root_repo = tmp_path / "repo-a"
    (root_repo / ".git").mkdir(parents=True)

    app = object.__new__(rpg.GuiApp)
    app.root_var = DummyVar(str(root_repo))
    app.repo_list = DummyListbox()
    app._repo_items = [("repo-a", "repo-a")]
    app._run_in_progress = True
    messages: list[str] = []
    app.log = messages.append

    app.refresh_repos()

    assert app.repo_list.deleted == 0
    assert app.repo_list.items == ["existing"]
    assert app._repo_items == [("repo-a", "repo-a")]
    assert messages == ["[INFO] Refresh is disabled while a run is in progress."]


def test_build_repair_status_summary_mentions_pass_fail_counts() -> None:
    app = object.__new__(rpg.GuiApp)

    summary = app._build_repair_status_summary(
        [
            {"name": "repo-a", "status": "FAIL"},
            {"name": "repo-b", "status": "PASS"},
        ]
    )

    assert "1 FAIL / 1 PASS" in summary
    assert "repo-a, repo-b" in summary


def test_gui_browse_helpers_update_variables(tmp_path: Path) -> None:
    class DummyVar:
        def __init__(self, value: str):
            self.value = value

        def get(self) -> str:
            return self.value

        def set(self, value: str) -> None:
            self.value = value

    class DummyDialog:
        def askdirectory(self, **kwargs):  # type: ignore[no-untyped-def]
            assert kwargs["title"] == "Choose the root directory"
            return str(tmp_path)

        def askopenfilename(self, **kwargs):  # type: ignore[no-untyped-def]
            assert kwargs["title"] == "Choose a policy file"
            return str(tmp_path / "POLICY.md")

        def asksaveasfilename(self, **kwargs):  # type: ignore[no-untyped-def]
            assert kwargs["title"] == "Choose the extra JSON export path"
            return str(tmp_path / "report.json")

    app = object.__new__(rpg.GuiApp)
    app.filedialog = DummyDialog()

    root_var = DummyVar("")
    policy_var = DummyVar("")
    report_var = DummyVar("")

    app._browse_directory(root_var, title="Choose the root directory")
    app._browse_existing_file(
        policy_var,
        title="Choose a policy file",
        filetypes=[("Markdown files", "*.md")],
    )
    app._browse_save_file(
        report_var,
        title="Choose the extra JSON export path",
        default_extension=".json",
        filetypes=[("JSON files", "*.json")],
    )

    assert root_var.get() == str(tmp_path)
    assert policy_var.get() == str(tmp_path / "POLICY.md")
    assert report_var.get() == str(tmp_path / "report.json")


def test_gui_repair_confirmation_text_uses_english_labels() -> None:
    class DummyVar:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

    app = object.__new__(rpg.GuiApp)
    app.allowed_remote_owners_var = DummyVar("axeljackal")
    app.rewrite_personal_paths_var = DummyVar(True)
    app.replace_text_file_var = DummyVar("ops/replace-text.txt")
    app.purge_detected_secret_files_var = DummyVar(True)
    app.purge_all_detected_secret_files_var = DummyVar(False)
    app.push_var = DummyVar(False)
    app.open_report_var = DummyVar(True)
    app.confirm_each_repo_fix_var = DummyVar(True)
    app.allow_non_owner_push_var = DummyVar(False)
    app._last_audit_reports_payload = [
        {
            "name": "repo-a",
            "status": "FAIL",
            "tracked_but_ignored": ["secret.txt"],
            "tracked_path_matches": ["<redacted-path>"],
            "history_path_matches": [],
            "secret_file_autopurge_candidates": [".env"],
            "secret_file_candidates": [".env"],
        }
    ]

    text = app._build_repair_confirmation_text(("repo-a",))

    assert "Repair will run with the following plan:" in text
    assert "Continue?" in text
    assert "Se va a ejecutar" not in text


def test_cli_defaults_follow_current_working_directory(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; "
                "import Repo_Privacy_Guardian as rpg; "
                "args = rpg.make_parser().parse_args([]); "
                "print(json.dumps({'root': args.root, 'report_dir': args.report_dir}))"
            ),
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert proc.returncode == 0
    payload = json.loads(proc.stdout.strip())
    assert Path(payload["root"]) == tmp_path
    assert Path(payload["report_dir"]) == tmp_path / "Audit_Results"


def test_public_docs_describe_cli_first_release_contract() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.MD").read_text(encoding="utf-8")

    required_snippets = [
        "Windows CLI: supported",
        "Linux CLI: supported",
        "macOS CLI: supported",
        "Windows GUI: supported",
        "GUI is optional",
        "CLI does not open a browser automatically",
        "Use `--gui` for the desktop interface",
        "`exfil_code_indicators` is intentionally manual-review only by default",
        "--check-tooling",
        "--install-missing-tools",
        "GitHub MCP is not a prerequisite",
        "winget",
        "--replace-text-file",
        "Recommended agent prompt template",
        "What It Does Not Try To Be",
        "Release Engineering Docs",
        "CHANGELOG",
        "python -m pip install .",
        "clear old `dist/`, `build/`, and `*.egg-info/` outputs",
        "1. install the base CLI",
        "Axel E. Sacca",
    ]

    for snippet in required_snippets:
        assert snippet in readme


def test_agents_doc_describes_agentic_cli_workflow() -> None:
    agents = (Path(__file__).resolve().parents[1] / "AGENTS.MD").read_text(encoding="utf-8")

    required_snippets = [
        "`repo-privacy-guardian ...`",
        "`python -m Repo_Privacy_Guardian ...`",
        "`python Repo_Privacy_Guardian.py ...`",
        "`--check-tooling`",
        "`--install-missing-tools`",
        "winget",
        "`--replace-text-file`",
        "Act as a release/security engineer.",
    ]

    for snippet in required_snippets:
        assert snippet in agents
