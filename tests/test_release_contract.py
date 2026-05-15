from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import fields
from datetime import datetime
from pathlib import Path

import pytest
import Repo_Privacy_Guardian as rpg
import repo_privacy_guardian_prompts as prompt_helpers
from repo_privacy_guardian.gui import state as gui_state_helpers
from repo_privacy_guardian_artifacts import RunArtifacts


SUBPROCESS_TEST_TIMEOUT_SECONDS = 60


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

    assert "Start safely with --check-tooling, then a --dry-run audit; fixes are opt-in." in help_text
    assert "First-time safe path (no writes):" in help_text
    assert "Read the result:" in help_text
    assert "PASS   no blocking publication issues were found" in help_text
    assert "REVIEW inspect advisory findings before publishing" in help_text
    assert "FAIL   do not publish until blocking findings are fixed" in help_text
    assert "Common CLI flow:" in help_text
    assert "repo-privacy-guardian --check-tooling" in help_text
    assert "repo-privacy-guardian --gui" in help_text
    assert "--compare-reports" in help_text


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


def test_run_cli_reports_artifact_creation_failure_without_pipeline(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(rpg, "build_cli_tooling_checks", lambda _config: [])
    monkeypatch.setattr(
        rpg,
        "create_run_artifacts",
        lambda _results_dir: (_ for _ in ()).throw(RuntimeError("refusing symlinked path")),
    )
    monkeypatch.setattr(
        rpg,
        "execute_guard_pipeline",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("pipeline should not run")),
    )

    parser = rpg.make_parser()
    args = parser.parse_args(
        [
            "--root",
            str(tmp_path),
            "--repos",
            "repo-a",
        ]
    )

    exit_code = rpg.run_cli(args)
    captured = capsys.readouterr()

    assert exit_code == rpg.EXIT_RUNTIME_ERROR
    assert "Could not create run artifacts" in captured.err
    assert "refusing symlinked path" in captured.err


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


def test_gui_runtime_assets_resolve_without_gui_imports() -> None:
    for filename in rpg.GUI_ASSET_FILENAMES:
        asset_path = rpg.gui_asset_path(filename)
        assert asset_path is not None
        assert asset_path.is_file()

    assert rpg.gui_asset_path("../app-icon.png") is None


def test_themeable_gui_asset_background_blends_near_white_pixels() -> None:
    image_module = pytest.importorskip("PIL.Image")
    image = image_module.new("RGBA", (3, 1))
    image.putdata(
        [
            (250, 250, 250, 255),
            (16, 160, 150, 255),
            (250, 220, 190, 255),
        ]
    )

    blended = rpg.blend_near_white_gui_asset_background(image, (21, 39, 45))

    assert blended.getpixel((0, 0)) == (21, 39, 45, 255)
    assert blended.getpixel((1, 0)) == (16, 160, 150, 255)
    assert blended.getpixel((2, 0)) == (250, 220, 190, 255)
    assert rpg.parse_hex_rgb("#15272D") == (21, 39, 45)
    assert rpg.parse_hex_rgb("not-a-color") is None


def test_module_import_does_not_require_gui_dependencies() -> None:
    proc = subprocess.run(
        [sys.executable, "-c", "import Repo_Privacy_Guardian; print('ok')"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TEST_TIMEOUT_SECONDS,
    )

    assert proc.returncode == 0
    assert "ok" in proc.stdout


def test_public_facade_exports_refactor_feature_helpers() -> None:
    import repo_privacy_guardian as package

    for name in (
        "AGENT_SUMMARY_SCHEMA_VERSION",
        "build_agent_summary",
        "format_agent_summary_handoff",
        "load_configured_suppressions",
        "apply_report_policy_post_processing",
        "REPORT_DIFF_SCHEMA_VERSION",
        "compare_report_payloads",
        "format_report_diff_summary",
    ):
        assert hasattr(rpg, name), name
    for name in (
        "main",
        "make_parser",
        "GuardRunConfig",
        "RepoReport",
        "GuiApp",
        "persist_run_outputs",
        "build_agent_summary",
        "format_agent_summary_handoff",
        "load_configured_suppressions",
        "REPORT_DIFF_SCHEMA_VERSION",
        "compare_report_files",
        "compare_report_payloads",
        "find_previous_report_json",
        "format_report_diff_summary",
    ):
        assert hasattr(package, name), name


def test_module_wrapper_runs_help_without_launching_gui() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "Repo_Privacy_Guardian"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TEST_TIMEOUT_SECONDS,
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
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TEST_TIMEOUT_SECONDS,
    )

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert "ok" in proc.stdout


def test_checkout_conftest_ignores_untracked_test_files_without_nested_pytest(monkeypatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    checkout_conftest = _load_support_module("checkout_conftest_direct_hook", "tests/conftest.py")

    monkeypatch.setattr(
        checkout_conftest,
        "_tracked_test_files",
        lambda: {"tests/test_tracked_public_signal.py"},
    )

    assert checkout_conftest.pytest_ignore_collect(
        repo_root / "tests" / "test_local_only_ignored.py",
        config=None,
    ) is True
    assert checkout_conftest.pytest_ignore_collect(
        repo_root / "tests" / "test_tracked_public_signal.py",
        config=None,
    ) is False


def test_release_readiness_script_exposes_help() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/release_readiness.py", "--help"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TEST_TIMEOUT_SECONDS,
    )

    assert proc.returncode == 0
    assert "release-readiness checks" in proc.stdout
    assert "--skip-self-audit" in proc.stdout


def test_release_contract_detects_stale_current_release_references() -> None:
    release_contract = _load_support_module("release_contract_support", "scripts/check_release_contract.py")

    assert release_contract._stale_current_release_references(
        "\n".join(
            [
                "`v1.2.3` is the current patch-level baseline.",
                "`v1.4.0` is the current minor release.",
                "`v1.4.6` is the current patch release with old notes.",
                "`v1.5.0` is the current minor release with current notes.",
            ]
        )
    ) == [
        "`v1.2.3` is the current patch-level",
        "`v1.4.0` is the current minor release",
        "`v1.4.6` is the current patch release",
    ]


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


def test_gui_local_repair_config_matches_cli_config_for_same_options(
    tmp_path: Path,
    monkeypatch,
) -> None:
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
    report_json = tmp_path / "Audit_Results" / "extra.json"

    app = object.__new__(rpg.GuiApp)
    app.root = DummyRoot()
    app.root_var = DummyVar(str(tmp_path))
    app.policy_var = DummyVar(str(policy))
    app.owner_emails_var = DummyVar("dev@example.com")
    app.allowed_remote_owners_var = DummyVar("axeljackal")
    app.report_dir_var = DummyVar(str(tmp_path / "Audit_Results"))
    app.report_json_var = DummyVar(str(report_json))
    app.replace_text_file_var = DummyVar("ops/replace-text.txt")
    app.public_only_var = DummyVar(True)
    app.github_owner_var = DummyVar("")
    app.github_repo_filters_var = DummyVar("")
    app.github_include_forks_var = DummyVar(False)
    app.github_fast_var = DummyVar(False)
    app.github_jobs_var = DummyVar("4")
    app.push_var = DummyVar(True)
    app.redact_var = DummyVar(True)
    app.rewrite_personal_paths_var = DummyVar(True)
    app.purge_detected_secret_files_var = DummyVar(True)
    app.purge_all_detected_secret_files_var = DummyVar(False)
    app.dry_run_var = DummyVar(True)
    app.low_confidence_blocking_var = DummyVar(True)
    app.audit_litellm_incident_var = DummyVar(True)
    app.audit_github_hardening_var = DummyVar(True)
    app.open_report_var = DummyVar(True)
    app.confirm_each_repo_fix_var = DummyVar(False)
    app.allow_non_owner_push_var = DummyVar(False)
    app.owner_name_var = DummyVar("Alice")
    app.noreply_var = DummyVar(rpg.DEFAULT_NOREPLY)
    app.placeholder_var = DummyVar(rpg.DEFAULT_PLACEHOLDER)
    app.max_matches_var = DummyVar("37")
    app._active_cancel_token = None
    app.log = lambda _msg: None
    app._on_gui_run_finished = lambda *args, **kwargs: None

    app._run_worker(["repo-a", "repo-b"], 37, True, ("repo-a", "repo-b"))

    cli_args = rpg.make_parser().parse_args(
        [
            "--root",
            str(tmp_path),
            "--policy",
            str(policy),
            "--repos",
            "repo-a",
            "repo-b",
            "--public-only",
            "--fix",
            "--push",
            "--dry-run",
            "--redact-third-party-emails",
            "--purge-detected-secret-files",
            "--rewrite-personal-paths",
            "--low-confidence-email-mode",
            "blocking",
            "--audit-litellm-incident",
            "--audit-github-hardening",
            "--owner-name",
            "Alice",
            "--owner-email",
            "dev@example.com",
            "--noreply-email",
            rpg.DEFAULT_NOREPLY,
            "--placeholder-email",
            rpg.DEFAULT_PLACEHOLDER,
            "--max-matches",
            "37",
            "--report-json",
            str(report_json),
            "--replace-text-file",
            "ops/replace-text.txt",
            "--open-report",
            "--no-confirm-each-repo",
            "--allow-remote-owner",
            "axeljackal",
        ]
    )
    cli_config = rpg.build_cli_guard_run_config(cli_args)
    gui_config = captured["config"]

    assert isinstance(gui_config, rpg.GuardRunConfig)
    assert cli_config.mode == "cli"
    assert gui_config.mode == "gui"
    for field in fields(rpg.GuardRunConfig):
        if field.name == "mode":
            continue
        assert getattr(gui_config, field.name) == getattr(cli_config, field.name)


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
    app._lock_repair_until_next_audit = lambda *args, **kwargs: started.setdefault(
        "lock",
        kwargs.get("reason_key") or (args[0] if args else None),
    )
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


def test_gui_logical_window_width_normalizes_high_dpi_geometry_once() -> None:
    class DummyRoot:
        def wm_geometry(self) -> str:
            return "2160x1290+30+30"

        def winfo_width(self) -> int:
            return 900

    class DummyScalingTracker:
        @staticmethod
        def get_window_scaling(_root: object) -> float:
            return 1.5

    class DummyCtk:
        ScalingTracker = DummyScalingTracker

    app = object.__new__(rpg.GuiApp)
    app.root = DummyRoot()
    app.ctk = DummyCtk()

    assert app._get_logical_window_width() == 1440


def test_gui_prompt_cards_stack_on_compact_layout() -> None:
    app = object.__new__(rpg.GuiApp)
    app._prompts_stack_width_threshold = 1240

    assert app._prompt_card_columns_for_width(1180) == 1
    assert app._prompt_card_columns_for_width(1440) == 2


def test_gui_prompt_card_wraplength_expands_for_single_column_layout() -> None:
    class DummyRoot:
        def wm_geometry(self) -> str:
            return "980x780+40+40"

        def winfo_width(self) -> int:
            return 980

    class DummyScalingTracker:
        @staticmethod
        def get_window_scaling(_root: object) -> float:
            return 1.0

    class DummyCtk:
        ScalingTracker = DummyScalingTracker

    app = object.__new__(rpg.GuiApp)
    app.root = DummyRoot()
    app.ctk = DummyCtk()

    assert app._prompt_card_text_wraplength(1) > app._prompt_card_text_wraplength(2)
    assert app._prompt_card_text_wraplength(1, mono=True) > app._prompt_card_text_wraplength(2, mono=True)


def test_gui_prompt_workflow_guide_stacks_and_hides_visual_on_compact_layout() -> None:
    class DummyGuide:
        def __init__(self) -> None:
            self.columns: list[tuple[int, dict[str, object]]] = []

        def grid_columnconfigure(self, column: int, **kwargs: object) -> None:
            self.columns.append((column, kwargs))

    class DummyWidget:
        def __init__(self) -> None:
            self.grid_calls: list[dict[str, object]] = []
            self.config: dict[str, object] = {}
            self.removed = False

        def grid(self, **kwargs: object) -> None:
            self.grid_calls.append(kwargs)
            self.removed = False

        def configure(self, **kwargs: object) -> None:
            self.config.update(kwargs)

        def grid_remove(self) -> None:
            self.removed = True

    guide = DummyGuide()
    title = DummyWidget()
    body = DummyWidget()
    info = DummyWidget()
    visual = DummyWidget()
    app = object.__new__(rpg.GuiApp)
    app._prompts_workflow_guide = guide
    app._prompts_workflow_title_label = title
    app._prompts_workflow_body_label = body
    app._prompts_workflow_info_badge = info
    app._prompts_visual_label = visual

    app._apply_prompts_workflow_layout(compact=True)

    assert guide.columns[-3:] == [(0, {"weight": 1}), (1, {"weight": 0}), (2, {"weight": 0})]
    assert title.grid_calls[-1]["row"] == 0
    assert title.grid_calls[-1]["column"] == 0
    assert info.grid_calls[-1]["column"] == 1
    assert body.grid_calls[-1]["row"] == 1
    assert body.grid_calls[-1]["column"] == 0
    assert body.grid_calls[-1]["columnspan"] == 2
    assert body.config["wraplength"] == 760
    assert visual.removed is True

    app._apply_prompts_workflow_layout(compact=False)

    assert guide.columns[-3:] == [(0, {"weight": 0}), (1, {"weight": 1}), (2, {"weight": 0})]
    assert info.grid_calls[-1]["column"] == 2
    assert body.grid_calls[-1]["row"] == 0
    assert body.grid_calls[-1]["column"] == 1
    assert body.grid_calls[-1]["columnspan"] == 1
    assert body.config["wraplength"] == 1040
    assert visual.removed is False


def test_gui_responsive_prompt_layout_regrids_without_rebuilding_cards() -> None:
    class DummyRoot:
        def wm_geometry(self) -> str:
            return "1770x1140+40+40"

        def winfo_width(self) -> int:
            return 1770

    class DummyScalingTracker:
        @staticmethod
        def get_window_scaling(_root: object) -> float:
            return 1.5

    class DummyCtk:
        ScalingTracker = DummyScalingTracker

    calls: list[tuple[str, object]] = []
    app = object.__new__(rpg.GuiApp)
    app.root = DummyRoot()
    app.ctk = DummyCtk()
    app._gui_destroying = False
    app._top_stack_width_threshold = 1220
    app._options_stack_width_threshold = 1220
    app._results_stack_width_threshold = 1240
    app._prompts_stack_width_threshold = 1240
    app._prompt_card_column_count = 2
    app._apply_header_flow_layout = lambda compact: calls.append(("header", compact))
    app._apply_top_layout = lambda compact: calls.append(("top", compact))
    app._apply_identity_actions_layout = lambda compact: calls.append(("identity", compact))
    app._apply_options_layout = lambda compact: calls.append(("options", compact))
    app._apply_results_layout = lambda compact: calls.append(("results", compact))
    app._apply_reports_decision_layout = lambda compact: calls.append(("reports_decision", compact))
    app._apply_prompts_workflow_layout = lambda compact: calls.append(("prompt_workflow", compact))
    app._apply_prompt_cards_layout = lambda columns: calls.append(("prompt_cards", columns))
    app._refresh_prompt_cards = lambda: (_ for _ in ()).throw(AssertionError("resize must not rebuild cards"))

    app._apply_responsive_layout()

    assert ("prompt_workflow", True) in calls
    assert ("prompt_cards", 1) in calls


def test_gui_reports_actions_reflow_when_compact_state_changes() -> None:
    calls: list[bool] = []
    app = object.__new__(rpg.GuiApp)
    app._compact_reports_actions_layout = False
    app._refresh_reports_tab = lambda: calls.append(app._compact_reports_actions_layout)  # type: ignore[method-assign]

    app._apply_reports_actions_layout(compact=True)

    assert app._compact_reports_actions_layout is True
    assert calls == [True]

    app._apply_reports_actions_layout(compact=True)

    assert calls == [True]


def test_gui_reports_decision_steps_stack_on_compact_layout() -> None:
    class DummySteps:
        def __init__(self) -> None:
            self.columns: list[tuple[object, dict[str, object]]] = []

        def grid_columnconfigure(self, column: object, **kwargs: object) -> None:
            self.columns.append((column, kwargs))

    class DummyWidget:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def grid_configure(self, **kwargs: object) -> None:
            self.calls.append(kwargs)

    steps = DummySteps()
    labels = [DummyWidget(), DummyWidget(), DummyWidget()]
    prompts_button = DummyWidget()
    app = object.__new__(rpg.GuiApp)
    app._compact_reports_decision_layout = False
    app._reports_agent_steps_frame = steps
    app._reports_agent_step_labels = labels
    app._reports_open_prompts_button = prompts_button

    app._apply_reports_decision_layout(compact=True)

    assert app._compact_reports_decision_layout is True
    assert labels[0].calls[-1]["row"] == 0
    assert labels[1].calls[-1]["row"] == 1
    assert labels[2].calls[-1]["row"] == 2
    assert labels[0].calls[-1]["column"] == 0
    assert prompts_button.calls[-1]["sticky"] == "w"

    rebuilt_labels = [DummyWidget(), DummyWidget(), DummyWidget()]
    app._reports_agent_step_labels = rebuilt_labels
    app._apply_reports_decision_layout(compact=True)

    assert rebuilt_labels[1].calls[-1]["row"] == 1
    assert rebuilt_labels[2].calls[-1]["column"] == 0

    app._apply_reports_decision_layout(compact=False)

    assert app._compact_reports_decision_layout is False
    assert rebuilt_labels[0].calls[-1]["row"] == 0
    assert rebuilt_labels[1].calls[-1]["row"] == 0
    assert rebuilt_labels[2].calls[-1]["row"] == 0
    assert rebuilt_labels[2].calls[-1]["column"] == 2
    assert prompts_button.calls[-1]["sticky"] == "e"


def test_gui_reports_decision_layout_does_not_unhide_prompt_button() -> None:
    class DummySteps:
        def grid_columnconfigure(self, column: object, **kwargs: object) -> None:
            del column, kwargs

    class DummyLabel:
        def grid_configure(self, **kwargs: object) -> None:
            del kwargs

    class HiddenButton:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def winfo_manager(self) -> str:
            return ""

        def grid_configure(self, **kwargs: object) -> None:
            self.calls.append(kwargs)

    hidden_button = HiddenButton()
    app = object.__new__(rpg.GuiApp)
    app._reports_agent_steps_frame = DummySteps()
    app._reports_agent_step_labels = [DummyLabel(), DummyLabel(), DummyLabel()]
    app._reports_open_prompts_button = hidden_button

    app._apply_reports_decision_layout(compact=True)

    assert hidden_button.calls == []


def test_gui_resize_ignores_callbacks_while_root_is_destroying() -> None:
    app = object.__new__(rpg.GuiApp)
    app._gui_destroying = True
    app._apply_responsive_layout = lambda: (_ for _ in ()).throw(AssertionError("destroying root must not relayout"))

    app._on_root_resize(object())


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


def test_gui_setup_settings_are_collapsible() -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class DummyWidget:
        def __init__(self) -> None:
            self.actions: list[str] = []
            self.kwargs: dict[str, object] = {}

        def configure(self, **kwargs: object) -> None:
            self.kwargs.update(kwargs)

        def grid(self) -> None:
            self.actions.append("grid")

        def grid_remove(self) -> None:
            self.actions.append("grid_remove")

    frame = DummyWidget()
    toggle_button = DummyWidget()
    hint_label = DummyWidget()

    app = object.__new__(rpg.GuiApp)
    app._setup_settings_visible = True
    app._setup_settings_frame = frame
    app._setup_settings_toggle_button = toggle_button
    app._setup_settings_hint_label = hint_label

    app._set_setup_settings_visibility(False)

    assert app._setup_settings_visible is False
    assert toggle_button.kwargs["text"] == "Open Settings"
    assert "saved and hidden" in str(hint_label.kwargs["text"])
    assert frame.actions == ["grid_remove"]

    app.github_owner_var = DummyVar("Acme")
    app._set_setup_settings_visibility(False)

    assert "Acme" in str(hint_label.kwargs["text"])

    app._toggle_setup_settings()

    assert app._setup_settings_visible is True
    assert toggle_button.kwargs["text"] == "Hide Settings"
    assert "Setup is open" in str(hint_label.kwargs["text"])
    assert frame.actions[-1] == "grid"


def test_gui_repair_options_are_collapsible() -> None:
    class DummyWidget:
        def __init__(self) -> None:
            self.actions: list[str] = []
            self.kwargs: dict[str, object] = {}

        def configure(self, **kwargs: object) -> None:
            self.kwargs.update(kwargs)

        def grid(self) -> None:
            self.actions.append("grid")

        def grid_remove(self) -> None:
            self.actions.append("grid_remove")

    card = DummyWidget()
    button = DummyWidget()
    hint = DummyWidget()
    app = object.__new__(rpg.GuiApp)
    app._repair_options_visible = True
    app._repair_options_card = card
    app._repair_options_toggle_button = button
    app._repair_options_hint_label = hint

    app._set_repair_options_visibility(False)

    assert app._repair_options_visible is False
    assert card.actions == ["grid_remove"]
    assert button.kwargs["text"] == "Show advanced Repair options"
    assert "hidden" in str(hint.kwargs["text"])

    app._toggle_repair_options()

    assert app._repair_options_visible is True
    assert card.actions[-1] == "grid"
    assert button.kwargs["text"] == "Hide advanced Repair options"
    assert "visible" in str(hint.kwargs["text"])


def test_gui_settings_payload_excludes_identity_secrets() -> None:
    class DummyVar:
        def __init__(self, value: object) -> None:
            self.value = value

        def get(self) -> object:
            return self.value

    app = object.__new__(rpg.GuiApp)
    app.root_var = DummyVar("C:/repos")
    app.policy_var = DummyVar("POLICY.md")
    app.report_dir_var = DummyVar("Audit_Results")
    app.report_json_var = DummyVar("")
    app.max_matches_var = DummyVar("50")
    app.github_owner_var = DummyVar("Acme")
    app.github_repo_filters_var = DummyVar("api")
    app.github_jobs_var = DummyVar("4")
    app.public_only_var = DummyVar(True)
    app.github_include_forks_var = DummyVar(False)
    app.github_fast_var = DummyVar(True)
    app.dry_run_var = DummyVar(False)
    app.low_confidence_blocking_var = DummyVar(False)
    app.audit_litellm_incident_var = DummyVar(False)
    app.audit_github_hardening_var = DummyVar(True)
    app.open_report_var = DummyVar(False)
    app._gui_appearance = rpg.GUI_APPEARANCE_DARK

    payload = app._current_gui_settings_payload(setup_completed=True)

    assert payload["setup_completed"] is True
    assert payload["gui_locale"] == rpg.GUI_LOCALE_DEFAULT
    assert payload["gui_appearance"] == rpg.GUI_APPEARANCE_DARK
    assert payload["github_owner"] == "Acme"
    assert "owner_emails" not in payload
    assert "noreply_email" not in payload
    assert "placeholder_email" not in payload
    assert "allowed_remote_owners" not in payload


def test_gui_settings_roundtrip_uses_private_json(tmp_path: Path) -> None:
    settings_path = tmp_path / "gui_settings.json"

    rpg.save_gui_settings(
        settings_path,
        {
            "setup_completed": True,
            "gui_locale": "es-419",
            "gui_appearance": "dark",
            "root": "C:/repos",
            "github_owner": "Acme",
        },
    )

    loaded = rpg.load_gui_settings(settings_path)

    assert loaded["schema_version"] == rpg.GUI_SETTINGS_SCHEMA_VERSION
    assert loaded["setup_completed"] is True
    assert loaded["gui_locale"] == "es-419"
    assert loaded["gui_appearance"] == "dark"
    assert loaded["root"] == "C:/repos"
    assert loaded["github_owner"] == "Acme"


def test_default_gui_settings_path_honors_env_override(tmp_path: Path) -> None:
    override = tmp_path / "custom-settings.json"

    assert rpg.default_gui_settings_path({rpg.GUI_SETTINGS_ENV_VAR: str(override)}) == override


def test_load_gui_settings_ignores_invalid_files(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{not-json", encoding="utf-8")
    invalid_schema = tmp_path / "invalid-schema.json"
    invalid_schema.write_text('{"schema_version": "bad"}', encoding="utf-8")

    assert rpg.load_gui_settings(invalid_json) == {}
    assert rpg.load_gui_settings(invalid_schema) == {}


def test_gui_locale_helpers_normalize_supported_languages() -> None:
    assert rpg.normalize_gui_locale("en-US") == rpg.GUI_LOCALE_DEFAULT
    assert rpg.normalize_gui_locale("es_AR") == rpg.GUI_LOCALE_ES_419
    assert rpg.normalize_gui_locale("Español") == rpg.GUI_LOCALE_ES_419
    assert rpg.normalize_gui_locale("pt-BR") == rpg.GUI_LOCALE_DEFAULT
    assert rpg.gui_locale_from_label("Español (Latinoamérica)") == rpg.GUI_LOCALE_ES_419


def test_gui_locale_constants_are_reexported_from_locale_module() -> None:
    from repo_privacy_guardian.gui import locale as gui_locale

    assert rpg.GUI_LOCALE_DEFAULT == gui_locale.GUI_LOCALE_DEFAULT
    assert rpg.GUI_LOCALE_ES_419 == gui_locale.GUI_LOCALE_ES_419
    assert rpg.GUI_LOCALE_OPTIONS == gui_locale.GUI_LOCALE_OPTIONS
    assert rpg.GITHUB_EMAIL_PRIVACY_HELP == gui_locale.GITHUB_EMAIL_PRIVACY_HELP


def test_gui_appearance_helpers_normalize_supported_modes() -> None:
    assert rpg.normalize_gui_appearance("system") == rpg.GUI_APPEARANCE_SYSTEM
    assert rpg.normalize_gui_appearance("Sistema") == rpg.GUI_APPEARANCE_SYSTEM
    assert rpg.normalize_gui_appearance("auto") == rpg.GUI_APPEARANCE_SYSTEM
    assert rpg.normalize_gui_appearance("dark") == rpg.GUI_APPEARANCE_DARK
    assert rpg.normalize_gui_appearance("Oscuro") == rpg.GUI_APPEARANCE_DARK
    assert rpg.normalize_gui_appearance("noche") == rpg.GUI_APPEARANCE_DARK
    assert rpg.normalize_gui_appearance("light") == rpg.GUI_APPEARANCE_LIGHT
    assert rpg.normalize_gui_appearance("Claro") == rpg.GUI_APPEARANCE_LIGHT
    assert rpg.normalize_gui_appearance("unknown") == rpg.GUI_APPEARANCE_DEFAULT
    assert rpg.gui_appearance_from_label("Sistema") == rpg.GUI_APPEARANCE_SYSTEM
    assert rpg.gui_appearance_from_label("Claro") == rpg.GUI_APPEARANCE_LIGHT
    assert rpg.gui_appearance_from_label("Dark") == rpg.GUI_APPEARANCE_DARK
    assert rpg.gui_appearance_label(rpg.GUI_APPEARANCE_SYSTEM, rpg.GUI_LOCALE_ES_419) == "Sistema"
    assert rpg.gui_appearance_label(rpg.GUI_APPEARANCE_DARK, rpg.GUI_LOCALE_ES_419) == "Oscuro"


def test_gui_theme_palette_uses_semantic_scrollbar_tokens() -> None:
    app = object.__new__(rpg.GuiApp)

    app._gui_appearance = rpg.GUI_APPEARANCE_LIGHT
    app._configure_gui_theme_palette()
    assert app._scrollbar_track == app._page_bg
    assert app._scrollbar_thumb != app._scrollbar_hover
    assert app._scrollbar_thumb != app._primary_button_fg
    assert app._output_empty_text != app._output_text

    app._gui_appearance = rpg.GUI_APPEARANCE_DARK
    app._configure_gui_theme_palette()
    assert app._scrollbar_track == app._page_bg
    assert app._scrollbar_thumb != app._scrollbar_hover
    assert app._scrollbar_thumb != app._primary_button_fg
    assert app._output_empty_text != app._output_text


def test_gui_system_appearance_resolves_to_effective_palette() -> None:
    class DummyCtk:
        @staticmethod
        def get_appearance_mode() -> str:
            return "Dark"

    app = object.__new__(rpg.GuiApp)
    app.ctk = DummyCtk()
    app._gui_appearance = rpg.GUI_APPEARANCE_SYSTEM

    app._configure_gui_theme_palette()

    assert app._current_appearance() == rpg.GUI_APPEARANCE_SYSTEM
    assert app._effective_appearance() == rpg.GUI_APPEARANCE_DARK
    assert app._page_bg == "#0F1D22"

    app._gui_appearance = rpg.GUI_APPEARANCE_LIGHT
    app._configure_gui_theme_palette()

    assert app._effective_appearance() == rpg.GUI_APPEARANCE_LIGHT
    assert app._page_bg == "#EEF5F2"


def test_gui_theme_translation_handles_ambiguous_section_colors() -> None:
    class DummyCtk:
        @staticmethod
        def get_appearance_mode() -> str:
            return "Light"

    app = object.__new__(rpg.GuiApp)
    app.ctk = DummyCtk()
    app._gui_appearance = rpg.GUI_APPEARANCE_LIGHT
    app._configure_gui_theme_palette()
    light_palette = app._theme_palette_snapshot()

    app._gui_appearance = rpg.GUI_APPEARANCE_DARK
    app._configure_gui_theme_palette()
    dark_palette = app._theme_palette_snapshot()

    assert app._translate_theme_color(
        light_palette["_secondary_button_fg"],
        "fg_color",
        old_palette=light_palette,
        new_palette=dark_palette,
        sibling_values={},
    ) == dark_palette["_secondary_button_fg"]
    assert app._translate_theme_color(
        light_palette["_success_text"],
        "text_color",
        old_palette=light_palette,
        new_palette=dark_palette,
        sibling_values={},
    ) == dark_palette["_success_text"]
    assert app._translate_theme_color(
        light_palette["_white_panel_border"],
        "border_color",
        old_palette=light_palette,
        new_palette=dark_palette,
        sibling_values={"fg_color": light_palette["_white_panel_fg"]},
    ) == dark_palette["_white_panel_border"]


def test_gui_fixed_theme_options_restore_non_palette_text_colors() -> None:
    class DummyWidget:
        def __init__(self) -> None:
            self.options: dict[str, object] = {}

        def configure(self, **kwargs: object) -> None:
            self.options.update(kwargs)

    app = object.__new__(rpg.GuiApp)
    app._fixed_theme_options = []
    widget = DummyWidget()

    app._register_fixed_theme_option(widget, "text_color", "#F8FAFC")
    widget.configure(text_color="#082326")
    app._refresh_fixed_theme_options()

    assert widget.options["text_color"] == "#F8FAFC"


def test_on_gui_run_finished_keeps_repair_locked_after_aborted_audit() -> None:
    seen: list[tuple[str, str]] = []

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app._lock_repair_until_next_audit = lambda *args, **kwargs: seen.append(
        ("lock", str(kwargs.get("reason_key") or (args[0] if args else None)))
    )
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
    assert ("lock", "lock_repair_cancelled") in seen
    assert ("tab", "1. Audit") in seen
    assert any(item == ("log", "[INFO] Flow: audit cancelled. Run Audit again when you are ready to continue.") for item in seen)
    assert not any(kind == "cooldown" for kind, _value in seen)


def test_on_gui_run_finished_keeps_repair_locked_after_remote_github_audit() -> None:
    seen: list[tuple[str, str]] = []

    app = object.__new__(rpg.GuiApp)
    app._run_in_progress = True
    app._active_cancel_token = rpg.CancellationToken()
    app._lock_repair_until_next_audit = lambda *args, **kwargs: seen.append(
        ("lock", str(kwargs.get("reason_key") or (args[0] if args else None)))
    )
    app._set_active_flow_tab = lambda tab: seen.append(("tab", tab))
    app._start_repair_cooldown = lambda reports_payload, selection_signature: seen.append(  # type: ignore[assignment]
        ("cooldown", str((reports_payload, selection_signature)))
    )
    app.log = lambda message: seen.append(("log", message))
    app._audit_tab_name = "1. Audit"
    app._reports_tab_name = "2. Reports"
    app._repair_tab_name = "2. Repair"

    app._on_gui_run_finished(False, ("github-owner", "acme"), [{"name": "repo-a"}], rpg.EXIT_OK)

    assert app._run_in_progress is False
    assert app._active_cancel_token is None
    assert ("lock", "lock_repair_remote") in seen
    assert ("tab", "2. Reports") in seen
    assert any("remote audit mode is audit-only" in value.lower() for kind, value in seen if kind == "log")
    assert not any(kind == "cooldown" for kind, _value in seen)


def test_gui_remote_selection_signature_includes_owner_and_filters() -> None:
    app = object.__new__(rpg.GuiApp)

    signature = app._run_selection_signature(["worker", "api"], github_owner="Acme")

    assert signature == ("github-owner", "acme", "api", "worker")


def test_parse_tk_drop_paths_uses_tk_splitter() -> None:
    paths = rpg.parse_tk_drop_paths(
        "{C:/Repos/Repo A} C:/Repos/RepoB",
        splitter=lambda _raw: ("C:/Repos/Repo A", "C:/Repos/RepoB"),
    )

    assert [str(path).replace("\\", "/") for path in paths] == ["C:/Repos/Repo A", "C:/Repos/RepoB"]


def test_parse_tk_drop_paths_falls_back_when_splitter_fails() -> None:
    paths = rpg.parse_tk_drop_paths("C:/Repos/RepoA", splitter=lambda _raw: (_ for _ in ()).throw(ValueError))

    assert len(paths) == 1
    assert str(paths[0]).replace("\\", "/") == "C:/Repos/RepoA"


def test_resolve_dropped_repository_targets_selects_single_repo_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo-a"
    (repo / ".git").mkdir(parents=True)

    root, selected, error = rpg.resolve_dropped_repository_targets([repo])

    assert error is None
    assert root == repo.resolve()
    assert selected == ["."]


def test_resolve_dropped_repository_targets_selects_sibling_repos(tmp_path: Path) -> None:
    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    (repo_a / ".git").mkdir(parents=True)
    (repo_b / ".git").mkdir(parents=True)

    root, selected, error = rpg.resolve_dropped_repository_targets([repo_a, repo_b])

    assert error is None
    assert root == tmp_path.resolve()
    assert selected == ["repo-a", "repo-b"]


def test_gui_repo_drop_sets_local_root_and_selection(tmp_path: Path) -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

        def set(self, value: str) -> None:
            self.value = value

    class DummyTk:
        def __init__(self, values: tuple[str, ...]) -> None:
            self.values = values

        def splitlist(self, _raw: str) -> tuple[str, ...]:
            return self.values

    class DummyRoot:
        def __init__(self, values: tuple[str, ...]) -> None:
            self.tk = DummyTk(values)

    class DummyListbox:
        def __init__(self) -> None:
            self.selected: set[int] = set()

        def selection_clear(self, _start: int, _end: str) -> None:
            self.selected.clear()

        def selection_set(self, index: int) -> None:
            self.selected.add(index)

    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    (repo_a / ".git").mkdir(parents=True)
    (repo_b / ".git").mkdir(parents=True)

    events: list[object] = []
    app = object.__new__(rpg.GuiApp)
    app.root = DummyRoot((str(repo_a), str(repo_b)))
    app.root_var = DummyVar("")
    app.github_owner_var = DummyVar("Acme")
    app._run_in_progress = False
    app._repo_items = []
    app.repo_list = DummyListbox()
    app.log = events.append
    app._github_owner_value = lambda: app.github_owner_var.get().strip() or None
    app._update_repo_summary = lambda: events.append("summary")
    app._set_setup_settings_visibility = lambda visible: events.append(("settings", visible))
    app._save_gui_setup_settings = lambda setup_completed: events.append(("save", setup_completed)) or True

    def refresh_repos() -> None:
        app._repo_items = [("repo-a", "repo-a"), ("repo-b", "repo-b")]

    app.refresh_repos = refresh_repos

    app._handle_repo_drop("ignored-by-splitter")

    assert app.root_var.get() == str(tmp_path.resolve())
    assert app.github_owner_var.get() == ""
    assert app.repo_list.selected == {0, 1}
    assert ("save", True) in events
    assert ("settings", False) in events


def test_choose_gui_font_family_prefers_available_candidates() -> None:
    picked = rpg.choose_gui_font_family(
        ("SF Pro Text", "Helvetica Neue", "Arial"),
        {"Arial", "Courier New"},
    )

    assert picked == "Arial"


def test_choose_gui_font_family_falls_back_to_first_candidate() -> None:
    picked = rpg.choose_gui_font_family(("Inter", "Noto Sans"), {"Menlo", "Courier"})
    assert picked == "Inter"


def test_gui_tooltip_catalog_covers_non_obvious_controls() -> None:
    required_keys = {
        "repositories_root",
        "settings_toggle",
        "policy_file",
        "audit_results_folder",
        "optional_json_copy",
        "github_owner",
        "github_repo_filters",
        "github_clone_workers",
        "github_include_forks",
        "github_fast",
        "max_findings",
        "gui_language",
        "gui_appearance",
        "save_setup",
        "advanced_identity",
        "noreply_email",
        "placeholder_email",
        "owner_name",
        "owner_emails",
        "git_user_name",
        "git_user_email",
        "apply_global_git_config",
        "apply_local_git_config",
        "read_current_git_identity",
        "open_github_email_settings",
        "public_only",
        "redact_third_party_emails",
        "low_confidence_blocking",
        "dry_run_preview",
        "audit_github_hardening",
        "audit_litellm_incident",
        "open_html_report",
        "confirm_each_repo_fix",
        "rewrite_personal_paths",
        "replace_text_rules",
        "force_push",
        "bypass_remote_owner_guardrail",
        "allowed_remote_owners",
        "purge_safe_secret_files",
        "purge_risky_secret_files",
        "repair_button",
        "run_audit",
        "stop_after_current_step",
        "refresh_repos",
        "select_all_repos",
        "clear_selection",
        "clear_log",
        "repo_drop_area",
        "workflow_overview",
        "audit_target_section",
        "settings_section",
        "owner_profile_section",
        "repositories_section",
        "execution_log_section",
        "reports_section",
        "latest_artifacts_section",
        "next_action_section",
        "prompts_section",
        "agent_workflow_section",
        "repair_options_section",
        "repair_flow_section",
        "reports_tab",
        "prompts_tab",
        "open_settings_tab",
        "open_agent_prompts_tab",
        "copy_agent_handoff",
        "compare_previous_report",
        "copy_prompt",
        "copy_prompt_command",
        "open_prompt_file",
    }

    assert required_keys <= set(rpg.GUI_TOOLTIP_TEXT)
    for locale, catalog in rpg.GUI_TOOLTIP_TEXT_BY_LOCALE.items():
        assert set(catalog) == set(rpg.GUI_TOOLTIP_TEXT), locale
        assert all(catalog[key].strip().endswith(".") for key in required_keys), locale


def test_gui_ui_locale_catalogs_have_parallel_keys() -> None:
    base_keys = set(rpg.GUI_UI_TEXT_BY_LOCALE[rpg.GUI_LOCALE_DEFAULT])

    assert base_keys
    for locale, catalog in rpg.GUI_UI_TEXT_BY_LOCALE.items():
        assert set(catalog) == base_keys, locale


def test_spanish_gui_locale_avoids_untranslated_ux_terms() -> None:
    spanish_catalogs = {
        "ui": rpg.GUI_UI_TEXT_BY_LOCALE[rpg.GUI_LOCALE_ES_419],
        "tooltips": rpg.GUI_TOOLTIP_TEXT_BY_LOCALE[rpg.GUI_LOCALE_ES_419],
        "prompts": {
            prompt.prompt_id: f"{prompt.title}\n{prompt.description}"
            for prompt in prompt_helpers.PROMPT_REGISTRY
            if prompt.locale == "es-419"
        },
    }
    forbidden_fragments = (
        "agent-first",
        "gated",
        "gate",
        "backend",
        "dashboard de reportes",
        "prompt",
        "audit-only",
        "handoff",
        "manual-review",
        "hardening advisory",
        "issues de tooling",
        "leaks confirmados",
        "github owner/org",
        "github owner / org",
        "owner u organización",
        "owner remoto",
        "owners remotos",
        "allowlist",
        "bypass",
        "guardrail",
        "workers",
        "clone shallow",
        "drag-and-drop",
        "runtime tk",
        "toggles",
        "settings de email github",
        "github email settings",
        "low-confidence",
        "dry run / preview",
        "hardening de release",
        "publication gate",
        "checks read-only",
        "tooling github",
        "trackeado",
        "untrack",
        "baseline",
        "fixes",
        "re-audite",
        "release/security",
    )

    for catalog_name, catalog in spanish_catalogs.items():
        for key, value in catalog.items():
            normalized = value.lower()
            for fragment in forbidden_fragments:
                assert fragment not in normalized, f"{catalog_name}.{key} contains untranslated fragment {fragment!r}"

    ui_catalog = spanish_catalogs["ui"]
    assert ui_catalog["tab_prompts"] == "3. Instrucciones"
    assert "modo solo auditoría" in ui_catalog["agent_handoff_prompt"]
    assert "Instrucciones IA" in ui_catalog["recommended_path_body"]


def test_gui_agent_handoff_uses_repo_relative_artifact_paths() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    run_dir = repo_root / "Audit_Results" / "agent-handoff-test"
    app = object.__new__(rpg.GuiApp)
    app._last_run_artifacts = RunArtifacts(
        run_id="agent-handoff-test",
        run_dir=run_dir,
        json_path=run_dir / "report.json",
        log_path=run_dir / "run.log",
        html_path=run_dir / "report.html",
        state_path=run_dir / "run_state.json",
        started_at=datetime.now(),
    )
    app._last_run_exit_code = rpg.EXIT_POLICY_FAILED
    app._last_audit_reports_payload = [
        {
            "name": "SampleRepo",
            "status": "FAIL",
            "failures": ["tracked secret matches"],
            "exfil_code_indicators": ["main.py:1:<redacted-url>"],
            "tracked_secret_fixture_matches": ["tests/fixtures/example.env:1:<redacted-secret>"],
            "reviewed_network_indicators": [
                "repo_privacy_guardian/github.py:1:with urllib.request.urlopen(request, timeout=8) as response:"
            ],
        }
    ]

    handoff = app._build_agent_handoff_text()

    assert handoff is not None
    assert "Audit_Results/agent-handoff-test/report.json" in handoff
    assert "Audit_Results/agent-handoff-test/run.log" in handoff
    assert str(repo_root) not in handoff
    assert "Run status: FAIL" in handoff
    assert "Blocking categories: 1" in handoff
    assert "Manual-review signals: 1" in handoff
    assert "Fixture/documentation context: 2" in handoff
    assert "Recommended next action:" in handoff
    assert "Do not paste raw secrets" in handoff


def test_gui_reports_next_action_tracks_policy_state() -> None:
    app = object.__new__(rpg.GuiApp)
    app._gui_locale = rpg.GUI_LOCALE_DEFAULT
    blocking_counts = app._reports_summary_counts(
        [
            {
                "name": "SampleRepo",
                "status": "FAIL",
                "failures": ["tracked secret matches"],
            }
        ]
    )
    manual_counts = app._reports_summary_counts(
        [
            {
                "name": "SampleRepo",
                "status": "PASS",
                "exfil_code_indicators": ["main.py:1:<redacted-url>"],
            }
        ]
    )
    reviewed_context_counts = app._reports_summary_counts(
        [
            {
                "name": "SampleRepo",
                "status": "PASS",
                "reviewed_network_indicators": ["repo_privacy_guardian/github.py:1:urlopen(request)"],
            }
        ]
    )

    assert app._reports_status_label(blocking_counts, rpg.EXIT_POLICY_FAILED) == "FAIL"
    assert app._reports_next_action_key(blocking_counts, rpg.EXIT_POLICY_FAILED, True) == "next_action_failed"
    assert app._reports_status_label(manual_counts, rpg.EXIT_OK) == "PASS/REVIEW"
    assert app._reports_next_action_key(manual_counts, rpg.EXIT_OK, True) == "next_action_manual"
    assert app._reports_status_label(reviewed_context_counts, rpg.EXIT_OK) == "PASS"
    assert reviewed_context_counts["fixture"] == 1
    empty_counts = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "blocking": 0,
        "manual": 0,
        "fixture": 0,
    }
    assert app._reports_next_action_key(empty_counts, None, False) == "next_action_run_audit"


def test_agentic_prompt_registry_has_parallel_locales_and_existing_files() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    by_locale: dict[str, set[str]] = {}
    for prompt in prompt_helpers.PROMPT_REGISTRY:
        by_locale.setdefault(prompt.locale, set()).add(prompt.prompt_id)
        path = prompt.path(repo_root)
        assert path.exists(), path
        assert prompt.title.strip()
        assert prompt.description.strip()
        assert prompt.command.startswith("repo-privacy-guardian")

    assert by_locale["en"] == by_locale["es-419"]
    assert {prompt.prompt_id for prompt in prompt_helpers.agentic_prompt_cards("en")} == by_locale["en"]
    assert {prompt.prompt_id for prompt in prompt_helpers.agentic_prompt_cards("es-419")} == by_locale["es-419"]


def test_agentic_prompt_copy_text_has_no_broken_template_markers() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    for prompt in prompt_helpers.PROMPT_REGISTRY:
        text = prompt_helpers.read_prompt_text(prompt, repo_root)
        assert "{{" not in text
        assert "}}" not in text
        assert "TODO" not in text
        assert "NPM_TOKEN" not in text
        assert "GITHUB_TOKEN=" not in text


def test_gui_repair_gate_note_tracks_repair_state() -> None:
    class DummyLabel:
        def __init__(self) -> None:
            self.config: dict[str, object] = {}

        def configure(self, **kwargs: object) -> None:
            self.config.update(kwargs)

    label = DummyLabel()
    app = object.__new__(rpg.GuiApp)
    app._gui_locale = rpg.GUI_LOCALE_ES_419
    app._repair_gate_note_label = label
    app._repair_ready = False
    app._last_audit_reports_payload = []

    app._update_repair_gate_note()
    assert label.config["text"] == rpg.GUI_UI_TEXT_BY_LOCALE[rpg.GUI_LOCALE_ES_419]["repair_stays_disabled"]

    app._last_audit_reports_payload = [{"name": "SampleRepo", "status": "PASS"}]
    app._update_repair_gate_note()
    assert label.config["text"] == rpg.GUI_UI_TEXT_BY_LOCALE[rpg.GUI_LOCALE_ES_419]["repair_review_pending_note"]

    app._repair_ready = True
    app._update_repair_gate_note()
    assert label.config["text"] == rpg.GUI_UI_TEXT_BY_LOCALE[rpg.GUI_LOCALE_ES_419]["repair_ready_note"]


def test_gui_state_helpers_cover_audit_stop_and_repair_labels() -> None:
    assert gui_state_helpers.audit_button_state(
        run_in_progress=False,
        has_targets=True,
        has_remote_target=False,
    ) == gui_state_helpers.ButtonState("run_audit", "normal")
    assert gui_state_helpers.audit_button_state(
        run_in_progress=False,
        has_targets=False,
        has_remote_target=False,
    ) == gui_state_helpers.ButtonState("audit_unavailable", "disabled")
    assert gui_state_helpers.audit_button_state(
        run_in_progress=True,
        has_targets=False,
        has_remote_target=True,
    ) == gui_state_helpers.ButtonState("run_audit", "disabled")
    assert gui_state_helpers.cancel_button_state(
        run_in_progress=True,
        cancel_requested=False,
    ) == gui_state_helpers.ButtonState("stop_after_current_step", "normal")
    assert gui_state_helpers.cancel_button_state(
        run_in_progress=True,
        cancel_requested=True,
    ) == gui_state_helpers.ButtonState("stopping_after_current_step", "disabled")
    assert gui_state_helpers.repair_button_state(repair_ready=True, run_in_progress=False) == "normal"
    assert gui_state_helpers.repair_button_state(repair_ready=True, run_in_progress=True) == "disabled"
    assert gui_state_helpers.repair_gate_note_state(
        repair_ready=False,
        has_audit_reports=False,
    ) == gui_state_helpers.RepairGateNoteState("repair_stays_disabled", "locked")
    assert gui_state_helpers.repair_gate_note_state(
        repair_ready=False,
        has_audit_reports=True,
    ) == gui_state_helpers.RepairGateNoteState("repair_review_pending_note", "review")
    assert gui_state_helpers.repair_gate_note_state(
        repair_ready=True,
        has_audit_reports=True,
    ) == gui_state_helpers.RepairGateNoteState("repair_ready_note", "ready")


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

        def grid(self, **kwargs) -> None:
            self.kwargs.update(kwargs)
            self.kwargs["grid"] = "1"

        def grid_remove(self) -> None:
            self.kwargs["grid_removed"] = "1"

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
    app._repo_empty_state_action_button = DummyWidget()
    app._audit_button = DummyWidget()
    app._select_all_button = DummyWidget()
    app._clear_selection_button = DummyWidget()
    app._refresh_button = DummyWidget()
    app._repair_button = None
    app._run_in_progress = False

    app.refresh_repos()

    assert "Root folder not found" in app._repo_summary_label.text
    assert app._repo_empty_state_title_label.text == "Root folder not found"
    assert app._repo_empty_state_body_label.text == rpg.GUI_UI_TEXT_BY_LOCALE[rpg.GUI_LOCALE_DEFAULT]["choose_valid_root"]
    assert app._repo_empty_state_action_button.text == "Choose Root"
    assert app._repo_empty_state_action_button.kwargs["state"] == "normal"
    assert app._repo_empty_state_action_button.kwargs["grid"] == "1"
    assert app._audit_button.kwargs["text"] == "Audit unavailable"
    assert app._audit_button.kwargs["state"] == "disabled"
    assert app._select_all_button.kwargs["state"] == "disabled"
    assert app._clear_selection_button.kwargs["state"] == "disabled"
    assert app._refresh_button.kwargs["state"] == "normal"
    assert app.repo_list.state == "disabled"


def test_refresh_repos_remote_owner_surfaces_audit_only_state(tmp_path: Path) -> None:
    class DummyVar:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class DummyListbox:
        def __init__(self) -> None:
            self.items: list[str] = ["stale"]
            self.state = "normal"

        def delete(self, _start, _end) -> None:
            self.items = []

        def curselection(self) -> tuple[int, ...]:
            return ()

        def configure(self, **kwargs) -> None:
            if "state" in kwargs:
                self.state = kwargs["state"]

    class DummyWidget:
        def __init__(self) -> None:
            self.text = ""
            self.kwargs: dict[str, object] = {}

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

    app = object.__new__(rpg.GuiApp)
    app.root_var = DummyVar(str(tmp_path / "missing-root"))
    app.github_owner_var = DummyVar("Acme")
    app.github_repo_filters_var = DummyVar("api, worker")
    app.repo_list = DummyListbox()
    app._repo_items = [("stale", "stale")]
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
    app._cancel_button = None
    app._run_in_progress = False
    app._active_cancel_token = None

    app.refresh_repos()

    assert app._repo_items == []
    assert app.repo_list.items == []
    assert app._repo_empty_state_title_label.text == "GitHub owner/org audit active"
    assert "2 named remote repositories" in app._repo_empty_state_body_label.text
    assert "audit-only" in app._repo_empty_state_body_label.text
    assert "local repository list is ignored" in app._repo_summary_label.text.lower()
    assert "keep Repair locked" in app._repo_summary_label.text
    assert app._audit_button.kwargs["text"] == "Run Audit"
    assert app._audit_button.kwargs["state"] == "normal"
    assert app.repo_list.state == "disabled"
    assert app._select_all_button.kwargs["state"] == "disabled"


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
            {
                "name": "repo-a",
                "status": "FAIL",
                "failures": ["secret-like patterns in tracked files"],
                "tracked_secret_low_confidence": ["settings.py:1:<redacted-secret>"],
            },
            {
                "name": "repo-b",
                "status": "PASS",
                "tracked_secret_fixture_matches": ["tests/fixtures/example.env:1:<redacted-secret>"],
            },
        ]
    )

    assert "1 FAIL / 1 PASS" in summary
    assert "repo-a, repo-b" in summary
    assert "1 blocking category" in summary
    assert "1 manual-review signal" in summary
    assert "1 fixture/documentation match kept non-blocking" in summary


def test_gui_state_repair_status_summary_uses_translation_callback() -> None:
    translations = rpg.GUI_UI_TEXT_BY_LOCALE[rpg.GUI_LOCALE_DEFAULT]

    def translate(key: str, **kwargs: object) -> str:
        return translations[key].format(**kwargs)

    summary = gui_state_helpers.build_repair_status_summary(
        [
            {
                "name": "repo-a",
                "status": "PASS",
                "history_secret_low_confidence": ["L1:src/settings.py:<redacted-secret>"],
            },
            {
                "name": "repo-b",
                "status": "PASS",
                "reviewed_network_indicators": ["repo_privacy_guardian/github.py:1:urlopen(request)"],
            },
            {"name": "repo-c", "status": "PASS"},
            {"name": "repo-d", "status": "PASS"},
        ],
        translate,
    )

    assert "repo-a, repo-b, repo-c, +1 more" in summary
    assert "All selected repositories passed" in summary
    assert "1 manual-review signal" in summary
    assert "1 fixture/documentation match kept non-blocking" in summary


def test_gui_state_collapsible_visibility_helpers_preserve_text_keys() -> None:
    setup_open = gui_state_helpers.setup_settings_visibility_state(visible=True, github_owner="Acme")
    assert setup_open.visible is True
    assert setup_open.toggle_text_key == "hide_settings"
    assert setup_open.hint_text_key == "setup_hint_open"
    assert setup_open.hint_kwargs == {}

    setup_remote = gui_state_helpers.setup_settings_visibility_state(visible=False, github_owner="Acme")
    assert setup_remote.visible is False
    assert setup_remote.toggle_text_key == "open_settings"
    assert setup_remote.hint_text_key == "setup_hint_remote"
    assert setup_remote.hint_kwargs == {"github_owner": "Acme"}

    setup_hidden = gui_state_helpers.setup_settings_visibility_state(visible=False, github_owner=None)
    assert setup_hidden.hint_text_key == "setup_hint_hidden"
    assert setup_hidden.hint_kwargs == {}

    repair_open = gui_state_helpers.repair_options_visibility_state(visible=True)
    assert repair_open.visible is True
    assert repair_open.toggle_text_key == "repair_advanced_toggle_hide"
    assert repair_open.hint_text_key == "repair_advanced_hint_visible"

    repair_hidden = gui_state_helpers.repair_options_visibility_state(visible=False)
    assert repair_hidden.visible is False
    assert repair_hidden.toggle_text_key == "repair_advanced_toggle_show"
    assert repair_hidden.hint_text_key == "repair_advanced_hint_hidden"

    identity_open = gui_state_helpers.advanced_identity_visibility_state(visible=True)
    assert identity_open.toggle_text_key == "hide_advanced_identity"
    assert identity_open.hint_text_key == "advanced_identity_visible"

    identity_hidden = gui_state_helpers.advanced_identity_visibility_state(visible=False)
    assert identity_hidden.toggle_text_key == "show_advanced_identity"
    assert identity_hidden.hint_text_key == "advanced_identity_hidden"


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
            "failures": ["secret-like patterns in tracked files"],
            "tracked_secret_low_confidence": ["settings.py:1:<redacted-secret>"],
            "tracked_secret_fixture_matches": ["tests/fixtures/example.env:1:<redacted-secret>"],
            "tracked_but_ignored": ["secret.txt"],
            "tracked_path_matches": ["<redacted-path>"],
            "history_path_matches": [],
            "secret_file_autopurge_candidates": [".env"],
            "secret_file_candidates": [".env"],
        }
    ]

    text = app._build_repair_confirmation_text(("repo-a",))

    assert "Repair will run with the following plan:" in text
    assert "Blocking categories: 1" in text
    assert "Manual-review signals: 1" in text
    assert "Fixture/documentation matches kept non-blocking: 1" in text
    assert "Continue?" in text
    assert "Se va a ejecutar" not in text


def test_gui_repair_confirmation_text_uses_selected_spanish_locale() -> None:
    class DummyVar:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

    app = object.__new__(rpg.GuiApp)
    app._gui_locale = rpg.GUI_LOCALE_ES_419
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
            "failures": ["secret-like patterns in tracked files"],
            "tracked_secret_low_confidence": ["settings.py:1:<redacted-secret>"],
            "tracked_secret_fixture_matches": ["tests/fixtures/example.env:1:<redacted-secret>"],
            "tracked_but_ignored": ["secret.txt"],
            "tracked_path_matches": ["<redacted-path>"],
            "history_path_matches": [],
            "secret_file_autopurge_candidates": [".env"],
            "secret_file_candidates": [".env"],
        }
    ]

    text = app._build_repair_confirmation_text(("repo-a",))

    assert "Reparar se va a ejecutar con este plan:" in text
    assert "Categorías bloqueantes: 1" in text
    assert "Señales de revisión manual: 1" in text
    assert "¿Continuar?" in text
    assert "Repair will run with the following plan:" not in text


def test_gui_locale_does_not_change_run_config_payload_mapping() -> None:
    class DummyVar:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

    def make_app(locale: str):
        app = object.__new__(rpg.GuiApp)
        app._gui_locale = locale
        app._gui_appearance = rpg.GUI_APPEARANCE_DEFAULT
        app.root_var = DummyVar("C:/repos")
        app.policy_var = DummyVar("docs/POLICY.md")
        app.report_dir_var = DummyVar("Audit_Results")
        app.report_json_var = DummyVar("")
        app.max_matches_var = DummyVar("50")
        app.github_owner_var = DummyVar("Acme")
        app.github_repo_filters_var = DummyVar("api")
        app.github_jobs_var = DummyVar("4")
        app.public_only_var = DummyVar(True)
        app.github_include_forks_var = DummyVar(False)
        app.github_fast_var = DummyVar(True)
        app.dry_run_var = DummyVar(True)
        app.low_confidence_blocking_var = DummyVar(False)
        app.audit_litellm_incident_var = DummyVar(False)
        app.audit_github_hardening_var = DummyVar(True)
        app.open_report_var = DummyVar(False)
        return app

    english_payload = make_app(rpg.GUI_LOCALE_DEFAULT)._current_gui_settings_payload(setup_completed=True)
    spanish_payload = make_app(rpg.GUI_LOCALE_ES_419)._current_gui_settings_payload(setup_completed=True)
    presentation_keys = {"gui_locale", "gui_appearance"}
    english_without_locale = {key: value for key, value in english_payload.items() if key not in presentation_keys}
    spanish_without_locale = {key: value for key, value in spanish_payload.items() if key not in presentation_keys}

    assert english_without_locale == spanish_without_locale
    assert english_payload["gui_locale"] == rpg.GUI_LOCALE_DEFAULT
    assert spanish_payload["gui_locale"] == rpg.GUI_LOCALE_ES_419
    assert english_payload["gui_appearance"] == rpg.GUI_APPEARANCE_DEFAULT
    assert spanish_payload["gui_appearance"] == rpg.GUI_APPEARANCE_DEFAULT


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
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TEST_TIMEOUT_SECONDS,
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
        "DOGFOODING",
        "confirmed leaks, intentional fixtures/examples",
        "05_DOGFOODING_AUDIT_ONLY.prompt.md",
        "Token-gated coverage",
        "secret scanning configuration",
        "immutable releases",
        "What It Does Not Try To Be",
        "Release Engineering Docs",
        "CHANGELOG",
        "python -m pip install .",
        "clear old `dist/`, `build/`, and `*.egg-info/` outputs",
        "1. install the base CLI",
        "Developed and maintained by **Okavango SAS**",
        "Original author",
        "Axel E. Sacca, CTO of Okavango SAS",
        "docs/ux-audit/after/audit-default-desktop-after.png",
        "Español (Latinoamérica)",
        "La CLI se mantiene en inglés para preservar compatibilidad con automatizaciones",
        'python -m pip install ".[gui]"',
        "## ⚡ 60-Second First Run",
        "want a coding agent to check whether another repo is safe to publish",
        "Do not apply fixes, rewrite history, push, or paste raw secrets/private paths/unredacted logs unless I explicitly approve.",
        "Typical first run for a coding agent/operator pair",
        "How to read the first result:",
        "`PASS`: no blocking publication issue was found.",
        "`REVIEW`: the repo may still be publishable",
        "`FAIL`: do not publish yet",
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
        "docs/DOGFOODING.md",
        "confirmed leak",
        "intentional fixture/example",
        "raw sensitive values",
        "Act as a release/security engineer.",
    ]

    for snippet in required_snippets:
        assert snippet in agents


def test_dogfooding_docs_preserve_audit_only_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    dogfooding = (root / "docs" / "DOGFOODING.md").read_text(encoding="utf-8")
    prompt = (root / "docs" / "prompts" / "05_DOGFOODING_AUDIT_ONLY.prompt.md").read_text(encoding="utf-8")

    dogfooding_required = [
        "The default posture is audit-only.",
        "repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes",
        "--audit-github-hardening",
        "Confirmed leak",
        "Intentional fixture/example",
        "Indeterminate/manual review",
        "Tooling/runtime issue",
        "do not paste raw secret values",
        "Audit_Results/<run_id>/report.json",
        "No destructive changes were applied.",
    ]
    prompt_required = [
        "sin activar fixes destructivos por default",
        "repo-privacy-guardian --root <root> --repos <repo> --dry-run --yes",
        "--audit-github-hardening",
        "confirmed leak",
        "fixture/documentacion intencional",
        "tooling/runtime issue",
        "No pegar secretos crudos",
        "No destructive changes applied.",
    ]

    for snippet in dogfooding_required:
        assert snippet in dogfooding
    for snippet in prompt_required:
        assert snippet in prompt
