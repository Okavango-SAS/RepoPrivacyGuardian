from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import Repo_Privacy_Guardian as rpg


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
        del artifacts, logger, results_dir, kwargs
        captured["config"] = config
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
        del artifacts, logger, results_dir, kwargs
        captured["config"] = config
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


def test_public_docs_describe_cli_first_release_contract() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.MD").read_text(encoding="utf-8")

    required_snippets = [
        "Windows CLI: supported",
        "Linux CLI: supported",
        "macOS CLI: best-effort",
        "GUI is optional",
        "CLI does not open a browser automatically",
        "Use `--gui` for the desktop interface",
        "`exfil_code_indicators` is intentionally manual-review only by default",
    ]

    for snippet in required_snippets:
        assert snippet in readme
