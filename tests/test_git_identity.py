import pytest
import subprocess
from unittest import mock
from pathlib import Path

from Repo_Privacy_Guardian import (
    validate_git_identity_inputs,
    apply_git_identity_config,
    read_git_identity_config,
    open_github_email_settings,
    resolve_identity_repo_path,
    GuiApp,
)

def test_validate_git_identity_inputs():
    assert validate_git_identity_inputs("John Doe", "12345+john@users.noreply.github.com") == []
    assert validate_git_identity_inputs("", "12345+john@users.noreply.github.com") == ["git user.name is required."]
    assert validate_git_identity_inputs("John Doe", "") == ["git user.email is required."]
    assert validate_git_identity_inputs("", "") == ["git user.name is required.", "git user.email is required."]
    assert validate_git_identity_inputs("John", "invalid-email") == ["git user.email must be a valid email address."]

@mock.patch("subprocess.run")
def test_apply_git_identity_global(mock_run):
    mock_run.return_value = mock.Mock(returncode=0)

    success, msg = apply_git_identity_config("global", "Alice", "12345+alice@users.noreply.github.com")
    assert success is True
    assert "Applied GLOBAL git identity" in msg
    mock_run.assert_any_call(
        ["git", "config", "--global", "user.name", "Alice"],
        cwd=None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=300,
    )
    mock_run.assert_any_call(
        ["git", "config", "--global", "user.email", "12345+alice@users.noreply.github.com"],
        cwd=None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=300,
    )

@mock.patch("subprocess.run")
def test_apply_git_identity_global_fail(mock_run):
    fail_mock = mock.Mock(returncode=1, stderr="Permission denied")
    mock_run.side_effect = [mock.Mock(returncode=0), fail_mock]

    success, msg = apply_git_identity_config("global", "Alice", "12345+alice@users.noreply.github.com")
    assert success is False
    assert "Failed to set user.email (global):" in msg

@mock.patch("webbrowser.open")
def test_open_github_email_settings(mock_open):
    mock_open.return_value = True
    success, msg = open_github_email_settings()
    assert success is True
    assert "Opened https://github.com/settings/emails" in msg

@mock.patch("webbrowser.open")
def test_open_github_email_settings_fail(mock_open):
    mock_open.side_effect = Exception("Browser not found")
    success, msg = open_github_email_settings()
    assert success is False
    assert "Browser not found" in msg

@mock.patch("Repo_Privacy_Guardian.GuiApp._handle_identity_validation")
def test_gui_apply_git_identity_local_validation_error(mock_validate):
    mock_validate.return_value = False
    app = object.__new__(GuiApp)
    app._read_identity_inputs = lambda: ("", "test@example.com")

    app.apply_git_identity_local_clicked()

    mock_validate.assert_called_once()
