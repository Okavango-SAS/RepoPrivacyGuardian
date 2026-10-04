from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "import_order",
    [
        ["repo_privacy_guardian.redaction"],
        ["repo_privacy_guardian.tooling"],
        ["repo_privacy_guardian.redaction", "repo_privacy_guardian.tooling"],
        ["repo_privacy_guardian.tooling", "repo_privacy_guardian.redaction"],
        ["Repo_Privacy_Guardian", "repo_privacy_guardian.redaction", "repo_privacy_guardian.tooling"],
        ["repo_privacy_guardian.core", "repo_privacy_guardian.tooling", "repo_privacy_guardian.redaction"],
    ],
)
def test_helpers_import_independently_and_keep_facade_identity(import_order: list[str]) -> None:
    # In-process imports would conceal the original coordinator cycle. Block side
    # effects before loading the package in an isolated, fresh interpreter.
    child_code = r'''
import importlib
import json
import socket
import subprocess
import sys
import urllib.request

sys.path.insert(0, sys.argv[1])
operations = []

def forbidden_operation(*args, **kwargs):
    operations.append("external-operation")
    raise AssertionError("Imports must not probe, install tools, or access the network")

for module, attributes in (
    (subprocess, ("run", "Popen", "check_output")),
    (socket, ("create_connection",)),
    (urllib.request, ("urlopen",)),
):
    for attribute in attributes:
        setattr(module, attribute, forbidden_operation)

order = json.loads(sys.argv[2])
for name in order:
    importlib.import_module(name)
if order[0] in {"repo_privacy_guardian.redaction", "repo_privacy_guardian.tooling"}:
    assert "repo_privacy_guardian.core" not in sys.modules

facade = importlib.import_module("Repo_Privacy_Guardian")
core = importlib.import_module("repo_privacy_guardian.core")
redaction = importlib.import_module("repo_privacy_guardian.redaction")
patterns = importlib.import_module("repo_privacy_guardian.redaction_patterns")
tooling = importlib.import_module("repo_privacy_guardian.tooling")
common = importlib.import_module("repo_privacy_guardian.tooling_common")

assert facade is core
assert facade.ToolingCheck is tooling.ToolingCheck is common.ToolingCheck
assert facade.subprocess_stdin is tooling.subprocess_stdin is common.subprocess_stdin
assert facade.GUI_INSTALL_PACKAGES is tooling.GUI_INSTALL_PACKAGES is common.GUI_INSTALL_PACKAGES
assert facade.REMEDIATION_INSTALL_PACKAGES is tooling.REMEDIATION_INSTALL_PACKAGES is common.REMEDIATION_INSTALL_PACKAGES
for name in vars(patterns):
    if name.isupper():
        assert getattr(core, name) is getattr(patterns, name), name
for name in vars(redaction):
    if name.isupper():
        assert getattr(redaction, name) is getattr(patterns, name), name
assert facade.redact_sensitive_text is redaction.redact_sensitive_text
assert redaction.redact_sensitive_text("Contact: fixture@example.invalid") == "Contact: <redacted-email>"
assert common.subprocess_stdin() == subprocess.DEVNULL
assert common.subprocess_stdin("fixture input") == subprocess.PIPE
assert not operations
print(json.dumps({"imports": order, "external_operations": operations}))
'''
    completed = subprocess.run(
        [sys.executable, "-I", "-c", child_code, str(REPO_ROOT), json.dumps(import_order)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"imports": import_order, "external_operations": []}


def test_tooling_facade_overrides_still_control_authentication(monkeypatch) -> None:
    import Repo_Privacy_Guardian as facade

    monkeypatch.setattr(facade, "resolve_github_hardening_token", lambda env=None, runner=None: None)
    monkeypatch.setattr(facade, "probe_command_available", lambda *args, **kwargs: (True, None))
    monkeypatch.setattr(facade, "build_system_tool_install_command", lambda *args, **kwargs: None)
    monkeypatch.setattr(facade, "read_github_cli_token", lambda runner=None: ("fixture-auth-result", "ready"))

    check = facade.build_github_tooling_check()

    assert check.state == "ready"
    assert check.blocking is False
    assert "authenticated GitHub CLI" in check.detail


def test_standalone_tooling_uses_lower_level_auth_without_loading_core() -> None:
    child_code = r'''
import importlib
import subprocess
import sys

sys.path.insert(0, sys.argv[1])

def forbidden_probe(*args, **kwargs):
    raise AssertionError("Explicit environment auth must not invoke a command")

subprocess.run = forbidden_probe
tooling = importlib.import_module("repo_privacy_guardian.tooling")
assert tooling.resolve_github_hardening_token({"GH_TOKEN": "fixture-auth-result"}) == "fixture-auth-result"
assert "repo_privacy_guardian.core" not in sys.modules
'''
    completed = subprocess.run(
        [sys.executable, "-I", "-c", child_code, str(REPO_ROOT)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
