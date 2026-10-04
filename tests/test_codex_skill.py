from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "repo-privacy-guardian"
SKILL_SOURCE = REPO_ROOT / "codex" / "skills" / SKILL_NAME
RESOLVER = SKILL_SOURCE / "scripts" / "resolve_repo_privacy_guardian.ps1"
INSTALLER = REPO_ROOT / "scripts" / "dev" / "install_codex_skill.ps1"


def _require(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _same_path(actual: str | Path, expected: Path) -> bool:
    return Path(actual).resolve() == expected.resolve()


@pytest.fixture
def powershell() -> str:
    command = shutil.which("pwsh") or shutil.which("powershell")
    if not command:
        pytest.skip("PowerShell is unavailable")
    return command


def _environment(**overrides: str) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("REPO_PRIVACY_GUARDIAN_REPO", None)
    environment.update(overrides)
    return environment


def _run_script(
    powershell: str,
    script: Path,
    *arguments: str,
    cwd: Path,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    _require(script.is_file(), "Expected versioned PowerShell script is missing")
    return subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *arguments,
        ],
        cwd=cwd,
        env=environment if environment is not None else _environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=30,
        check=False,
    )


def _resolve(
    powershell: str,
    script: Path,
    start: Path,
    *,
    environment: dict[str, str] | None = None,
) -> dict:
    result = _run_script(
        powershell,
        script,
        "-StartPath",
        str(start),
        "-Json",
        cwd=start,
        environment=environment,
    )
    _require(result.returncode == 0, "Backend resolution failed; diagnostics were captured privately")
    try:
        resolution = json.loads(result.stdout)
    except (ValueError, TypeError):
        pytest.fail("Resolver did not return valid JSON", pytrace=False)
    _require(isinstance(resolution, dict), "Resolver JSON must be an object")
    return resolution


def _make_backend(root: Path, *, name: str = SKILL_NAME) -> Path:
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(f'[project]\nname = "{name}"\n', encoding="utf-8")
    (root / "Repo_Privacy_Guardian.py").write_text(
        'print("test backend executed")\n', encoding="utf-8"
    )
    package = root / "repo_privacy_guardian"
    package.mkdir()
    (package / "core.py").write_text("", encoding="utf-8")
    return root


def _copy_install_source(root: Path) -> Path:
    _make_backend(root)
    _require(SKILL_SOURCE.is_dir(), "Expected versioned skill source is missing")
    source = root / "codex" / "skills" / SKILL_NAME
    shutil.copytree(SKILL_SOURCE, source)
    installer = root / "scripts" / "dev" / INSTALLER.name
    installer.parent.mkdir(parents=True)
    shutil.copy2(INSTALLER, installer)
    return installer


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _require_repo_resolution(resolution: dict, expected: Path) -> None:
    _require(resolution.get("kind") == "repo", "Expected a repository backend")
    _require(_same_path(resolution["repoRoot"], expected), "Resolver chose the wrong repository")
    _require(_same_path(resolution["cwd"], expected), "Repository command has the wrong working directory")
    command = resolution.get("command")
    _require(isinstance(command, list) and len(command) >= 3, "Expected an argument-array command")
    _require(command[-2:] == ["-m", "Repo_Privacy_Guardian"], "Expected the maintained module entry point")
    _require(Path(command[0]).is_absolute(), "Backend interpreter must be an absolute executable path")


def test_resolver_prefers_nearest_checkout_over_environment(powershell: str, tmp_path: Path) -> None:
    outer = _make_backend(tmp_path / "workspace with spaces")
    nearest = _make_backend(outer / "nested checkout")
    start = nearest / "sub directory"
    start.mkdir()
    fallback = _make_backend(tmp_path / "environment backend")

    resolution = _resolve(
        powershell,
        RESOLVER,
        start,
        environment=_environment(REPO_PRIVACY_GUARDIAN_REPO=str(fallback)),
    )
    _require_repo_resolution(resolution, nearest)
    command_result = subprocess.run(
        resolution["command"],
        cwd=resolution["cwd"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    _require(command_result.returncode == 0, "Resolved command could not execute the selected backend")
    _require(command_result.stdout.strip() == "test backend executed", "Resolved command executed the wrong entry point")


def test_resolver_uses_environment_after_rejecting_unrelated_project(powershell: str, tmp_path: Path) -> None:
    unrelated = _make_backend(tmp_path / "unrelated workspace", name="another-project")
    expected = _make_backend(tmp_path / "configured backend")
    resolution = _resolve(
        powershell,
        RESOLVER,
        unrelated,
        environment=_environment(REPO_PRIVACY_GUARDIAN_REPO=str(expected)),
    )
    _require_repo_resolution(resolution, expected)


def test_installer_links_outside_sessions_and_force_refreshes(powershell: str, tmp_path: Path) -> None:
    codex_home = tmp_path / "Codex home with spaces"
    installed = codex_home / "skills" / SKILL_NAME
    result = _run_script(powershell, INSTALLER, "-CodexHome", str(codex_home), cwd=tmp_path)
    _require(result.returncode == 0, "Skill installation failed; diagnostics were captured privately")
    _require(installed.is_dir(), "Installer did not create the skill directory")
    metadata_path = installed / ".local" / "install.json"
    _require(metadata_path.is_file(), "Installer did not persist local repository linkage")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    _require(metadata.get("schemaVersion") == 1, "Unexpected install metadata schema")
    _require(_same_path(metadata["repoRoot"], REPO_ROOT), "Installation linked the wrong backend")
    _require(_same_path(metadata["skillSource"], SKILL_SOURCE), "Installation recorded the wrong source")
    _require(_same_path(metadata["installer"], INSTALLER), "Installation recorded the wrong installer")
    _require(bool(metadata.get("installedAt")), "Installation timestamp is missing")
    _require(not (SKILL_SOURCE / ".local").exists(), "Local machine metadata must not enter the versioned source")

    outside = tmp_path / "outside workspace"
    outside.mkdir()
    fallback = _make_backend(tmp_path / "alternative backend")
    resolution = _resolve(
        powershell,
        installed / "scripts" / RESOLVER.name,
        outside,
        environment=_environment(REPO_PRIVACY_GUARDIAN_REPO=str(fallback)),
    )
    _require_repo_resolution(resolution, REPO_ROOT)

    (installed / "SKILL.md").write_text("stale installed content", encoding="utf-8")
    (installed / "obsolete.txt").write_text("stale installed file", encoding="utf-8")
    sibling = codex_home / "skills" / "other-skill"
    sibling.mkdir()
    (sibling / "keep.txt").write_text("keep", encoding="utf-8")
    result = _run_script(
        powershell, INSTALLER, "-CodexHome", str(codex_home), "-Force", cwd=tmp_path
    )
    _require(result.returncode == 0, "Skill refresh failed; diagnostics were captured privately")
    source_snapshot = _snapshot(SKILL_SOURCE)
    installed_snapshot = {name: payload for name, payload in _snapshot(installed).items() if not name.startswith(".local/")}
    _require(installed_snapshot == source_snapshot, "Forced refresh did not reproduce the current source")
    _require((sibling / "keep.txt").read_text(encoding="utf-8") == "keep", "Refresh changed a neighboring skill")


def test_installer_uses_codex_home_environment(powershell: str, tmp_path: Path) -> None:
    codex_home = tmp_path / "environment Codex home"
    result = _run_script(
        powershell,
        INSTALLER,
        cwd=tmp_path,
        environment=_environment(CODEX_HOME=str(codex_home)),
    )
    _require(result.returncode == 0, "Environment-selected skill installation failed")
    _require(
        (codex_home / "skills" / SKILL_NAME / ".local" / "install.json").is_file(),
        "Installer ignored the configured Codex home",
    )


@pytest.mark.parametrize("existing", [False, True])
def test_installer_whatif_changes_nothing(powershell: str, tmp_path: Path, existing: bool) -> None:
    codex_home = tmp_path / "preview Codex home"
    if existing:
        installed = codex_home / "skills" / SKILL_NAME
        installed.mkdir(parents=True)
        (installed / "keep.txt").write_text("keep", encoding="utf-8")
    before = _snapshot(codex_home) if existing else {}
    result = _run_script(
        powershell, INSTALLER, "-CodexHome", str(codex_home), "-Force", "-WhatIf", cwd=tmp_path
    )
    _require(result.returncode == 0, "Installation preview failed; diagnostics were captured privately")
    if existing:
        _require(_snapshot(codex_home) == before, "WhatIf unexpectedly changed local files")
    else:
        _require(not codex_home.exists(), "WhatIf unexpectedly created local files")


def test_installer_refuses_existing_target_and_preserves_files(powershell: str, tmp_path: Path) -> None:
    codex_home = tmp_path / "existing Codex home"
    installed = codex_home / "skills" / SKILL_NAME
    installed.mkdir(parents=True)
    (installed / "user-owned.txt").write_text("must survive", encoding="utf-8")
    sibling = codex_home / "skills" / "unrelated.txt"
    sibling.write_text("must also survive", encoding="utf-8")
    before = _snapshot(codex_home)
    result = _run_script(powershell, INSTALLER, "-CodexHome", str(codex_home), cwd=tmp_path)
    _require(result.returncode != 0, "Existing target must require explicit Force")
    _require(_snapshot(codex_home) == before, "Rejected installation changed existing files")


def test_installer_rejects_source_destination_overlap(powershell: str, tmp_path: Path) -> None:
    fixture_root = tmp_path / "fixture checkout"
    installer = _copy_install_source(fixture_root)
    source = fixture_root / "codex" / "skills" / SKILL_NAME
    before = _snapshot(source)
    result = _run_script(
        powershell,
        installer,
        "-CodexHome",
        str(fixture_root / "codex"),
        "-Force",
        cwd=tmp_path,
    )
    _require(result.returncode != 0, "Installer must reject replacing its own source")
    _require(_snapshot(source) == before, "Rejected overlap installation changed source files")


def test_installer_rejects_linked_destination_parent(powershell: str, tmp_path: Path) -> None:
    codex_home = tmp_path / "linked Codex home"
    codex_home.mkdir()
    external = tmp_path / "external skills"
    external.mkdir()
    (external / "keep.txt").write_text("external data", encoding="utf-8")
    linked = codex_home / "skills"
    if os.name == "nt":
        junction_script = tmp_path / "make_test_junction.ps1"
        junction_script.write_text(
            "param([string]$Link, [string]$Target)\n"
            '$ErrorActionPreference = "Stop"\n'
            "New-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n",
            encoding="utf-8",
        )
        result = _run_script(
            powershell, junction_script, "-Link", str(linked), "-Target", str(external), cwd=tmp_path
        )
        _require(result.returncode == 0, "Could not create the isolated test junction")
    else:
        linked.symlink_to(external, target_is_directory=True)
    before = _snapshot(external)
    result = _run_script(
        powershell, INSTALLER, "-CodexHome", str(codex_home), "-Force", cwd=tmp_path
    )
    _require(result.returncode != 0, "Installer must reject linked destination components")
    _require(_snapshot(external) == before, "Rejected installation changed files beyond the destination")


@pytest.mark.parametrize("metadata_contents", ["not valid JSON", '{"schemaVersion": 1, "repoRoot": "missing-backend"}'])
def test_resolver_recovers_from_invalid_local_metadata(
    powershell: str, tmp_path: Path, metadata_contents: str
) -> None:
    installed = tmp_path / "skills" / SKILL_NAME
    shutil.copytree(SKILL_SOURCE, installed)
    local = installed / ".local"
    local.mkdir()
    (local / "install.json").write_text(metadata_contents, encoding="utf-8")
    start = tmp_path / "outside"
    start.mkdir()
    expected = _make_backend(tmp_path / "valid configured backend")
    resolution = _resolve(
        powershell,
        installed / "scripts" / RESOLVER.name,
        start,
        environment=_environment(REPO_PRIVACY_GUARDIAN_REPO=str(expected)),
    )
    _require_repo_resolution(resolution, expected)


def test_resolver_path_fallback_returns_an_application(powershell: str, tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cli = bin_dir / (f"{SKILL_NAME}.cmd" if os.name == "nt" else SKILL_NAME)
    cli.write_text("@echo off\n" if os.name == "nt" else "#!/bin/sh\nexit 0\n", encoding="utf-8")
    if os.name != "nt":
        cli.chmod(0o755)
    start = tmp_path / "outside"
    start.mkdir()
    resolution = _resolve(
        powershell, RESOLVER, start, environment=_environment(PATH=str(bin_dir))
    )
    _require(resolution.get("kind") == "path", "Expected the installed CLI fallback")
    _require(resolution.get("repoRoot") is None, "PATH backend should not claim a source checkout")
    command = resolution.get("command")
    _require(isinstance(command, list) and len(command) == 1, "PATH command must be a single executable argument")
    _require(_same_path(command[0], cli), "PATH fallback did not use the discovered application")


def test_resolver_fails_when_no_backend_is_available(powershell: str, tmp_path: Path) -> None:
    result = _run_script(
        powershell,
        RESOLVER,
        "-StartPath",
        str(tmp_path),
        "-Json",
        cwd=tmp_path,
        environment=_environment(PATH=""),
    )
    _require(result.returncode != 0, "Missing backend must fail instead of inventing a command")
