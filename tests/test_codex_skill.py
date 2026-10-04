from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import venv
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


_POWERSHELLS = [command for name in ("pwsh", "powershell") if (command := shutil.which(name))]


@pytest.fixture(params=_POWERSHELLS or [None], ids=lambda command: Path(command).stem if command else "unavailable")
def powershell(request: pytest.FixtureRequest) -> str:
    if not request.param:
        pytest.skip("PowerShell is unavailable")
    return str(request.param)


@pytest.fixture
def isolated_path():
    # Resolver fallback scenarios must not inherit the real checkout under --basetemp.
    with tempfile.TemporaryDirectory(prefix="rpg-codex-skill-") as temporary:
        root = Path(temporary).resolve()
        for ancestor in (root, *root.parents):
            _require(
                not all((ancestor / relative).is_file() for relative in (
                    "Repo_Privacy_Guardian.py", "repo_privacy_guardian/core.py", "pyproject.toml"
                )),
                "Skill fixtures require an external temporary root without a checkout ancestor",
            )
        yield root


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
    _require(not result.stderr.strip(), "Successful resolution leaked candidate diagnostics")
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


def test_resolver_prefers_nearest_checkout_over_environment(powershell: str, isolated_path: Path) -> None:
    outer = _make_backend(isolated_path / "workspace with spaces")
    nearest = _make_backend(outer / "nested checkout")
    start = nearest / "sub directory"
    start.mkdir()
    fallback = _make_backend(isolated_path / "environment backend")

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


def test_resolver_uses_environment_after_rejecting_unrelated_project(powershell: str, isolated_path: Path) -> None:
    unrelated = _make_backend(isolated_path / "unrelated workspace", name="another-project")
    expected = _make_backend(isolated_path / "configured backend")
    resolution = _resolve(
        powershell,
        RESOLVER,
        unrelated,
        environment=_environment(REPO_PRIVACY_GUARDIAN_REPO=str(expected)),
    )
    _require_repo_resolution(resolution, expected)


def test_installer_links_outside_sessions_and_force_refreshes(powershell: str, isolated_path: Path) -> None:
    codex_home = isolated_path / "Codex home with spaces"
    installed = codex_home / "skills" / SKILL_NAME
    result = _run_script(powershell, INSTALLER, "-CodexHome", str(codex_home), cwd=isolated_path)
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

    outside = isolated_path / "outside workspace"
    outside.mkdir()
    fallback = _make_backend(isolated_path / "alternative backend")
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
        powershell, INSTALLER, "-CodexHome", str(codex_home), "-Force", cwd=isolated_path
    )
    _require(result.returncode == 0, "Skill refresh failed; diagnostics were captured privately")
    source_snapshot = _snapshot(SKILL_SOURCE)
    installed_snapshot = {name: payload for name, payload in _snapshot(installed).items() if not name.startswith(".local/")}
    _require(installed_snapshot == source_snapshot, "Forced refresh did not reproduce the current source")
    _require((sibling / "keep.txt").read_text(encoding="utf-8") == "keep", "Refresh changed a neighboring skill")


def test_installer_uses_codex_home_environment(powershell: str, isolated_path: Path) -> None:
    codex_home = isolated_path / "environment Codex home"
    result = _run_script(
        powershell,
        INSTALLER,
        cwd=isolated_path,
        environment=_environment(CODEX_HOME=str(codex_home)),
    )
    _require(result.returncode == 0, "Environment-selected skill installation failed")
    _require(
        (codex_home / "skills" / SKILL_NAME / ".local" / "install.json").is_file(),
        "Installer ignored the configured Codex home",
    )


@pytest.mark.parametrize("existing", [False, True])
def test_installer_whatif_changes_nothing(powershell: str, isolated_path: Path, existing: bool) -> None:
    codex_home = isolated_path / "preview Codex home"
    if existing:
        installed = codex_home / "skills" / SKILL_NAME
        installed.mkdir(parents=True)
        (installed / "keep.txt").write_text("keep", encoding="utf-8")
    before = _snapshot(codex_home) if existing else {}
    result = _run_script(
        powershell, INSTALLER, "-CodexHome", str(codex_home), "-Force", "-WhatIf", cwd=isolated_path
    )
    _require(result.returncode == 0, "Installation preview failed; diagnostics were captured privately")
    if existing:
        _require(_snapshot(codex_home) == before, "WhatIf unexpectedly changed local files")
    else:
        _require(not codex_home.exists(), "WhatIf unexpectedly created local files")


def test_installer_refuses_existing_target_and_preserves_files(powershell: str, isolated_path: Path) -> None:
    codex_home = isolated_path / "existing Codex home"
    installed = codex_home / "skills" / SKILL_NAME
    installed.mkdir(parents=True)
    (installed / "user-owned.txt").write_text("must survive", encoding="utf-8")
    sibling = codex_home / "skills" / "unrelated.txt"
    sibling.write_text("must also survive", encoding="utf-8")
    before = _snapshot(codex_home)
    result = _run_script(powershell, INSTALLER, "-CodexHome", str(codex_home), cwd=isolated_path)
    _require(result.returncode != 0, "Existing target must require explicit Force")
    _require(_snapshot(codex_home) == before, "Rejected installation changed existing files")


def test_installer_rejects_source_destination_overlap(powershell: str, isolated_path: Path) -> None:
    fixture_root = isolated_path / "fixture checkout"
    installer = _copy_install_source(fixture_root)
    source = fixture_root / "codex" / "skills" / SKILL_NAME
    before = _snapshot(source)
    result = _run_script(
        powershell,
        installer,
        "-CodexHome",
        str(fixture_root / "codex"),
        "-Force",
        cwd=isolated_path,
    )
    _require(result.returncode != 0, "Installer must reject replacing its own source")
    _require(_snapshot(source) == before, "Rejected overlap installation changed source files")


def test_installer_rejects_linked_destination_parent(powershell: str, isolated_path: Path) -> None:
    codex_home = isolated_path / "linked Codex home"
    codex_home.mkdir()
    external = isolated_path / "external skills"
    external.mkdir()
    (external / "keep.txt").write_text("external data", encoding="utf-8")
    linked = codex_home / "skills"
    if os.name == "nt":
        junction_script = isolated_path / "make_test_junction.ps1"
        junction_script.write_text(
            "param([string]$Link, [string]$Target)\n"
            '$ErrorActionPreference = "Stop"\n'
            "New-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n",
            encoding="utf-8",
        )
        result = _run_script(
            powershell, junction_script, "-Link", str(linked), "-Target", str(external), cwd=isolated_path
        )
        _require(result.returncode == 0, "Could not create the isolated test junction")
    else:
        linked.symlink_to(external, target_is_directory=True)
    before = _snapshot(external)
    result = _run_script(
        powershell, INSTALLER, "-CodexHome", str(codex_home), "-Force", cwd=isolated_path
    )
    _require(result.returncode != 0, "Installer must reject linked destination components")
    _require(_snapshot(external) == before, "Rejected installation changed files beyond the destination")


@pytest.mark.parametrize("metadata_contents", ["not valid JSON", '{"schemaVersion": 1, "repoRoot": "missing-backend"}'])
def test_resolver_recovers_from_invalid_local_metadata(
    powershell: str, isolated_path: Path, metadata_contents: str
) -> None:
    installed = isolated_path / "skills" / SKILL_NAME
    shutil.copytree(SKILL_SOURCE, installed)
    local = installed / ".local"
    local.mkdir()
    (local / "install.json").write_text(metadata_contents, encoding="utf-8")
    start = isolated_path / "outside"
    start.mkdir()
    expected = _make_backend(isolated_path / "valid configured backend")
    resolution = _resolve(
        powershell,
        installed / "scripts" / RESOLVER.name,
        start,
        environment=_environment(REPO_PRIVACY_GUARDIAN_REPO=str(expected)),
    )
    _require_repo_resolution(resolution, expected)


def test_resolver_path_fallback_returns_an_application(powershell: str, isolated_path: Path) -> None:
    bin_dir = isolated_path / "bin"
    bin_dir.mkdir()
    cli = bin_dir / (f"{SKILL_NAME}.cmd" if os.name == "nt" else SKILL_NAME)
    cli.write_text("@echo off\n" if os.name == "nt" else "#!/bin/sh\nexit 0\n", encoding="utf-8")
    if os.name != "nt":
        cli.chmod(0o755)
    start = isolated_path / "outside"
    start.mkdir()
    resolution = _resolve(
        powershell, RESOLVER, start, environment=_environment(PATH=str(bin_dir))
    )
    _require(resolution.get("kind") == "path", "Expected the installed CLI fallback")
    _require(resolution.get("repoRoot") is None, "PATH backend should not claim a source checkout")
    command = resolution.get("command")
    _require(isinstance(command, list) and len(command) == 1, "PATH command must be a single executable argument")
    _require(_same_path(command[0], cli), "PATH fallback did not use the discovered application")


def test_resolver_fails_when_no_backend_is_available(powershell: str, isolated_path: Path) -> None:
    result = _run_script(
        powershell,
        RESOLVER,
        "-StartPath",
        str(isolated_path),
        "-Json",
        cwd=isolated_path,
        environment=_environment(PATH=""),
    )
    _require(result.returncode != 0, "Missing backend must fail instead of inventing a command")


def test_resolver_skips_unusable_local_python(powershell: str, isolated_path: Path) -> None:
    backend = _make_backend(isolated_path / "backend")
    local = backend / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    local.parent.mkdir(parents=True)
    local.write_text("unusable interpreter", encoding="utf-8")
    resolution = _resolve(powershell, RESOLVER, backend)
    _require_repo_resolution(resolution, backend)
    _require(not _same_path(resolution["command"][0], local), "An unusable local interpreter shadowed PATH")


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher fixtures")
def test_resolver_probes_python_version_before_next_launcher(powershell: str, isolated_path: Path) -> None:
    backend = _make_backend(isolated_path / "backend")
    bin_dir = isolated_path / "launcher directory"
    bin_dir.mkdir()
    # The first launcher executes the same probe with a controlled legacy version.
    (bin_dir / "python.cmd").write_text(
        f'@echo off\necho synthetic-probe-output\necho synthetic-probe-diagnostic 1>&2\n'
        f'"{sys.executable}" -c "import sys; sys.version_info=(3, 9); exec(sys.argv[1])" "%~2"\n',
        encoding="utf-8",
    )
    supported = bin_dir / "py.cmd"
    supported.write_text(f'@echo off\n"{sys.executable}" %2 "%~3"\n', encoding="utf-8")
    resolution = _resolve(powershell, RESOLVER, backend, environment=_environment(PATH=str(bin_dir)))
    _require_repo_resolution(resolution, backend)
    _require(_same_path(resolution["command"][0], supported), "A legacy Python shadowed the supported launcher")
    _require(resolution["command"][1] == "-3", "The py launcher prefix was lost")


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher lifecycle fixture")
def test_resolver_bounds_hanging_probe_and_stops_its_child(powershell: str, isolated_path: Path) -> None:
    backend = _make_backend(isolated_path / "backend")
    bin_dir = isolated_path / "launcher directory"
    bin_dir.mkdir()
    marker = isolated_path / "probe-child-pid.txt"
    (bin_dir / "python.cmd").write_text(
        f'@echo off\n"{sys.executable}" -c "import os,time,pathlib; pathlib.Path(os.environ[\'RPG_TEST_PID\']).write_text(str(os.getpid())); time.sleep(30)"\n',
        encoding="utf-8",
    )
    supported = bin_dir / "python3.cmd"
    supported.write_text(f'@echo off\n"{sys.executable}" %*\n', encoding="utf-8")
    started = time.monotonic()
    resolution = _resolve(
        powershell, RESOLVER, backend,
        environment=_environment(PATH=str(bin_dir), RPG_TEST_PID=str(marker)),
    )
    _require_repo_resolution(resolution, backend)
    _require(_same_path(resolution["command"][0], supported), "A hanging launcher prevented fallback")
    _require(time.monotonic() - started < 12, "Python readiness probing exceeded its bounded cleanup window")
    _require(marker.is_file(), "The controlled hanging probe did not start")
    import ctypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, int(marker.read_text(encoding="utf-8")))
    if handle:
        try:
            exit_code = ctypes.c_ulong()
            _require(bool(kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code))), "Could not inspect probe cleanup")
            _require(exit_code.value != 259, "A timed-out Python probe left its child running")
        finally:
            kernel.CloseHandle(handle)


@pytest.mark.skipif(os.name != "nt", reason="Windows local interpreter fixture")
def test_resolver_prefers_supported_local_python(powershell: str, isolated_path: Path) -> None:
    backend = _make_backend(isolated_path / "backend")
    local = backend / ".venv" / "Scripts" / "python.exe"
    venv.EnvBuilder(with_pip=False).create(backend / ".venv")
    resolution = _resolve(powershell, RESOLVER, backend)
    _require_repo_resolution(resolution, backend)
    _require(_same_path(resolution["command"][0], local), "A supported local environment lost precedence")


def test_resolver_rejects_checkout_without_supported_python(powershell: str, isolated_path: Path) -> None:
    backend = _make_backend(isolated_path / "backend")
    result = _run_script(
        powershell, RESOLVER, "-StartPath", str(backend), "-Json", cwd=backend,
        environment=_environment(PATH=""),
    )
    _require(result.returncode != 0, "A checkout without supported Python must report a setup failure")
    _require(not result.stdout.strip(), "Failure diagnostics entered the JSON output channel")


@pytest.mark.parametrize("source", ["start", "environment"])
def test_resolver_relative_paths_follow_powershell_location(
    powershell: str, isolated_path: Path, source: str
) -> None:
    initial = isolated_path / "initial shell directory"
    initial.mkdir()
    location = isolated_path / "new shell directory"
    location.mkdir()
    backend = _make_backend(location / "backend with spaces")
    outside = location / "outside"
    outside.mkdir()
    driver = initial / "resolve_after_location.ps1"
    driver.write_text(
        "param([string]$Location, [string]$Resolver, [string]$Source)\n"
        "Set-Location -LiteralPath $Location\n"
        "if ($Source -eq 'environment') {\n"
        "  $env:REPO_PRIVACY_GUARDIAN_REPO = './backend with spaces'\n"
        "  & $Resolver -StartPath './outside' -Json\n"
        "} else { & $Resolver -StartPath './backend with spaces' -Json }\n",
        encoding="utf-8",
    )
    result = _run_script(
        powershell, driver, "-Location", str(location), "-Resolver", str(RESOLVER),
        "-Source", source, cwd=initial,
    )
    _require(result.returncode == 0, "Relative resolver inputs failed after Set-Location")
    _require_repo_resolution(json.loads(result.stdout), backend)


def test_installer_relative_home_follows_powershell_location(powershell: str, isolated_path: Path) -> None:
    initial = isolated_path / "initial shell directory"
    initial.mkdir()
    location = isolated_path / "new shell directory"
    location.mkdir()
    driver = initial / "install_after_location.ps1"
    driver.write_text(
        "param([string]$Location, [string]$Installer)\n"
        "Set-Location -LiteralPath $Location\n"
        "& $Installer -CodexHome './Codex home with spaces'\n",
        encoding="utf-8",
    )
    result = _run_script(
        powershell, driver, "-Location", str(location), "-Installer", str(INSTALLER), cwd=initial,
    )
    _require(result.returncode == 0, "Relative Codex home failed after Set-Location")
    _require(
        (location / "Codex home with spaces" / "skills" / SKILL_NAME / ".local" / "install.json").is_file(),
        "Installer used the process directory instead of PowerShell's location",
    )
    _require(not (initial / "Codex home with spaces").exists(), "Installer changed the initial shell directory")


@pytest.mark.parametrize("script, argument", [(RESOLVER, "-StartPath"), (INSTALLER, "-CodexHome")])
def test_skill_paths_reject_non_filesystem_provider(
    powershell: str, isolated_path: Path, script: Path, argument: str
) -> None:
    result = _run_script(powershell, script, argument, "Env:", cwd=isolated_path)
    _require(result.returncode != 0, "Non-filesystem paths must be rejected")
    _require(not (isolated_path / "Env:").exists(), "Provider rejection created a filesystem destination")


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", ["copy", "metadata", "validation"])
def test_installer_failure_preserves_previous_skill(
    powershell: str, isolated_path: Path, existing: bool, failure: str
) -> None:
    home = isolated_path / "Codex home"
    target = home / "skills" / SKILL_NAME
    sibling = home / "skills" / "other-skill"
    sibling.mkdir(parents=True)
    (sibling / "keep.txt").write_text("neighbor survives", encoding="utf-8")
    if existing:
        target.mkdir()
        (target / "SKILL.md").write_text("previous working skill", encoding="utf-8")
        (target / "custom.json").write_text('{"custom": true}', encoding="utf-8")
    before = _snapshot(home)
    driver = isolated_path / "inject_install_failure.ps1"
    driver.write_text(
        "param([string]$Installer, [string]$CodexHome, [string]$Failure)\n"
        "$ErrorActionPreference = 'Stop'\n"
        "function Copy-Item {\n"
        "  param([string]$LiteralPath, [string]$Destination)\n"
        "  if ($Failure -eq 'copy') { throw 'Controlled copy failure' }\n"
        "  Microsoft.PowerShell.Management\\Copy-Item @PSBoundParameters\n"
        "  if ($Failure -eq 'validation') { [IO.File]::WriteAllText($Destination, 'incomplete copy') }\n"
        "}\n"
        "function New-Item {\n"
        "  param([string]$ItemType, [string]$Path, [switch]$Force)\n"
        "  $item = Microsoft.PowerShell.Management\\New-Item @PSBoundParameters\n"
        "  if ($Failure -eq 'metadata' -and (Split-Path -Leaf $Path) -eq '.local') {\n"
        "    Microsoft.PowerShell.Management\\New-Item -ItemType Directory -Path (Join-Path $Path 'install.json') | Out-Null\n"
        "  }\n"
        "  return $item\n"
        "}\n"
        "& $Installer -CodexHome $CodexHome -Force\n",
        encoding="utf-8",
    )
    result = _run_script(
        powershell, driver, "-Installer", str(INSTALLER), "-CodexHome", str(home),
        "-Failure", failure, cwd=isolated_path,
    )
    _require(result.returncode != 0, "Controlled installation failure was ignored")
    _require(_snapshot(home) == before, "Failed installation changed the working skill or neighbor")
    _require(
        sorted(path.name for path in (home / "skills").iterdir()) ==
        sorted(["other-skill", *([SKILL_NAME] if existing else [])]),
        "Failed installation left staging, backup, or partial destination files",
    )


def test_installer_and_metadata_resolver_preserve_unicode_checkout(
    powershell: str, isolated_path: Path
) -> None:
    backend = isolated_path / "checkout caf\u00e9 \u03bb"
    installer = _copy_install_source(backend)
    home = isolated_path / "Codex home"
    result = _run_script(powershell, installer, "-CodexHome", str(home), cwd=isolated_path)
    _require(result.returncode == 0, "Installation could not validate its UTF-8 checkout metadata")
    installed = home / "skills" / SKILL_NAME
    metadata = json.loads((installed / ".local" / "install.json").read_text(encoding="utf-8"))
    _require(_same_path(metadata["repoRoot"], backend), "Installed metadata changed a Unicode checkout path")
    outside = isolated_path / "outside"
    outside.mkdir()
    resolution = _resolve(powershell, installed / "scripts" / RESOLVER.name, outside)
    _require_repo_resolution(resolution, backend)
    _require(resolution["source"] == "installed-metadata", "Unicode metadata did not resolve its linked checkout")


def test_installer_keeps_concurrent_destination_and_previous_backup(
    powershell: str, isolated_path: Path
) -> None:
    home = isolated_path / "Codex home"
    target = home / "skills" / SKILL_NAME
    target.mkdir(parents=True)
    (target / "SKILL.md").write_text("previous working skill", encoding="utf-8")
    (target / "custom.json").write_text('{"custom": true}', encoding="utf-8")
    previous = _snapshot(target)
    driver = isolated_path / "recreate_destination_during_install.ps1"
    driver.write_text(
        "param([string]$Installer, [string]$CodexHome)\n"
        "$ErrorActionPreference = 'Stop'\n"
        "function Rename-Item {\n"
        "  param([string]$LiteralPath, [string]$NewName)\n"
        "  Microsoft.PowerShell.Management\\Rename-Item @PSBoundParameters\n"
        "  Microsoft.PowerShell.Management\\New-Item -ItemType Directory -Path $LiteralPath | Out-Null\n"
        "  [IO.File]::WriteAllText((Join-Path $LiteralPath 'concurrent.txt'), 'concurrent owner data')\n"
        "}\n"
        "& $Installer -CodexHome $CodexHome -Force\n",
        encoding="utf-8",
    )
    result = _run_script(
        powershell, driver, "-Installer", str(INSTALLER), "-CodexHome", str(home), cwd=isolated_path,
    )
    _require(result.returncode != 0, "A concurrent destination must cause replacement to fail")
    _require(
        _snapshot(target) == {"concurrent.txt": b"concurrent owner data"},
        "Installer changed or nested the staged skill inside a concurrently created destination",
    )
    backups = list((home / "skills").glob(f".{SKILL_NAME}.backup-*"))
    _require(len(backups) == 1, "The previous skill backup was not retained for reviewed recovery")
    _require(_snapshot(backups[0]) == previous, "A concurrent replacement changed the previous skill backup")
    _require(
        not list((home / "skills").glob(f".{SKILL_NAME}.stage-*")),
        "Concurrent replacement left staged skill contents behind",
    )


def test_installer_restores_backup_after_native_rename_failure(
    powershell: str, isolated_path: Path
) -> None:
    home = isolated_path / "Codex home"
    target = home / "skills" / SKILL_NAME
    target.mkdir(parents=True)
    (target / "SKILL.md").write_text("previous working skill", encoding="utf-8")
    (target / "custom.json").write_text('{"custom": true}', encoding="utf-8")
    previous = _snapshot(home)
    driver = isolated_path / "remove_staged_source_before_swap.ps1"
    driver.write_text(
        "param([string]$Installer, [string]$CodexHome)\n"
        "$ErrorActionPreference = 'Stop'\n"
        "function Rename-Item {\n"
        "  param([string]$LiteralPath, [string]$NewName)\n"
        "  Microsoft.PowerShell.Management\\Rename-Item @PSBoundParameters\n"
        "  $parent = Split-Path -Parent $LiteralPath\n"
        "  $staged = @(Get-ChildItem -LiteralPath $parent -Force -Directory | Where-Object Name -Like '.repo-privacy-guardian.stage-*')\n"
        "  if ($staged.Count -ne 1) { throw 'Controlled fixture needs one staged directory' }\n"
        "  $isolatedRoot = [IO.Path]::GetFullPath((Split-Path -Parent $CodexHome))\n"
        "  $heldStage = Join-Path $isolatedRoot 'test-held-stage'\n"
        "  if (-not $staged[0].FullName.StartsWith($isolatedRoot + [IO.Path]::DirectorySeparatorChar)) {\n"
        "    throw 'The controlled move must stay within its isolated test root'\n"
        "  }\n"
        "  [IO.Directory]::Move($staged[0].FullName, $heldStage)\n"
        "}\n"
        "& $Installer -CodexHome $CodexHome -Force\n",
        encoding="utf-8",
    )
    result = _run_script(
        powershell, driver, "-Installer", str(INSTALLER), "-CodexHome", str(home), cwd=isolated_path,
    )
    _require(result.returncode != 0, "A missing staged source must cause the native replacement to fail")
    _require(_snapshot(home) == previous, "Native replacement failure did not restore the byte-identical prior skill")
    _require(
        sorted(path.name for path in (home / "skills").iterdir()) == [SKILL_NAME],
        "Restored installation left an unexpected staging or backup directory",
    )


def test_first_install_refuses_destination_created_during_preparation(
    powershell: str, isolated_path: Path
) -> None:
    home = isolated_path / "Codex home"
    target = home / "skills" / SKILL_NAME
    driver = isolated_path / "create_destination_during_preparation.ps1"
    driver.write_text(
        "param([string]$Installer, [string]$CodexHome)\n"
        "$ErrorActionPreference = 'Stop'\n"
        "function New-Item {\n"
        "  param([string]$ItemType, [string]$Path, [switch]$Force)\n"
        "  $item = Microsoft.PowerShell.Management\\New-Item @PSBoundParameters\n"
        "  if ((Split-Path -Leaf $Path) -eq '.local') {\n"
        "    $concurrentTarget = Join-Path $CodexHome 'skills/repo-privacy-guardian'\n"
        "    Microsoft.PowerShell.Management\\New-Item -ItemType Directory -Path $concurrentTarget | Out-Null\n"
        "    [IO.File]::WriteAllText((Join-Path $concurrentTarget 'concurrent.txt'), 'concurrent owner data')\n"
        "  }\n"
        "  return $item\n"
        "}\n"
        "& $Installer -CodexHome $CodexHome\n",
        encoding="utf-8",
    )
    result = _run_script(
        powershell, driver, "-Installer", str(INSTALLER), "-CodexHome", str(home), cwd=isolated_path,
    )
    _require(result.returncode != 0, "An unexpected target must require reviewed Force authorization")
    _require(
        _snapshot(target) == {"concurrent.txt": b"concurrent owner data"},
        "First installation replaced an unexpected concurrent destination",
    )
    _require(
        sorted(path.name for path in (home / "skills").iterdir()) == [SKILL_NAME],
        "Rejected first installation left staging or backup directories",
    )
