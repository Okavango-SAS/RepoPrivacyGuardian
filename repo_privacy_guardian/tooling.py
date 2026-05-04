"""Tooling preflight and optional installer helpers."""

from __future__ import annotations

# ruff: noqa: F403,F405
from repo_privacy_guardian.core import *


def _missing_executable_message(executable: str) -> str:
    binary = Path(str(executable)).name.lower()
    if binary == "git":
        return "Git executable not found. Install Git and ensure it is available on PATH."
    return f"Required executable not found: {executable}"


def probe_git_available(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[bool, str | None]:
    try:
        proc = runner(
            ["git", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
            timeout=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return False, _missing_executable_message("git")
    except subprocess.TimeoutExpired:
        return False, "Git executable probe timed out."
    except Exception as exc:
        return False, f"Unable to execute git --version: {exc}"

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown git startup failure"
        return False, f"Git executable is not usable: {detail}"

    return True, None


def probe_command_available(
    executable: str,
    version_args: tuple[str, ...] = ("--version",),
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[bool, str | None]:
    try:
        proc = runner(
            [executable, *version_args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
            timeout=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return False, _missing_executable_message(executable)
    except subprocess.TimeoutExpired:
        return False, f"{executable} probe timed out."
    except Exception as exc:
        return False, f"Unable to execute {executable} {' '.join(version_args)}: {exc}"

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown startup failure"
        return False, f"{executable} is not usable: {detail}"
    return True, None


def probe_python_module_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def probe_git_filter_repo_available() -> bool:
    return probe_python_module_available("git_filter_repo")


def resolve_windows_powershell(
    which: Callable[[str], str | None] = shutil.which,
) -> str | None:
    for candidate in ("powershell", "pwsh"):
        resolved = which(candidate)
        if resolved:
            return candidate
    return None


def probe_windows_winget_bootstrap_available(
    *,
    platform_name: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[bool, str | None]:
    current_platform = platform_name or sys.platform
    if not current_platform.startswith("win"):
        return False, "winget bootstrap is only supported on Windows."

    shell = resolve_windows_powershell(which=which)
    if not shell:
        return False, "PowerShell is not available, so App Installer bootstrap cannot run automatically."

    try:
        proc = runner(
            [shell, "-NoProfile", "-Command", "Get-Command Add-AppxPackage | Out-Null"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
        )
    except Exception as exc:
        return False, f"Unable to probe Add-AppxPackage support: {exc}"

    if proc.returncode == 0:
        return True, None

    detail = proc.stderr.strip() or proc.stdout.strip() or "Add-AppxPackage support is unavailable."
    return False, detail


def build_winget_bootstrap_command(
    *,
    platform_name: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str] | None:
    current_platform = platform_name or sys.platform
    if not current_platform.startswith("win"):
        return None

    shell = resolve_windows_powershell(which=which)
    if not shell:
        return None

    script = (
        "$ErrorActionPreference='Stop'; "
        "if (Get-Command winget -ErrorAction SilentlyContinue) { exit 0 }; "
        f"try {{ Add-AppxPackage -RegisterByFamilyName -MainPackage '{WINGET_PACKAGE_FAMILY_NAME}' -ErrorAction Stop }} catch {{}}; "
        "if (Get-Command winget -ErrorAction SilentlyContinue) { exit 0 }; "
        "$temp = Join-Path $env:TEMP ('RepoPrivacyGuardian-winget-bootstrap-' + [guid]::NewGuid().ToString() + '.msixbundle'); "
        f"Invoke-WebRequest -Uri '{WINGET_BOOTSTRAP_URL}' -OutFile $temp; "
        "try { Add-AppxPackage -Path $temp -ErrorAction Stop } finally { Remove-Item $temp -Force -ErrorAction SilentlyContinue }; "
        "if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { "
        "throw 'App Installer was added but winget is still unavailable. Restart the session and try again.' "
        "}"
    )
    return [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]


def build_windows_winget_tooling_check(
    *,
    platform_name: str | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
) -> ToolingCheck | None:
    current_platform = platform_name or sys.platform
    if not current_platform.startswith("win"):
        return None

    winget_ready, winget_error = probe_command_available("winget", runner=runner)
    if winget_ready:
        return ToolingCheck(
            name="winget",
            state="ready",
            blocking=False,
            detail="Windows App Installer / winget is available.",
        )

    bootstrap_ready, bootstrap_error = probe_windows_winget_bootstrap_available(
        platform_name=current_platform,
        runner=runner,
        which=which,
    )
    auto_install_command = (
        build_winget_bootstrap_command(platform_name=current_platform, which=which)
        if bootstrap_ready
        else None
    )
    detail = (
        "Windows App Installer / winget is not available. Automatic bootstrap can install it from the official Microsoft bundle."
        if bootstrap_ready
        else (
            "Windows App Installer / winget is not available. "
            + (bootstrap_error or winget_error or _missing_executable_message("winget"))
        )
    )
    return ToolingCheck(
        name="winget",
        state="warning",
        blocking=False,
        detail=detail,
        install_hint=(
            f"Bootstrap App Installer from {WINGET_BOOTSTRAP_URL}"
            if bootstrap_ready
            else f"Install App Installer manually from {WINGET_BOOTSTRAP_URL}"
        ),
        auto_install_command=auto_install_command,
    )


def ensure_windows_winget_available(
    logger: Callable[[str], None],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> bool:
    if not sys.platform.startswith("win"):
        return False

    winget_ready, _winget_error = probe_command_available("winget", runner=runner)
    if winget_ready:
        return True

    bootstrap_command = build_winget_bootstrap_command()
    if not bootstrap_command:
        logger(
            f"[TOOLING] winget/App Installer is missing and automatic bootstrap is unavailable. "
            f"Install it from {WINGET_BOOTSTRAP_URL}."
        )
        return False

    logger(f"[TOOLING] Bootstrapping winget/App Installer from {WINGET_BOOTSTRAP_URL}")
    try:
        proc = runner(
            bootstrap_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
        )
    except Exception as exc:
        logger(f"[TOOLING] winget bootstrap failed: {exc}")
        return False

    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown winget bootstrap failure"
        logger(f"[TOOLING] winget bootstrap failed: {detail}")
        return False

    winget_ready, winget_error = probe_command_available("winget", runner=runner)
    if winget_ready:
        logger("[TOOLING] winget/App Installer bootstrap completed.")
        return True

    logger(
        "[TOOLING] winget bootstrap completed but the command is still unavailable. "
        + (winget_error or "Restart the session and try again.")
    )
    return False


def build_system_tool_install_command(
    tool_name: str,
    *,
    platform_name: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str] | None:
    current_platform = platform_name or sys.platform

    windows_ids = {
        "git": "Git.Git",
        "gh": "GitHub.cli",
    }
    brew_names = {
        "git": "git",
        "gh": "gh",
    }
    apt_names = {
        "git": "git",
        "gh": "gh",
    }
    dnf_names = apt_names
    choco_names = {
        "git": "git",
        "gh": "gh",
    }

    if current_platform.startswith("win"):
        if which("winget") and tool_name in windows_ids:
            return [
                "winget",
                "install",
                "--id",
                windows_ids[tool_name],
                "-e",
                "--source",
                "winget",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ]
        if which("choco") and tool_name in choco_names:
            return ["choco", "install", choco_names[tool_name], "-y"]
        if tool_name in windows_ids:
            return [
                "winget",
                "install",
                "--id",
                windows_ids[tool_name],
                "-e",
                "--source",
                "winget",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ]
        return None

    if which("brew") and tool_name in brew_names:
        return ["brew", "install", brew_names[tool_name]]
    if which("apt-get") and tool_name in apt_names:
        return ["apt-get", "install", "-y", apt_names[tool_name]]
    if which("dnf") and tool_name in dnf_names:
        return ["dnf", "install", "-y", dnf_names[tool_name]]
    return None


def format_install_command(command: list[str] | None) -> str | None:
    if not command:
        return None
    return shlex.join(command)


def build_python_package_install_command(packages: list[str]) -> list[str]:
    return [sys.executable, "-m", "pip", "install", *packages]


def collect_auto_installable_tooling_checks(
    checks: list[ToolingCheck],
    *,
    blocking_only: bool = False,
) -> list[ToolingCheck]:
    selected: list[ToolingCheck] = []
    for check in checks:
        if check.state == "ready" or not check.auto_install_command:
            continue
        if blocking_only and not check.blocking:
            continue
        selected.append(check)
    return selected


def command_uses_executable(command: list[str] | None, executable: str) -> bool:
    if not command:
        return False
    return Path(command[0]).name.lower() == executable.lower()


def build_github_optional_tooling_checks() -> list[ToolingCheck]:
    checks: list[ToolingCheck] = []
    github_check = build_github_tooling_check()
    if github_check.state != "ready" and command_uses_executable(github_check.auto_install_command, "winget"):
        winget_check = build_windows_winget_tooling_check()
        if winget_check and winget_check.state != "ready":
            checks.append(winget_check)
    checks.append(github_check)
    return checks


def summarize_tooling_checks(
    checks: list[ToolingCheck],
    logger: Callable[[str], None],
    *,
    include_ready: bool = True,
) -> tuple[int, int]:
    blocking_failures = 0
    warnings = 0
    for check in checks:
        if check.state == "ready" and not include_ready:
            continue
        logger(f"[TOOLING] {check.name}: {check.state.upper()} - {check.detail}")
        if check.install_hint and check.state != "ready":
            logger(f"[TOOLING] {check.name} install hint: {check.install_hint}")
        if check.state == "missing" and check.blocking:
            blocking_failures += 1
        elif check.state != "ready":
            warnings += 1
    return blocking_failures, warnings


def install_missing_tooling(
    checks: list[ToolingCheck],
    logger: Callable[[str], None],
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    for check in checks:
        if check.state == "ready" or not check.auto_install_command:
            continue
        command = check.auto_install_command
        executable = Path(command[0]).name.lower()
        if executable == "winget":
            if not ensure_windows_winget_available(logger, runner=runner):
                logger(f"[TOOLING] Skipping install for {check.name}: winget/App Installer is still unavailable.")
                continue
        logger(f"[TOOLING] Attempting install for {check.name}: {format_install_command(command)}")
        try:
            proc = runner(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdin=subprocess_stdin(),
                timeout=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            logger(f"[TOOLING] Install timed out for {check.name}.")
            continue
        except Exception as exc:
            logger(f"[TOOLING] Install attempt failed for {check.name}: {exc}")
            continue
        if proc.returncode == 0:
            logger(f"[TOOLING] Install completed for {check.name}.")
        else:
            detail = proc.stderr.strip() or proc.stdout.strip() or "unknown install failure"
            logger(f"[TOOLING] Install failed for {check.name}: {detail}")


def prompt_gui_tooling_install(
    checks: list[ToolingCheck],
    logger: Callable[[str], None],
    *,
    blocking_only: bool = True,
    title: str = "Install Missing GUI Tooling",
    intro: str = "Repo Privacy Guardian detected missing GUI prerequisites that can be installed automatically.",
    confirm_question: str = "Install them now and retry GUI startup?",
) -> bool | None:
    installable = collect_auto_installable_tooling_checks(checks, blocking_only=blocking_only)
    if not installable or not has_desktop_display():
        return None

    try:
        import tkinter as tk
        from tkinter import TclError, messagebox
    except ModuleNotFoundError:
        logger("[TOOLING] Tkinter is unavailable, so the GUI install prompt could not be shown.")
        return None

    detail_lines = [
        f"- {check.name}: {check.detail}"
        for check in installable
    ]
    prompt_message = (
        intro
        + "\n\n"
        + "\n".join(detail_lines)
        + "\n\n"
        + confirm_question
    )

    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except TclError:
            pass
        accepted = messagebox.askyesno(
            title,
            prompt_message,
            parent=root,
        )
        return bool(accepted)
    except TclError as exc:
        logger(f"[TOOLING] Unable to display GUI install prompt: {exc}")
        return None
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass


def has_desktop_display(
    *,
    platform_name: str | None = None,
    env: dict[str, str] | None = None,
) -> bool:
    current_platform = platform_name or sys.platform
    current_env = env or os.environ
    if current_platform.startswith("win") or current_platform == "darwin":
        return True
    return bool(
        current_env.get("DISPLAY")
        or current_env.get("WAYLAND_DISPLAY")
        or current_env.get("MIR_SOCKET")
    )


def load_gui_runtime() -> tuple[object, object, object, object, type[BaseException]]:
    if not has_desktop_display():
        raise RuntimeError(
            "GUI mode requires a desktop session with DISPLAY/Wayland support. "
            "Use the CLI in headless environments."
        )

    try:
        import tkinter as tk
        from tkinter import TclError, filedialog, messagebox
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Tkinter is not available in this Python installation. "
            "Install Python with Tk support, or use the CLI instead."
        ) from exc

    try:
        import customtkinter as ctk
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "GUI dependencies are not installed. Install them with: "
            f"{sys.executable} -m pip install {' '.join(GUI_INSTALL_PACKAGES)} "
            "or re-run with --gui --install-missing-tools."
        ) from exc

    return tk, messagebox, filedialog, ctk, TclError


def build_github_tooling_check() -> ToolingCheck:
    env_token = resolve_github_hardening_token(env=os.environ)
    if env_token:
        return ToolingCheck(
            name="github-auth",
            state="ready",
            blocking=False,
            detail=(
                "GitHub hardening token-gated checks can use a configured token or GitHub CLI token. "
                "Branch protection, Actions, immutable releases, and security-alert checks may require "
                "Administration(read), Dependabot alerts(read), or security_events-equivalent access."
            ),
        )

    gh_available, gh_error = probe_command_available("gh")
    install_command = build_system_tool_install_command("gh")
    install_hint = format_install_command(install_command)

    if not gh_available:
        return ToolingCheck(
            name="github-auth",
            state="warning",
            blocking=False,
            detail=(
                "GitHub hardening audit will be partial until you configure "
                "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, or install/authenticate gh. "
                "Without auth, coverage is limited to public metadata, local CODEOWNERS, and any public "
                "metadata endpoints GitHub allows unauthenticated."
            ),
            install_hint=install_hint,
            auto_install_command=install_command,
        )

    gh_token, gh_status = read_github_cli_token()
    if gh_token:
        return ToolingCheck(
            name="github-auth",
            state="ready",
            blocking=False,
            detail=(
                "GitHub hardening token-gated checks can use the authenticated GitHub CLI token. "
                "Repository admin/security permissions still determine which GitHub API checks are complete."
            ),
        )

    return ToolingCheck(
        name="github-auth",
        state="warning",
        blocking=False,
        detail=(
            "GitHub CLI is installed but not authenticated. "
            "Run `gh auth login` or configure REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN."
            + (f" Details: {gh_status}" if gh_status and gh_status != "not_authenticated" else "")
        ),
        install_hint="gh auth login",
    )


def build_cli_tooling_checks(config: GuardRunConfig) -> list[ToolingCheck]:
    checks: list[ToolingCheck] = []

    git_ok, git_error = probe_git_available()
    git_install = build_system_tool_install_command("git")
    winget_check_added = False
    if not git_ok and command_uses_executable(git_install, "winget"):
        winget_check = build_windows_winget_tooling_check()
        if winget_check and winget_check.state != "ready":
            checks.append(winget_check)
            winget_check_added = True
    checks.append(
        ToolingCheck(
            name="git",
            state="ready" if git_ok else "missing",
            blocking=True,
            detail="Git executable available." if git_ok else (git_error or _missing_executable_message("git")),
            install_hint=(None if git_ok else format_install_command(git_install)),
            auto_install_command=(None if git_ok else git_install),
        )
    )

    if config.fix:
        remediation_ready = probe_git_filter_repo_available()
        remediation_cmd = build_python_package_install_command(REMEDIATION_INSTALL_PACKAGES)
        checks.append(
            ToolingCheck(
                name="git-filter-repo",
                state="ready" if remediation_ready else "warning",
                blocking=False,
                detail=(
                    "Rewrite-based remediation tooling is available."
                    if remediation_ready
                    else "Rewrite-based remediations may fail until git-filter-repo is installed."
                ),
                install_hint=(
                    None
                    if remediation_ready
                    else f"{sys.executable} -m pip install {' '.join(REMEDIATION_INSTALL_PACKAGES)}"
                ),
                auto_install_command=(None if remediation_ready else remediation_cmd),
            )
        )

    if config.audit_github_hardening or config.github_owner:
        github_check = build_github_tooling_check()
        if (
            not winget_check_added
            and github_check.state != "ready"
            and command_uses_executable(github_check.auto_install_command, "winget")
        ):
            winget_check = build_windows_winget_tooling_check()
            if winget_check and winget_check.state != "ready":
                checks.append(winget_check)
                winget_check_added = True
        checks.append(github_check)

    return checks


def build_gui_tooling_checks() -> list[ToolingCheck]:
    checks: list[ToolingCheck] = []

    git_ok, git_error = probe_git_available()
    git_install = build_system_tool_install_command("git")
    if not git_ok and command_uses_executable(git_install, "winget"):
        winget_check = build_windows_winget_tooling_check()
        if winget_check and winget_check.state != "ready":
            checks.append(winget_check)
    checks.append(
        ToolingCheck(
            name="git",
            state="ready" if git_ok else "missing",
            blocking=True,
            detail="Git executable available." if git_ok else (git_error or _missing_executable_message("git")),
            install_hint=(None if git_ok else format_install_command(git_install)),
            auto_install_command=(None if git_ok else git_install),
        )
    )

    if not has_desktop_display():
        checks.append(
            ToolingCheck(
                name="desktop-session",
                state="missing",
                blocking=True,
                detail=(
                    "GUI mode requires a desktop session with DISPLAY/Wayland support. "
                    "Use the CLI in headless environments."
                ),
            )
        )
    else:
        checks.append(
            ToolingCheck(
                name="desktop-session",
                state="ready",
                blocking=True,
                detail="Desktop session detected.",
            )
        )

    tkinter_ready = probe_python_module_available("tkinter")
    checks.append(
        ToolingCheck(
            name="tkinter",
            state="ready" if tkinter_ready else "missing",
            blocking=True,
            detail=(
                "Tkinter is available."
                if tkinter_ready
                else "Tkinter is not available in this Python installation."
            ),
            install_hint=(
                None
                if tkinter_ready
                else "Install Python with Tk support, or install python3-tk on Linux desktop environments."
            ),
        )
    )

    customtkinter_ready = probe_python_module_available("customtkinter")
    customtkinter_cmd = build_python_package_install_command(GUI_INSTALL_PACKAGES)
    checks.append(
        ToolingCheck(
            name="customtkinter",
            state="ready" if customtkinter_ready else "missing",
            blocking=True,
            detail=(
                "GUI dependency customtkinter is available."
                if customtkinter_ready
                else "GUI dependency customtkinter is not installed."
            ),
            install_hint=(
                None
                if customtkinter_ready
                else f"{sys.executable} -m pip install {' '.join(GUI_INSTALL_PACKAGES)}"
            ),
            auto_install_command=(None if customtkinter_ready else customtkinter_cmd),
        )
    )

    tkinterdnd2_ready = probe_python_module_available("tkinterdnd2")
    tkinterdnd2_cmd = build_python_package_install_command(GUI_DRAG_DROP_INSTALL_PACKAGES)
    checks.append(
        ToolingCheck(
            name="tkinterdnd2",
            state="ready" if tkinterdnd2_ready else "missing",
            blocking=False,
            detail=(
                "Optional GUI drag-and-drop dependency tkinterdnd2 is available."
                if tkinterdnd2_ready
                else "Optional GUI drag-and-drop dependency tkinterdnd2 is not installed; Browse/Refresh still works."
            ),
            install_hint=(
                None
                if tkinterdnd2_ready
                else f"{sys.executable} -m pip install {' '.join(GUI_DRAG_DROP_INSTALL_PACKAGES)}"
            ),
            auto_install_command=(None if tkinterdnd2_ready else tkinterdnd2_cmd),
        )
    )

    return checks
