#!/usr/bin/env python3
"""
Repository Publication Guard

Audits repositories for public-release safety and can optionally apply automated fixes.
The checks are aligned with docs/POLICY.md.

Features:
- CLI mode (audit and optional fix)
- Optional desktop GUI mode
- History and working-tree scans for secrets/PII/path leaks
- Git identity and commit metadata checks
- .gitignore completeness checks based on policy + baseline patterns
- Optional automated fixes (history rewrite, ignore hygiene, force push)
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
import html  # noqa: F401 - re-exported for extracted reporting
import importlib.util  # noqa: F401 - re-exported for extracted tooling
import inspect
import json
import os
import re
import shlex  # noqa: F401 - re-exported for extracted tooling
import shutil
import subprocess
import stat
import sys
import tempfile
import threading  # noqa: F401 - re-exported for extracted GUI
import time
import traceback
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import socket  # noqa: F401 - re-exported for extracted scanner
from typing import Any, Callable, Iterable, Mapping, cast

from repo_privacy_guardian import artifacts as artifact_helpers
from repo_privacy_guardian import agent_summary as agent_summary_helpers  # noqa: F401 - re-exported for extracted reporting
from repo_privacy_guardian import github as github_helpers
from repo_privacy_guardian import github_fix_guide
from repo_privacy_guardian import metrics as metrics_helpers
from repo_privacy_guardian import prompts as prompt_helpers  # noqa: F401 - re-exported for extracted GUI
from repo_privacy_guardian import runtime
from repo_privacy_guardian import strict_profiles
from repo_privacy_guardian import suppressions as suppression_helpers
from repo_privacy_guardian.runtime import (
    CancellationToken,  # noqa: F401 - re-exported for extracted GUI
    EXIT_ABORTED,
    EXIT_OK,
    EXIT_POLICY_FAILED,
    EXIT_RUNTIME_ERROR,
    describe_no_target_resolution,
    discover_repository_targets,  # noqa: F401 - re-exported for extracted scanner
    resolve_run_status,
    validate_repository_root,
)


def default_root_dir() -> Path:
    return Path.cwd()


def default_results_dir() -> Path:
    return default_root_dir() / "Audit_Results"


def source_tree_root() -> Path:
    package_root = Path(__file__).resolve().parent
    repo_root = package_root.parent
    if (repo_root / "docs" / "POLICY.md").exists():
        return repo_root
    return package_root


def default_policy_path() -> Path:
    repo_policy = source_tree_root() / "docs" / "POLICY.md"
    if repo_policy.exists():
        return repo_policy

    try:
        from importlib import resources

        packaged_policy = resources.files("repo_privacy_guardian_resources").joinpath("POLICY.md")
        packaged_policy_path = Path(str(packaged_policy))
        if packaged_policy_path.exists():
            return packaged_policy_path
    except (ImportError, ModuleNotFoundError, OSError):
        pass

    return repo_policy


DEFAULT_ROOT = default_root_dir()
DEFAULT_POLICY = default_policy_path()
DEFAULT_NOREPLY = "noreply@github.com"
DEFAULT_PLACEHOLDER = "redacted-contributor@example.invalid"
DEFAULT_RESULTS_DIR = default_results_dir()
GUI_DEFAULT_PUBLIC_ONLY = False
GUI_INSTALL_EXTRA = "repo-privacy-guardian[gui]"
REMEDIATION_INSTALL_EXTRA = "repo-privacy-guardian[remediation]"
GUI_DRAG_DROP_INSTALL_PACKAGES = ["tkinterdnd2>=0.4.3,<0.5"]
GUI_INSTALL_PACKAGES = ["customtkinter>=5.2.2,<6", *GUI_DRAG_DROP_INSTALL_PACKAGES]
REMEDIATION_INSTALL_PACKAGES = ["git-filter-repo>=2.45,<3"]
GUI_SETTINGS_ENV_VAR = "REPO_PRIVACY_GUARDIAN_GUI_SETTINGS"
GUI_SETTINGS_SCHEMA_VERSION = 1
GUI_SETTINGS_MAX_BYTES = 32 * 1024
GUI_LOCALE_DEFAULT = "en"
GUI_LOCALE_ES_419 = "es-419"
GUI_LOCALE_OPTIONS: tuple[tuple[str, str], ...] = (
    (GUI_LOCALE_DEFAULT, "English"),
    (GUI_LOCALE_ES_419, "Español (Latinoamérica)"),
)
GUI_APPEARANCE_LIGHT = "light"
GUI_APPEARANCE_DARK = "dark"
GUI_APPEARANCE_SYSTEM = "system"
GUI_APPEARANCE_DEFAULT = GUI_APPEARANCE_SYSTEM
GUI_APPEARANCE_OPTIONS_BY_LOCALE: dict[str, tuple[tuple[str, str], ...]] = {
    GUI_LOCALE_DEFAULT: (
        (GUI_APPEARANCE_SYSTEM, "System"),
        (GUI_APPEARANCE_LIGHT, "Light"),
        (GUI_APPEARANCE_DARK, "Dark"),
    ),
    GUI_LOCALE_ES_419: (
        (GUI_APPEARANCE_SYSTEM, "Sistema"),
        (GUI_APPEARANCE_LIGHT, "Claro"),
        (GUI_APPEARANCE_DARK, "Oscuro"),
    ),
}
GUI_ASSET_PACKAGE = "repo_privacy_guardian_assets"
GUI_ASSET_FILENAMES: tuple[str, ...] = (
    "app-icon.png",
    "header-watermark.png",
    "repo-dropzone.png",
    "reports-evidence.png",
    "prompts-workflow.png",
    "repair-gate.png",
    "icon-audit.png",
    "icon-copy.png",
    "icon-folder.png",
    "icon-open.png",
    "icon-refresh.png",
    "icon-repair.png",
    "icon-report.png",
    "icon-settings.png",
    "icon-stop.png",
)
GUI_THEMEABLE_ASSET_FILENAMES: frozenset[str] = frozenset(
    {
        "prompts-workflow.png",
        "repair-gate.png",
        "repo-dropzone.png",
        "reports-evidence.png",
    }
)
WINGET_BOOTSTRAP_URL = "https://aka.ms/getwinget"
WINGET_PACKAGE_FAMILY_NAME = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
GITHUB_EMAIL_SETTINGS_URL = "https://github.com/settings/emails"
LITELLM_INCIDENT_ID = "litellm-2026-03"
EXFIL_INDICATOR_MODE = "advisory"
GITHUB_HARDENING_MODE = "advisory"
REDACTED_EMAIL = "<redacted-email>"
REDACTED_IDENTITY_TOKEN = "<redacted-identity-token>"
# Redaction placeholder, not a credential.
REDACTED_SECRET = "<redacted-secret>"  # nosec B105
REDACTED_PATH = "<redacted-path>"


def gui_asset_path(filename: str) -> Path | None:
    if filename not in GUI_ASSET_FILENAMES:
        return None

    source_tree_asset = source_tree_root() / GUI_ASSET_PACKAGE / filename
    if source_tree_asset.exists():
        return source_tree_asset

    try:
        from importlib import resources

        packaged_asset = resources.files(GUI_ASSET_PACKAGE).joinpath(filename)
        packaged_asset_path = Path(str(packaged_asset))
        if packaged_asset_path.exists():
            return packaged_asset_path
    except (ImportError, ModuleNotFoundError, OSError):
        pass

    return None


def parse_hex_rgb(color: str) -> tuple[int, int, int] | None:
    value = color.strip()
    if len(value) != 7 or not value.startswith("#"):
        return None
    try:
        return (int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16))
    except ValueError:
        return None


def blend_near_white_gui_asset_background(image, background_rgb: tuple[int, int, int]):
    output = image.convert("RGBA")
    pixels = []
    get_pixel_data = getattr(output, "get_flattened_data", output.getdata)
    for red, green, blue, alpha in get_pixel_data():
        is_low_saturation_light_pixel = min(red, green, blue) >= 232 and max(red, green, blue) - min(red, green, blue) <= 28
        if alpha and is_low_saturation_light_pixel:
            pixels.append((*background_rgb, alpha))
        else:
            pixels.append((red, green, blue, alpha))
    output.putdata(pixels)
    return output


EMAIL_NOISE_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "localdomain",
}
SSH_REMOTE_PSEUDO_EMAILS = {
    ("git", "github.com"),
    ("git", "ssh.github.com"),
    ("git", "gitlab.com"),
    ("git", "bitbucket.org"),
    ("git", "ssh.dev.azure.com"),
    ("git", "vs-ssh.visualstudio.com"),
    ("hg", "bitbucket.org"),
}
GITHUB_EMAIL_PRIVACY_HELP = (
    "Use GitHub Email Settings to verify private-email and push-block protections, "
    "and to copy your noreply address when needed."
)

DEFAULT_IGNORE_BASELINE = [
    ".venv/",
    ".pkg-venv/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".env",
    ".env.*",
    "!.env.example",
    "wsa-config.local.yaml",
    "Audit_Results/",
    "sessions/*",
    "artifacts/",
    "exports/",
    "*.log",
    "*.tmp",
    "*.bak",
    "*-pre-publication-fix-*.bundle",
    ".vscode/",
    ".idea/",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
]
MAX_TRACKED_TEXT_SCAN_BYTES = 5 * 1024 * 1024
DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 300
DEFAULT_GIT_STREAM_TIMEOUT_SECONDS = 300
REPO_LOCK_FILENAME = "repo-privacy-guardian.lock"
REPO_LOCK_WAIT_SECONDS = 10.0
REPO_LOCK_RETRY_SECONDS = 0.2
MAX_GITHUB_CLONE_JOBS = 16
TEMP_TREE_CLEANUP_ATTEMPTS = 5
TEMP_TREE_CLEANUP_RETRY_SECONDS = 0.2
RUN_STATE_FILENAME = "run_state.json"

# Allow committed template files such as `.env.example` while keeping real
# environment files and local variants sensitive by default.
ENV_SENSITIVE_FILENAME_RE = r"(^|/)\.env(?:\.(?!example$)[^/]+)?$"

SENSITIVE_FILENAME_RE = re.compile(
    ENV_SENSITIVE_FILENAME_RE
    + r"|"
    r"\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|"
    r"(^|/)id_(?:rsa|dsa|ecdsa|ed25519)$|"
    r"(^|/)\.(?:npmrc|pypirc|netrc|dockercfg)$|"
    r"(^|/)\.docker/config\.json$|"
    r"(^|/)\.aws/credentials$|"
    r"(^|/)\.kube/config$|"
    r"(^|/)kubeconfig$|"
    r"(^|/)(secrets?|credentials?|token)([._-]|$)|"
    r"(^|/)__pycache__(/|$)|"
    r"\.pyc$",
    re.IGNORECASE,
)

HIGH_CONFIDENCE_SECRET_CONTENT_RE = re.compile(
    r"gh[opsru]_[A-Za-z0-9]{36,}|"
    r"github_pat_[A-Za-z0-9_]{40,}|"
    r"\bgl(?:pat|oas|dt|rtr|rt|cbt|ptt|ft|imt|agent|wt|soat)-[A-Za-z0-9_-]{16,}\b|"
    r"\bcf(?:k|ut|at)_[A-Za-z0-9]{40,}\b|"
    r"AKIA[0-9A-Z]{16}|"
    r"(?i:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?|"
    r"AIza[0-9A-Za-z\-_]{35}|"
    r"\bya29\.[0-9A-Za-z\-_]{32,}\b|"
    r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{32,}\b|"
    r"\bsk-ant-(?:api\d{2}-|admin)[A-Za-z0-9_-]{20,}\b|"
    r"x(?:ox[baprs]|app|wfp)-[A-Za-z0-9-]+|"
    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+|"
    r"https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{32,}|"
    r"(?:sk|rk)_live_[0-9A-Za-z]{24,}|"
    r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}|"
    r"npm_[A-Za-z0-9]{36}|"
    r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b|"
    r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b|"
    r"(?i:heroku[_-]?api[_-]?key)\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?|"
    r"(?i:(?:AccountKey|storage[_-]?key))\s*[=:]\s*['\"]?[A-Za-z0-9+/=]{88}['\"]?|"
    r"(?i:cloudflare[_-]?(?:api[_-]?)?(?:token|key))\s*[=:]\s*['\"]?[A-Za-z0-9_-]{37,64}['\"]?|"
    r"(?i:datadog[_-]?(?:api|app(?:lication)?)?[_-]?key)\s*[=:]\s*['\"]?[0-9a-f]{32,40}['\"]?|"
    r"(?i:twilio[_-]?auth[_-]?token)\s*[=:]\s*['\"]?[0-9a-f]{32}['\"]?|"
    r"(?i:mailgun[_-]?api[_-]?key)\s*[=:]\s*['\"]?key-[0-9a-f]{32}['\"]?|"
    r"(?i:\b(?:https?|ssh|ftp|ftps|sftp|mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|rediss|amqp|amqps)://[^\s:/?#'\"`<>]+:[^\s@'\"`<>]{3,}@[^\s'\"`<>]+)|"
    r"(?i:\bauthorization\s*:\s*(?:bearer|token|basic)\s+[A-Za-z0-9._~+/=-]{16,})|"
    r"BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"
)
SECRET_CONTENT_RE = HIGH_CONFIDENCE_SECRET_CONTENT_RE

LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?P<key>\b(?:password|passwd|pwd|passphrase|secret|api[_-]?key|apikey|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"private[_-]?key|connection[_-]?string|webhook[_-]?url|dsn)\b)"
    r"(?P<sep>\s*(?:=|:)\s*)"
    r"(?P<quote>['\"]?)"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{12,})"
    r"(?P=quote)"
)

SECRET_FIXTURE_PATH_RE = re.compile(
    r"(^|/)(test|tests|fixture|fixtures|mock|mocks|sample|samples|demo|spec|benchmarks?)(/|$)",
    re.IGNORECASE,
)
SECRET_DOCUMENTATION_PATH_RE = re.compile(r"(^|/)(docs?|examples?)(/|$)", re.IGNORECASE)
SECRET_DOCUMENTATION_FILE_RE = re.compile(
    r"readme|changelog|contributing|copilot|instructions|policy|roadmap|"
    r"checklist|known_issues|lessons|operations|troubleshooting|versioning",
    re.IGNORECASE,
)
SECRET_SAFE_PLACEHOLDER_RE = re.compile(
    r"(?i)\b(?:example|sample|dummy|fake|fixture|mock|placeholder|redacted|"
    r"changeme|change-me|not-a-real|your[_-]?(?:token|key|secret|password)|"
    r"insert[_-]?here|todo|example\.invalid|localhost)\b|"
    r"<[^>\n]{1,80}>|"
    r"\$\{[A-Za-z0-9_:-]{1,80}\}|"
    r"%[A-Za-z0-9_]{1,80}%|"
    r"\b[A-Z0-9_]{2,}_(?:TOKEN|KEY|SECRET|PASSWORD)\b|"
    r"\b(?:x{8,}|a{16,}|b{16,}|c{16,}|0{16,})\b|"
    r"([A-Za-z0-9])\1{15,}"
)

SECRET_REMEDIATE_FILENAME_RE = re.compile(
    ENV_SENSITIVE_FILENAME_RE
    + r"|"
    r"\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|"
    r"(^|/)id_(?:rsa|dsa|ecdsa|ed25519)$|"
    r"(^|/)\.(?:npmrc|pypirc|netrc|dockercfg)$|"
    r"(^|/)\.docker/config\.json$|"
    r"(^|/)\.aws/credentials$|"
    r"(^|/)\.kube/config$|"
    r"(^|/)kubeconfig$|"
    r"(^|/)(secret|credential|token|password|passwd|api[_-]?key)([._-]|$)",
    re.IGNORECASE,
)

PERSONAL_PATH_RE = re.compile(
    r"(?i)"
    r"[A-Za-z]:(?:\\\\|\\|/)(?:Users|Documents and Settings|home)(?:\\\\|\\|/)[A-Za-z0-9][A-Za-z0-9._-]*"
    r"|/(?:Users|home)/[A-Za-z0-9][A-Za-z0-9._-]*"
)
PERSONAL_PATH_LITERAL_PATTERNS = (
    re.compile(
        r"(?i)[A-Za-z]:/(?:Users|home)/[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:/[^\s\"'`<>|]+){0,8}"
    ),
    re.compile(
        r"(?i)[A-Za-z]:\\(?:Users|home)\\[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:\\[^\s\"'`<>|]+){0,8}"
    ),
    re.compile(
        r"(?i)[A-Za-z]:\\\\(?:Users|home)\\\\[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:\\\\[^\s\"'`<>|]+){0,8}"
    ),
    re.compile(
        r"(?i)/(?:Users|home)/[A-Za-z0-9][A-Za-z0-9._-]*"
        r"(?:/[^\s\"'`<>|]+){0,8}"
    ),
)
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SIMPLE_EMAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

EMAIL_LOW_CONFIDENCE_PATH_RE = re.compile(
    r"(^|/)(test|tests|docs|doc|example|examples|fixture|fixtures|mock|mocks|"
    r"sample|samples|demo|benchmarks?|spec)(/|$)",
    re.IGNORECASE,
)
EMAIL_LOW_CONFIDENCE_FILE_RE = re.compile(
    r"readme|changelog|contributing|copilot|instructions|policy|roadmap|"
    r"checklist|known_issues|lessons",
    re.IGNORECASE,
)
EMAIL_LOW_CONFIDENCE_SNIPPET_RE = re.compile(
    r"\b(mock|fixture|dummy|sample|placeholder|test|assert|expect|pytest|unittest)\b|"
    r"vi\.spyon|mockresolvedvalue|auth\.login\(|next_public_support_email",
    re.IGNORECASE,
)
POLICY_MINIMUM_BASELINE_RE = re.compile(r"^(minimum baseline|minimo recomendado)\b", re.IGNORECASE)
POLICY_MINIMUM_BASELINE_END_RE = re.compile(
    r"^(check currently ignored sensitive paths|comprobar ignored)\b",
    re.IGNORECASE,
)

is_git_repository = runtime.is_git_repository
GITHUB_REPO_API_URL = github_helpers.GITHUB_REPO_API_URL
GITHUB_API_VERSION = github_helpers.GITHUB_API_VERSION
GITHUB_HARDENING_TOKEN_ENV_KEYS = github_helpers.GITHUB_HARDENING_TOKEN_ENV_KEYS
urllib = github_helpers.urllib
read_github_cli_token = github_helpers.read_github_cli_token
infer_github_username_from_noreply = github_helpers.infer_github_username_from_noreply
parse_github_remote_owner = github_helpers.parse_github_remote_owner
parse_github_remote_slug = github_helpers.parse_github_remote_slug
fetch_github_owner_repositories = github_helpers.fetch_github_owner_repositories
validate_outbound_https_url = github_helpers.validate_outbound_https_url
github_repo_api_url = github_helpers.github_repo_api_url
is_public_github_remote = github_helpers.is_public_github_remote
build_github_api_headers = github_helpers.build_github_api_headers
github_api_get_json = github_helpers.github_api_get_json
github_api_probe_enabled = github_helpers.github_api_probe_enabled


def render_ignore_baseline(patterns: list[str] | None = None) -> str:
    baseline = DEFAULT_IGNORE_BASELINE if patterns is None else patterns
    return "\n".join(baseline) + "\n"


def repo_display_name(repo: Path) -> str:
    name = repo.name.strip()
    if name:
        return name
    try:
        resolved_name = repo.resolve().name.strip()
    except OSError:
        resolved_name = ""
    return resolved_name or "."


def process_exists(pid: int) -> bool | None:
    """Best-effort compatibility probe; repository locks do not use PID liveness."""
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            error_code = ctypes.get_last_error()
        except Exception:
            return None

        if error_code == 5:
            return True
        if error_code == 87:
            return False
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def subprocess_stdin(input_text: str | None = None) -> int:
    return subprocess.PIPE if input_text is not None else subprocess.DEVNULL


def streaming_popen_kwargs() -> dict[str, Any]:
    return {
        "stdin": subprocess.DEVNULL,
        "start_new_session": True,
    }


def _close_fd_safely(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _write_all_to_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while len(view) > 0:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while writing lock metadata")
        view = view[written:]


def _fsync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    fd: int | None = None
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
        os.fsync(fd)
    except OSError:
        return
    finally:
        _close_fd_safely(fd)


def _write_json_to_locked_fd(fd: int, payload: dict[str, object]) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    if data:
        _write_all_to_fd(fd, data)
    os.fsync(fd)


def _read_json_from_locked_fd(fd: int) -> dict[str, object] | None:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        size = os.fstat(fd).st_size
        if size <= 0:
            return None
        raw = os.read(fd, size)
        if not raw:
            return None
        return json.loads(raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def acquire_advisory_file_lock(fd: int) -> bool:
    if os.name == "nt":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK, errno.EPERM}:
                return False
            raise
        return True

    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
            return False
        raise
    return True


def release_advisory_file_lock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return

    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


def repo_has_dirty_worktree(clean_status: str | None) -> bool:
    return len((clean_status or "").splitlines()) > 1


def _path_has_existing_symlink_ancestor(path: Path) -> bool:
    current = path
    while True:
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _apply_private_permissions(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(mode)
    except OSError:
        pass


def ensure_private_directory(path: Path) -> None:
    if _path_has_existing_symlink_ancestor(path):
        raise RuntimeError(f"Refusing to use symlinked directory path: {path}")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise RuntimeError(f"Expected a directory path: {path}")
    _apply_private_permissions(path, 0o700)


def write_private_text_file(path: Path, content: str) -> None:
    ensure_private_directory(path.parent)
    if path.is_symlink():
        raise RuntimeError(f"Refusing to write through symlinked file path: {path}")

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-",
        dir=str(path.parent),
        text=True,
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        _apply_private_permissions(temp_path, 0o600)
        os.replace(temp_path, path)
        _apply_private_permissions(path, 0o600)
        _fsync_parent_directory(path)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def append_private_text_file(path: Path, content: str) -> None:
    ensure_private_directory(path.parent)
    if path.is_symlink():
        raise RuntimeError(f"Refusing to append through symlinked file path: {path}")

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8", newline="") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    _apply_private_permissions(path, 0o600)


def write_private_json_file(path: Path, payload: dict[str, object]) -> None:
    write_private_text_file(
        path,
        json.dumps(payload, indent=2, sort_keys=True),
    )


def create_private_temp_text_file(prefix: str, filename: str, content: str) -> Path:
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
    ensure_private_directory(temp_dir)
    out_path = temp_dir / filename
    write_private_text_file(out_path, content)
    return out_path


def cleanup_private_temp_text_file(path: Path | None) -> None:
    if path is None:
        return
    try:
        if path.exists() or path.is_symlink():
            path.unlink()
    except OSError:
        pass
    temp_dir = path.parent
    try:
        if temp_dir.exists() and temp_dir.name.startswith("repo-publication-guard-"):
            temp_dir.rmdir()
    except OSError:
        pass


def _make_path_writable_and_retry_remove(
    remove_func: Callable[[str], None],
    path: str,
    _exc_info: object,
) -> None:
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        remove_func(path)
    except OSError:
        pass


def remove_private_temp_tree(path: Path, *, required_prefix: str) -> tuple[bool, str | None]:
    if not path.name.startswith(required_prefix):
        return False, f"refusing to remove unexpected temporary directory path: {path}"
    if _path_has_existing_symlink_ancestor(path):
        return False, f"refusing to recursively remove temporary directory path with symlinked path component: {path}"

    last_error: str | None = None
    for attempt in range(1, TEMP_TREE_CLEANUP_ATTEMPTS + 1):
        try:
            if not path.exists():
                return True, None
            shutil.rmtree(path, onerror=_make_path_writable_and_retry_remove)
        except OSError as exc:
            last_error = str(exc)

        if not path.exists():
            return True, None
        last_error = f"temporary directory still exists after cleanup attempt {attempt}: {path}"
        if attempt < TEMP_TREE_CLEANUP_ATTEMPTS:
            time.sleep(TEMP_TREE_CLEANUP_RETRY_SECONDS)

    return False, last_error


def read_text_file_for_scan(path: Path, *, max_bytes: int = MAX_TRACKED_TEXT_SCAN_BYTES) -> str | None:
    try:
        if path.is_symlink():
            return None
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    return data.decode("utf-8", errors="replace")

EXFIL_ACTIVE_CODE_RE = re.compile(
    r"(?i)"
    r"Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|"
    r"requests\.(?:get|post|put|patch|delete|head|options|request|Session)|"
    r"httpx\.(?:get|post|put|patch|delete|head|options|request|Client|AsyncClient)|"
    r"aiohttp\.(?:request|ClientSession)|"
    r"urllib\.request\.urlopen|"
    r"\burlopen\s*\(|"
    r"websockets\.connect|"
    r"socket\.(?:socket|create_connection)|"
    r"\bfetch\s*\(|"
    r"axios\.(?:get|post|put|patch|delete|head|options|request|create)|"
    r"navigator\.sendBeacon|"
    r"new\s+WebSocket\s*\(|"
    r"XMLHttpRequest"
)
EXFIL_REVIEW_TERM_RE = re.compile(r"(?i)\b(upload|webhook|telemetry|analytics)\b")
EXFIL_REVIEW_CONTEXT_RE = re.compile(
    r"(?i)"
    r"https?://|"
    r"\b(send|post|get|put|patch|delete|emit|publish|push|export|beacon|track|ingest|collector|endpoint)\b"
)
EXFIL_IMPORT_LINE_RE = re.compile(r"^\s*(?:from\s+\S+\s+import\s+.+|import\s+.+)$")
EXFIL_META_LINE_RE = re.compile(
    r"\b(?:line_has_exfil_indicator|is_exfil_indicator_noise|exfil_code_indicators|EXFIL_[A-Z_]+)\b"
)
EXFIL_PATTERN_LITERAL_RE = re.compile(r"^\s*r?[\"'][A-Za-z0-9_.\\|?*+()[\]-]+[\"']\s*,?\s*$")
EXFIL_TEST_FIXTURE_WRITE_RE = re.compile(r"\b(?:_write|write_text|write_bytes)\s*\(")


def is_exfil_indicator_noise(line: str, *, rel_path: str | None = None) -> bool:
    stripped = line.strip()
    normalized_rel = (rel_path or "").replace("\\", "/").lower()
    if not stripped:
        return True
    if stripped.startswith(("#", "//", "/*", "*", "*/")):
        return True
    if EXFIL_IMPORT_LINE_RE.match(stripped):
        return True
    if EXFIL_META_LINE_RE.search(stripped):
        return True
    if EXFIL_PATTERN_LITERAL_RE.match(stripped):
        return True
    if normalized_rel.startswith("tests/") and EXFIL_TEST_FIXTURE_WRITE_RE.search(stripped) and "\\n" in stripped:
        return True
    return False


def line_has_exfil_indicator(line: str, *, rel_path: str | None = None) -> bool:
    stripped = line.strip()
    if is_exfil_indicator_noise(stripped, rel_path=rel_path):
        return False
    if EXFIL_ACTIVE_CODE_RE.search(stripped):
        return True
    if EXFIL_REVIEW_TERM_RE.search(stripped) and EXFIL_REVIEW_CONTEXT_RE.search(stripped):
        return True
    return False

LITELLM_REFERENCE_RE = re.compile(r"(?i)\blitellm\b")
LITELLM_COMPROMISED_VERSION_RE = re.compile(r"(?i)\blitellm\b[^\n]{0,64}\b1\.82\.(?:7|8)\b")
LITELLM_INSTALL_COMMAND_RE = re.compile(
    r"(?i)(pip\s+install\s+litellm|uv\s+add\s+litellm|poetry\s+add\s+litellm)"
)
LITELLM_IOC_RE = re.compile(r"(?i)litellm_init\.pth|models\.litellm\.cloud|checkmarx\.zone")
LITELLM_COMPROMISED_1828_RE = re.compile(r"(?i)\b1\.82\.8\b")
LITELLM_COMPROMISED_1827_RE = re.compile(r"(?i)\b1\.82\.7\b")

SUPPLY_CHAIN_CANDIDATE_FILENAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "constraints.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "pipfile",
    "pipfile.lock",
    "setup.py",
    "setup.cfg",
    "environment.yml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".gitlab-ci.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
}

CODE_EXTENSIONS = {
    ".py",
    ".ps1",
    ".psm1",
    ".sh",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rs",
}


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class RepoExecutionLock:
    repo: Path
    lock_path: Path
    owner_token: str
    acquired_at: datetime
    lock_fd: int


@dataclass
class ToolingCheck:
    name: str
    state: str
    blocking: bool
    detail: str
    install_hint: str | None = None
    auto_install_command: list[str] | None = None


@dataclass
class GuardRunConfig:
    mode: str
    root: Path
    policy: Path
    repos: list[str] | None
    public_only: bool
    fix: bool
    push: bool
    dry_run: bool
    redact_third_party_emails: bool
    purge_detected_secret_files: bool
    purge_all_detected_secret_files: bool
    low_confidence_email_mode: str
    owner_name: str
    owner_emails: list[str]
    noreply_email: str
    placeholder_email: str
    max_matches: int
    audit_litellm_incident: bool = False
    audit_github_hardening: bool = False
    rewrite_personal_paths: bool = False
    open_report: bool = False
    confirm_each_repo_fix: bool = True
    allow_non_owner_push: bool = False
    allowed_remote_owners: list[str] = field(default_factory=list)
    replace_text_file: str | None = None
    report_json: str | None = None
    github_owner: str | None = None
    github_include_forks: bool = False
    github_fast: bool = False
    github_jobs: int = 4
    agent_summary: bool = False
    strict_profile: str | None = None
    github_hardening_findings_blocking: bool = False
    suppressions: str | None = None


RunArtifacts = artifact_helpers.RunArtifacts


@dataclass
class GitHubCloneResult:
    remote: github_helpers.GitHubRemoteRepository
    path: Path
    error: str | None = None


class RunLogger(artifact_helpers.RunLogger):
    def __init__(self, log_path: Path, sink: Callable[[str], None] | None = None) -> None:
        super().__init__(
            log_path,
            sink=sink,
            ensure_private_directory=ensure_private_directory,
            write_private_text_file=write_private_text_file,
            append_private_text_file=append_private_text_file,
            redact_sensitive_text=redact_sensitive_text,
            stdout=sys.stdout,
            now_factory=datetime.now,
        )


class RunStateTracker(artifact_helpers.RunStateTracker):
    def __init__(self, path: Path, *, artifacts: RunArtifacts, config: GuardRunConfig) -> None:
        super().__init__(
            path,
            run_id=artifacts.run_id,
            started_at=artifacts.started_at,
            mode=config.mode,
            root=config.root,
            policy=config.policy,
            requested_repositories=list(config.repos or []),
            pid=os.getpid(),
            write_private_json_file=write_private_json_file,
            now_factory=datetime.now,
        )


from repo_privacy_guardian.gui import locale as gui_locale_helpers  # noqa: E402

GUI_TOOLTIP_TEXT = gui_locale_helpers.GUI_TOOLTIP_TEXT
GUI_TOOLTIP_TEXT_BY_LOCALE = gui_locale_helpers.GUI_TOOLTIP_TEXT_BY_LOCALE
GUI_TOOLTIP_TEXT_ES_419 = gui_locale_helpers.GUI_TOOLTIP_TEXT_ES_419
GUI_UI_TEXT_BY_LOCALE = gui_locale_helpers.GUI_UI_TEXT_BY_LOCALE
choose_gui_font_family = gui_locale_helpers.choose_gui_font_family
gui_font_candidates = gui_locale_helpers.gui_font_candidates


@dataclass
class RepoReport:
    name: str
    path: str
    origin_url: str | None = None
    upstream_url: str | None = None
    branch: str | None = None
    head: str | None = None
    origin_head: str | None = None
    clean_status: str | None = None
    fsck_ok: bool = True
    fsck_output: list[str] = field(default_factory=list)

    author_emails: list[str] = field(default_factory=list)
    committer_emails: list[str] = field(default_factory=list)
    author_identity_tokens: list[str] = field(default_factory=list)
    committer_identity_tokens: list[str] = field(default_factory=list)
    unexpected_emails: list[str] = field(default_factory=list)
    unexpected_emails_owned_repo: list[str] = field(default_factory=list)
    unexpected_emails_third_party_repo: list[str] = field(default_factory=list)
    unexpected_identity_tokens: list[str] = field(default_factory=list)
    unexpected_identity_tokens_owned_repo: list[str] = field(default_factory=list)
    unexpected_identity_tokens_third_party_repo: list[str] = field(default_factory=list)
    email_ownership_evaluated: bool = False

    tracked_secret_matches: list[str] = field(default_factory=list)
    tracked_secret_high_confidence: list[str] = field(default_factory=list)
    tracked_secret_low_confidence: list[str] = field(default_factory=list)
    tracked_secret_fixture_matches: list[str] = field(default_factory=list)
    tracked_secret_documentation_matches: list[str] = field(default_factory=list)
    tracked_path_matches: list[str] = field(default_factory=list)
    tracked_email_matches: list[str] = field(default_factory=list)
    tracked_email_high_confidence: list[str] = field(default_factory=list)
    tracked_email_low_confidence: list[str] = field(default_factory=list)
    tracked_secret_files: list[str] = field(default_factory=list)

    history_secret_matches: list[str] = field(default_factory=list)
    history_secret_high_confidence: list[str] = field(default_factory=list)
    history_secret_low_confidence: list[str] = field(default_factory=list)
    history_secret_fixture_matches: list[str] = field(default_factory=list)
    history_secret_documentation_matches: list[str] = field(default_factory=list)
    history_path_matches: list[str] = field(default_factory=list)
    history_email_matches: list[str] = field(default_factory=list)
    history_email_high_confidence: list[str] = field(default_factory=list)
    history_email_low_confidence: list[str] = field(default_factory=list)
    email_confidence_evaluated: bool = False
    secret_confidence_evaluated: bool = False
    low_confidence_email_mode: str = "informational"
    history_secret_files: list[str] = field(default_factory=list)
    git_metadata_secret_matches: list[str] = field(default_factory=list)
    git_metadata_secret_low_confidence: list[str] = field(default_factory=list)

    history_sensitive_added: list[str] = field(default_factory=list)
    history_sensitive_deleted: list[str] = field(default_factory=list)

    secret_file_candidates: list[str] = field(default_factory=list)
    secret_file_autopurge_candidates: list[str] = field(default_factory=list)
    secret_file_manual_review_candidates: list[str] = field(default_factory=list)
    secret_history_purge_paths: list[str] = field(default_factory=list)

    tracked_but_ignored: list[str] = field(default_factory=list)
    gitignore_missing_patterns: list[str] = field(default_factory=list)
    exfil_code_indicators: list[str] = field(default_factory=list)
    github_hardening_checked: bool = False
    github_hardening_findings: list[str] = field(default_factory=list)
    github_hardening_warnings: list[str] = field(default_factory=list)
    github_hardening_fix_guide: list[str] = field(default_factory=list)
    github_hardening_findings_blocking: bool = False
    strict_profile: str | None = None
    suppressed_findings: list[dict[str, str]] = field(default_factory=list)

    litellm_reference_hits: list[str] = field(default_factory=list)
    litellm_compromised_reference_hits: list[str] = field(default_factory=list)
    litellm_install_command_hits: list[str] = field(default_factory=list)
    litellm_ioc_hits: list[str] = field(default_factory=list)
    litellm_incident_severity: str = "NONE"

    backups_created: list[str] = field(default_factory=list)
    fix_actions: list[str] = field(default_factory=list)
    fix_errors: list[str] = field(default_factory=list)
    execution_errors: list[str] = field(default_factory=list)

    status: str = "PASS"
    failures: list[str] = field(default_factory=list)

    def finalize(self) -> None:
        owned_unexpected = (
            self.unexpected_emails_owned_repo
            if self.email_ownership_evaluated
            else self.unexpected_emails
        )
        owned_unexpected_identity_tokens = (
            self.unexpected_identity_tokens_owned_repo
            if self.email_ownership_evaluated
            else self.unexpected_identity_tokens
        )
        history_email_high_confidence = (
            self.history_email_high_confidence
            if self.email_confidence_evaluated
            else self.history_email_matches
        )
        low_confidence_emails = self.tracked_email_low_confidence + self.history_email_low_confidence
        low_confidence_blocking = self.low_confidence_email_mode == "blocking"
        tracked_secret_high_confidence = (
            self.tracked_secret_high_confidence
            if self.secret_confidence_evaluated
            else self.tracked_secret_matches
        )
        history_secret_high_confidence = (
            self.history_secret_high_confidence
            if self.secret_confidence_evaluated
            else self.history_secret_matches
        )
        worktree_dirty = repo_has_dirty_worktree(self.clean_status)

        checks = [
            (worktree_dirty, "working tree is not clean"),
            (not self.fsck_ok, "git fsck failed"),
            (bool(owned_unexpected), "unexpected commit metadata emails in owned repository"),
            (
                bool(owned_unexpected_identity_tokens),
                "unexpected commit metadata identity tokens in owned repository",
            ),
            (bool(tracked_secret_high_confidence), "secret-like patterns in tracked files"),
            (bool(self.git_metadata_secret_matches), "secret-like patterns in git metadata"),
            (bool(self.tracked_path_matches), "personal path patterns in tracked files"),
            (bool(history_secret_high_confidence), "secret-like patterns in history patches"),
            (bool(self.history_path_matches), "personal path patterns in history patches"),
            (
                bool(history_email_high_confidence),
                "high-confidence email addresses in history patches",
            ),
            (
                bool(low_confidence_blocking and low_confidence_emails),
                "low-confidence email matches configured as blocking",
            ),
            (bool(self.history_sensitive_added), "sensitive filenames added in history"),
            (bool(self.history_sensitive_deleted), "sensitive filenames deleted in history"),
            (bool(self.tracked_but_ignored), "tracked files that should be ignored"),
            (bool(self.gitignore_missing_patterns), "missing required .gitignore patterns"),
            (
                bool(self.litellm_incident_severity in {"CRITICAL", "HIGH"}),
                "LiteLLM supply-chain incident indicators detected",
            ),
            (
                bool(self.github_hardening_findings_blocking and self.github_hardening_findings),
                "GitHub hardening findings configured as blocking",
            ),
            (bool(self.fix_errors), "fix execution errors occurred"),
            (bool(self.execution_errors), "repository execution errors occurred"),
        ]
        self.failures = [reason for bad, reason in checks if bad]
        self.status = "FAIL" if self.failures else "PASS"


def print_report(report: RepoReport, logger: Callable[[str], None]) -> None:  # pragma: no cover
    decision_status, decision_message = email_remediation_decision(report)
    guidance_level, guidance_risk, guidance_consequence, guidance_suggestion = repo_user_guidance(report)
    logger(f"\n=== {report.name} ===")
    logger(f"path: {report.path}")
    logger(f"origin: {redact_sensitive_text(report.origin_url or '-')}")
    logger(f"upstream: {redact_sensitive_text(report.upstream_url or '-')}")
    logger(f"branch/head/upstream_head: {report.branch or '-'} / {report.head or '-'} / {report.origin_head or '-'}")
    logger(f"status: {report.status}")
    if report.failures:
        logger("failures:")
        for item in report.failures:
            logger(f"  - {item}")

    logger(f"low_confidence_email_mode: {report.low_confidence_email_mode}")
    logger(f"email_remediation_decision: {decision_status} - {decision_message}")
    logger(f"user_guidance: {guidance_level}")
    logger(f"risk: {guidance_risk}")
    logger(f"possible_consequence: {guidance_consequence}")
    logger(f"suggestion: {guidance_suggestion}")

    logger(f"unexpected_emails: {len(report.unexpected_emails)}")
    logger(f"unexpected_emails_owned_repo: {len(report.unexpected_emails_owned_repo)}")
    logger(f"unexpected_emails_third_party_repo: {len(report.unexpected_emails_third_party_repo)}")
    logger(f"unexpected_identity_tokens: {len(report.unexpected_identity_tokens)}")
    logger(
        f"unexpected_identity_tokens_owned_repo: {len(report.unexpected_identity_tokens_owned_repo)}"
    )
    logger(
        "unexpected_identity_tokens_third_party_repo: "
        f"{len(report.unexpected_identity_tokens_third_party_repo)}"
    )
    logger(f"tracked_secret_matches: {len(report.tracked_secret_matches)}")
    logger(f"tracked_secret_high_confidence: {len(report.tracked_secret_high_confidence)}")
    logger(f"tracked_secret_low_confidence: {len(report.tracked_secret_low_confidence)}")
    logger(f"tracked_secret_fixture_matches: {len(report.tracked_secret_fixture_matches)}")
    logger(f"tracked_secret_documentation_matches: {len(report.tracked_secret_documentation_matches)}")
    logger(f"tracked_secret_files: {len(report.tracked_secret_files)}")
    logger(f"git_metadata_secret_matches: {len(report.git_metadata_secret_matches)}")
    logger(f"git_metadata_secret_low_confidence: {len(report.git_metadata_secret_low_confidence)}")
    logger(f"tracked_path_matches: {len(report.tracked_path_matches)}")
    logger(f"tracked_email_matches: {len(report.tracked_email_matches)}")
    logger(f"tracked_email_high_confidence: {len(report.tracked_email_high_confidence)}")
    logger(f"tracked_email_low_confidence: {len(report.tracked_email_low_confidence)}")
    logger(f"history_secret_matches: {len(report.history_secret_matches)}")
    logger(f"history_secret_high_confidence: {len(report.history_secret_high_confidence)}")
    logger(f"history_secret_low_confidence: {len(report.history_secret_low_confidence)}")
    logger(f"history_secret_fixture_matches: {len(report.history_secret_fixture_matches)}")
    logger(f"history_secret_documentation_matches: {len(report.history_secret_documentation_matches)}")
    logger(f"history_secret_files: {len(report.history_secret_files)}")
    logger(f"history_path_matches: {len(report.history_path_matches)}")
    logger(f"history_email_matches: {len(report.history_email_matches)}")
    logger(f"history_email_high_confidence: {len(report.history_email_high_confidence)}")
    logger(f"history_email_low_confidence: {len(report.history_email_low_confidence)}")
    logger(f"history_sensitive_added: {len(report.history_sensitive_added)}")
    logger(f"history_sensitive_deleted: {len(report.history_sensitive_deleted)}")
    logger(f"secret_file_candidates: {len(report.secret_file_candidates)}")
    logger(f"secret_autopurge_candidates: {len(report.secret_file_autopurge_candidates)}")
    logger(f"secret_manual_review_candidates: {len(report.secret_file_manual_review_candidates)}")
    logger(f"tracked_but_ignored: {len(report.tracked_but_ignored)}")
    logger(f"gitignore_missing_patterns: {len(report.gitignore_missing_patterns)}")
    logger(f"exfil_code_indicators: {len(report.exfil_code_indicators)}")
    logger(f"exfil_indicator_mode: {EXFIL_INDICATOR_MODE}")
    logger(f"github_hardening_checked: {report.github_hardening_checked}")
    logger(f"github_hardening_findings: {len(report.github_hardening_findings)}")
    logger(f"github_hardening_warnings: {len(report.github_hardening_warnings)}")
    logger(f"github_hardening_fix_guide: {len(report.github_hardening_fix_guide)}")
    logger(f"suppressed_findings: {len(report.suppressed_findings)}")
    logger(f"github_hardening_mode: {GITHUB_HARDENING_MODE}")
    logger(f"litellm_incident_severity: {report.litellm_incident_severity}")
    logger(f"litellm_reference_hits: {len(report.litellm_reference_hits)}")
    logger(f"litellm_compromised_reference_hits: {len(report.litellm_compromised_reference_hits)}")
    logger(f"litellm_install_command_hits: {len(report.litellm_install_command_hits)}")
    logger(f"litellm_ioc_hits: {len(report.litellm_ioc_hits)}")
    logger(f"execution_errors: {len(report.execution_errors)}")

    if report.litellm_compromised_reference_hits:
        logger("litellm_compromised_reference_samples:")
        for item in report.litellm_compromised_reference_hits[:8]:
            logger(f"  - {item}")
    if report.litellm_ioc_hits:
        logger("litellm_ioc_samples:")
        for item in report.litellm_ioc_hits[:8]:
            logger(f"  - {item}")
    if report.exfil_code_indicators:
        logger("exfil_code_indicator_samples:")
        for item in report.exfil_code_indicators[:8]:
            logger(f"  - {item}")
    if report.github_hardening_findings:
        logger("github_hardening_findings_samples:")
        for item in report.github_hardening_findings[:8]:
            logger(f"  - {item}")
    if report.github_hardening_warnings:
        logger("github_hardening_warnings_samples:")
        for item in report.github_hardening_warnings[:8]:
            logger(f"  - {item}")

    detected_preview = build_detected_findings_preview(report)
    logger(f"detected_findings_preview: {len(detected_preview)}")
    if detected_preview:
        logger("detected_findings_preview_items:")
        for item in detected_preview[:12]:
            logger(f"  - {item}")
        if len(detected_preview) > 12:
            logger(f"  - ... and {len(detected_preview) - 12} more")

    planned_removals = build_planned_removals_preview(report)
    logger(f"planned_deletions_preview: {len(planned_removals)}")
    if planned_removals:
        logger("planned_deletions_preview_items:")
        for item in planned_removals:
            logger(f"  - {item}")

    if report.fix_actions:
        logger("fix_actions:")
        for action in report.fix_actions:
            logger(f"  - {action}")

    if report.fix_errors:
        logger("fix_errors:")
        for err in report.fix_errors:
            logger(f"  - {err}")
    if report.execution_errors:
        logger("execution_errors:")
        for err in report.execution_errors:
            logger(f"  - {err}")


def create_run_artifacts(base_dir: Path) -> RunArtifacts:
    return artifact_helpers.create_run_artifacts(
        base_dir,
        ensure_private_directory=ensure_private_directory,
        path_has_existing_symlink_ancestor=_path_has_existing_symlink_ancestor,
        apply_private_permissions=_apply_private_permissions,
        run_state_filename=RUN_STATE_FILENAME,
        now_factory=datetime.now,
    )


def enforce_results_dir(requested_dir: Path | None) -> tuple[Path, bool]:
    logical_base = default_results_dir()
    base = logical_base.resolve()
    safe_base = logical_base if _path_has_existing_symlink_ancestor(logical_base) else base
    if requested_dir is None:
        return safe_base, False

    if _path_has_existing_symlink_ancestor(requested_dir):
        return requested_dir, False

    requested = requested_dir.resolve()
    if requested == base:
        return requested, False

    try:
        requested.relative_to(base)
        return requested, False
    except ValueError:
        return safe_base, True


def resolve_optional_json_export_path(raw_value: str | None, default_name: str) -> Path | None:
    return artifact_helpers.resolve_optional_json_export_path(
        raw_value,
        default_name,
        ensure_private_directory=ensure_private_directory,
    )


def resolve_github_hardening_token(
    env: Mapping[str, str] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str | None:
    return github_helpers.resolve_github_hardening_token(
        env=env,
        runner=runner,
        read_cli_token=read_github_cli_token,
    )

from repo_privacy_guardian import tooling as tooling_helpers  # noqa: E402

_TOOLING_EXPORT_NAMES = (
    "_missing_executable_message",
    "probe_git_available",
    "probe_command_available",
    "probe_python_module_available",
    "probe_git_filter_repo_available",
    "resolve_windows_powershell",
    "probe_windows_winget_bootstrap_available",
    "build_winget_bootstrap_command",
    "build_windows_winget_tooling_check",
    "ensure_windows_winget_available",
    "build_system_tool_install_command",
    "format_install_command",
    "build_python_package_install_command",
    "collect_auto_installable_tooling_checks",
    "command_uses_executable",
    "build_github_optional_tooling_checks",
    "summarize_tooling_checks",
    "install_missing_tooling",
    "prompt_gui_tooling_install",
    "has_desktop_display",
    "load_gui_runtime",
    "build_github_tooling_check",
    "build_cli_tooling_checks",
    "build_gui_tooling_checks",
)
_TOOLING_ORIGINALS = {name: getattr(tooling_helpers, name) for name in _TOOLING_EXPORT_NAMES}
_TOOLING_SYNC_NAMES = (
    *_TOOLING_EXPORT_NAMES,
    "read_github_cli_token",
    "resolve_github_hardening_token",
)


def _sync_tooling_public_overrides() -> None:
    for name in _TOOLING_SYNC_NAMES:
        original = _TOOLING_ORIGINALS.get(name, getattr(tooling_helpers, name, None))
        current = globals().get(name, original)
        if getattr(current, "_rpg_tooling_wrapper", False):
            current = original
        if current is not None:
            setattr(tooling_helpers, name, current)


def _make_tooling_wrapper(name: str):
    original = _TOOLING_ORIGINALS[name]

    def wrapper(*args, **kwargs):
        _sync_tooling_public_overrides()
        return original(*args, **kwargs)

    wrapper.__name__ = name
    wrapper.__doc__ = getattr(original, "__doc__", None)
    wrapper._rpg_tooling_wrapper = True  # type: ignore[attr-defined]
    return wrapper


for _tooling_name in _TOOLING_EXPORT_NAMES:
    globals()[_tooling_name] = _make_tooling_wrapper(_tooling_name)
_missing_executable_message = globals()["_missing_executable_message"]
probe_git_available = globals()["probe_git_available"]
probe_command_available = globals()["probe_command_available"]
probe_python_module_available = globals()["probe_python_module_available"]
probe_git_filter_repo_available = globals()["probe_git_filter_repo_available"]
resolve_windows_powershell = globals()["resolve_windows_powershell"]
probe_windows_winget_bootstrap_available = globals()["probe_windows_winget_bootstrap_available"]
build_winget_bootstrap_command = globals()["build_winget_bootstrap_command"]
build_windows_winget_tooling_check = globals()["build_windows_winget_tooling_check"]
ensure_windows_winget_available = globals()["ensure_windows_winget_available"]
build_system_tool_install_command = globals()["build_system_tool_install_command"]
format_install_command = globals()["format_install_command"]
build_python_package_install_command = globals()["build_python_package_install_command"]
collect_auto_installable_tooling_checks = globals()["collect_auto_installable_tooling_checks"]
command_uses_executable = globals()["command_uses_executable"]
build_github_optional_tooling_checks = globals()["build_github_optional_tooling_checks"]
summarize_tooling_checks = globals()["summarize_tooling_checks"]
install_missing_tooling = globals()["install_missing_tooling"]
prompt_gui_tooling_install = globals()["prompt_gui_tooling_install"]
has_desktop_display = globals()["has_desktop_display"]
load_gui_runtime = globals()["load_gui_runtime"]
build_github_tooling_check = globals()["build_github_tooling_check"]
build_cli_tooling_checks = globals()["build_cli_tooling_checks"]
build_gui_tooling_checks = globals()["build_gui_tooling_checks"]

def audit_github_release_hardening(
    repo: Path,
    remote_url: str,
    token: str | None = None,
) -> tuple[list[str], list[str]]:
    return github_helpers.audit_github_release_hardening(
        repo=repo,
        remote_url=remote_url,
        token=token,
        token_resolver=resolve_github_hardening_token,
        json_getter=github_api_get_json,
        probe_enabled=github_api_probe_enabled,
        text_normalizer=normalize_text_values,
    )


def _github_clone_dir_name(remote: github_helpers.GitHubRemoteRepository) -> str:
    base = remote.name.strip() or remote.full_name.replace("/", "__")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._") or "repository"


def clone_github_remote_repository(
    remote: github_helpers.GitHubRemoteRepository,
    destination_root: Path,
    *,
    fast: bool,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> GitHubCloneResult:
    destination = destination_root / _github_clone_dir_name(remote)
    if remote.private:
        cmd = ["gh", "repo", "clone", remote.full_name, str(destination)]
        if fast:
            cmd.extend(["--", "--depth", "1"])
    else:
        clone_source = remote.clone_url or remote.html_url
        cmd = ["git", "clone", "--quiet"]
        if fast:
            cmd.extend(["--depth", "1"])
        cmd.extend([clone_source, str(destination)])

    try:
        proc = runner(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
            timeout=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        tool = "gh" if remote.private else "git"
        detail = (
            "private repository clone requires authenticated GitHub CLI (`gh repo clone`)"
            if remote.private
            else "Git executable not found"
        )
        return GitHubCloneResult(remote=remote, path=destination, error=f"{tool} unavailable: {detail}")
    except subprocess.TimeoutExpired:
        return GitHubCloneResult(
            remote=remote,
            path=destination,
            error=f"clone timed out after {DEFAULT_SUBPROCESS_TIMEOUT_SECONDS}s",
        )
    except Exception as exc:
        return GitHubCloneResult(remote=remote, path=destination, error=f"clone failed to start: {exc}")

    if proc.returncode != 0:
        detail = redact_sensitive_text((proc.stderr or proc.stdout or "unknown clone failure").strip())
        return GitHubCloneResult(remote=remote, path=destination, error=f"clone failed: {detail[:240]}")
    if not is_git_repository(destination):
        return GitHubCloneResult(remote=remote, path=destination, error="clone completed but no .git directory was found")
    return GitHubCloneResult(remote=remote, path=destination)


def clone_github_remote_repositories(
    remotes: list[github_helpers.GitHubRemoteRepository],
    destination_root: Path,
    *,
    fast: bool,
    jobs: int,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[GitHubCloneResult]:
    if not remotes:
        return []
    max_workers = normalize_github_jobs(jobs)
    if max_workers == 1 or len(remotes) == 1:
        return [
            clone_github_remote_repository(remote, destination_root, fast=fast, runner=runner)
            for remote in remotes
        ]

    indexed: dict[int, GitHubCloneResult] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                clone_github_remote_repository,
                remote,
                destination_root,
                fast=fast,
                runner=runner,
            ): index
            for index, remote in enumerate(remotes)
        }
        for future in as_completed(futures):
            index = futures[future]
            try:
                indexed[index] = future.result()
            except Exception as exc:
                remote = remotes[index]
                indexed[index] = GitHubCloneResult(
                    remote=remote,
                    path=destination_root / _github_clone_dir_name(remote),
                    error=f"unexpected clone worker failure: {exc}",
                )
    return [indexed[index] for index in sorted(indexed)]


def build_github_clone_failure_report(result: GitHubCloneResult) -> RepoReport:
    report = RepoReport(name=result.remote.name, path=str(result.path))
    report.origin_url = result.remote.html_url or result.remote.clone_url or None
    report.execution_errors.append(f"GitHub remote clone failed for {result.remote.full_name}: {result.error}")
    report.finalize()
    return report


def prepare_github_remote_audit_repositories(
    config: GuardRunConfig,
    logger: Callable[[str], None],
) -> tuple[list[Path], list[RepoReport], Path | None, str | None]:
    owner = (config.github_owner or "").strip()
    token = resolve_github_hardening_token()
    remotes, warnings = fetch_github_owner_repositories(
        owner,
        token=token,
        include_forks=config.github_include_forks,
        public_only=config.public_only,
        repo_names=config.repos,
    )
    for warning in warnings:
        logger(f"[WARN] {warning}")

    if not remotes:
        requested = f" matching --repos {', '.join(config.repos)}" if config.repos else ""
        public_filter = " public" if config.public_only else ""
        return (
            [],
            [],
            None,
            f"No{public_filter} GitHub repositories{requested} were discovered for {owner}.",
        )

    temp_root = Path(tempfile.mkdtemp(prefix="repo-privacy-guardian-github-"))
    ensure_private_directory(temp_root)
    logger(
        f"[INFO] GitHub remote audit discovered {len(remotes)} repositories for {owner}; "
        f"cloning with {normalize_github_jobs(config.github_jobs)} worker(s)."
    )
    clone_results = clone_github_remote_repositories(
        remotes,
        temp_root,
        fast=config.github_fast,
        jobs=config.github_jobs,
    )

    repos: list[Path] = []
    failure_reports: list[RepoReport] = []
    for result in clone_results:
        if result.error:
            failure_reports.append(build_github_clone_failure_report(result))
        else:
            repos.append(result.path)

    return repos, failure_reports, temp_root, None

from repo_privacy_guardian import redaction as redaction_helpers  # noqa: E402

is_relevant_email_candidate = redaction_helpers.is_relevant_email_candidate
extract_email_match_context = redaction_helpers.extract_email_match_context
is_low_confidence_email_context = redaction_helpers.is_low_confidence_email_context
extract_secret_match_context = redaction_helpers.extract_secret_match_context
classify_secret_match_context = redaction_helpers.classify_secret_match_context
split_email_matches_by_confidence = redaction_helpers.split_email_matches_by_confidence
extract_personal_path_literals = redaction_helpers.extract_personal_path_literals
split_unexpected_emails_by_origin_ownership = redaction_helpers.split_unexpected_emails_by_origin_ownership
_redact_low_confidence_secret_assignment = redaction_helpers._redact_low_confidence_secret_assignment
redact_sensitive_text = redaction_helpers.redact_sensitive_text
_redact_email_list = redaction_helpers._redact_email_list
_redact_identity_list = redaction_helpers._redact_identity_list
_redact_text_list = redaction_helpers._redact_text_list
from repo_privacy_guardian import reporting as reporting_helpers  # noqa: E402

sanitize_report_for_export = reporting_helpers.sanitize_report_for_export
validate_fix_preconditions = reporting_helpers.validate_fix_preconditions
build_fix_preflight_summary = reporting_helpers.build_fix_preflight_summary
email_decision_context = reporting_helpers.email_decision_context
email_remediation_decision = reporting_helpers.email_remediation_decision
repo_user_guidance = reporting_helpers.repo_user_guidance
classify_repo_severity = reporting_helpers.classify_repo_severity
classify_litellm_incident_severity = reporting_helpers.classify_litellm_incident_severity
build_detected_findings_preview = reporting_helpers.build_detected_findings_preview
build_planned_removals_preview = reporting_helpers.build_planned_removals_preview
report_contains_sensitive_findings = reporting_helpers.report_contains_sensitive_findings
render_html_report = reporting_helpers.render_html_report
persist_run_outputs = reporting_helpers.persist_run_outputs
open_html_report_in_browser = reporting_helpers.open_html_report_in_browser
AGENT_SUMMARY_SCHEMA_VERSION = agent_summary_helpers.AGENT_SUMMARY_SCHEMA_VERSION
build_agent_summary = agent_summary_helpers.build_agent_summary
format_agent_summary_handoff = agent_summary_helpers.format_agent_summary_handoff

def build_run_settings(config: GuardRunConfig, results_dir: Path) -> dict[str, str]:
    return {
        "mode": config.mode,
        "root": str(config.root),
        "policy": str(config.policy),
        "public_only": str(config.public_only),
        "fix": str(config.fix),
        "push": str(config.push),
        "dry_run": str(config.dry_run),
        "purge_detected_secret_files": str(config.purge_detected_secret_files),
        "purge_all_detected_secret_files": str(config.purge_all_detected_secret_files),
        "audit_litellm_incident": str(config.audit_litellm_incident),
        "audit_github_hardening": str(config.audit_github_hardening),
        "rewrite_personal_paths": str(config.rewrite_personal_paths),
        "open_report": str(config.open_report),
        "low_confidence_email_mode": config.low_confidence_email_mode,
        "redact_third_party_emails": str(config.redact_third_party_emails),
        "max_matches": str(config.max_matches),
        "confirm_each_repo_fix": str(config.confirm_each_repo_fix),
        "allow_non_owner_push": str(config.allow_non_owner_push),
        "allowed_remote_owners": ",".join(config.allowed_remote_owners),
        "replace_text_file": str(config.replace_text_file or ""),
        "exfil_indicator_mode": EXFIL_INDICATOR_MODE,
        "results_dir": str(results_dir),
        "report_json": str(config.report_json or ""),
        "github_owner": str(config.github_owner or ""),
        "github_include_forks": str(config.github_include_forks),
        "github_fast": str(config.github_fast),
        "github_jobs": str(config.github_jobs),
        "agent_summary": str(config.agent_summary),
        "strict_profile": str(config.strict_profile or ""),
        "github_hardening_findings_blocking": str(config.github_hardening_findings_blocking),
        "suppressions": str(config.suppressions or ""),
    }


def load_configured_suppressions(config: GuardRunConfig) -> list[suppression_helpers.SuppressionRule]:
    if not config.suppressions:
        return []
    return suppression_helpers.load_suppression_rules(Path(config.suppressions))


def apply_report_policy_post_processing(
    report: RepoReport,
    *,
    config: GuardRunConfig,
    suppression_rules: list[suppression_helpers.SuppressionRule],
) -> None:
    report.strict_profile = config.strict_profile
    report.github_hardening_findings_blocking = config.github_hardening_findings_blocking
    if (report.github_hardening_findings or report.github_hardening_warnings) and not report.github_hardening_fix_guide:
        report.github_hardening_fix_guide = github_fix_guide.build_github_hardening_fix_guide(
            report.github_hardening_findings,
            report.github_hardening_warnings,
        )
    suppressed = suppression_helpers.apply_suppression_rules(
        report,
        suppression_rules,
        redact_sensitive_text=redact_sensitive_text,
    )
    if suppressed:
        report.suppressed_findings.extend(suppressed)
    report.finalize()


def execute_guard_pipeline(
    config: GuardRunConfig,
    artifacts: RunArtifacts,
    logger: Callable[[str], None],
    results_dir: Path,
    require_confirmation: bool = False,
    confirm_callback: Callable[[], bool] | None = None,
    confirm_repo_fix_callback: Callable[[Path, int, int], bool] | None = None,
    cancel_callback: Callable[[], bool] | None = None,
) -> int:
    run_settings = build_run_settings(config, results_dir)
    reports: list[RepoReport] = []
    supply_chain_payload: dict[str, object] | None = None
    exit_code = EXIT_OK
    total_repositories = 0
    remote_temp_root: Path | None = None
    remote_no_targets_error: str | None = None
    state_tracker = RunStateTracker(artifacts.state_path, artifacts=artifacts, config=config)
    run_metrics = metrics_helpers.RunMetrics()
    suppression_rules: list[suppression_helpers.SuppressionRule] = []

    guard_kwargs: dict[str, object] = {
        "root": config.root,
        "policy_path": config.policy,
        "noreply_email": config.noreply_email,
        "placeholder_email": config.placeholder_email,
        "owner_name": config.owner_name,
        "owner_emails": config.owner_emails,
        "redact_third_party": config.redact_third_party_emails,
        "purge_detected_secret_files": config.purge_detected_secret_files,
        "purge_all_detected_secret_files": config.purge_all_detected_secret_files,
        "low_confidence_email_mode": config.low_confidence_email_mode,
        "push": config.push,
        "dry_run": config.dry_run,
        "max_matches": config.max_matches,
        "audit_litellm_incident": config.audit_litellm_incident,
        "audit_github_hardening": config.audit_github_hardening,
        "allow_non_owner_push": config.allow_non_owner_push,
        "allowed_remote_owners": config.allowed_remote_owners,
        "replace_text_file": config.replace_text_file,
        "logger": logger,
    }

    guard_init_params = inspect.signature(RepoPublicationGuard.__init__).parameters
    guard_kwargs = {
        key: value
        for key, value in guard_kwargs.items()
        if key in guard_init_params
    }
    guard = cast(Any, RepoPublicationGuard)(**guard_kwargs)
    guard.rewrite_personal_paths = config.rewrite_personal_paths

    def cancellation_requested() -> bool:
        if cancel_callback is None:
            return False
        try:
            return bool(cancel_callback())
        except Exception:
            return False

    def mark_aborted(message: str, *, phase: str, completed: int, total: int) -> None:
        nonlocal exit_code
        logger(f"[INFO] {message}")
        logger(f"\n[SUMMARY] ABORTED {completed}/{total}")
        exit_code = EXIT_ABORTED
        state_tracker.update(
            phase=phase,
            total_repositories=total,
            completed_repositories=completed,
            current_repository="",
        )

    try:
        preflight_started = run_metrics.begin_phase()
        state_tracker.update(phase="preflight")
        git_ok, git_error = probe_git_available()
        if not git_ok:
            logger(f"[ERROR] {git_error}")
            exit_code = EXIT_RUNTIME_ERROR
        elif strict_profile_errors := strict_profiles.validate_strict_profile_runtime(
            profile=config.strict_profile,
            fix=config.fix,
            push=config.push,
        ):
            for error in strict_profile_errors:
                logger(f"[ERROR] {error}")
            logger("\n[SUMMARY] ERROR 0/0")
            exit_code = EXIT_RUNTIME_ERROR
            state_tracker.update(
                phase="invalid-config",
                total_repositories=0,
                completed_repositories=0,
                current_repository="",
            )
        elif config.github_owner and (config.fix or config.push):
            logger("[ERROR] --github-owner is audit-only and cannot be combined with --fix or --push.")
            logger("\n[SUMMARY] ERROR 0/0")
            exit_code = EXIT_RUNTIME_ERROR
            state_tracker.update(
                phase="invalid-config",
                total_repositories=0,
                completed_repositories=0,
                current_repository="",
            )
        else:
            if config.suppressions:
                try:
                    suppression_rules = load_configured_suppressions(config)
                    logger(f"[INFO] Loaded {len(suppression_rules)} suppression rule(s).")
                except ValueError as exc:
                    logger(f"[ERROR] Suppression file rejected: {exc}")
                    logger("\n[SUMMARY] ERROR 0/0")
                    exit_code = EXIT_RUNTIME_ERROR
                    state_tracker.update(
                        phase="invalid-config",
                        total_repositories=0,
                        completed_repositories=0,
                        current_repository="",
                    )
                    return exit_code
            run_metrics.end_phase("preflight", preflight_started)
            state_tracker.update(performance=run_metrics.snapshot())
            if config.low_confidence_email_mode == "blocking":
                logger("[INFO] Email policy: low-confidence findings are blocking.")
            else:
                logger("[INFO] Email policy: low-confidence findings are informational.")
            if config.strict_profile:
                logger(f"[INFO] Strict profile: {strict_profiles.describe_strict_profile(config.strict_profile)}")
            if config.audit_github_hardening:
                if config.github_hardening_findings_blocking:
                    logger("[INFO] GitHub hardening audit enabled: findings are blocking under release profile.")
                else:
                    logger(
                        "[INFO] GitHub hardening audit enabled: advisory/manual-review only by default."
                    )
            if config.github_owner:
                logger(
                    "[INFO] GitHub remote audit enabled: repositories are cloned into a temporary private directory."
                )

            if config.purge_all_detected_secret_files and not config.purge_detected_secret_files:
                logger("[WARN] --purge-all-detected-secret-files implies --purge-detected-secret-files")
                guard.purge_detected_secret_files = True
                run_settings["purge_detected_secret_files"] = str(True)

            repos: list[Path] = []
            if cancellation_requested():
                mark_aborted(
                    "Run cancelled by operator before repository discovery.",
                    phase="aborted",
                    completed=0,
                    total=0,
                )
            else:
                discovery_started = run_metrics.begin_phase()
                if config.github_owner:
                    state_tracker.update(phase="github-discovery")
                    try:
                        repos, clone_failure_reports, remote_temp_root, remote_no_targets_error = (
                            prepare_github_remote_audit_repositories(config, logger)
                        )
                        for failure_report in clone_failure_reports:
                            apply_report_policy_post_processing(
                                failure_report,
                                config=config,
                                suppression_rules=suppression_rules,
                            )
                            reports.append(failure_report)
                            print_report(failure_report, logger)
                    except Exception as exc:
                        logger(f"[ERROR] GitHub remote audit setup failed: {exc}")
                        logger(traceback.format_exc())
                        logger("\n[SUMMARY] ERROR 0/0")
                        exit_code = EXIT_RUNTIME_ERROR
                        state_tracker.update(
                            phase="invalid-config",
                            total_repositories=0,
                            completed_repositories=0,
                            current_repository="",
                        )
                else:
                    root_error = validate_repository_root(config.root)
                    if root_error:
                        logger(f"[ERROR] {root_error}")
                        logger("\n[SUMMARY] ERROR 0/0")
                        exit_code = EXIT_RUNTIME_ERROR
                        state_tracker.update(
                            phase="invalid-config",
                            total_repositories=0,
                            completed_repositories=0,
                            current_repository="",
                        )
                    else:
                        try:
                            repos = guard.discover_repositories(config.repos, public_only=config.public_only)
                        except RuntimeError as exc:
                            if not str(exc).startswith("Root "):
                                raise
                            logger(f"[ERROR] {exc}")
                            logger("\n[SUMMARY] ERROR 0/0")
                            exit_code = EXIT_RUNTIME_ERROR
                            repos = []
                            state_tracker.update(
                                phase="invalid-config",
                                total_repositories=0,
                                completed_repositories=0,
                                current_repository="",
                            )
                run_metrics.end_phase("discovery", discovery_started)
                state_tracker.update(performance=run_metrics.snapshot())
            total_repositories = len(repos) + len(reports)
            if exit_code == EXIT_OK:
                state_tracker.update(
                    phase="discovered",
                    total_repositories=total_repositories,
                    completed_repositories=len(reports),
                    current_repository="",
                )
            if not repos:
                if exit_code != EXIT_OK:
                    pass
                elif reports:
                    failed = sum(1 for rep in reports if rep.status != "PASS")
                    summary_status = "PASS" if failed == 0 else "FAIL"
                    summary_count = len(reports) - failed if failed == 0 else failed
                    logger(f"\n[SUMMARY] {summary_status} {summary_count}/{len(reports)}")
                    exit_code = EXIT_OK if failed == 0 else EXIT_POLICY_FAILED
                elif config.github_owner and remote_no_targets_error:
                    logger(f"[ERROR] {remote_no_targets_error}")
                    logger("[ERROR] Check --github-owner, auth/rate limits, --repos filters, fork filtering, or --public-only.")
                    logger("\n[SUMMARY] ERROR 0/0")
                    exit_code = EXIT_RUNTIME_ERROR
                    state_tracker.update(
                        phase="no-targets",
                        total_repositories=0,
                        completed_repositories=0,
                        current_repository="",
                    )
                else:
                    no_targets_error, no_targets_guidance = describe_no_target_resolution(
                        root=config.root,
                        repo_filters=config.repos,
                        public_only=config.public_only,
                    )
                    logger(f"[ERROR] {no_targets_error}")
                    logger(no_targets_guidance)
                    logger("\n[SUMMARY] ERROR 0/0")
                    exit_code = EXIT_RUNTIME_ERROR
                    state_tracker.update(
                        phase="no-targets",
                        total_repositories=0,
                        completed_repositories=0,
                        current_repository="",
                    )
            else:
                if config.fix:
                    for line in build_fix_preflight_summary(config, repos):
                        logger(line)

                if config.fix and config.push and require_confirmation:
                    confirmed = confirm_callback() if confirm_callback else False
                    if not confirmed:
                        mark_aborted(
                            "Run aborted by user confirmation gate.",
                            phase="aborted",
                            completed=0,
                            total=0,
                        )
                        repos = []
                        total_repositories = 0

                completed_repo_iterations = 0
                for index, repo in enumerate(repos, start=1):
                    if cancellation_requested():
                        mark_aborted(
                            "Run cancelled by operator before the next repository started.",
                            phase="aborted",
                            completed=len(reports),
                            total=total_repositories,
                        )
                        break

                    repo_name = repo_display_name(repo)
                    state_tracker.update(
                        phase="fixing" if config.fix else "auditing",
                        current_repository=repo_name,
                        completed_repositories=len(reports),
                        total_repositories=total_repositories,
                    )
                    repo_lock: RepoExecutionLock | None = None
                    report = RepoReport(name=repo_name, path=str(repo))
                    report.low_confidence_email_mode = config.low_confidence_email_mode

                    try:
                        acquire_repo_lock = getattr(guard, "acquire_repo_lock", None)
                        if callable(acquire_repo_lock):
                            repo_lock = cast(RepoExecutionLock | None, acquire_repo_lock(repo))
                        logger(f"[AUDIT] {repo_name}")
                        audit_started = run_metrics.begin_phase()
                        report = guard.audit_repo(repo)
                        audit_elapsed = time.perf_counter() - audit_started
                        run_metrics.end_phase("audit", audit_started)
                        run_metrics.add_repo_timing(repo_name, "audit", audit_elapsed)

                        if config.fix:
                            run_fix = True
                            if config.confirm_each_repo_fix and confirm_repo_fix_callback:
                                run_fix = bool(confirm_repo_fix_callback(repo, index, len(repos)))

                            if cancellation_requested():
                                logger(
                                    f"[INFO] {repo_name}: repair skipped because the run was cancelled."
                                )
                                report.fix_actions.append("repair skipped because the run was cancelled")
                            elif run_fix:
                                logger(f"[FIX] {repo_name}")
                                fix_started = run_metrics.begin_phase()
                                fixed = guard.apply_fixes(repo, report)
                                fix_elapsed = time.perf_counter() - fix_started
                                run_metrics.end_phase("fix", fix_started)
                                run_metrics.add_repo_timing(repo_name, "fix", fix_elapsed)
                                logger(f"[RE-AUDIT] {repo_name}")
                                reaudit_started = run_metrics.begin_phase()
                                report = guard.audit_repo(repo)
                                reaudit_elapsed = time.perf_counter() - reaudit_started
                                run_metrics.end_phase("re-audit", reaudit_started)
                                run_metrics.add_repo_timing(repo_name, "re-audit", reaudit_elapsed)
                                report.backups_created = fixed.backups_created
                                report.fix_actions = fixed.fix_actions
                                report.fix_errors = fixed.fix_errors
                            else:
                                report.fix_actions.append("fix skipped by per-repository confirmation gate")
                    except Exception as exc:
                        report.execution_errors.append(str(exc))
                        logger(f"[ERROR] {repo_name}: repository execution failed: {exc}")
                        logger(traceback.format_exc())
                    finally:
                        release_repo_lock = getattr(guard, "release_repo_lock", None)
                        if callable(release_repo_lock):
                            release_repo_lock(repo_lock)

                    apply_report_policy_post_processing(
                        report,
                        config=config,
                        suppression_rules=suppression_rules,
                    )
                    reports.append(report)
                    completed_repo_iterations += 1
                    print_report(report, logger)
                    state_tracker.update(
                        phase="fixing" if config.fix else "auditing",
                        current_repository="",
                        completed_repositories=len(reports),
                        total_repositories=total_repositories,
                        performance=run_metrics.snapshot(),
                    )

                if repos and exit_code == EXIT_OK and cancellation_requested() and completed_repo_iterations < len(repos):
                    mark_aborted(
                        "Run cancelled by operator after the active repository finished.",
                        phase="aborted",
                        completed=len(reports),
                        total=total_repositories,
                    )

                if repos and exit_code != EXIT_ABORTED:
                    passed = sum(1 for rep in reports if rep.status == "PASS")
                    failed = len(reports) - passed
                    summary_status = "PASS" if failed == 0 else "FAIL"
                    summary_count = passed if failed == 0 else failed
                    logger(f"\n[SUMMARY] {summary_status} {summary_count}/{len(reports)}")
                    if exit_code == EXIT_OK and reports:
                        exit_code = EXIT_OK if failed == 0 else EXIT_POLICY_FAILED

        if config.audit_litellm_incident and exit_code not in {EXIT_ABORTED, EXIT_RUNTIME_ERROR}:
            if cancellation_requested():
                mark_aborted(
                    "Run cancelled by operator before the supply-chain audit started.",
                    phase="aborted",
                    completed=len(reports),
                    total=max(total_repositories, len(reports)),
                )
            else:
                state_tracker.update(phase="supply-chain")
                supply_chain_root = remote_temp_root if config.github_owner and remote_temp_root else config.root
                supply_chain_repo_filters = None if config.github_owner else config.repos
                supply_chain_payload = run_litellm_global_supply_chain_scan(
                    root=supply_chain_root,
                    repo_filters=supply_chain_repo_filters,
                    max_matches=config.max_matches,
                    logger=logger,
                )
                global_severity = str(supply_chain_payload.get("severity", "NONE")).upper()
                if global_severity in {"CRITICAL", "HIGH"} and exit_code == EXIT_OK:
                    logger(
                        "[SUPPLY-CHAIN] Global incident severity is HIGH/CRITICAL. "
                        "Run marked as FAIL-equivalent for operator action."
                    )
                    exit_code = EXIT_POLICY_FAILED
    except Exception as exc:
        logger(f"[ERROR] Unhandled runtime error: {exc}")
        logger(traceback.format_exc())
        exit_code = EXIT_RUNTIME_ERROR
    finally:
        try:
            state_tracker.update(
                phase="persisting",
                current_repository="",
                completed_repositories=len(reports),
                total_repositories=max(total_repositories, len(reports)),
            )
        except Exception:
            pass

        try:
            persist_started = run_metrics.begin_phase()
            persist_kwargs: dict[str, Any] = {
                "reports": reports,
                "artifacts": artifacts,
                "root_path": config.root,
                "policy_path": config.policy,
                "run_settings": run_settings,
                "logger": logger,
                "optional_json_export": config.report_json,
                "optional_supply_chain_payload": supply_chain_payload,
                "exit_code": exit_code,
            }

            persist_params = inspect.signature(persist_run_outputs).parameters
            if "optional_supply_chain_payload" not in persist_params:
                persist_kwargs.pop("optional_supply_chain_payload", None)
            if "exit_code" not in persist_params:
                persist_kwargs.pop("exit_code", None)
            cast(Any, persist_run_outputs)(**persist_kwargs)
            run_metrics.end_phase("report_persistence", persist_started)
            if config.audit_litellm_incident and supply_chain_payload is not None:
                persist_litellm_supply_chain_output(
                    artifacts=artifacts,
                    payload=supply_chain_payload,
                    logger=logger,
                )
            if config.open_report:
                open_html_report_in_browser(artifacts.html_path, logger)
        except Exception as exc:
            logger(f"[ERROR] Failed to finalize run artifacts: {exc}")
            logger(traceback.format_exc())
            exit_code = EXIT_RUNTIME_ERROR
        finally:
            if remote_temp_root is not None:
                cleanup_started = run_metrics.begin_phase()
                removed, cleanup_error = remove_private_temp_tree(
                    remote_temp_root,
                    required_prefix="repo-privacy-guardian-github-",
                )
                run_metrics.end_phase("remote_clone_cleanup", cleanup_started)
                if removed:
                    logger("[INFO] Removed temporary GitHub clone directory.")
                else:
                    logger(f"[WARN] Could not remove temporary GitHub clone directory: {cleanup_error}")
            passed = sum(1 for rep in reports if rep.status == "PASS")
            failed = len(reports) - passed
            try:
                state_tracker.update(
                    status=resolve_run_status(exit_code),
                    phase="finished",
                    current_repository="",
                    completed_repositories=len(reports),
                    total_repositories=max(total_repositories, len(reports)),
                    pass_count=passed,
                    fail_count=failed,
                    exit_code=exit_code,
                    performance=run_metrics.snapshot(),
                )
            except Exception:
                pass

    return exit_code


def parse_positive_int(raw_value: str) -> int:
    try:
        parsed = int(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def normalize_github_jobs(value: int) -> int:
    return min(MAX_GITHUB_CLONE_JOBS, max(1, value))


def is_github_noreply_email(email: str) -> bool:
    lowered = email.strip().lower()
    if not lowered:
        return False
    return lowered == DEFAULT_NOREPLY or lowered.endswith("@users.noreply.github.com")


def validate_git_identity_inputs(user_name: str, user_email: str) -> list[str]:
    errors: list[str] = []
    normalized_name = user_name.strip()
    normalized_email = user_email.strip()

    if not normalized_name:
        errors.append("git user.name is required.")

    if not normalized_email:
        errors.append("git user.email is required.")
    elif not SIMPLE_EMAIL_RE.match(normalized_email):
        errors.append("git user.email must be a valid email address.")
    elif not is_github_noreply_email(normalized_email):
        errors.append(
            "git user.email should be a GitHub noreply address "
            "(for example: <id+username>@users.noreply.github.com)."
        )

    return errors


def run_git_command(args: list[str], cwd: Path | None = None) -> CommandResult:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
            timeout=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return CommandResult(127, "", _missing_executable_message("git"))
    except subprocess.TimeoutExpired:
        return CommandResult(124, "", f"git command timed out after {DEFAULT_SUBPROCESS_TIMEOUT_SECONDS}s")
    except Exception as exc:
        return CommandResult(1, "", f"Unable to execute git {' '.join(args)}: {exc}")
    return CommandResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())


def apply_git_identity_config(
    scope: str,
    user_name: str,
    user_email: str,
    repo_path: Path | None = None,
    git_runner: Callable[[list[str], Path | None], CommandResult] | None = None,
) -> tuple[bool, str]:
    validation_errors = validate_git_identity_inputs(user_name, user_email)
    if validation_errors:
        return False, " ".join(validation_errors)

    normalized_scope = scope.strip().lower()
    if normalized_scope not in {"global", "local"}:
        return False, "Unsupported git config scope. Use 'global' or 'local'."

    if normalized_scope == "local" and repo_path is None:
        return False, "Local git config requires a target repository path."

    runner = git_runner or run_git_command
    scope_flag = "--global" if normalized_scope == "global" else "--local"
    target_cwd = repo_path if normalized_scope == "local" else None

    for key, value in (("user.name", user_name.strip()), ("user.email", user_email.strip())):
        result = runner(["config", scope_flag, key, value], target_cwd)
        if result.returncode != 0:
            detail = result.stderr or result.stdout or "Unknown git error."
            return False, f"Failed to set {key} ({normalized_scope}): {detail}"

    target = str(repo_path) if repo_path else "global git configuration"
    return True, f"Applied {normalized_scope.upper()} git identity on {target}."


def _read_git_config_value(
    key: str,
    scope_args: list[str],
    repo_path: Path | None,
    git_runner: Callable[[list[str], Path | None], CommandResult],
) -> str:
    result = git_runner(["config", *scope_args, "--get", key], repo_path)
    if result.returncode == 0:
        value = result.stdout.strip()
        return value if value else "(not set)"

    detail = (result.stderr or result.stdout).strip()
    if detail:
        return f"(error: {detail})"
    return "(not set)"


def read_git_identity_config(
    repo_path: Path | None = None,
    git_runner: Callable[[list[str], Path | None], CommandResult] | None = None,
) -> dict[str, str]:
    runner = git_runner or run_git_command

    values = {
        "global.user.name": _read_git_config_value("user.name", ["--global"], None, runner),
        "global.user.email": _read_git_config_value("user.email", ["--global"], None, runner),
    }

    if repo_path is None:
        values["local.user.name"] = "(n/a - select one repository)"
        values["local.user.email"] = "(n/a - select one repository)"
        values["effective.user.name"] = "(n/a - select one repository)"
        values["effective.user.email"] = "(n/a - select one repository)"
        return values

    values["local.user.name"] = _read_git_config_value("user.name", ["--local"], repo_path, runner)
    values["local.user.email"] = _read_git_config_value("user.email", ["--local"], repo_path, runner)
    values["effective.user.name"] = _read_git_config_value("user.name", [], repo_path, runner)
    values["effective.user.email"] = _read_git_config_value("user.email", [], repo_path, runner)
    return values


def format_git_identity_status(config_values: dict[str, str], repo_path: Path | None) -> str:
    repo_label = str(repo_path) if repo_path else "n/a"
    return "\n".join(
        [
            "Git identity status",
            f"Repository context: {repo_label}",
            "",
            f"Global user.name: {config_values.get('global.user.name', '(unknown)')}",
            f"Global user.email: {config_values.get('global.user.email', '(unknown)')}",
            f"Local user.name: {config_values.get('local.user.name', '(unknown)')}",
            f"Local user.email: {config_values.get('local.user.email', '(unknown)')}",
            f"Effective user.name: {config_values.get('effective.user.name', '(unknown)')}",
            f"Effective user.email: {config_values.get('effective.user.email', '(unknown)')}",
        ]
    )


def open_github_email_settings(
    opener: Callable[[str], bool] | None = None,
) -> tuple[bool, str]:
    open_url = opener or webbrowser.open
    try:
        opened = bool(open_url(GITHUB_EMAIL_SETTINGS_URL))
    except Exception as exc:
        return False, f"Unable to open {GITHUB_EMAIL_SETTINGS_URL}: {exc}"

    if not opened:
        return False, f"Browser could not open {GITHUB_EMAIL_SETTINGS_URL}. Open it manually."

    return True, f"Opened {GITHUB_EMAIL_SETTINGS_URL}."


def resolve_identity_repo_path(root: Path, selected_repo_names: list[str]) -> tuple[Path | None, str | None]:
    if len(selected_repo_names) > 1:
        return None, "Select exactly one repository to apply LOCAL git config."

    if len(selected_repo_names) == 1:
        candidate = root / selected_repo_names[0]
        if (candidate / ".git").exists():
            return candidate, None
        return None, f"Selected path is not a git repository: {candidate}"

    if (root / ".git").exists():
        return root, None

    return None, "Select one repository first (or set Root to a git repository)."


def normalize_repo_filters(repo_names: list[str]) -> list[str] | None:
    return repo_names if repo_names else None


def normalize_csv_values(raw_value: str) -> list[str]:
    if not raw_value:
        return []
    return list(dict.fromkeys(item.strip() for item in raw_value.split(",") if item.strip()))


def normalize_text_values(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))


from repo_privacy_guardian.scanner import RepoPublicationGuard  # noqa: E402

def default_gui_settings_path(env: Mapping[str, str] | None = None) -> Path:
    current_env = os.environ if env is None else env
    override = (current_env.get(GUI_SETTINGS_ENV_VAR) or "").strip()
    if override:
        return Path(override).expanduser()

    if os.name == "nt":
        base = current_env.get("LOCALAPPDATA") or current_env.get("APPDATA")
        if base:
            return Path(base) / "RepoPrivacyGuardian" / "gui_settings.json"

    xdg_config = (current_env.get("XDG_CONFIG_HOME") or "").strip()
    if xdg_config:
        return Path(xdg_config).expanduser() / "repo-privacy-guardian" / "gui_settings.json"

    return Path.home() / ".config" / "repo-privacy-guardian" / "gui_settings.json"


def load_gui_settings(path: Path | None = None) -> dict[str, object]:
    settings_path = path or default_gui_settings_path()
    try:
        if not settings_path.exists() or settings_path.is_symlink():
            return {}
        if settings_path.stat().st_size > GUI_SETTINGS_MAX_BYTES:
            return {}
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(payload, dict):
        return {}
    try:
        schema_version = int(payload.get("schema_version") or 0)
    except (TypeError, ValueError):
        return {}
    if schema_version != GUI_SETTINGS_SCHEMA_VERSION:
        return {}
    return payload


def save_gui_settings(path: Path, payload: dict[str, object]) -> None:
    safe_payload = dict(payload)
    safe_payload["schema_version"] = GUI_SETTINGS_SCHEMA_VERSION
    write_private_json_file(path, safe_payload)


def gui_setting_str(settings: Mapping[str, object], key: str, default: str) -> str:
    value = settings.get(key)
    if isinstance(value, str):
        return value
    return default


def gui_setting_bool(settings: Mapping[str, object], key: str, default: bool) -> bool:
    value = settings.get(key)
    if isinstance(value, bool):
        return value
    return default


def normalize_gui_locale(value: object) -> str:
    if not isinstance(value, str):
        return GUI_LOCALE_DEFAULT
    normalized = value.strip().lower().replace("_", "-")
    if normalized in {"en", "en-us", "english"}:
        return GUI_LOCALE_DEFAULT
    if normalized in {"es", "es-419", "es-ar", "es-cl", "es-co", "es-mx", "spanish", "espanol", "español"}:
        return GUI_LOCALE_ES_419
    return GUI_LOCALE_DEFAULT


def gui_locale_label(locale: str) -> str:
    labels = dict(GUI_LOCALE_OPTIONS)
    return labels.get(normalize_gui_locale(locale), labels[GUI_LOCALE_DEFAULT])


def gui_locale_from_label(label: str) -> str:
    for locale, display_label in GUI_LOCALE_OPTIONS:
        if label == display_label:
            return locale
    return normalize_gui_locale(label)


def normalize_gui_appearance(value: object) -> str:
    if not isinstance(value, str):
        return GUI_APPEARANCE_DEFAULT
    normalized = value.strip().lower().replace("_", "-")
    if normalized in {"system", "sistema", "auto", "automatic", "automático", "automatico", "os"}:
        return GUI_APPEARANCE_SYSTEM
    if normalized in {"dark", "oscuro", "noche"}:
        return GUI_APPEARANCE_DARK
    if normalized in {"light", "claro", "day", "dia", "día"}:
        return GUI_APPEARANCE_LIGHT
    return GUI_APPEARANCE_DEFAULT


def gui_appearance_options(locale: str) -> tuple[tuple[str, str], ...]:
    normalized_locale = normalize_gui_locale(locale)
    return GUI_APPEARANCE_OPTIONS_BY_LOCALE.get(
        normalized_locale,
        GUI_APPEARANCE_OPTIONS_BY_LOCALE[GUI_LOCALE_DEFAULT],
    )


def gui_appearance_label(appearance: str, locale: str) -> str:
    normalized_appearance = normalize_gui_appearance(appearance)
    for option, label in gui_appearance_options(locale):
        if option == normalized_appearance:
            return label
    return gui_appearance_options(locale)[0][1]


def gui_appearance_from_label(label: str) -> str:
    for options in GUI_APPEARANCE_OPTIONS_BY_LOCALE.values():
        for appearance, display_label in options:
            if label == display_label:
                return appearance
    return normalize_gui_appearance(label)


def parse_tk_drop_paths(raw_data: str, splitter: Callable[[str], Iterable[str]] | None = None) -> list[Path]:
    raw_value = raw_data.strip()
    if not raw_value:
        return []

    parts: Iterable[str]
    if splitter is not None:
        try:
            parts = splitter(raw_value)
        except Exception:
            parts = [raw_value]
    else:
        parts = [raw_value]

    return [Path(item).expanduser() for item in parts if item and str(item).strip()]


def resolve_dropped_repository_targets(paths: list[Path]) -> tuple[Path | None, list[str], str | None]:
    directories: list[Path] = []
    for raw_path in paths:
        try:
            candidate = raw_path.expanduser()
            if not candidate.exists():
                continue
            directories.append(candidate if candidate.is_dir() else candidate.parent)
        except OSError:
            continue

    if not directories:
        return None, [], "Drop one or more existing repository folders."

    resolved = [path.resolve() for path in directories]
    if len(resolved) == 1:
        repo_dir = resolved[0]
        selected = ["."] if is_git_repository(repo_dir) else []
        return repo_dir, selected, None

    if all(is_git_repository(path) for path in resolved):
        parents = {path.parent for path in resolved}
        if len(parents) == 1:
            parent = next(iter(parents))
            return parent, [path.name for path in resolved], None

    try:
        common_root = Path(os.path.commonpath([str(path) for path in resolved]))
    except ValueError:
        return None, [], "Dropped repositories must live on the same drive."
    return common_root, [], None


def build_guard_run_config(
    *,
    mode: str,
    root: Path,
    policy: Path,
    repos: list[str] | None,
    public_only: bool,
    fix: bool,
    push: bool,
    dry_run: bool,
    redact_third_party_emails: bool,
    purge_detected_secret_files: bool,
    purge_all_detected_secret_files: bool,
    rewrite_personal_paths: bool,
    low_confidence_email_mode: str,
    owner_name: str,
    owner_emails: list[str],
    noreply_email: str,
    placeholder_email: str,
    max_matches: int,
    open_report: bool,
    confirm_each_repo_fix: bool,
    allow_non_owner_push: bool,
    allowed_remote_owners: list[str],
    replace_text_file: str | None,
    report_json: str | None,
    github_owner: str | None = None,
    github_include_forks: bool = False,
    github_fast: bool = False,
    github_jobs: int = 4,
    audit_litellm_incident: bool = False,
    audit_github_hardening: bool = False,
    agent_summary: bool = False,
    strict_profile: str | None = None,
    suppressions: str | None = None,
) -> GuardRunConfig:
    normalized_owner_emails = normalize_text_values(owner_emails)
    normalized_allowed_remote_owners = normalize_text_values(allowed_remote_owners)
    inferred_owner = infer_github_username_from_noreply(noreply_email)
    if inferred_owner and inferred_owner not in normalized_allowed_remote_owners:
        normalized_allowed_remote_owners.append(inferred_owner)
    strict_profile_config = strict_profiles.build_strict_profile_config(
        profile=strict_profile,
        low_confidence_email_mode=low_confidence_email_mode,
        audit_github_hardening=audit_github_hardening,
    )

    return GuardRunConfig(
        mode=mode,
        root=root,
        policy=policy,
        repos=repos,
        public_only=public_only,
        fix=fix,
        push=push,
        dry_run=dry_run,
        redact_third_party_emails=redact_third_party_emails,
        purge_detected_secret_files=purge_detected_secret_files,
        purge_all_detected_secret_files=purge_all_detected_secret_files,
        rewrite_personal_paths=rewrite_personal_paths,
        low_confidence_email_mode=strict_profile_config.low_confidence_email_mode,
        owner_name=owner_name,
        owner_emails=normalized_owner_emails,
        noreply_email=noreply_email,
        placeholder_email=placeholder_email,
        max_matches=max_matches,
        audit_litellm_incident=audit_litellm_incident,
        audit_github_hardening=audit_github_hardening,
        open_report=open_report,
        confirm_each_repo_fix=confirm_each_repo_fix,
        allow_non_owner_push=allow_non_owner_push,
        allowed_remote_owners=normalized_allowed_remote_owners,
        replace_text_file=replace_text_file,
        report_json=report_json,
        github_owner=(github_owner.strip() if github_owner and github_owner.strip() else None),
        github_include_forks=github_include_forks,
        github_fast=github_fast,
        github_jobs=normalize_github_jobs(github_jobs),
        agent_summary=agent_summary,
        strict_profile=strict_profile_config.name,
        github_hardening_findings_blocking=strict_profile_config.github_hardening_findings_blocking,
        suppressions=(suppressions.strip() if suppressions and suppressions.strip() else None),
    )


def discover_python_executables_for_supply_chain(
    root: Path,
    repo_filters: list[str] | None,
) -> list[Path]:
    candidates: list[Path] = [Path(sys.executable)]

    repo_paths: list[Path] = []
    if repo_filters:
        for item in repo_filters:
            path = Path(item)
            if not path.is_absolute():
                path = root / path
            repo_paths.append(path)
    else:
        if root.exists():
            for child in root.iterdir():
                if child.is_dir() and (child / ".git").exists():
                    repo_paths.append(child)

    search_roots = [root, *repo_paths]
    env_names = [".venv", "venv", "env"]
    for base in search_roots:
        if not base.exists():
            continue
        for env_name in env_names:
            env_dir = base / env_name
            if not env_dir.exists():
                continue
            for python_candidate in [
                env_dir / "Scripts" / "python.exe",
                env_dir / "bin" / "python",
            ]:
                if python_candidate.exists():
                    candidates.append(python_candidate)

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = str(candidate.resolve()) if candidate.exists() else str(candidate)
        normalized = resolved.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(Path(resolved))
    return unique


def probe_litellm_installation(python_executable: Path) -> dict[str, object]:
    probe_script = (
        "import hashlib, importlib.metadata as m, json;"
        "from pathlib import Path;"
        "payload={'installed': False};"
        "\ntry: dist = m.distribution('litellm')"
        "\nexcept m.PackageNotFoundError: pass"
        "\nelse:"
        "\n site_root = Path(dist.locate_file(''));"
        "\n pth = site_root / 'litellm_init.pth';"
        "\n proxy = site_root / 'litellm' / 'proxy' / 'proxy_server.py';"
        "\n proxy_sha = hashlib.sha256(proxy.read_bytes()).hexdigest() if proxy.exists() else '';"
        "\n payload.update({'installed': True, 'version': str(dist.version), 'location': str(site_root), "
        "'litellm_init_pth': str(pth) if pth.exists() else '', 'proxy_server': str(proxy) if proxy.exists() else '',"
        "'proxy_server_sha256': proxy_sha});"
        "\nprint(json.dumps(payload))"
    )

    try:
        result = subprocess.run(
            [str(python_executable), "-c", probe_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
            timeout=12,
        )
    except Exception as exc:
        return {
            "python": str(python_executable),
            "error": f"probe_failed: {exc}",
            "installed": False,
        }

    if result.returncode != 0:
        return {
            "python": str(python_executable),
            "error": f"probe_exit_{result.returncode}: {result.stderr.strip()[:240]}",
            "installed": False,
        }

    try:
        payload = json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError:
        payload = {
            "installed": False,
            "error": "probe_invalid_json",
        }

    payload["python"] = str(python_executable)
    return payload


def probe_litellm_pip_cache_hits(python_executable: Path, max_matches: int) -> list[str]:
    try:
        out = subprocess.run(
            [str(python_executable), "-m", "pip", "cache", "list", "litellm"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess_stdin(),
            timeout=12,
        )
    except Exception:
        return []

    if out.returncode != 0:
        return []

    hits = [line.strip() for line in out.stdout.splitlines() if "litellm" in line.lower()]
    return hits[:max_matches]


def run_litellm_global_supply_chain_scan(
    root: Path,
    repo_filters: list[str] | None,
    max_matches: int,
    logger: Callable[[str], None],
) -> dict[str, object]:
    payload: dict[str, Any] = {
        "incident": LITELLM_INCIDENT_ID,
        "python_probes": [],
        "pip_cache_hits": [],
        "severity": "NONE",
        "critical_evidence": [],
        "high_evidence": [],
        "medium_evidence": [],
    }

    interpreters = discover_python_executables_for_supply_chain(root, repo_filters)
    for python_executable in interpreters:
        probe = probe_litellm_installation(python_executable)
        payload["python_probes"].append(probe)

        if probe.get("installed"):
            version = str(probe.get("version", ""))
            descriptor = f"{probe.get('python')} :: {version} :: {probe.get('location', '-')}"
            if LITELLM_COMPROMISED_1828_RE.search(version):
                payload["critical_evidence"].append(f"installed compromised version (1.82.8): {descriptor}")
            elif LITELLM_COMPROMISED_1827_RE.search(version):
                payload["high_evidence"].append(f"installed compromised version (1.82.7): {descriptor}")
            else:
                payload["medium_evidence"].append(f"litellm installed (non-compromised version): {descriptor}")

            litellm_init_pth = str(probe.get("litellm_init_pth", "")).strip()
            if litellm_init_pth:
                payload["critical_evidence"].append(f"IoC file present: {litellm_init_pth}")

    if interpreters:
        cache_hits = probe_litellm_pip_cache_hits(interpreters[0], max_matches=max_matches)
        payload["pip_cache_hits"] = cache_hits
        for hit in cache_hits:
            if LITELLM_COMPROMISED_1828_RE.search(hit):
                payload["critical_evidence"].append(f"pip cache evidence: {hit}")
            elif LITELLM_COMPROMISED_1827_RE.search(hit):
                payload["high_evidence"].append(f"pip cache evidence: {hit}")
            else:
                payload["medium_evidence"].append(f"pip cache reference: {hit}")

    severity = "NONE"
    if payload["critical_evidence"]:
        severity = "CRITICAL"
    elif payload["high_evidence"]:
        severity = "HIGH"
    elif payload["medium_evidence"]:
        severity = "MEDIUM"
    payload["severity"] = severity

    logger(f"[SUPPLY-CHAIN] Incident profile: {LITELLM_INCIDENT_ID}")
    logger(f"[SUPPLY-CHAIN] Global severity: {severity}")
    logger(f"[SUPPLY-CHAIN] Python environments probed: {len(interpreters)}")
    logger(f"[SUPPLY-CHAIN] Critical evidence: {len(payload['critical_evidence'])}")
    logger(f"[SUPPLY-CHAIN] High evidence: {len(payload['high_evidence'])}")
    logger(f"[SUPPLY-CHAIN] Medium evidence: {len(payload['medium_evidence'])}")

    for item in payload["critical_evidence"][:8]:
        logger(f"[SUPPLY-CHAIN][CRITICAL] {item}")
    for item in payload["high_evidence"][:8]:
        logger(f"[SUPPLY-CHAIN][HIGH] {item}")

    return payload


def persist_litellm_supply_chain_output(
    artifacts: RunArtifacts,
    payload: dict[str, object],
    logger: Callable[[str], None],
) -> None:
    if not payload:
        return
    out_path = artifacts.run_dir / "supply_chain_litellm.json"
    write_private_text_file(out_path, json.dumps(payload, indent=2))
    logger(f"[INFO] Supply-chain report written to {out_path}")


from repo_privacy_guardian.gui.app import GuiApp  # noqa: E402

def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit/fix repository public-release safety based on docs/POLICY.md. "
            "Start safely with --check-tooling, then a --dry-run audit; fixes are opt-in. "
            "Outbound/exfil indicators remain advisory/manual-review by default."
        ),
        epilog=(
            "First-time safe path (no writes):\n"
            "  repo-privacy-guardian --check-tooling\n"
            "  repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes\n"
            "\n"
            "Read the result:\n"
            "  PASS   no blocking publication issues were found\n"
            "  REVIEW inspect advisory findings before publishing\n"
            "  FAIL   do not publish until blocking findings are fixed\n"
            "\n"
            "Common CLI flow:\n"
            "  repo-privacy-guardian --check-tooling\n"
            "  repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes\n"
            "  repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --dry-run --yes\n"
            "  repo-privacy-guardian --gui\n"
            "\n"
            "Agentic handoff:\n"
            "  Paste the README 60-Second First Run prompt into your coding agent; keep fixes and pushes approval-gated."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--root", default=str(default_root_dir()), help="Root folder containing repositories")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY), help="Policy markdown path")
    parser.add_argument("--repos", nargs="*", help="Repo folder names or absolute paths")
    parser.add_argument(
        "--public-only",
        action="store_true",
        help="Only include repositories with publicly accessible GitHub origin",
    )

    parser.add_argument("--fix", action="store_true", help="Apply automated fixes")
    parser.add_argument("--push", action="store_true", help="Force-push rewritten history to origin")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed")
    parser.add_argument(
        "--redact-third-party-emails",
        action="store_true",
        help="Redact non-owner emails to placeholder",
    )
    parser.add_argument(
        "--purge-detected-secret-files",
        action="store_true",
        help="When fixing, add secret files to .gitignore, untrack them, and purge them from history (safe candidates only)",
    )
    parser.add_argument(
        "--purge-all-detected-secret-files",
        action="store_true",
        help="When fixing, purge all detected secret files including risky/manual-review candidates",
    )
    parser.add_argument(
        "--rewrite-personal-paths",
        action="store_true",
        help="When fixing, rewrite detected personal absolute paths in tracked content/history",
    )
    parser.add_argument(
        "--low-confidence-email-mode",
        choices=["informational", "blocking"],
        default="informational",
        help="Treat low-confidence email findings as informational (default) or blocking",
    )
    parser.add_argument(
        "--strict-profile",
        choices=list(strict_profiles.STRICT_PROFILE_CHOICES),
        help=(
            "Apply a documented policy preset: audit-only rejects writes, internal is explicit current behavior, "
            "release promotes low-confidence emails and opt-in GitHub hardening findings to blocking."
        ),
    )
    parser.add_argument(
        "--suppressions",
        help=(
            "Versioned JSON suppression file for advisory/manual-review findings. "
            "High-confidence secrets, path leaks, git metadata blocking findings, fsck, dirty tree, and runtime errors cannot be suppressed."
        ),
    )
    parser.add_argument(
        "--agent-summary",
        action="store_true",
        help="Print a safe agent handoff summary and always write agent_summary.json in the run artifacts.",
    )
    parser.add_argument(
        "--audit-litellm-incident",
        action="store_true",
        help="Enable supply-chain incident audit checks for LiteLLM March-2026 indicators",
    )
    parser.add_argument(
            "--audit-github-hardening",
            action="store_true",
            help=(
                "Enable optional GitHub repository settings audit for GitHub remotes. "
                "Uses read-only GitHub API calls; token-gated checks require "
                "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, or authenticated gh."
            ),
        )
    parser.add_argument(
        "--github-owner",
        help=(
            "Opt-in remote audit: discover repositories for this GitHub user/org, "
            "clone them into a temporary private directory, audit, then remove the clones"
        ),
    )
    parser.add_argument(
        "--github-include-forks",
        action="store_true",
        help="With --github-owner, include forked repositories (forks are skipped by default)",
    )
    parser.add_argument(
        "--github-fast",
        action="store_true",
        help="With --github-owner, use shallow clones before auditing current files and available history",
    )
    parser.add_argument(
        "--github-jobs",
        type=parse_positive_int,
        default=4,
        help=f"With --github-owner, number of concurrent clone workers (default: 4, max: {MAX_GITHUB_CLONE_JOBS})",
    )

    parser.add_argument("--owner-name", default="Owner", help="Owner display name for rewritten commits")
    parser.add_argument(
        "--owner-email",
        action="append",
        default=[],
        help="Owner private email(s) to replace with noreply (can repeat)",
    )
    parser.add_argument("--noreply-email", default=DEFAULT_NOREPLY, help="Target noreply email")
    parser.add_argument(
        "--placeholder-email",
        default=DEFAULT_PLACEHOLDER,
        help="Placeholder email for redacted contributors",
    )
    parser.add_argument("--max-matches", type=parse_positive_int, default=50, help="Max findings per check")
    parser.add_argument(
        "--report-json",
        help="Optional extra JSON export path. Main JSON/LOG/HTML artifacts are always written to a timestamped run folder",
    )
    parser.add_argument(
        "--report-dir",
        default=str(default_results_dir()),
        help="Requested base directory for timestamped run folders; values outside Audit_Results are ignored by policy",
    )
    parser.add_argument(
        "--replace-text-file",
        help=(
            "Advanced remediation input: merge an explicit git-filter-repo replace-text file "
            "into the generated rewrite plan"
        ),
    )

    parser.add_argument("--yes", action="store_true", help="Skip destructive action confirmation prompt")
    parser.add_argument(
        "--check-tooling",
        action="store_true",
        help="Check required/optional local tooling for the selected mode and exit",
    )
    parser.add_argument(
        "--install-missing-tools",
        action="store_true",
        help="Attempt to install supported missing tools before continuing",
    )
    report_open_group = parser.add_mutually_exclusive_group()
    report_open_group.add_argument(
        "--open-report",
        action="store_true",
        help="Open the generated HTML report in a browser after a CLI run completes",
    )
    report_open_group.add_argument(
        "--no-open-report",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-confirm-each-repo",
        action="store_true",
        help="Disable per-repository fix confirmation prompts in CLI mode",
    )
    parser.add_argument(
        "--allow-non-owner-push",
        action="store_true",
        help="Bypass remote owner verification before force push (unsafe)",
    )
    parser.add_argument(
        "--allow-remote-owner",
        action="append",
        default=[],
        help="Allow force-push only when origin owner matches this value (can repeat)",
    )
    parser.add_argument("--gui", action="store_true", help="Launch the optional desktop GUI")
    return parser


def build_cli_guard_run_config(args: argparse.Namespace) -> GuardRunConfig:
    return build_guard_run_config(
        mode="cli",
        root=Path(args.root),
        policy=Path(args.policy),
        repos=args.repos,
        public_only=args.public_only,
        fix=args.fix,
        push=args.push,
        dry_run=args.dry_run,
        redact_third_party_emails=args.redact_third_party_emails,
        purge_detected_secret_files=args.purge_detected_secret_files,
        purge_all_detected_secret_files=args.purge_all_detected_secret_files,
        rewrite_personal_paths=args.rewrite_personal_paths,
        low_confidence_email_mode=args.low_confidence_email_mode,
        owner_name=args.owner_name,
        owner_emails=args.owner_email,
        noreply_email=args.noreply_email,
        placeholder_email=args.placeholder_email,
        max_matches=args.max_matches,
        open_report=bool(args.open_report),
        confirm_each_repo_fix=not args.no_confirm_each_repo,
        allow_non_owner_push=args.allow_non_owner_push,
        allowed_remote_owners=args.allow_remote_owner,
        replace_text_file=args.replace_text_file,
        report_json=args.report_json,
        github_owner=args.github_owner,
        github_include_forks=args.github_include_forks,
        github_fast=args.github_fast,
        github_jobs=args.github_jobs,
        audit_litellm_incident=args.audit_litellm_incident,
        audit_github_hardening=args.audit_github_hardening,
        agent_summary=args.agent_summary,
        strict_profile=args.strict_profile,
        suppressions=args.suppressions,
    )


def run_cli(args: argparse.Namespace) -> int:  # pragma: no cover
    config = build_cli_guard_run_config(args)

    tooling_checks = build_cli_tooling_checks(config)
    if args.install_missing_tools:
        install_missing_tooling(tooling_checks, print)
        tooling_checks = build_cli_tooling_checks(config)

    if args.check_tooling:
        blocking_failures, _warnings = summarize_tooling_checks(tooling_checks, print, include_ready=True)
        return EXIT_POLICY_FAILED if blocking_failures else EXIT_OK

    enforced_results_dir, forced = enforce_results_dir(Path(args.report_dir))
    try:
        artifacts = create_run_artifacts(enforced_results_dir)
    except Exception as exc:
        print(
            f"[ERROR] Could not create run artifacts under {enforced_results_dir}: {exc}",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR
    cli_logger = RunLogger(artifacts.log_path, sink=print)
    if forced:
        cli_logger(
            f"[WARN] report-dir was forced to {default_results_dir()} to comply with mandatory Audit_Results policy"
        )
    cli_logger(f"[INFO] Run artifacts directory: {artifacts.run_dir}")
    cli_logger(f"[INFO] Run state manifest: {artifacts.state_path}")
    if args.no_open_report:
        cli_logger(
            "[INFO] --no-open-report is accepted for compatibility. "
            "CLI already defaults to not opening the browser automatically."
        )
    blocking_failures, warnings = summarize_tooling_checks(tooling_checks, cli_logger, include_ready=False)
    if blocking_failures:
        if args.install_missing_tools:
            cli_logger("[ERROR] Required tooling is still missing after install attempts.")
        else:
            cli_logger(
                "[ERROR] Required tooling is missing. Re-run with --check-tooling or --install-missing-tools."
            )
        return EXIT_RUNTIME_ERROR
    if warnings and not args.install_missing_tools:
        cli_logger("[INFO] Optional tooling warnings detected. Re-run with --check-tooling for a focused summary.")

    def confirm_force_push() -> bool:
        print("WARNING: --fix with --push rewrites history and force-pushes.")
        answer = input("Continue? [y/N]: ").strip().lower()
        return answer in {"y", "yes"}

    def confirm_repo_fix(repo: Path, index: int, total: int) -> bool:
        print(f"[CONFIRM] Repository {index}/{total}: {repo_display_name(repo)}")
        print("Applying fixes may modify tracked files and rewrite history.")
        answer = input("Apply fixes for this repository? [y/N]: ").strip().lower()
        return answer in {"y", "yes"}

    return execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=cli_logger,
        results_dir=enforced_results_dir,
        require_confirmation=not args.yes,
        confirm_callback=confirm_force_push,
        confirm_repo_fix_callback=(
            confirm_repo_fix if config.fix and config.confirm_each_repo_fix and not args.yes else None
        ),
    )


def should_launch_gui(args: argparse.Namespace) -> bool:
    return bool(args.gui)


def launch_gui(
    *,
    check_tooling_only: bool = False,
    install_missing_tools: bool = False,
) -> int:
    tooling_checks = build_gui_tooling_checks()
    if not check_tooling_only and not install_missing_tools:
        accepted_install = prompt_gui_tooling_install(tooling_checks, print)
        if accepted_install:
            install_missing_tooling(tooling_checks, print)
            tooling_checks = build_gui_tooling_checks()
    if install_missing_tools:
        install_missing_tooling(tooling_checks, print)
        tooling_checks = build_gui_tooling_checks()
    blocking_failures, _warnings = summarize_tooling_checks(
        tooling_checks,
        print,
        include_ready=check_tooling_only,
    )
    if check_tooling_only:
        return EXIT_POLICY_FAILED if blocking_failures else EXIT_OK
    if blocking_failures:
        print(
            "[ERROR] GUI tooling is not ready. Re-run with --gui --check-tooling "
            "or --gui --install-missing-tools.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR
    try:
        app = GuiApp()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR
    app.run()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = make_parser()
    if not raw_args:
        parser.print_help()
        return 0

    args = parser.parse_args(raw_args)

    if should_launch_gui(args):
        return launch_gui(
            check_tooling_only=bool(args.check_tooling),
            install_missing_tools=bool(args.install_missing_tools),
        )

    return run_cli(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
