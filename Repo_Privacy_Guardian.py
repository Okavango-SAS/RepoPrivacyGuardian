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
import html
import importlib.util
import inspect
import json
import os
import re
import shlex
import shutil
import subprocess
import stat
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import socket
from typing import Callable, Iterable, Mapping

import repo_privacy_guardian_artifacts as artifact_helpers
import repo_privacy_guardian_github as github_helpers
import repo_privacy_guardian_prompts as prompt_helpers
import repo_privacy_guardian_runtime as runtime
from repo_privacy_guardian_runtime import (
    CancellationToken,
    EXIT_ABORTED,
    EXIT_OK,
    EXIT_POLICY_FAILED,
    EXIT_RUNTIME_ERROR,
    describe_no_target_resolution,
    discover_repository_targets,
    resolve_run_status,
    validate_repository_root,
)


def default_root_dir() -> Path:
    return Path.cwd()


def default_results_dir() -> Path:
    return default_root_dir() / "Audit_Results"


def default_policy_path() -> Path:
    repo_policy = Path(__file__).resolve().parent / "docs" / "POLICY.md"
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
GUI_APPEARANCE_DEFAULT = GUI_APPEARANCE_LIGHT
GUI_APPEARANCE_OPTIONS_BY_LOCALE: dict[str, tuple[tuple[str, str], ...]] = {
    GUI_LOCALE_DEFAULT: (
        (GUI_APPEARANCE_LIGHT, "Light"),
        (GUI_APPEARANCE_DARK, "Dark"),
    ),
    GUI_LOCALE_ES_419: (
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

    source_tree_asset = Path(__file__).resolve().parent / GUI_ASSET_PACKAGE / filename
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


def streaming_popen_kwargs() -> dict[str, object]:
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
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
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
    if path.is_symlink():
        return False, f"refusing to recursively remove symlinked temporary directory path: {path}"

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


def gui_font_candidates(platform_name: str | None = None) -> dict[str, tuple[str, ...]]:
    current_platform = platform_name or sys.platform
    if current_platform.startswith("win"):
        return {
            "ui": ("Segoe UI", "Arial", "TkDefaultFont"),
            "mono": ("Cascadia Mono", "Cascadia Code", "Consolas", "Courier New", "TkFixedFont"),
        }
    if current_platform == "darwin":
        return {
            "ui": ("SF Pro Text", "Helvetica Neue", "Arial", "TkDefaultFont"),
            "mono": ("SF Mono", "Menlo", "Monaco", "Courier", "TkFixedFont"),
        }
    return {
        "ui": ("Inter", "Noto Sans", "DejaVu Sans", "Liberation Sans", "Arial", "TkDefaultFont"),
        "mono": ("JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono", "Courier New", "TkFixedFont"),
    }


GUI_TOOLTIP_TEXT: dict[str, str] = {
    "repositories_root": (
        "Local folder that contains one or more git repositories. Drop repository folders into the list "
        "or use Browse/Refresh to update local targets."
    ),
    "settings_toggle": "Shows or hides setup-only controls. Saved non-secret preferences stay local to this desktop user.",
    "policy_file": "Markdown policy file used by both CLI and GUI to define the publication gate rules.",
    "audit_results_folder": (
        "Base directory for timestamped JSON, HTML, log, and run-state artifacts. Policy keeps outputs under Audit_Results."
    ),
    "optional_json_copy": "Optional second JSON export path for automation. The timestamped report.json is always written.",
    "github_owner": (
        "Opt-in remote audit mode for a GitHub user or organization. The GUI discovers matching repositories, "
        "clones them temporarily, audits them, and keeps Repair locked."
    ),
    "github_repo_filters": (
        "Comma-separated remote repository names to include when GitHub owner/org audit is active. Leave empty "
        "to discover all matching repositories."
    ),
    "github_clone_workers": (
        "Number of concurrent clone workers for GitHub owner/org audit. Higher values can be faster but use more "
        "network, disk, and process capacity."
    ),
    "github_include_forks": (
        "Includes forked repositories in GitHub owner/org discovery. Off by default to avoid auditing inherited "
        "or third-party content unintentionally."
    ),
    "github_fast": (
        "Uses shallow clones in GitHub owner/org audit. Faster for large repos, but history available to the scanner may be limited."
    ),
    "max_findings": (
        "Maximum number of samples retained per check in logs and reports. Lower values keep reports shorter; "
        "higher values aid deep triage."
    ),
    "gui_language": "Language for GUI labels, contextual help, and dialogs. This does not change CLI flags, reports, or behavior.",
    "gui_appearance": "Light or dark GUI theme applied on the next GUI launch. This is presentation-only and does not change CLI flags, reports, or policy behavior.",
    "save_setup": "Stores only non-secret GUI preferences and collapses setup controls so the main view stays focused on Audit.",
    "advanced_identity": (
        "Shows optional Git identity and GitHub email privacy controls used when Repair rewrites or redacts identity metadata."
    ),
    "noreply_email": "GitHub noreply address used as the safe replacement identity during reviewed repair.",
    "placeholder_email": "Neutral placeholder used when redacting third-party contributor emails during reviewed repair.",
    "owner_name": "Display name to use for rewritten owner commits when identity repair is explicitly authorized.",
    "owner_emails": (
        "Comma-separated private owner emails that can be replaced with the noreply address during reviewed repair."
    ),
    "git_user_name": "Value to read or write for git user.name when applying local/global Git identity settings.",
    "git_user_email": "Noreply-style email to read or write for git user.email in local/global Git config.",
    "apply_global_git_config": (
        "Writes git config --global user.name and user.email for all repositories on this machine after confirmation."
    ),
    "apply_local_git_config": "Writes git user.name and user.email only for the selected local repository.",
    "read_current_git_identity": "Reads effective Git identity without changing local or global Git config.",
    "open_github_email_settings": (
        "Opens GitHub email settings so private-email and push-block protections can be verified manually."
    ),
    "public_only": (
        "Filters local targets to repositories whose GitHub origin is publicly reachable. Useful before public-release checks."
    ),
    "redact_third_party_emails": (
        "During Repair, replaces non-owner contributor emails with the placeholder email. It does nothing during Audit."
    ),
    "low_confidence_blocking": (
        "Turns noisy low-confidence email findings into blocking failures. Leave off unless you want a stricter review gate."
    ),
    "dry_run_preview": "Runs Repair in preview mode so planned changes are reported without writing to repositories.",
    "audit_github_hardening": (
        "Adds read-only GitHub settings checks such as branch protection, Actions permissions, secret scanning, and Dependabot."
    ),
    "audit_litellm_incident": "Adds targeted checks for LiteLLM March 2026 supply-chain incident indicators.",
    "open_html_report": "Opens the generated HTML report automatically after a GUI run finishes.",
    "confirm_each_repo_fix": (
        "Prompts before applying Repair to each repository so multi-repo runs can be reviewed one target at a time."
    ),
    "rewrite_personal_paths": (
        "During Repair, rewrites reviewed personal path findings in tracked content and history using replace-text rules."
    ),
    "replace_text_rules": "Optional git-filter-repo replace-text file for literal substitutions the tool cannot infer safely.",
    "force_push": (
        "After a history rewrite, force-pushes changed history to origin. Use only after backups and collaborator coordination."
    ),
    "bypass_remote_owner_guardrail": (
        "Disables the remote-owner safety check before force push. This is intentionally unsafe and requires explicit acceptance."
    ),
    "allowed_remote_owners": "Comma-separated allowlist of remote owners accepted for force-push guardrails.",
    "purge_safe_secret_files": "Purges secret-file candidates classified as safer to remove automatically after review.",
    "purge_risky_secret_files": (
        "Also purges ambiguous/manual-review secret-file candidates. Use only after confirming every candidate."
    ),
    "repair_button": "Runs Repair only after a completed Audit and review window unlock the safety gate.",
    "run_audit": "Runs the publication-gate audit for selected repositories or all visible repositories if confirmed.",
    "stop_after_current_step": (
        "Requests cooperative cancellation. The active repository step finishes cleanly before the run stops."
    ),
    "refresh_repos": "Reloads local repository targets from the current Root folder.",
    "select_all_repos": "Selects every visible local repository target for the next Audit or Repair run.",
    "clear_selection": (
        "Clears local repository selection. If you run Audit with nothing selected, the GUI asks before running all."
    ),
    "clear_log": "Clears only the on-screen log. Existing Audit_Results artifacts are not deleted.",
    "repo_drop_area": (
        "Drag local repository folders here to set the Root and selection automatically. Browse/Refresh remains the fallback."
    ),
    "reports_tab": "Shows the latest local artifact paths and quick-open actions without exposing raw sensitive evidence.",
    "prompts_tab": "Copy vetted agentic IDE prompts that use the CLI-first audit and repair workflow.",
    "open_settings_tab": "Moves advanced parity controls into Settings so Audit stays focused on choosing targets and running the scan.",
    "repair_options_toggle": "Shows advanced Repair toggles. Keep them hidden until audited findings have been reviewed.",
    "copy_prompt": "Copies the full prompt text to the clipboard so it can be pasted into an agentic IDE session.",
    "copy_prompt_command": "Copies the recommended CLI command template for this prompt.",
    "open_prompt_file": "Opens the tracked prompt file for review in the default local application.",
}

GUI_TOOLTIP_TEXT_ES_419: dict[str, str] = {
    "repositories_root": (
        "Carpeta local que contiene uno o más repositorios git. Arrastrá carpetas de repositorios a la lista "
        "o usá Buscar/Actualizar para refrescar los objetivos locales."
    ),
    "settings_toggle": "Muestra u oculta controles de configuración inicial. Las preferencias no secretas quedan guardadas sólo para este usuario.",
    "policy_file": "Archivo Markdown de política usado por CLI y GUI para definir las reglas del gate de publicación.",
    "audit_results_folder": (
        "Carpeta base para artefactos con timestamp: JSON, HTML, log y estado de corrida. La política mantiene salidas en Audit_Results."
    ),
    "optional_json_copy": "Ruta opcional para una segunda copia JSON destinada a automatización. El report.json con timestamp siempre se escribe.",
    "github_owner": (
        "Modo remoto opt-in para auditar un usuario u organización de GitHub. La GUI descubre repositorios, "
        "los clona temporalmente, los audita y mantiene Reparar bloqueado."
    ),
    "github_repo_filters": (
        "Nombres de repositorios remotos separados por coma para incluir cuando GitHub owner/org está activo. Dejalo vacío "
        "para descubrir todos los repositorios que coincidan."
    ),
    "github_clone_workers": (
        "Cantidad de clones concurrentes para auditoría GitHub owner/org. Valores más altos pueden ser más rápidos, "
        "pero usan más red, disco y procesos."
    ),
    "github_include_forks": (
        "Incluye repositorios fork en el discovery de GitHub owner/org. Viene apagado para evitar auditar contenido heredado "
        "o de terceros sin querer."
    ),
    "github_fast": (
        "Usa clones shallow en auditoría GitHub owner/org. Es más rápido en repos grandes, pero limita el historial disponible para el scanner."
    ),
    "max_findings": (
        "Cantidad máxima de muestras retenidas por check en logs y reportes. Valores bajos acortan reportes; "
        "valores altos ayudan en triage profundo."
    ),
    "gui_language": "Idioma de etiquetas, ayuda contextual y diálogos de la GUI. No cambia flags, reportes ni contrato CLI.",
    "gui_appearance": "Tema claro u oscuro aplicado en el próximo inicio de la GUI. Es sólo presentación y no cambia flags, reportes ni política.",
    "save_setup": "Guarda sólo preferencias no secretas de la GUI y colapsa la configuración para enfocar la vista principal en Auditar.",
    "advanced_identity": (
        "Muestra controles opcionales de identidad Git y privacidad de email GitHub usados cuando Reparar reescribe o redacta metadatos."
    ),
    "noreply_email": "Dirección noreply de GitHub usada como identidad segura de reemplazo durante una reparación revisada.",
    "placeholder_email": "Placeholder neutral usado al redactar emails de terceros durante una reparación revisada.",
    "owner_name": "Nombre visible a usar en commits del owner reescritos cuando se autoriza reparación de identidad.",
    "owner_emails": (
        "Emails privados del owner separados por coma que pueden reemplazarse por la dirección noreply durante una reparación revisada."
    ),
    "git_user_name": "Valor que se lee o escribe en git user.name al aplicar configuración Git local/global.",
    "git_user_email": "Email estilo noreply que se lee o escribe en git user.email en la configuración Git local/global.",
    "apply_global_git_config": (
        "Escribe git config --global user.name y user.email para todos los repositorios de esta máquina luego de confirmar."
    ),
    "apply_local_git_config": "Escribe git user.name y user.email sólo para el repositorio local seleccionado.",
    "read_current_git_identity": "Lee la identidad Git efectiva sin cambiar la configuración local ni global.",
    "open_github_email_settings": (
        "Abre GitHub email settings para verificar manualmente privacidad de email y bloqueo de pushes con email privado."
    ),
    "public_only": (
        "Filtra objetivos locales a repositorios cuyo origin GitHub sea públicamente accesible. Útil antes de checks de release público."
    ),
    "redact_third_party_emails": (
        "Durante Reparar, reemplaza emails de contribuidores no owner con el placeholder. No hace nada durante Auditar."
    ),
    "low_confidence_blocking": (
        "Convierte hallazgos ruidosos de email low-confidence en fallas bloqueantes. Dejalo apagado salvo que quieras un gate más estricto."
    ),
    "dry_run_preview": "Ejecuta Reparar en modo preview para reportar cambios planeados sin escribir en repositorios.",
    "audit_github_hardening": (
        "Agrega checks read-only de settings GitHub como branch protection, permisos de Actions, secret scanning y Dependabot."
    ),
    "audit_litellm_incident": "Agrega checks focalizados para indicadores del incidente supply-chain de LiteLLM de marzo de 2026.",
    "open_html_report": "Abre automáticamente el reporte HTML generado cuando termina una corrida desde GUI.",
    "confirm_each_repo_fix": (
        "Pregunta antes de aplicar Reparar en cada repositorio para revisar corridas multi-repo objetivo por objetivo."
    ),
    "rewrite_personal_paths": (
        "Durante Reparar, reescribe hallazgos revisados de rutas personales en contenido trackeado e historial usando reglas replace-text."
    ),
    "replace_text_rules": "Archivo replace-text opcional para sustituciones literales que la herramienta no puede inferir de forma segura.",
    "force_push": (
        "Después de reescribir historial, fuerza push a origin. Usalo sólo luego de backups y coordinación con colaboradores."
    ),
    "bypass_remote_owner_guardrail": (
        "Desactiva el check de safety del owner remoto antes del force push. Es intencionalmente riesgoso y requiere aceptación explícita."
    ),
    "allowed_remote_owners": "Allowlist separada por coma de owners remotos aceptados por el guardrail de force-push.",
    "purge_safe_secret_files": "Purga candidatos de archivos secretos clasificados como más seguros de remover automáticamente luego de revisión.",
    "purge_risky_secret_files": (
        "También purga candidatos ambiguos o manual-review. Usalo sólo después de confirmar cada candidato."
    ),
    "repair_button": "Ejecuta Reparar sólo después de una Auditoría completa y de que la ventana de revisión libere el gate de seguridad.",
    "run_audit": "Ejecuta la auditoría del publication gate para repositorios seleccionados o todos los visibles si lo confirmás.",
    "stop_after_current_step": (
        "Solicita cancelación cooperativa. El paso activo del repositorio termina limpiamente antes de detener la corrida."
    ),
    "refresh_repos": "Recarga objetivos de repositorios locales desde la carpeta Root actual.",
    "select_all_repos": "Selecciona todos los repositorios locales visibles para la próxima Auditoría o Reparación.",
    "clear_selection": (
        "Limpia la selección local. Si ejecutás Auditar sin selección, la GUI pregunta antes de correr todos."
    ),
    "clear_log": "Limpia sólo el log en pantalla. Los artefactos existentes en Audit_Results no se eliminan.",
    "repo_drop_area": (
        "Arrastrá carpetas de repositorios locales acá para configurar Root y selección automáticamente. Buscar/Actualizar sigue disponible."
    ),
    "reports_tab": "Muestra rutas de artefactos de la última corrida y acciones rápidas sin exponer evidencia sensible cruda.",
    "prompts_tab": "Copia prompts revisados para IDEs agénticas que usan el flujo CLI-first de auditoría y reparación.",
    "open_settings_tab": "Mueve controles avanzados de paridad a Configuración para que Auditar quede enfocado en objetivos y ejecución.",
    "repair_options_toggle": "Muestra toggles avanzados de Reparar. Mantenelos ocultos hasta revisar los hallazgos auditados.",
    "copy_prompt": "Copia el prompt completo al portapapeles para pegarlo en una sesión de IDE agéntica.",
    "copy_prompt_command": "Copia el comando CLI recomendado para este prompt.",
    "open_prompt_file": "Abre el archivo de prompt trackeado para revisarlo en la aplicación local predeterminada.",
}

GUI_TOOLTIP_TEXT_BY_LOCALE: dict[str, dict[str, str]] = {
    GUI_LOCALE_DEFAULT: GUI_TOOLTIP_TEXT,
    GUI_LOCALE_ES_419: GUI_TOOLTIP_TEXT_ES_419,
}

GUI_UI_TEXT_BY_LOCALE: dict[str, dict[str, str]] = {
    GUI_LOCALE_DEFAULT: {
        "header_title": "Repo Privacy Guardian",
        "header_subtitle": "Start with Audit: choose a root, review findings, then Repair only after the safety gate unlocks.",
        "workflow_audit": "1 Audit",
        "workflow_review": "2 Review findings",
        "workflow_repair": "3 Repair if needed",
        "workflow_parity": "CLI parity: same backend",
        "tab_audit": "1. Audit",
        "tab_reports": "2. Reports",
        "tab_prompts": "3. Prompts",
        "tab_settings": "4. Settings",
        "tab_repair": "5. Repair",
        "audit_target": "Audit Target",
        "audit_target_body": "Choose local repositories here. Advanced policy, GitHub owner/org, and identity controls live in Settings.",
        "open_settings_tab": "Open Settings",
        "last_run": "Last run",
        "last_run_none": "No GUI run has finished in this session yet.",
        "reports_dashboard": "Reports Dashboard",
        "reports_dashboard_body": "Open local evidence from the latest run. Treat artifacts as sensitive even when values are redacted.",
        "latest_artifacts": "Latest artifacts",
        "latest_artifacts_none": "Run Audit to create report.json, report.html, run.log, and run_state.json.",
        "open_html_report_action": "Open HTML report",
        "open_json_report_action": "Open report.json",
        "open_run_log_action": "Open run.log",
        "open_artifacts_folder_action": "Open artifacts folder",
        "prompts_library": "Agentic Prompt Library",
        "prompts_library_body": "Copy a vetted prompt into Codex, Claude Code, Antigravity, GitHub Copilot, Cursor, or a similar agentic IDE. Prompts use the CLI-first workflow and avoid raw sensitive evidence.",
        "copy_prompt": "Copy prompt",
        "copy_command": "Copy command",
        "open_prompt": "Open prompt",
        "prompt_command": "Command",
        "prompt_copied": "Prompt copied to clipboard.",
        "prompt_command_copied": "Command copied to clipboard.",
        "prompt_open_failed": "Could not open prompt file: {error}",
        "settings_companion_title": "Advanced Settings",
        "settings_companion_body": "These controls preserve CLI parity but stay out of the main audit path.",
        "repair_advanced_toggle_show": "Show advanced Repair options",
        "repair_advanced_toggle_hide": "Hide advanced Repair options",
        "repair_advanced_hint_hidden": "Advanced write options are hidden. Review the audit summary first, then expand only if repair is needed.",
        "repair_advanced_hint_visible": "Advanced Repair options are visible. Confirm the latest audit context before any write action.",
        "recommended_path": "Recommended path",
        "recommended_path_body": "Choose a local root or drop repository folders below. Then run Audit and review findings before Repair.",
        "repositories_root": "Repositories Root",
        "choose_repositories_root": "Choose the repositories root directory",
        "setup_initial_hint": "Initial setup is open. Save it once, then the main screen stays focused on Audit.",
        "hide_settings": "Hide Settings",
        "open_settings": "Open Settings",
        "setup_settings": "Setup & Settings",
        "settings_status": "Use these controls for policy/output overrides, GitHub owner audits, and advanced identity setup.",
        "gui_language": "GUI Language",
        "gui_appearance": "GUI Theme",
        "policy_file": "Policy File",
        "choose_policy_file": "Choose a policy file",
        "audit_results_folder": "Audit Results Folder",
        "choose_results_folder": "Choose the base results directory",
        "optional_json_copy": "Optional JSON Copy",
        "choose_json_copy": "Choose the extra JSON export path",
        "github_owner": "GitHub Owner / Org",
        "github_owner_placeholder": "optional owner or organization",
        "remote_repo_filters": "Remote repo filters",
        "remote_repo_filters_placeholder": "repo-a, repo-b",
        "clone_workers": "Clone workers",
        "include_forks": "Include forks",
        "fast_shallow_clone": "Fast shallow clone",
        "max_findings": "Max findings per check",
        "settings_persist_note": "These settings persist locally for the GUI. Secret/token values are not stored here.",
        "save_setup": "Save Setup",
        "advanced_identity_hidden": "Advanced identity settings are hidden for the normal audit-only path.",
        "advanced_identity_visible": "Advanced identity settings are visible. Use them only when Repair needs custom metadata.",
        "show_advanced_identity": "Show advanced identity settings",
        "hide_advanced_identity": "Hide advanced identity settings",
        "owner_profile": "Owner Profile (repair defaults)",
        "owner_profile_body": "Used by Repair when rewriting or redacting commit identity metadata.",
        "noreply_email": "Noreply Email",
        "placeholder_email": "Placeholder Email",
        "owner_name": "Owner Name",
        "private_emails_to_replace": "Private emails to replace",
        "optional_git_identity": "Optional: Git Identity & GitHub Email Privacy",
        "git_user_name": "git user.name",
        "git_user_email": "git user.email (noreply)",
        "apply_global_git_config": "Apply Global Git Config",
        "apply_local_git_config": "Apply Local Git Config",
        "read_current_git_identity": "Read Current Git Identity",
        "open_github_email_settings": "Open GitHub Email Settings",
        "github_email_privacy_help": GITHUB_EMAIL_PRIVACY_HELP,
        "identity_help": (
            "Use this only if your local Git identity needs privacy-safe noreply settings. "
            "Use GitHub Email Settings to verify private-email and push-block protections, and to copy your noreply address when needed."
        ),
        "repair_plan_options": "Repair Plan Options",
        "review_output_options": "Review & Output Options",
        "review_output_info": "CLI-equivalent run toggles. They do not rewrite history on their own.",
        "only_audit_public_remotes": "Only audit public remotes",
        "redact_third_party_emails": "Redact third-party emails during repair",
        "low_confidence_blocking": "Treat low-confidence emails as blocking",
        "dry_run_preview": "Dry run / preview repair",
        "audit_github_hardening": "Audit GitHub release hardening",
        "audit_litellm_incident": "Audit LiteLLM incident (Mar-2026)",
        "open_html_report": "Open HTML report automatically",
        "confirm_each_repo_fix": "Confirm each repository during repair",
        "repair_write_actions": "Repair Write Actions",
        "repair_write_info": "These options are only applied when you click Repair.",
        "repair_write_body": "Only applied when you click Repair. Review the latest audit summary before enabling them.",
        "rewrite_personal_paths": "Rewrite personal paths in history",
        "rewrite_personal_paths_body": "Uses reviewed replace-text rules during repair to rewrite detected personal paths.",
        "replace_text_rules": "Additional Replace-Text Rules",
        "choose_replace_text_file": "Choose an explicit replace-text file",
        "replace_text_rules_body": "Optional operator-reviewed literal replacements for cleanup the tool cannot infer safely.",
        "force_push": "Force-push rewritten history",
        "bypass_remote_owner_guardrail": "Bypass remote-owner guardrail",
        "allowed_remote_owners": "Allowed remote owners",
        "allowed_remote_owners_body": "Use a comma-separated allowlist. Leave bypass off to keep owner verification active.",
        "purge_safe_secret_files": "Purge safe secret-file candidates",
        "purge_risky_secret_files": "Purge risky manual-review candidates too",
        "purge_body": "Safe mode skips ambiguous files. Risky mode also includes candidates that still need manual judgment.",
        "repair_flow": "Repair Flow",
        "audit_required": "Audit required",
        "audit_again_required": "Audit again required",
        "latest_audit_summary": "Latest audit summary",
        "no_audit_results": "No audit results in this session yet. Run Audit first, then review the summary before applying write actions.",
        "repair_stays_disabled": "Repair stays disabled until Audit finishes and the review window completes.",
        "repair_review_pending_note": "Review the audit summary first. Repair unlocks when the review window completes.",
        "repair_ready_note": "Repair is available for reviewed cleanup actions. Keep destructive options off unless explicitly approved.",
        "repair_tab_locked": "Repair tab locked",
        "before_repair": "Before Repair, do this:",
        "repair_lock_step_1": "1. Run Audit and confirm the selected repositories are the ones you want to review.",
        "repair_lock_step_2": "2. Read the log and findings summary before enabling any write actions.",
        "repair_lock_step_3": "3. Come back here only when you are ready to confirm a repair plan.",
        "go_to_audit": "Go to Audit",
        "repositories": "Repositories",
        "run_audit": "Run Audit",
        "audit_unavailable": "Audit unavailable",
        "stop_after_current_step": "Stop After Current Step",
        "stopping_after_current_step": "Stopping after current step...",
        "refresh": "Refresh",
        "repo_summary_default": "Select repositories, drop repository folders, or leave empty to audit every repository shown under Root.",
        "repo_drop_hint": "Drag repository folders here, or use Browse / Refresh.",
        "repo_drop_ready": "Drag repository folders here to set the audit target, or use Browse / Refresh.",
        "repo_drop_unavailable": "Drag-and-drop is unavailable in this Tk runtime. Use Browse / Refresh. ({error})",
        "repo_drop_registration_failed": "Drag-and-drop registration failed. Use Browse / Refresh. ({error})",
        "repo_targets_unavailable": "Repository targets unavailable",
        "choose_valid_root": "Choose a valid Root folder to load one or more git repositories.",
        "run_audit_available_hint": "Run Audit becomes available once at least one repository target is visible in this list.",
        "select_all": "Select All",
        "clear_selection": "Clear Selection",
        "clear_log": "Clear Log",
        "execution_log": "Execution Log",
        "execution_log_empty": (
            "Audit output will appear here.\n"
            "Run Audit to stream progress, then open report.html, report.json, or run.log from Reports."
        ),
        "browse": "Browse…",
        "save_as": "Save As…",
        "setup_hint_open": "Setup is open. Save it once, then the main screen stays focused on Audit.",
        "setup_hint_remote": "Settings hidden. GitHub owner/org remote audit is active for {github_owner} (audit-only; local list ignored). Open Settings to edit.",
        "setup_hint_hidden": "Setup is saved and hidden. Open Settings for policy, output, GitHub, or identity controls.",
        "all_matching_repositories": "all matching repositories",
        "named_remote_repo_singular": "{count} named remote repository",
        "named_remote_repo_plural": "{count} named remote repositories",
        "github_remote_state": (
            "Audit will discover {filter_text} for {github_owner}, clone them into a temporary private directory, "
            "and remove the clones when the run finishes. Remote mode is audit-only, so Repair stays unavailable for these targets."
        ),
        "repo_empty_invalid_root_title": "Root folder not found",
        "repo_empty_invalid_root_hint": "Pick a valid directory, then refresh the repository list.",
        "repo_empty_no_repos_title": "No repositories found",
        "repo_empty_no_repos_hint": "Clone a repository here or point Root at a folder that already contains git repositories.",
        "repo_empty_github_remote_title": "GitHub owner/org audit active",
        "repo_empty_github_remote_hint": "Local repository selection is paused. Open Settings to edit or clear the GitHub owner/org.",
        "repo_summary_remote": (
            "GitHub owner/org audit is active for {github_owner}. The local repository list is ignored; Audit will discover "
            "{filter_text} through GitHub and keep Repair locked because remote mode is audit-only."
        ),
        "repo_summary_invalid_root": "Root folder not found. Choose a valid directory before running Audit.",
        "repo_summary_no_repos": "No git repositories detected under Root yet. Choose another folder or refresh after cloning.",
        "repo_word_singular": "repository",
        "repo_word_plural": "repositories",
        "no_repos_selected": "No repositories selected.",
        "selected_count": "{count} selected.",
        "current_root_available": " Current Root is available in the list.",
        "current_root_label": "Current Root",
        "repo_summary_targets": (
            "Step 2: {total} {repo_word} shown under Root. {selected_text} "
            "Leave the selection empty to audit every repository shown.{root_hint}"
        ),
        "lock_repair_default": "Repair (run audit first)",
        "lock_repair_run_again": "Repair (run audit again)",
        "lock_repair_cancelled": "Repair (audit cancelled)",
        "lock_repair_failed": "Repair (audit failed)",
        "lock_repair_remote": "Repair (remote audit is audit-only)",
        "lock_repair_in_progress": "Repair (audit in progress)",
        "lock_repair_no_results": "Repair (no audited results yet)",
        "lock_repair_message": "{reason}. Run Audit again before applying more write actions.",
        "repair_wait": "Repair (wait {seconds}s)",
        "repair": "Repair",
        "review_window": "Review window",
        "repair_ready": "Repair ready",
        "optional_cleanup": "Optional cleanup",
        "repair_unlocks_after_review": " Repair unlocks after the review window completes.",
        "repair_now_available": " Repair is now available if you still want to apply reviewed cleanup actions.",
        "repair_unlocks_in": " Repair unlocks in {seconds}s.",
        "repair_lock_default_reason": "Repair stays locked until a valid audit has completed.",
        "repair_lock_message": "{reason}\n\nRun Audit, review the results, and return here only when the repair plan is ready to confirm.",
        "last_audit_failed": "Last audit: {label}. {failed} FAIL / {passed} PASS.{detail_text} Review the findings and confirm every write action before Repair.",
        "last_audit_passed_manual": "Last audit: {label}. All selected repositories passed.{detail_text} Classify advisory findings before publication; Repair is optional and should only apply reviewed cleanup actions.",
        "last_audit_passed": "Last audit: {label}. All selected repositories passed.{detail_text} Repair is optional; use it only if you still want to apply reviewed cleanup actions.",
        "blocking_category_singular": "{count} blocking category",
        "blocking_category_plural": "{count} blocking categories",
        "manual_signal_singular": "{count} manual-review signal",
        "manual_signal_plural": "{count} manual-review signals",
        "fixture_match_singular": "{count} fixture/documentation match kept non-blocking",
        "fixture_match_plural": "{count} fixture/documentation matches kept non-blocking",
        "repair_plan_intro": "Repair will run with the following plan:",
        "active_options": "Active options:",
        "yes": "YES",
        "no": "NO",
        "auto_owner": "(auto from noreply if available)",
        "plan_rewrite_paths": "- Rewrite personal paths: {value}",
        "plan_replace_text": "- Explicit replace-text file: {value}",
        "plan_purge_safe": "- Purge SAFE: {value}",
        "plan_purge_risky": "- Purge RISKY: {value}",
        "plan_force_push": "- Force push remote: {value}",
        "plan_open_report": "- Open HTML report automatically: {value}",
        "plan_confirm_each_repo": "- Confirm each repo fix: {value}",
        "plan_allow_bypass": "- Allow non-owner push bypass: {value}",
        "plan_allowed_owners": "- Allowed push owner(s): {value}",
        "repair_baseline_changes": "Repair baseline changes:",
        "baseline_gitignore": "- May add missing .gitignore patterns",
        "baseline_untrack": "- May run git rm --cached on tracked-but-ignored files",
        "baseline_rewrite": "- May rewrite history with git-filter-repo depending on the selected options",
        "risky_warning_1": "WARNING: you selected RISKY options (purge all, force push, or owner-guardrail bypass).",
        "risky_warning_2": "This can remove historical content irreversibly and/or bypass remote-owner protections.",
        "audited_findings_summary": "Explicit summary of audited findings:",
        "repo_status_line": "- {name} [{status}]",
        "blocking_categories_line": "  * Blocking categories: {count}",
        "manual_review_signals_line": "  * Manual-review signals: {count}",
        "fixture_context_line": "  * Fixture/documentation matches kept non-blocking: {count}",
        "planned_untrack_line": "  * Planned untrack (tracked-but-ignored): {count}",
        "planned_path_rewrite_line": "  * Planned personal-path rewrite: {count} findings",
        "personal_paths_disabled": "  * Personal paths: rewrite disabled",
        "planned_purge_risky_line": "  * Planned Purge RISKY: {count} candidates",
        "planned_purge_safe_line": "  * Planned Purge SAFE: {count} candidates",
        "more_items": "    - ... and {count} more",
        "secret_purge_disabled": "  * Secret-file purge: disabled",
        "continue_question": "Continue?",
        "rerun_if_changed": "(If you changed the repo selection or options, run Audit again first.)",
        "dialog_repair_locked_title": "Repair Locked",
        "dialog_repair_locked_review": "Repair becomes available only after a completed audit and a 10-second review window.",
        "dialog_repair_locked_no_results": "There are no audit results in this session yet. Run Audit first.",
        "dialog_new_audit_required_title": "New Audit Required",
        "dialog_new_audit_required": "The current repo selection does not match the last audit. Run Audit again before Repair.",
        "dialog_confirm_repair_title": "Confirm Repair Plan",
        "dialog_risk_title": "Risk Acceptance Required",
        "dialog_risk_message": "You selected RISKY options (purge all, force push, or owner-guardrail bypass).\nConfirm that you accept continuing AT YOUR OWN RISK.",
        "dialog_invalid_git_identity": "Invalid Git identity",
        "dialog_confirm_global_git_config": "Confirm Global Git Config",
        "dialog_confirm_global_git_config_message": "This updates git config --global for all repositories on this machine. Continue?",
        "dialog_global_git_config": "Global Git Config",
        "dialog_local_git_config": "Local Git Config",
        "dialog_read_git_identity": "Read Git Identity",
        "dialog_read_git_identity_select_one": "Select zero or one repository to inspect local/effective git identity.",
        "dialog_not_git_repo": "Not a git repository: {candidate}",
        "dialog_current_git_identity": "Current Git Identity",
        "dialog_github_email_settings": "GitHub Email Settings",
        "dialog_run_in_progress": "Run In Progress",
        "dialog_run_in_progress_message": "There is already an execution in progress. Wait until it finishes.",
        "dialog_remote_audit_only": "Remote Audit Is Audit-Only",
        "dialog_remote_audit_only_message": "GitHub owner/org remote audit cannot be combined with Repair. Clear GitHub Owner / Org before repairing local repositories.",
        "dialog_run_all_title": "Run all repositories",
        "dialog_run_all_message": "No repositories selected. Run {action_name} for all repositories under Root?",
        "dialog_invalid_max_matches": "Invalid Max Matches",
        "dialog_invalid_max_matches_message": "Max matches must be a positive integer.",
        "dialog_invalid_github_jobs": "Invalid GitHub Jobs",
        "dialog_invalid_github_jobs_message": "GitHub clone workers must be a positive integer.",
        "action_repair": "repair",
        "action_audit": "audit",
        "confirm_repo_repair_title": "Confirm Repair for This Repository",
        "confirm_repo_repair_message": "Repository {index}/{total}: {repo_name}\n\nApply Repair to this repository?\nYou can answer No to skip only this repository.",
        "install_github_tooling_title": "Install GitHub Tooling",
        "install_github_tooling_intro": "GitHub hardening checks work best with GitHub CLI (`gh`) and, on Windows, a healthy App Installer / winget setup.",
        "install_github_tooling_confirm": "Install or repair that tooling now?",
        "github_auth_needed_title": "GitHub Authentication Still Needed",
        "github_auth_needed_message": "GitHub CLI is installed, but token-gated hardening checks still need authentication.\n\nRun `gh auth login`, or set REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN.",
    },
    GUI_LOCALE_ES_419: {
        "header_title": "Repo Privacy Guardian",
        "header_subtitle": "Empezá por Auditar: elegí una carpeta raíz, revisá hallazgos y usá Reparar sólo cuando se libere el gate de seguridad.",
        "workflow_audit": "1 Auditar",
        "workflow_review": "2 Revisar hallazgos",
        "workflow_repair": "3 Reparar si hace falta",
        "workflow_parity": "Paridad CLI: mismo backend",
        "tab_audit": "1. Auditar",
        "tab_reports": "2. Reportes",
        "tab_prompts": "3. Prompts",
        "tab_settings": "4. Configuración",
        "tab_repair": "5. Reparar",
        "audit_target": "Objetivo de auditoría",
        "audit_target_body": "Elegí repositorios locales acá. Los controles avanzados de política, GitHub owner/org e identidad viven en Configuración.",
        "open_settings_tab": "Abrir configuración",
        "last_run": "Última corrida",
        "last_run_none": "Todavía no terminó ninguna corrida GUI en esta sesión.",
        "reports_dashboard": "Dashboard de reportes",
        "reports_dashboard_body": "Abrí evidencia local de la última corrida. Tratá los artefactos como sensibles incluso cuando los valores estén redactados.",
        "latest_artifacts": "Últimos artefactos",
        "latest_artifacts_none": "Ejecutá Auditar para crear report.json, report.html, run.log y run_state.json.",
        "open_html_report_action": "Abrir reporte HTML",
        "open_json_report_action": "Abrir report.json",
        "open_run_log_action": "Abrir run.log",
        "open_artifacts_folder_action": "Abrir carpeta de artefactos",
        "prompts_library": "Biblioteca de prompts agénticos",
        "prompts_library_body": "Copiá un prompt revisado en Codex, Claude Code, Antigravity, GitHub Copilot, Cursor o una IDE agéntica similar. Los prompts usan el flujo CLI-first y evitan evidencia sensible cruda.",
        "copy_prompt": "Copiar prompt",
        "copy_command": "Copiar comando",
        "open_prompt": "Abrir prompt",
        "prompt_command": "Comando",
        "prompt_copied": "Prompt copiado al portapapeles.",
        "prompt_command_copied": "Comando copiado al portapapeles.",
        "prompt_open_failed": "No se pudo abrir el archivo de prompt: {error}",
        "settings_companion_title": "Configuración avanzada",
        "settings_companion_body": "Estos controles preservan paridad CLI pero quedan fuera del camino principal de auditoría.",
        "repair_advanced_toggle_show": "Mostrar opciones avanzadas de Reparar",
        "repair_advanced_toggle_hide": "Ocultar opciones avanzadas de Reparar",
        "repair_advanced_hint_hidden": "Las opciones avanzadas de escritura están ocultas. Revisá el resumen de auditoría y expandí sólo si hace falta reparar.",
        "repair_advanced_hint_visible": "Las opciones avanzadas de Reparar están visibles. Confirmá el contexto de la última auditoría antes de cualquier acción de escritura.",
        "recommended_path": "Camino recomendado",
        "recommended_path_body": "Elegí una carpeta raíz local o arrastrá repositorios abajo. Después ejecutá Auditar y revisá hallazgos antes de Reparar.",
        "repositories_root": "Carpeta raíz de repositorios",
        "choose_repositories_root": "Elegir la carpeta raíz de repositorios",
        "setup_initial_hint": "La configuración inicial está abierta. Guardala una vez y la pantalla principal queda enfocada en Auditar.",
        "hide_settings": "Ocultar configuración",
        "open_settings": "Abrir configuración",
        "setup_settings": "Setup y configuración",
        "settings_status": "Usá estos controles para política/salida, auditorías GitHub owner/org e identidad avanzada.",
        "gui_language": "Idioma de la GUI",
        "gui_appearance": "Tema de la GUI",
        "policy_file": "Archivo de política",
        "choose_policy_file": "Elegir un archivo de política",
        "audit_results_folder": "Carpeta de resultados",
        "choose_results_folder": "Elegir la carpeta base de resultados",
        "optional_json_copy": "Copia JSON opcional",
        "choose_json_copy": "Elegir la ruta extra de export JSON",
        "github_owner": "GitHub owner / org",
        "github_owner_placeholder": "owner u organización opcional",
        "remote_repo_filters": "Filtros de repos remotos",
        "remote_repo_filters_placeholder": "repo-a, repo-b",
        "clone_workers": "Workers de clone",
        "include_forks": "Incluir forks",
        "fast_shallow_clone": "Clone shallow rápido",
        "max_findings": "Máx. hallazgos por check",
        "settings_persist_note": "Estas preferencias quedan guardadas localmente para la GUI. No se guardan secretos ni tokens.",
        "save_setup": "Guardar setup",
        "advanced_identity_hidden": "La identidad avanzada está oculta para el flujo normal audit-only.",
        "advanced_identity_visible": "La identidad avanzada está visible. Usala sólo si Reparar necesita metadatos personalizados.",
        "show_advanced_identity": "Mostrar identidad avanzada",
        "hide_advanced_identity": "Ocultar identidad avanzada",
        "owner_profile": "Perfil del owner (defaults de reparación)",
        "owner_profile_body": "Lo usa Reparar al reescribir o redactar metadatos de identidad de commits.",
        "noreply_email": "Email noreply",
        "placeholder_email": "Email placeholder",
        "owner_name": "Nombre del owner",
        "private_emails_to_replace": "Emails privados a reemplazar",
        "optional_git_identity": "Opcional: identidad Git y privacidad de email GitHub",
        "git_user_name": "git user.name",
        "git_user_email": "git user.email (noreply)",
        "apply_global_git_config": "Aplicar config Git global",
        "apply_local_git_config": "Aplicar config Git local",
        "read_current_git_identity": "Leer identidad Git actual",
        "open_github_email_settings": "Abrir settings de email GitHub",
        "github_email_privacy_help": (
            "Usá GitHub Email Settings para verificar privacidad de email, bloqueo de pushes con email privado "
            "y copiar tu dirección noreply cuando haga falta."
        ),
        "identity_help": (
            "Usá esto sólo si tu identidad Git local necesita settings noreply seguros. "
            "Usá GitHub Email Settings para verificar privacidad de email, bloqueo de pushes con email privado y copiar tu dirección noreply cuando haga falta."
        ),
        "repair_plan_options": "Opciones del plan de reparación",
        "review_output_options": "Opciones de revisión y salida",
        "review_output_info": "Toggles equivalentes al CLI. No reescriben historial por sí solos.",
        "only_audit_public_remotes": "Auditar sólo remotos públicos",
        "redact_third_party_emails": "Redactar emails de terceros al reparar",
        "low_confidence_blocking": "Tratar emails low-confidence como bloqueantes",
        "dry_run_preview": "Dry run / preview de reparación",
        "audit_github_hardening": "Auditar hardening de release GitHub",
        "audit_litellm_incident": "Auditar incidente LiteLLM (mar-2026)",
        "open_html_report": "Abrir reporte HTML automáticamente",
        "confirm_each_repo_fix": "Confirmar cada repositorio al reparar",
        "repair_write_actions": "Acciones de escritura de Reparar",
        "repair_write_info": "Estas opciones sólo se aplican cuando hacés clic en Reparar.",
        "repair_write_body": "Sólo se aplican cuando hacés clic en Reparar. Revisá el último resumen de auditoría antes de activarlas.",
        "rewrite_personal_paths": "Reescribir rutas personales en historial",
        "rewrite_personal_paths_body": "Usa reglas replace-text revisadas durante Reparar para reescribir rutas personales detectadas.",
        "replace_text_rules": "Reglas replace-text adicionales",
        "choose_replace_text_file": "Elegir un archivo replace-text explícito",
        "replace_text_rules_body": "Reemplazos literales revisados por operador para limpieza que la herramienta no puede inferir con seguridad.",
        "force_push": "Force-push del historial reescrito",
        "bypass_remote_owner_guardrail": "Bypass del guardrail de owner remoto",
        "allowed_remote_owners": "Owners remotos permitidos",
        "allowed_remote_owners_body": "Usá una allowlist separada por coma. Dejá bypass apagado para mantener verificación de owner.",
        "purge_safe_secret_files": "Purgar candidatos seguros de archivos secretos",
        "purge_risky_secret_files": "Purgar también candidatos riesgosos/manual-review",
        "purge_body": "El modo seguro omite archivos ambiguos. El modo riesgoso también incluye candidatos que requieren juicio manual.",
        "repair_flow": "Flujo de reparación",
        "audit_required": "Auditoría requerida",
        "audit_again_required": "Nueva auditoría requerida",
        "latest_audit_summary": "Último resumen de auditoría",
        "no_audit_results": "Todavía no hay resultados de auditoría en esta sesión. Ejecutá Auditar primero y revisá el resumen antes de aplicar acciones de escritura.",
        "repair_stays_disabled": "Reparar queda deshabilitado hasta que Auditar termine y se complete la ventana de revisión.",
        "repair_review_pending_note": "Revisá primero el resumen de auditoría. Reparar se habilita cuando termina la ventana de revisión.",
        "repair_ready_note": "Reparar está disponible para limpiezas revisadas. Mantené apagadas las opciones destructivas salvo aprobación explícita.",
        "repair_tab_locked": "Pestaña Reparar bloqueada",
        "before_repair": "Antes de Reparar, hacé esto:",
        "repair_lock_step_1": "1. Ejecutá Auditar y confirmá que seleccionaste los repositorios correctos.",
        "repair_lock_step_2": "2. Leé el log y el resumen de hallazgos antes de activar acciones de escritura.",
        "repair_lock_step_3": "3. Volvé acá sólo cuando estés listo para confirmar un plan de reparación.",
        "go_to_audit": "Ir a Auditar",
        "repositories": "Repositorios",
        "run_audit": "Ejecutar Auditar",
        "audit_unavailable": "Auditoría no disponible",
        "stop_after_current_step": "Detener luego del paso actual",
        "stopping_after_current_step": "Deteniendo luego del paso actual...",
        "refresh": "Actualizar",
        "repo_summary_default": "Seleccioná repositorios, arrastrá carpetas o dejá vacío para auditar todo lo visible bajo Root.",
        "repo_drop_hint": "Arrastrá carpetas de repositorios acá, o usá Buscar / Actualizar.",
        "repo_drop_ready": "Arrastrá carpetas de repositorios acá para configurar el objetivo de auditoría, o usá Buscar / Actualizar.",
        "repo_drop_unavailable": "Drag-and-drop no está disponible en este runtime Tk. Usá Buscar / Actualizar. ({error})",
        "repo_drop_registration_failed": "Falló el registro de drag-and-drop. Usá Buscar / Actualizar. ({error})",
        "repo_targets_unavailable": "Objetivos de repositorio no disponibles",
        "choose_valid_root": "Elegí una carpeta Root válida para cargar uno o más repositorios git.",
        "run_audit_available_hint": "Ejecutar Auditar queda disponible cuando hay al menos un repositorio visible en esta lista.",
        "select_all": "Seleccionar todo",
        "clear_selection": "Limpiar selección",
        "clear_log": "Limpiar log",
        "execution_log": "Log de ejecución",
        "execution_log_empty": (
            "La salida de Auditar va a aparecer acá.\n"
            "Ejecutá Auditar para ver el progreso y luego abrí report.html, report.json o run.log desde Reportes."
        ),
        "browse": "Buscar…",
        "save_as": "Guardar como…",
        "setup_hint_open": "Setup abierto. Guardalo una vez y la pantalla principal queda enfocada en Auditar.",
        "setup_hint_remote": "Configuración oculta. Auditoría remota GitHub owner/org activa para {github_owner} (audit-only; se ignora la lista local). Abrí Configuración para editar.",
        "setup_hint_hidden": "Setup guardado y oculto. Abrí Configuración para política, salida, GitHub o identidad.",
        "all_matching_repositories": "todos los repositorios que coincidan",
        "named_remote_repo_singular": "{count} repositorio remoto nombrado",
        "named_remote_repo_plural": "{count} repositorios remotos nombrados",
        "github_remote_state": (
            "Auditar va a descubrir {filter_text} para {github_owner}, clonarlos en una carpeta privada temporal "
            "y eliminar los clones al finalizar. El modo remoto es audit-only, así que Reparar queda no disponible para esos objetivos."
        ),
        "repo_empty_invalid_root_title": "Carpeta Root no encontrada",
        "repo_empty_invalid_root_hint": "Elegí un directorio válido y después actualizá la lista de repositorios.",
        "repo_empty_no_repos_title": "No se encontraron repositorios",
        "repo_empty_no_repos_hint": "Cloná un repositorio acá o apuntá Root a una carpeta que ya contenga repositorios git.",
        "repo_empty_github_remote_title": "Auditoría GitHub owner/org activa",
        "repo_empty_github_remote_hint": "La selección local está pausada. Abrí Configuración para editar o limpiar GitHub owner/org.",
        "repo_summary_remote": (
            "La auditoría GitHub owner/org está activa para {github_owner}. La lista local se ignora; Auditar va a descubrir "
            "{filter_text} vía GitHub y mantener Reparar bloqueado porque el modo remoto es audit-only."
        ),
        "repo_summary_invalid_root": "Carpeta Root no encontrada. Elegí un directorio válido antes de ejecutar Auditar.",
        "repo_summary_no_repos": "No se detectaron repositorios git bajo Root. Elegí otra carpeta o actualizá después de clonar.",
        "repo_word_singular": "repositorio",
        "repo_word_plural": "repositorios",
        "no_repos_selected": "No hay repositorios seleccionados.",
        "selected_count": "{count} seleccionados.",
        "current_root_available": " La carpeta Root actual está disponible en la lista.",
        "current_root_label": "Root actual",
        "repo_summary_targets": (
            "Paso 2: {total} {repo_word} visibles bajo Root. {selected_text} "
            "Dejá la selección vacía para auditar todos los repositorios visibles.{root_hint}"
        ),
        "lock_repair_default": "Reparar (ejecutá auditoría primero)",
        "lock_repair_run_again": "Reparar (volvé a auditar)",
        "lock_repair_cancelled": "Reparar (auditoría cancelada)",
        "lock_repair_failed": "Reparar (auditoría fallida)",
        "lock_repair_remote": "Reparar (auditoría remota es audit-only)",
        "lock_repair_in_progress": "Reparar (auditoría en curso)",
        "lock_repair_no_results": "Reparar (sin resultados auditados)",
        "lock_repair_message": "{reason}. Ejecutá Auditar nuevamente antes de aplicar más acciones de escritura.",
        "repair_wait": "Reparar (esperá {seconds}s)",
        "repair": "Reparar",
        "review_window": "Ventana de revisión",
        "repair_ready": "Reparación lista",
        "optional_cleanup": "Limpieza opcional",
        "repair_unlocks_after_review": " Reparar se desbloquea cuando termina la ventana de revisión.",
        "repair_now_available": " Reparar ya está disponible si todavía querés aplicar acciones de limpieza revisadas.",
        "repair_unlocks_in": " Reparar se desbloquea en {seconds}s.",
        "repair_lock_default_reason": "Reparar queda bloqueado hasta que termine una auditoría válida.",
        "repair_lock_message": "{reason}\n\nEjecutá Auditar, revisá los resultados y volvé acá sólo cuando el plan de reparación esté listo para confirmar.",
        "last_audit_failed": "Última auditoría: {label}. {failed} FAIL / {passed} PASS.{detail_text} Revisá los hallazgos y confirmá cada acción de escritura antes de Reparar.",
        "last_audit_passed_manual": "Última auditoría: {label}. Todos los repositorios seleccionados pasaron.{detail_text} Clasificá hallazgos advisory antes de publicar; Reparar es opcional y sólo debería aplicar limpiezas revisadas.",
        "last_audit_passed": "Última auditoría: {label}. Todos los repositorios seleccionados pasaron.{detail_text} Reparar es opcional; usalo sólo si todavía querés aplicar acciones de limpieza revisadas.",
        "blocking_category_singular": "{count} categoría bloqueante",
        "blocking_category_plural": "{count} categorías bloqueantes",
        "manual_signal_singular": "{count} señal manual-review",
        "manual_signal_plural": "{count} señales manual-review",
        "fixture_match_singular": "{count} coincidencia fixture/documentación mantenida no bloqueante",
        "fixture_match_plural": "{count} coincidencias fixture/documentación mantenidas no bloqueantes",
        "repair_plan_intro": "Reparar se va a ejecutar con este plan:",
        "active_options": "Opciones activas:",
        "yes": "SÍ",
        "no": "NO",
        "auto_owner": "(auto desde noreply si está disponible)",
        "plan_rewrite_paths": "- Reescribir rutas personales: {value}",
        "plan_replace_text": "- Archivo replace-text explícito: {value}",
        "plan_purge_safe": "- Purgar SAFE: {value}",
        "plan_purge_risky": "- Purgar RISKY: {value}",
        "plan_force_push": "- Force push remoto: {value}",
        "plan_open_report": "- Abrir reporte HTML automáticamente: {value}",
        "plan_confirm_each_repo": "- Confirmar fix por repositorio: {value}",
        "plan_allow_bypass": "- Permitir bypass de push no-owner: {value}",
        "plan_allowed_owners": "- Owner(s) permitidos para push: {value}",
        "repair_baseline_changes": "Cambios baseline de Reparar:",
        "baseline_gitignore": "- Puede agregar patrones faltantes a .gitignore",
        "baseline_untrack": "- Puede ejecutar git rm --cached sobre archivos trackeados pero ignorados",
        "baseline_rewrite": "- Puede reescribir historial con git-filter-repo según las opciones seleccionadas",
        "risky_warning_1": "WARNING: seleccionaste opciones RISKY (purgar todo, force push o bypass del guardrail de owner).",
        "risky_warning_2": "Esto puede remover contenido histórico irreversiblemente o saltar protecciones de owner remoto.",
        "audited_findings_summary": "Resumen explícito de hallazgos auditados:",
        "repo_status_line": "- {name} [{status}]",
        "blocking_categories_line": "  * Categorías bloqueantes: {count}",
        "manual_review_signals_line": "  * Señales manual-review: {count}",
        "fixture_context_line": "  * Coincidencias fixture/documentación mantenidas no bloqueantes: {count}",
        "planned_untrack_line": "  * Untrack planeado (trackeado pero ignorado): {count}",
        "planned_path_rewrite_line": "  * Reescritura planeada de rutas personales: {count} hallazgos",
        "personal_paths_disabled": "  * Rutas personales: reescritura deshabilitada",
        "planned_purge_risky_line": "  * Purga RISKY planeada: {count} candidatos",
        "planned_purge_safe_line": "  * Purga SAFE planeada: {count} candidatos",
        "more_items": "    - ... y {count} más",
        "secret_purge_disabled": "  * Purga de archivos secretos: deshabilitada",
        "continue_question": "¿Continuar?",
        "rerun_if_changed": "(Si cambiaste la selección u opciones, ejecutá Auditar de nuevo primero.)",
        "dialog_repair_locked_title": "Reparar bloqueado",
        "dialog_repair_locked_review": "Reparar queda disponible sólo después de una auditoría completa y una ventana de revisión de 10 segundos.",
        "dialog_repair_locked_no_results": "Todavía no hay resultados de auditoría en esta sesión. Ejecutá Auditar primero.",
        "dialog_new_audit_required_title": "Se requiere nueva auditoría",
        "dialog_new_audit_required": "La selección actual de repositorios no coincide con la última auditoría. Ejecutá Auditar de nuevo antes de Reparar.",
        "dialog_confirm_repair_title": "Confirmar plan de reparación",
        "dialog_risk_title": "Se requiere aceptación de riesgo",
        "dialog_risk_message": "Seleccionaste opciones RISKY (purgar todo, force push o bypass del guardrail de owner).\nConfirmá que aceptás continuar BAJO TU PROPIO RIESGO.",
        "dialog_invalid_git_identity": "Identidad Git inválida",
        "dialog_confirm_global_git_config": "Confirmar config Git global",
        "dialog_confirm_global_git_config_message": "Esto actualiza git config --global para todos los repositorios de esta máquina. ¿Continuar?",
        "dialog_global_git_config": "Config Git global",
        "dialog_local_git_config": "Config Git local",
        "dialog_read_git_identity": "Leer identidad Git",
        "dialog_read_git_identity_select_one": "Seleccioná cero o un repositorio para inspeccionar la identidad Git local/efectiva.",
        "dialog_not_git_repo": "No es un repositorio git: {candidate}",
        "dialog_current_git_identity": "Identidad Git actual",
        "dialog_github_email_settings": "Settings de email GitHub",
        "dialog_run_in_progress": "Ejecución en curso",
        "dialog_run_in_progress_message": "Ya hay una ejecución en curso. Esperá a que termine.",
        "dialog_remote_audit_only": "Auditoría remota es audit-only",
        "dialog_remote_audit_only_message": "La auditoría remota GitHub owner/org no puede combinarse con Reparar. Limpiá GitHub Owner / Org antes de reparar repositorios locales.",
        "dialog_run_all_title": "Ejecutar en todos los repositorios",
        "dialog_run_all_message": "No hay repositorios seleccionados. ¿Ejecutar {action_name} para todos los repositorios bajo Root?",
        "dialog_invalid_max_matches": "Máx. hallazgos inválido",
        "dialog_invalid_max_matches_message": "Máx. hallazgos debe ser un entero positivo.",
        "dialog_invalid_github_jobs": "Workers GitHub inválidos",
        "dialog_invalid_github_jobs_message": "Workers de clone GitHub debe ser un entero positivo.",
        "action_repair": "reparar",
        "action_audit": "auditar",
        "confirm_repo_repair_title": "Confirmar reparación para este repositorio",
        "confirm_repo_repair_message": "Repositorio {index}/{total}: {repo_name}\n\n¿Aplicar Reparar a este repositorio?\nPodés responder No para omitir sólo este repositorio.",
        "install_github_tooling_title": "Instalar tooling GitHub",
        "install_github_tooling_intro": "Los checks de hardening GitHub funcionan mejor con GitHub CLI (`gh`) y, en Windows, App Installer / winget funcionando correctamente.",
        "install_github_tooling_confirm": "¿Instalar o reparar ese tooling ahora?",
        "github_auth_needed_title": "Todavía falta autenticación GitHub",
        "github_auth_needed_message": "GitHub CLI está instalado, pero los checks con token todavía necesitan autenticación.\n\nEjecutá `gh auth login`, o configurá REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN o GH_TOKEN.",
    },
}


def choose_gui_font_family(
    candidates: tuple[str, ...],
    available_families: set[str] | None = None,
) -> str:
    if not candidates:
        raise ValueError("At least one font candidate is required.")

    if available_families:
        lowered = {family.lower() for family in available_families}
        for candidate in candidates:
            if candidate.lower() in lowered:
                return candidate

    return candidates[0]


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
            (bool(self.fix_errors), "fix execution errors occurred"),
            (bool(self.execution_errors), "repository execution errors occurred"),
        ]
        self.failures = [reason for bad, reason in checks if bad]
        self.status = "FAIL" if self.failures else "PASS"


class RepoPublicationGuard:  # pragma: no cover
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
        audit_litellm_incident: bool,
        audit_github_hardening: bool,
        allow_non_owner_push: bool,
        allowed_remote_owners: list[str],
        replace_text_file: str | None,
        logger: Callable[[str], None],
    ) -> None:
        self.root = root
        self.policy_path = policy_path
        self.noreply_email = noreply_email
        self.placeholder_email = placeholder_email
        self.owner_name = owner_name
        self.owner_emails = set(owner_emails)
        self.redact_third_party = redact_third_party
        self.purge_detected_secret_files = purge_detected_secret_files
        self.purge_all_detected_secret_files = purge_all_detected_secret_files
        self.low_confidence_email_mode = (
            low_confidence_email_mode
            if low_confidence_email_mode in {"informational", "blocking"}
            else "informational"
        )
        self.push = push
        self.dry_run = dry_run
        self.max_matches = max_matches
        self.audit_litellm_incident = audit_litellm_incident
        self.audit_github_hardening = audit_github_hardening
        self.allow_non_owner_push = allow_non_owner_push
        self.allowed_remote_owners = {
            owner.strip().lower()
            for owner in allowed_remote_owners
            if owner.strip()
        }
        self.replace_text_file = replace_text_file
        self.rewrite_personal_paths = False
        self.log = logger
        self._repo_runtime_issues: list[str] = []

        inferred_owner = infer_github_username_from_noreply(self.noreply_email)
        if inferred_owner:
            self.allowed_remote_owners.add(inferred_owner.lower())

        self.required_ignore_patterns = self._load_required_ignore_patterns()

    def _record_repo_runtime_issue(self, issue: str) -> None:
        normalized = issue.strip()
        if not normalized:
            return
        self._repo_runtime_issues.append(normalized)

    def _flush_repo_runtime_issues(self) -> list[str]:
        issues = normalize_text_values(self._repo_runtime_issues)
        self._repo_runtime_issues = []
        return issues

    def _run(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                input=input_text,
                stdin=subprocess_stdin(input_text),
                timeout=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            return CommandResult(127, "", _missing_executable_message(cmd[0]))
        except subprocess.TimeoutExpired:
            return CommandResult(
                124,
                "",
                f"Command timed out after {DEFAULT_SUBPROCESS_TIMEOUT_SECONDS}s: {shlex.join(cmd)}",
            )
        except Exception as exc:
            return CommandResult(1, "", f"Unable to execute {shlex.join(cmd)}: {exc}")
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def _run_checked(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        result = self._run(cmd, cwd=cwd, input_text=input_text)
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed ({result.returncode}): {shlex.join(cmd)}\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        return result

    def _git(self, repo: Path, *args: str) -> CommandResult:
        return self._run(["git", "-C", str(repo), *args])

    def _git_checked(self, repo: Path, *args: str) -> CommandResult:
        return self._run_checked(["git", "-C", str(repo), *args])

    def _read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def _load_required_ignore_patterns(self) -> list[str]:
        patterns = list(DEFAULT_IGNORE_BASELINE)
        if not self.policy_path.exists():
            return list(dict.fromkeys(patterns))

        raw = self._read_text(self.policy_path)
        in_block = False
        extracted: list[str] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if POLICY_MINIMUM_BASELINE_RE.match(stripped):
                in_block = True
                continue
            if in_block and POLICY_MINIMUM_BASELINE_END_RE.match(stripped):
                break
            if in_block and stripped.startswith("- "):
                candidate = stripped[2:].strip()
                if re.match(r"^[!A-Za-z0-9_.*\-/]+$", candidate):
                    extracted.append(candidate)

        patterns.extend(extracted)
        return list(dict.fromkeys(patterns))

    def _resolve_git_dir(self, repo: Path) -> Path:
        result = self._git(repo, "rev-parse", "--absolute-git-dir")
        if result.returncode == 0 and result.stdout.strip():
            git_dir = Path(result.stdout.strip())
            return git_dir if git_dir.is_absolute() else (repo / git_dir)
        return repo / ".git"

    def _read_lock_metadata(self, lock_path: Path) -> dict[str, object] | None:
        try:
            return json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _open_repo_lock_fd(self, lock_path: Path) -> int:
        if lock_path.is_symlink():
            raise RuntimeError(f"Refusing to use symlinked lock file path: {lock_path}")

        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(lock_path), flags, 0o600)
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ELOOP:
                raise RuntimeError(f"Refusing to use symlinked lock file path: {lock_path}") from exc
            raise
        _apply_private_permissions(lock_path, 0o600)
        return fd

    def _format_repo_lock_holder(self, metadata: dict[str, object] | None) -> str:
        if not metadata:
            return "unknown holder"

        details: list[str] = []
        owner_token = str(metadata.get("owner_token") or "").strip()
        if owner_token:
            details.append(owner_token)

        host = str(metadata.get("host") or "").strip()
        if host:
            details.append(f"host={host}")

        pid_raw = metadata.get("pid")
        if isinstance(pid_raw, int):
            details.append(f"pid={pid_raw}")

        acquired_at = str(metadata.get("acquired_at") or "").strip()
        if acquired_at:
            details.append(f"acquired_at={acquired_at}")

        return ", ".join(details) if details else "unknown holder"

    def acquire_repo_lock(self, repo: Path) -> RepoExecutionLock:
        git_dir = self._resolve_git_dir(repo)
        lock_parent = git_dir if git_dir.is_dir() else repo
        ensure_private_directory(lock_parent)
        lock_path = lock_parent / REPO_LOCK_FILENAME
        owner_token = f"{os.getpid()}-{threading.get_ident()}-{time.time_ns()}"
        deadline = time.monotonic() + REPO_LOCK_WAIT_SECONDS
        waiting_logged = False

        while True:
            fd: int | None = None
            acquired = False
            try:
                fd = self._open_repo_lock_fd(lock_path)
                acquired = acquire_advisory_file_lock(fd)
            except RuntimeError:
                raise
            except OSError as exc:
                raise RuntimeError(
                    f"Unable to open repository execution lock at {lock_path}: {exc}"
                ) from exc

            if not acquired:
                _close_fd_safely(fd)
                metadata = self._read_lock_metadata(lock_path)
                if time.monotonic() >= deadline:
                    holder = self._format_repo_lock_holder(metadata)
                    raise RuntimeError(
                        f"repository execution lock is busy ({holder}); retry after the active run finishes"
                    )
                if not waiting_logged:
                    self.log(f"[INFO] {repo_display_name(repo)}: waiting for repository execution lock")
                    waiting_logged = True
                time.sleep(REPO_LOCK_RETRY_SECONDS)
                continue

            acquired_at = datetime.now()
            payload = {
                "repo": str(repo),
                "owner_token": owner_token,
                "pid": os.getpid(),
                "thread_id": threading.get_ident(),
                "host": socket.gethostname(),
                "python_executable": sys.executable,
                "lock_kind": "os-advisory-file-lock",
                "acquired_at": acquired_at.isoformat(timespec="seconds"),
            }
            try:
                _write_json_to_locked_fd(fd, payload)
            except OSError:
                try:
                    release_advisory_file_lock(fd)
                except OSError:
                    pass
                _close_fd_safely(fd)
                raise
            self.log(f"[INFO] {repo_display_name(repo)}: acquired repository execution lock")
            return RepoExecutionLock(
                repo=repo,
                lock_path=lock_path,
                owner_token=owner_token,
                acquired_at=acquired_at,
                lock_fd=fd,
            )

    def release_repo_lock(self, repo_lock: RepoExecutionLock | None) -> None:
        if repo_lock is None:
            return

        metadata = _read_json_from_locked_fd(repo_lock.lock_fd) or self._read_lock_metadata(repo_lock.lock_path)
        owner_changed = (
            metadata is not None
            and str(metadata.get("owner_token") or "").strip()
            not in {"", repo_lock.owner_token}
        )
        if owner_changed:
            self.log(
                f"[WARN] {repo_display_name(repo_lock.repo)}: repository execution lock owner changed before release; releasing OS lock only"
            )
        try:
            release_payload = {
                "status": "released",
                "released_at": datetime.now().isoformat(timespec="seconds"),
                "previous_owner_token": repo_lock.owner_token,
                "pid": os.getpid(),
                "host": socket.gethostname(),
            }
            _write_json_to_locked_fd(repo_lock.lock_fd, release_payload)
        except OSError as exc:
            self.log(
                f"[WARN] {repo_display_name(repo_lock.repo)}: could not update repository execution lock metadata: {exc}"
            )

        try:
            release_advisory_file_lock(repo_lock.lock_fd)
            self.log(f"[INFO] {repo_display_name(repo_lock.repo)}: released repository execution lock")
        except OSError as exc:
            self.log(f"[WARN] {repo_display_name(repo_lock.repo)}: could not release repository execution lock: {exc}")
        finally:
            _close_fd_safely(repo_lock.lock_fd)

    def _read_local_git_config(self, repo: Path, key: str) -> str | None:
        result = self._git(repo, "config", "--local", "--get", key)
        if result.returncode != 0:
            return None
        value = result.stdout.strip()
        return value if value else None

    def _capture_local_identity(self, repo: Path) -> dict[str, str | None]:
        return {
            "user.name": self._read_local_git_config(repo, "user.name"),
            "user.email": self._read_local_git_config(repo, "user.email"),
        }

    def _restore_local_identity(self, repo: Path, original_identity: dict[str, str | None]) -> None:
        if self.dry_run:
            return

        for key, original_value in original_identity.items():
            if original_value is None:
                self._git(repo, "config", "--local", "--unset-all", key)
                continue
            self._git_checked(repo, "config", "--local", key, original_value)

    def discover_repositories(
        self,
        repo_filters: list[str] | None,
        public_only: bool,
    ) -> list[Path]:
        repos, skipped, root_error = discover_repository_targets(self.root, repo_filters)
        if root_error:
            raise RuntimeError(root_error)

        for skipped_path in skipped:
            self.log(f"[WARN] Not a git repo or missing path: {skipped_path}")

        if public_only:
            filtered: list[Path] = []
            visibility_cache: dict[str, tuple[bool | None, str]] = {}
            for repo in repos:
                origin = self._git(repo, "remote", "get-url", "origin")
                if origin.returncode != 0:
                    self.log(f"[WARN] {repo_display_name(repo)}: origin remote unavailable; excluded by public-only filter")
                    continue

                remote_url = origin.stdout.strip()
                if not remote_url:
                    self.log(f"[WARN] {repo_display_name(repo)}: empty origin remote; excluded by public-only filter")
                    continue

                if remote_url not in visibility_cache:
                    visibility_cache[remote_url] = is_public_github_remote(remote_url)

                is_public, reason = visibility_cache[remote_url]
                if is_public:
                    filtered.append(repo)
                    continue

                if reason == "not_github":
                    self.log(
                        f"[INFO] {repo_display_name(repo)}: origin is not a GitHub remote; excluded by public-only filter"
                    )
                elif reason in {"private", "private_or_not_found"}:
                    self.log(
                        f"[INFO] {repo_display_name(repo)}: origin appears private (or not publicly accessible); excluded"
                    )
                else:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: unable to verify public visibility ({reason}); excluded"
                    )

            repos = filtered

        return repos

    def _iter_tracked_files(self, repo: Path) -> list[Path]:
        result = self._git(repo, "ls-files", "-z")
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown git ls-files failure"
            self._record_repo_runtime_issue(
                f"tracked-file enumeration failed: {detail}"
            )
            return []
        files: list[Path] = []
        for chunk in result.stdout.split("\x00"):
            if not chunk:
                continue
            files.append(repo / chunk)
        return files

    def _scan_tracked_content(
        self,
        repo: Path,
        regex: re.Pattern[str],
        only_code_files: bool = False,
        path_filter: Callable[[str], bool] | None = None,
    ) -> list[str]:
        matches: list[str] = []
        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            if path_filter and not path_filter(rel):
                continue
            if only_code_files and file_path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append(f"{rel}:{idx}:{line.strip()[:240]}")
                    if len(matches) >= self.max_matches:
                        return matches
        return matches

    def _append_secret_taxonomy_match(
        self,
        *,
        rel_path: str | None,
        line_number: int,
        line: str,
        high_confidence: list[str],
        low_confidence: list[str],
        fixtures: list[str],
        documentation: list[str],
        history: bool = False,
    ) -> None:
        has_high_confidence_secret = SECRET_CONTENT_RE.search(line) is not None
        has_low_confidence_secret = (
            not has_high_confidence_secret
            and LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE.search(line) is not None
        )
        if not has_high_confidence_secret and not has_low_confidence_secret:
            return

        rel = rel_path or "-"
        snippet = line.strip()[:240]
        entry = f"L{line_number}:{rel}:{snippet}" if history else f"{rel}:{line_number}:{snippet}"
        context = classify_secret_match_context(rel_path, snippet)

        if context == "fixture":
            if len(fixtures) < self.max_matches:
                fixtures.append(entry)
            return
        if context == "documentation":
            if len(documentation) < self.max_matches:
                documentation.append(entry)
            return
        if has_high_confidence_secret:
            if len(high_confidence) < self.max_matches:
                high_confidence.append(entry)
            return
        if len(low_confidence) < self.max_matches:
            low_confidence.append(entry)

    def _scan_tracked_secret_taxonomy(
        self,
        repo: Path,
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        high_confidence: list[str] = []
        low_confidence: list[str] = []
        fixtures: list[str] = []
        documentation: list[str] = []

        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                self._append_secret_taxonomy_match(
                    rel_path=rel,
                    line_number=idx,
                    line=line,
                    high_confidence=high_confidence,
                    low_confidence=low_confidence,
                    fixtures=fixtures,
                    documentation=documentation,
                )
        return high_confidence, low_confidence, fixtures, documentation

    def _scan_exfil_code_indicators(self, repo: Path) -> list[str]:
        matches: list[str] = []
        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            if file_path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                if line_has_exfil_indicator(line, rel_path=rel):
                    matches.append(f"{rel}:{idx}:{line.strip()[:240]}")
                    if len(matches) >= self.max_matches:
                        return matches
        return matches

    def _is_supply_chain_candidate_path(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/").strip().lower()
        file_name = Path(normalized).name

        if file_name in SUPPLY_CHAIN_CANDIDATE_FILENAMES:
            return True
        if normalized.startswith(".github/workflows/"):
            return True
        if normalized.startswith(".gitlab/") and file_name.endswith((".yml", ".yaml")):
            return True
        if normalized.startswith("ci/") or normalized.startswith("scripts/"):
            return file_name.endswith((".py", ".sh", ".ps1", ".yml", ".yaml", ".toml", ".txt"))

        return False

    def _scan_litellm_incident(self, repo: Path, report: RepoReport) -> None:
        report.litellm_reference_hits = self._scan_tracked_content(
            repo,
            LITELLM_REFERENCE_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_compromised_reference_hits = self._scan_tracked_content(
            repo,
            LITELLM_COMPROMISED_VERSION_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_install_command_hits = self._scan_tracked_content(
            repo,
            LITELLM_INSTALL_COMMAND_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_ioc_hits = self._scan_tracked_content(
            repo,
            LITELLM_IOC_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_incident_severity = classify_litellm_incident_severity(report)

    def _scan_git_metadata_secrets(self, repo: Path, report: RepoReport) -> None:
        high_confidence: list[str] = []
        low_confidence: list[str] = []

        def inspect_value(label: str, value: str | None) -> None:
            if not value:
                return
            snippet = value.strip()[:240]
            normalized_assignment = re.sub(r"^([^\s=]+)\s+", r"\1=", snippet, count=1)
            candidates = [snippet]
            if normalized_assignment != snippet:
                candidates.append(normalized_assignment)
            if any(SECRET_CONTENT_RE.search(candidate) for candidate in candidates):
                if len(high_confidence) < self.max_matches:
                    high_confidence.append(f"{label}:{snippet}")
                return
            low_confidence_candidate = next(
                (
                    candidate
                    for candidate in candidates
                    if LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE.search(candidate)
                ),
                None,
            )
            if low_confidence_candidate:
                if len(low_confidence) < self.max_matches:
                    low_confidence.append(f"{label}:{low_confidence_candidate}")

        inspect_value("origin_url", report.origin_url)
        inspect_value("upstream_url", report.upstream_url)

        config = self._git(
            repo,
            "config",
            "--local",
            "--get-regexp",
            r"^(http\..*\.extraheader|url\..*\.insteadOf|credential\..*)",
        )
        if config.returncode not in {0, 1}:
            detail = (config.stderr or config.stdout or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"git metadata secret scan failed with exit code {config.returncode}{suffix}"
            )
            report.git_metadata_secret_matches = high_confidence
            report.git_metadata_secret_low_confidence = low_confidence
            return

        for line in config.stdout.splitlines():
            inspect_value("git_config", line)

        report.git_metadata_secret_matches = high_confidence
        report.git_metadata_secret_low_confidence = low_confidence

    def _scan_github_hardening(self, repo: Path, report: RepoReport) -> None:
        findings, warnings = audit_github_release_hardening(
            repo=repo,
            remote_url=report.origin_url or report.upstream_url or "",
        )
        report.github_hardening_checked = True
        report.github_hardening_findings = findings[: self.max_matches]
        report.github_hardening_warnings = warnings[: self.max_matches]

    def _finalize_git_stream_process(
        self,
        proc: subprocess.Popen[str],
        timeout: int = DEFAULT_GIT_STREAM_TIMEOUT_SECONDS,
    ) -> tuple[int | None, str]:
        stderr_text = ""
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._terminate_process_if_running(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        finally:
            if proc.stderr is not None:
                try:
                    stderr_text = proc.stderr.read()
                except Exception:
                    stderr_text = ""
            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            if proc.stderr is not None:
                try:
                    proc.stderr.close()
                except Exception:
                    pass
        return proc.returncode, stderr_text

    def _terminate_process_if_running(self, proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=2)
            return
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass

    def _scan_history_patch(self, repo: Path, regex: re.Pattern[str]) -> list[str]:
        cmd = [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "-p",
            "--no-color",
            "--pretty=format:",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **streaming_popen_kwargs(),
            )
        except FileNotFoundError:
            self._record_repo_runtime_issue("history patch scan failed to start: Git executable not found")
            return []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history patch scan failed to start: {exc}")
            return []
        matches: list[str] = []
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        terminated_early = False
        try:
            stream = proc.stdout
            if stream is None:
                return matches
            for idx, line in enumerate(stream, start=1):
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history patch scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if regex.search(line):
                    matches.append(f"L{idx}:{line.strip()[:240]}")
                    if len(matches) >= self.max_matches:
                        self._terminate_process_if_running(proc)
                        terminated_early = True
                        break
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history patch scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif not terminated_early and returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history patch scan failed with exit code {returncode}{suffix}"
            )
        return matches

    def _scan_history_secret_taxonomy(
        self,
        repo: Path,
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        cmd = [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "-p",
            "--no-color",
            "--pretty=format:",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **streaming_popen_kwargs(),
            )
        except FileNotFoundError:
            self._record_repo_runtime_issue("history secret taxonomy scan failed to start: Git executable not found")
            return [], [], [], []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history secret taxonomy scan failed to start: {exc}")
            return [], [], [], []

        high_confidence: list[str] = []
        low_confidence: list[str] = []
        fixtures: list[str] = []
        documentation: list[str] = []
        current_file: str | None = None
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        try:
            stream = proc.stdout
            if stream is None:
                return high_confidence, low_confidence, fixtures, documentation
            for idx, raw_line in enumerate(stream, start=1):
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history secret taxonomy scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if raw_line.startswith("diff --git "):
                    match = re.match(r"diff --git a/(.+?) b/(.+)$", raw_line.strip())
                    current_file = match.group(2) if match else None
                    continue
                if raw_line.startswith("+++") or raw_line.startswith("---"):
                    continue
                if not (raw_line.startswith("+") or raw_line.startswith("-")):
                    continue

                self._append_secret_taxonomy_match(
                    rel_path=current_file,
                    line_number=idx,
                    line=raw_line[1:],
                    high_confidence=high_confidence,
                    low_confidence=low_confidence,
                    fixtures=fixtures,
                    documentation=documentation,
                    history=True,
                )
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history secret taxonomy scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history secret taxonomy scan failed with exit code {returncode}{suffix}"
            )
        return high_confidence, low_confidence, fixtures, documentation

    def _scan_history_non_allowed_emails(self, repo: Path) -> list[str]:
        cmd = [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "-p",
            "--no-color",
            "--pretty=format:",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **streaming_popen_kwargs(),
            )
        except FileNotFoundError:
            self._record_repo_runtime_issue("history email scan failed to start: Git executable not found")
            return []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history email scan failed to start: {exc}")
            return []
        matches: list[str] = []
        current_file: str | None = None
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        terminated_early = False
        try:
            stream = proc.stdout
            if stream is None:
                return matches
            for idx, line in enumerate(stream, start=1):
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history email scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if line.startswith("diff --git "):
                    match = re.match(r"diff --git a/(.+?) b/(.+)$", line.strip())
                    current_file = match.group(2) if match else None
                    continue
                emails = [
                    email
                    for email in EMAIL_RE.findall(line)
                    if is_relevant_email_candidate(email)
                ]
                leaked = [email for email in emails if not self._is_allowed_email(email)]
                if leaked:
                    uniq = ", ".join(sorted(set(leaked)))
                    rel_path = current_file or "-"
                    matches.append(f"L{idx}:{rel_path}:{uniq}:{line.strip()[:200]}")
                    if len(matches) >= self.max_matches:
                        self._terminate_process_if_running(proc)
                        terminated_early = True
                        break
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history email scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif not terminated_early and returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history email scan failed with exit code {returncode}{suffix}"
            )
        return matches

    def _scan_tracked_non_allowed_emails(self, repo: Path) -> list[str]:
        matches: list[str] = []
        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                emails = [
                    email
                    for email in EMAIL_RE.findall(line)
                    if is_relevant_email_candidate(email)
                ]
                leaked = [email for email in emails if not self._is_allowed_email(email)]
                if not leaked:
                    continue
                uniq = ", ".join(sorted(set(leaked)))
                matches.append(f"{rel}:{idx}:{uniq}:{line.strip()[:200]}")
                if len(matches) >= self.max_matches:
                    return matches
        return matches

    def _scan_history_secret_files(self, repo: Path) -> list[str]:
        cmd = [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "-p",
            "--no-color",
            "--pretty=format:",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **streaming_popen_kwargs(),
            )
        except FileNotFoundError:
            self._record_repo_runtime_issue("history secret-file scan failed to start: Git executable not found")
            return []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history secret-file scan failed to start: {exc}")
            return []

        files: list[str] = []
        seen: set[str] = set()
        current_file: str | None = None
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        terminated_early = False

        try:
            stream = proc.stdout
            if stream is None:
                return files
            for line in stream:
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history secret-file scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if line.startswith("diff --git "):
                    match = re.match(r"diff --git a/(.+?) b/(.+)$", line.strip())
                    if match:
                        current_file = match.group(2)
                    else:
                        current_file = None
                    continue

                if not current_file:
                    continue

                if line.startswith("+++") or line.startswith("---"):
                    continue

                if not (line.startswith("+") or line.startswith("-")):
                    continue

                line_context = line[1:] if line.startswith(("+", "-")) else line
                if (
                    SECRET_CONTENT_RE.search(line_context)
                    and classify_secret_match_context(current_file, line_context) == "active"
                    and current_file not in seen
                ):
                    seen.add(current_file)
                    files.append(current_file)
                    if len(files) >= self.max_matches:
                        self._terminate_process_if_running(proc)
                        terminated_early = True
                        break
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history secret-file scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif not terminated_early and returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history secret-file scan failed with exit code {returncode}{suffix}"
            )

        return files

    def _extract_file_paths_from_match_lines(self, matches: list[str]) -> list[str]:
        seen: set[str] = set()
        files: list[str] = []
        for item in matches:
            if ":" not in item:
                continue
            candidate = item.split(":", 1)[0].strip()
            if not candidate or candidate.startswith("L"):
                continue
            if candidate not in seen:
                seen.add(candidate)
                files.append(candidate)
        return files

    def _build_secret_remediation_plan(self, report: RepoReport) -> None:
        combined = sorted(set(report.tracked_secret_files + report.history_secret_files))
        report.secret_file_candidates = combined

        autopurge: list[str] = []
        manual_review: list[str] = []
        for path in combined:
            if SECRET_REMEDIATE_FILENAME_RE.search(path):
                autopurge.append(path)
            else:
                manual_review.append(path)

        report.secret_file_autopurge_candidates = autopurge
        report.secret_file_manual_review_candidates = manual_review

    def _normalize_gitignore_entry(self, rel_path: str) -> str:
        path = rel_path.replace("\\", "/").strip("/")
        if not path:
            return rel_path
        return f"{path}"

    def _build_secret_gitignore_entries(self, secret_paths: list[str]) -> list[str]:
        entries = [self._normalize_gitignore_entry(path) for path in secret_paths]
        return sorted(set(entries))

    def _append_gitignore_lines(self, repo: Path, lines: list[str], header: str) -> bool:
        if not lines:
            return False

        gitignore = repo / ".gitignore"
        if gitignore.is_symlink():
            raise RuntimeError(f"Refusing to update symlinked .gitignore: {gitignore}")
        existing_text = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.exists() else ""
        existing_lines = {
            line.strip()
            for line in existing_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        missing = [line for line in lines if line not in existing_lines]
        if not missing:
            return False

        block = ["", f"# {header}"] + missing
        new_text = existing_text.rstrip() + "\n" + "\n".join(block) + "\n"
        write_private_text_file(gitignore, new_text)
        return True

    def _history_file_matches(self, repo: Path, diff_filter: str) -> list[str]:
        out = self._git(repo, "log", "--all", f"--diff-filter={diff_filter}", "--name-only", "--pretty=format:")
        if out.returncode != 0:
            return []
        hits: list[str] = []
        for idx, line in enumerate(out.stdout.splitlines(), start=1):
            item = line.strip()
            if not item:
                continue
            if SENSITIVE_FILENAME_RE.search(item):
                hits.append(f"{idx}:{item}")
                if len(hits) >= self.max_matches:
                    break
        return hits

    def _unique_commit_metadata_values(self, repo: Path, field: str) -> list[str]:
        out = self._git(repo, "log", "--all", f"--pretty=format:{field}")
        if out.returncode != 0:
            return []
        return sorted({line.strip() for line in out.stdout.splitlines() if line.strip()})

    def _unique_commit_emails(self, repo: Path, field: str) -> list[str]:
        return [
            value
            for value in self._unique_commit_metadata_values(repo, field)
            if SIMPLE_EMAIL_RE.match(value)
        ]

    def _unique_commit_identity_tokens(self, repo: Path, field: str) -> list[str]:
        return [
            value
            for value in self._unique_commit_metadata_values(repo, field)
            if not SIMPLE_EMAIL_RE.match(value)
        ]

    def _resolve_upstream_head(self, repo: Path) -> str | None:
        upstream = self._git(
            repo,
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        )
        if upstream.returncode != 0 or not upstream.stdout.strip():
            return None
        return self._git(repo, "rev-parse", "--short", "@{upstream}").stdout.strip() or None

    def _is_allowed_email(self, email: str) -> bool:
        if not email:
            return True
        if email == self.noreply_email:
            return True
        if email == self.placeholder_email:
            return True
        if email == "noreply@github.com":
            return True
        if email.endswith("@users.noreply.github.com"):
            return True
        return False

    def audit_repo(self, repo: Path) -> RepoReport:
        report = RepoReport(name=repo_display_name(repo), path=str(repo))
        report.low_confidence_email_mode = self.low_confidence_email_mode
        self._repo_runtime_issues = []

        report.origin_url = self._git(repo, "remote", "get-url", "origin").stdout.strip() or None
        report.upstream_url = self._git(repo, "remote", "get-url", "upstream").stdout.strip() or None
        report.branch = self._git(repo, "branch", "--show-current").stdout.strip() or None
        report.head = self._git(repo, "rev-parse", "--short", "HEAD").stdout.strip() or None
        report.origin_head = self._resolve_upstream_head(repo)
        report.clean_status = self._git(repo, "status", "--short", "--branch").stdout.strip()

        fsck = self._git(repo, "fsck", "--full")
        report.fsck_ok = fsck.returncode == 0
        if fsck.stdout.strip() or fsck.stderr.strip():
            payload = (fsck.stdout + "\n" + fsck.stderr).strip()
            report.fsck_output = payload.splitlines()[: self.max_matches]

        report.author_emails = self._unique_commit_emails(repo, "%ae")
        report.committer_emails = self._unique_commit_emails(repo, "%ce")
        report.author_identity_tokens = self._unique_commit_identity_tokens(repo, "%ae")
        report.committer_identity_tokens = self._unique_commit_identity_tokens(repo, "%ce")

        all_emails = sorted(set(report.author_emails + report.committer_emails))
        all_identity_tokens = sorted(
            set(report.author_identity_tokens + report.committer_identity_tokens)
        )
        report.unexpected_emails = [email for email in all_emails if not self._is_allowed_email(email)]
        (
            report.unexpected_emails_owned_repo,
            report.unexpected_emails_third_party_repo,
        ) = split_unexpected_emails_by_origin_ownership(
            report.unexpected_emails,
            report.origin_url,
            self.allowed_remote_owners,
        )
        report.unexpected_identity_tokens = all_identity_tokens
        (
            report.unexpected_identity_tokens_owned_repo,
            report.unexpected_identity_tokens_third_party_repo,
        ) = split_unexpected_emails_by_origin_ownership(
            report.unexpected_identity_tokens,
            report.origin_url,
            self.allowed_remote_owners,
        )
        report.email_ownership_evaluated = True

        (
            report.tracked_secret_high_confidence,
            report.tracked_secret_low_confidence,
            report.tracked_secret_fixture_matches,
            report.tracked_secret_documentation_matches,
        ) = self._scan_tracked_secret_taxonomy(repo)
        report.tracked_secret_matches = list(report.tracked_secret_high_confidence)
        report.tracked_secret_files = self._extract_file_paths_from_match_lines(report.tracked_secret_matches)
        self._scan_git_metadata_secrets(repo, report)
        report.tracked_path_matches = self._scan_tracked_content(repo, PERSONAL_PATH_RE)
        report.tracked_email_matches = self._scan_tracked_non_allowed_emails(repo)
        (
            report.tracked_email_high_confidence,
            report.tracked_email_low_confidence,
        ) = split_email_matches_by_confidence(report.tracked_email_matches)

        (
            report.history_secret_high_confidence,
            report.history_secret_low_confidence,
            report.history_secret_fixture_matches,
            report.history_secret_documentation_matches,
        ) = self._scan_history_secret_taxonomy(repo)
        report.history_secret_matches = list(report.history_secret_high_confidence)
        report.history_secret_files = self._scan_history_secret_files(repo)
        report.history_path_matches = self._scan_history_patch(repo, PERSONAL_PATH_RE)
        report.history_email_matches = self._scan_history_non_allowed_emails(repo)
        (
            report.history_email_high_confidence,
            report.history_email_low_confidence,
        ) = split_email_matches_by_confidence(report.history_email_matches)
        report.email_confidence_evaluated = True
        report.secret_confidence_evaluated = True

        self._build_secret_remediation_plan(report)

        report.history_sensitive_added = self._history_file_matches(repo, "A")
        report.history_sensitive_deleted = self._history_file_matches(repo, "D")

        ignored = self._git(repo, "ls-files", "-ci", "--exclude-standard")
        if ignored.returncode == 0:
            report.tracked_but_ignored = [
                line.strip() for line in ignored.stdout.splitlines() if line.strip()
            ][: self.max_matches]

        report.exfil_code_indicators = self._scan_exfil_code_indicators(repo)

        if self.audit_github_hardening:
            self._scan_github_hardening(repo, report)

        if self.audit_litellm_incident:
            self._scan_litellm_incident(repo, report)

        gitignore = repo / ".gitignore"
        if gitignore.exists():
            raw_lines = {
                line.strip()
                for line in self._read_text(gitignore).splitlines()
                if line.strip() and not line.strip().startswith("#")
            }
            report.gitignore_missing_patterns = [
                pattern for pattern in self.required_ignore_patterns if pattern not in raw_lines
            ]
        else:
            report.gitignore_missing_patterns = list(self.required_ignore_patterns)

        report.execution_errors.extend(self._flush_repo_runtime_issues())
        report.finalize()
        return report

    def _ensure_git_filter_repo(self) -> None:
        probe = self._run([sys.executable, "-m", "git_filter_repo", "--help"])
        if probe.returncode == 0:
            return
        detail = probe.stderr.strip() or probe.stdout.strip()
        raise RuntimeError(
            "git-filter-repo is required for remediation that rewrites history. "
            f"Install it with: {sys.executable} -m pip install {' '.join(REMEDIATION_INSTALL_PACKAGES)} "
            "or re-run with --install-missing-tools."
            + (f"\nDetails: {detail}" if detail else "")
        )

    def _write_mailmap(self, report: RepoReport) -> Path | None:
        lines: list[str] = []
        mapped_old_values: set[str] = set()

        def add_mapping(name: str, new_email: str, old_value: str) -> None:
            normalized = old_value.strip()
            if not normalized or normalized in mapped_old_values:
                return
            mapped_old_values.add(normalized)
            lines.append(f"{name} <{new_email}> <{normalized}>")

        unique_emails = sorted(set(report.author_emails + report.committer_emails))
        for email in unique_emails:
            if not email:
                continue
            if email == self.noreply_email:
                continue
            if email == "noreply@github.com":
                continue
            if email == self.placeholder_email:
                continue

            if email in self.owner_emails:
                add_mapping(self.owner_name, self.noreply_email, email)
                continue

            if email.endswith("@users.noreply.github.com"):
                if self.redact_third_party:
                    add_mapping("Redacted Contributor", self.placeholder_email, email)
                continue

            if self.redact_third_party:
                add_mapping("Redacted Contributor", self.placeholder_email, email)

        owned_identity_tokens = (
            report.unexpected_identity_tokens_owned_repo
            if report.email_ownership_evaluated
            else report.unexpected_identity_tokens
        )
        for token in owned_identity_tokens:
            add_mapping(self.owner_name, self.noreply_email, token)

        if self.redact_third_party:
            for token in report.unexpected_identity_tokens_third_party_repo:
                add_mapping("Redacted Contributor", self.placeholder_email, token)

        if not lines:
            return None

        return create_private_temp_text_file(
            "repo-publication-guard-",
            "mailmap.txt",
            "\n".join(lines) + "\n",
        )

    def _write_replace_text_file(self, report: RepoReport) -> Path | None:
        replacement_map: dict[str, str] = {}

        candidate_lines = (
            report.tracked_email_matches
            + report.history_email_matches
            + report.tracked_path_matches
            + report.history_path_matches
        )

        for line in candidate_lines:
            for email in EMAIL_RE.findall(line):
                if not is_relevant_email_candidate(email):
                    continue
                if self._is_allowed_email(email):
                    continue

                if email in self.owner_emails:
                    replacement_map[email] = self.noreply_email
                elif self.redact_third_party:
                    replacement_map[email] = self.placeholder_email

        if getattr(self, "rewrite_personal_paths", False):
            for line in report.tracked_path_matches + report.history_path_matches:
                for path_literal in extract_personal_path_literals(line):
                    replacement_map[path_literal] = REDACTED_PATH
        elif report.tracked_path_matches or report.history_path_matches:
            report.fix_actions.append(
                "path remediation skipped: explicit opt-in required (--rewrite-personal-paths)"
            )

        extra_replace_lines: list[str] = []
        replace_text_file = getattr(self, "replace_text_file", None)
        if replace_text_file:
            replace_path = Path(replace_text_file).expanduser().resolve()
            try:
                raw_extra_lines = replace_path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError as exc:
                raise RuntimeError(
                    f"Unable to read --replace-text-file '{replace_path}': {exc}"
                ) from exc

            extra_replace_lines = [
                line.strip()
                for line in raw_extra_lines.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if extra_replace_lines:
                report.fix_actions.append(
                    f"merged explicit replace-text mappings from {replace_path}"
                )

        if not replacement_map and not extra_replace_lines:
            return None

        lines = [f"literal:{src}==>{dst}" for src, dst in sorted(replacement_map.items())]
        lines.extend(extra_replace_lines)
        lines = list(dict.fromkeys(lines))
        return create_private_temp_text_file(
            "repo-publication-guard-",
            "replace-text.txt",
            "\n".join(lines) + "\n",
        )

    def _append_missing_gitignore_patterns(self, repo: Path, missing: list[str]) -> bool:
        return self._append_gitignore_lines(
            repo,
            missing,
            "Added by Repo_Privacy_Guardian.py (policy baseline)",
        )

    def _remove_tracked_ignored(self, repo: Path) -> list[str]:
        out = self._git(repo, "ls-files", "-ci", "--exclude-standard")
        if out.returncode != 0:
            return []
        files = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        if not files:
            return []

        if self.dry_run:
            return files

        for file_path in files:
            self._git_checked(repo, "rm", "--cached", "--", file_path)
        return files

    def _save_remotes(self, repo: Path) -> dict[str, str]:
        names = self._git(repo, "remote").stdout.splitlines()
        remotes: dict[str, str] = {}
        for name in names:
            name = name.strip()
            if not name:
                continue
            url = self._git(repo, "remote", "get-url", name).stdout.strip()
            if url:
                remotes[name] = url
        return remotes

    def _restore_remotes(self, repo: Path, remotes: dict[str, str]) -> None:
        existing = {
            line.strip()
            for line in self._git(repo, "remote").stdout.splitlines()
            if line.strip()
        }
        for name, url in remotes.items():
            if name in existing:
                continue
            self._git_checked(repo, "remote", "add", name, url)

    def _is_file_tracked(self, repo: Path, rel_path: str) -> bool:
        probe = self._git(repo, "ls-files", "--error-unmatch", "--", rel_path)
        return probe.returncode == 0

    def _apply_secret_file_remediation(self, repo: Path, report: RepoReport) -> None:
        if not report.secret_file_candidates:
            return

        report.fix_actions.append(
            f"detected secret-file candidates: {len(report.secret_file_candidates)}"
        )
        preview = ", ".join(report.secret_file_candidates[:5])
        report.fix_actions.append(f"secret-file candidates preview: {preview}")
        if len(report.secret_file_candidates) > 5:
            report.fix_actions.append("secret-file candidates preview truncated")

        if not self.purge_detected_secret_files:
            report.fix_actions.append(
                "secret remediation available: re-run with --purge-detected-secret-files"
            )
            report.fix_actions.append(
                "for aggressive mode use --purge-all-detected-secret-files (risky)"
            )
            return

        targets = (
            list(report.secret_file_candidates)
            if self.purge_all_detected_secret_files
            else list(report.secret_file_autopurge_candidates)
        )

        if not targets:
            report.fix_actions.append(
                "secret remediation skipped: no safe auto-purge candidates"
            )
            if report.secret_file_manual_review_candidates:
                report.fix_actions.append(
                    f"manual review required for {len(report.secret_file_manual_review_candidates)} files"
                )
                report.fix_actions.append(
                    "to purge manual-review files, add --purge-all-detected-secret-files"
                )
            return

        report.secret_history_purge_paths = sorted(set(targets))

        ignore_entries = self._build_secret_gitignore_entries(targets)
        if self.dry_run:
            report.fix_actions.append(
                f"[dry-run] would append secret file ignore entries: {len(ignore_entries)}"
            )
            preview_entries = ", ".join(ignore_entries[:5])
            if preview_entries:
                report.fix_actions.append(f"[dry-run] ignore entries preview: {preview_entries}")
            if len(ignore_entries) > 5:
                report.fix_actions.append("[dry-run] ignore entries preview truncated")
        else:
            changed = self._append_gitignore_lines(
                repo,
                ignore_entries,
                "Added by Repo_Privacy_Guardian.py (secret remediation)",
            )
            if changed:
                report.fix_actions.append("appended secret file entries to .gitignore")

        tracked_targets = [path for path in targets if self._is_file_tracked(repo, path)]
        if tracked_targets:
            if self.dry_run:
                report.fix_actions.append(
                    f"[dry-run] would untrack secret files: {len(tracked_targets)}"
                )
                preview_targets = ", ".join(tracked_targets[:5])
                if preview_targets:
                    report.fix_actions.append(f"[dry-run] secret file untrack preview: {preview_targets}")
                if len(tracked_targets) > 5:
                    report.fix_actions.append("[dry-run] secret file untrack preview truncated")
            else:
                for path in tracked_targets:
                    self._git_checked(repo, "rm", "--cached", "--", path)
                report.fix_actions.append(f"untracked secret files: {len(tracked_targets)}")

        report.fix_actions.append(
            f"prepared secret-history purge paths: {len(report.secret_history_purge_paths)}"
        )
        if report.secret_file_manual_review_candidates and not self.purge_all_detected_secret_files:
            report.fix_actions.append(
                f"manual review candidates kept (no auto-purge): {len(report.secret_file_manual_review_candidates)}"
            )

    def _rewrite_history(self, repo: Path, report: RepoReport) -> None:
        mailmap = self._write_mailmap(report)
        replace_text = self._write_replace_text_file(report)

        purge_by_filename_signals = bool(report.history_sensitive_added or report.history_sensitive_deleted)
        purge_paths = sorted(set(report.secret_history_purge_paths))
        needs_history_purge = bool(purge_by_filename_signals or purge_paths)
        do_rewrite = bool(mailmap) or bool(replace_text) or needs_history_purge
        if not do_rewrite:
            report.fix_actions.append("history rewrite skipped (no mappings required)")
            return

        remotes = self._save_remotes(repo)

        if self.dry_run:
            report.fix_actions.append("[dry-run] history rewrite would run")
            report.fix_actions.append(f"[dry-run] mailmap enabled: {bool(mailmap)}")
            report.fix_actions.append(f"[dry-run] replace-text enabled: {bool(replace_text)}")
            if purge_paths:
                preview_paths = ", ".join(purge_paths[:5])
                report.fix_actions.append(f"[dry-run] purge paths preview: {preview_paths}")
                if len(purge_paths) > 5:
                    report.fix_actions.append("[dry-run] purge paths preview truncated")
            if purge_by_filename_signals:
                report.fix_actions.append("[dry-run] sensitive filename signal purge regex enabled")
            return

        try:
            self._ensure_git_filter_repo()

            cmd = [sys.executable, "-m", "git_filter_repo", "--force"]
            if mailmap:
                cmd.extend(["--mailmap", str(mailmap)])
            if replace_text:
                cmd.extend(["--replace-text", str(replace_text)])

            if needs_history_purge:
                for purge_path in purge_paths:
                    cmd.extend(["--path", purge_path])

                if purge_by_filename_signals:
                    # Purge common sensitive/local artifacts from whole history.
                    cmd.extend(
                        [
                            "--path-regex",
                            r"(^|.*/)__pycache__/.*|.*\.pyc$|(^|.*/)\.env(\..*)?$|"
                            r".*\.(pem|key|p12|pfx|kdbx)$|(^|.*/)id_rsa$",
                        ]
                    )

                cmd.append("--invert-paths")

            self._run_checked(cmd, cwd=repo, input_text="y\n")
            self._restore_remotes(repo, remotes)
            report.fix_actions.append("history rewritten with git-filter-repo")
        finally:
            cleanup_private_temp_text_file(mailmap)
            cleanup_private_temp_text_file(replace_text)

    def _make_backup_bundle(self, repo: Path) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        bundle = self.root / f"{repo_display_name(repo)}-pre-publication-fix-{stamp}.bundle"
        if self.dry_run:
            return bundle
        self._git_checked(repo, "bundle", "create", str(bundle), "--all")
        _apply_private_permissions(bundle, 0o600)
        return bundle

    def _commit_if_needed(self, repo: Path, message: str) -> str:
        porcelain = self._git(repo, "status", "--porcelain").stdout.strip()
        if not porcelain:
            return "none"
        if self.dry_run:
            return "preview"
        self._git_checked(repo, "add", "-A")
        self._git_checked(repo, "commit", "-m", message)
        return "committed"

    def _set_local_identity(self, repo: Path) -> None:
        if self.dry_run:
            return
        self._git_checked(repo, "config", "--local", "user.name", self.owner_name)
        self._git_checked(repo, "config", "--local", "user.email", self.noreply_email)

    def _validate_push_owner(self, report: RepoReport) -> None:
        if self.allow_non_owner_push:
            return

        if not self.allowed_remote_owners:
            raise RuntimeError(
                "push blocked: no allowed remote owners configured. "
                "Use --allow-remote-owner or --allow-non-owner-push."
            )

        owner = parse_github_remote_owner(report.origin_url or "")
        if not owner:
            raise RuntimeError(
                "push blocked: unable to infer origin owner from remote URL. "
                "Use --allow-non-owner-push to bypass this guardrail."
            )

        if owner.lower() not in self.allowed_remote_owners:
            allowed = ", ".join(sorted(self.allowed_remote_owners))
            raise RuntimeError(
                f"push blocked: origin owner '{owner}' is not in allowed owner set ({allowed})."
            )

    def _push_if_requested(self, repo: Path, report: RepoReport) -> None:
        if not self.push:
            return

        branch = report.branch or "main"
        if self.dry_run:
            report.fix_actions.append("[dry-run] force push skipped")
            return

        self._validate_push_owner(report)
        report.fix_actions.append("validated remote owner before force push")

        self._git_checked(repo, "fetch", "origin", branch)
        self._git_checked(repo, "push", "--force-with-lease", "origin", branch)
        # Restore tracking relationship
        self._git(repo, "branch", "--set-upstream-to", f"origin/{branch}", branch)

    def apply_fixes(self, repo: Path, report: RepoReport) -> RepoReport:
        report.fix_errors.extend(validate_fix_preconditions(report))
        if report.fix_errors:
            return report

        original_identity = self._capture_local_identity(repo)
        try:
            self.log(f"[FIX] {repo_display_name(repo)}: creating backup bundle")
            bundle = self._make_backup_bundle(repo)
            report.backups_created.append(str(bundle))

            self._set_local_identity(repo)

            if report.gitignore_missing_patterns:
                if self.dry_run:
                    report.fix_actions.append(
                        "[dry-run] would append missing .gitignore patterns"
                    )
                else:
                    changed = self._append_missing_gitignore_patterns(
                        repo,
                        report.gitignore_missing_patterns,
                    )
                    if changed:
                        report.fix_actions.append("appended missing .gitignore patterns")

            self._apply_secret_file_remediation(repo, report)

            removed = self._remove_tracked_ignored(repo)
            if removed:
                report.fix_actions.append(f"untracked ignored files: {len(removed)}")

            commit_state = self._commit_if_needed(
                repo,
                "chore(security): align ignore rules and untrack sensitive/local artifacts",
            )
            if commit_state == "preview":
                report.fix_actions.append("[dry-run] would commit ignore-hygiene changes")
            elif commit_state == "committed":
                report.fix_actions.append("committed ignore-hygiene changes")

            self.log(f"[FIX] {repo_display_name(repo)}: rewriting history (emails + sensitive artifacts)")
            self._rewrite_history(repo, report)

            if not self.dry_run:
                self._git(repo, "reflog", "expire", "--expire=now", "--all")
                self._git(repo, "gc", "--prune=now")
                report.fix_actions.append("reflog/gc cleanup completed")

            self._push_if_requested(repo, report)
            if self.push:
                report.fix_actions.append("force push completed")

        except Exception as exc:
            report.fix_errors.append(str(exc))
        finally:
            try:
                self._restore_local_identity(repo, original_identity)
                if not self.dry_run:
                    report.fix_actions.append("restored local git identity")
            except Exception as exc:
                report.fix_errors.append(f"failed to restore local git identity: {exc}")

        return report


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
    base = default_results_dir().resolve()
    if requested_dir is None:
        return base, False

    requested = requested_dir.resolve()
    if requested == base:
        return requested, False

    try:
        requested.relative_to(base)
        return requested, False
    except ValueError:
        return base, True


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


def is_relevant_email_candidate(email: str) -> bool:
    lowered = email.strip().lower()
    if not lowered or "@" not in lowered:
        return False

    if lowered == DEFAULT_PLACEHOLDER.lower():
        return True

    local, domain = lowered.rsplit("@", 1)
    if not local or not domain:
        return False

    if domain in EMAIL_NOISE_DOMAINS:
        return False
    if domain.endswith(".local") or domain.endswith(".invalid") or domain.endswith(".example"):
        return False
    if domain.replace(".", "").isdigit():
        return False

    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False

    return True


def extract_email_match_context(match_line: str) -> tuple[str | None, str]:
    if not match_line:
        return None, ""

    if match_line.startswith("L"):
        parts = match_line.split(":", 3)
        if len(parts) == 4:
            return parts[1] if parts[1] != "-" else None, parts[3]
        parts = match_line.split(":", 2)
        snippet = parts[2] if len(parts) == 3 else match_line
        return None, snippet

    parts = match_line.split(":", 3)
    if len(parts) >= 4:
        return parts[0], parts[3]
    if len(parts) >= 2:
        return parts[0], parts[-1]
    return None, match_line


def is_low_confidence_email_context(rel_path: str | None, snippet: str) -> bool:
    normalized_path = (rel_path or "").replace("\\", "/").strip().lower()
    normalized_snippet = (snippet or "").strip().lower()

    if normalized_path:
        if EMAIL_LOW_CONFIDENCE_PATH_RE.search(normalized_path):
            return True
        file_name = Path(normalized_path).name
        if EMAIL_LOW_CONFIDENCE_FILE_RE.search(file_name):
            return True

    if EMAIL_LOW_CONFIDENCE_SNIPPET_RE.search(normalized_snippet):
        return True

    return False


def extract_secret_match_context(match_line: str) -> tuple[str | None, str]:
    if not match_line:
        return None, ""

    if match_line.startswith("L"):
        parts = match_line.split(":", 3)
        if len(parts) == 4:
            return parts[1] if parts[1] != "-" else None, parts[3]
        parts = match_line.split(":", 2)
        snippet = parts[2] if len(parts) == 3 else match_line
        return None, snippet

    parts = match_line.split(":", 2)
    if len(parts) == 3:
        return parts[0], parts[2]
    if len(parts) >= 2:
        return parts[0], parts[-1]
    return None, match_line


def classify_secret_match_context(rel_path: str | None, snippet: str) -> str:
    normalized_path = (rel_path or "").replace("\\", "/").strip().lower()
    normalized_snippet = (snippet or "").strip()
    if not normalized_path or not normalized_snippet:
        return "active"

    if not SECRET_SAFE_PLACEHOLDER_RE.search(normalized_snippet):
        return "active"

    if SECRET_FIXTURE_PATH_RE.search(normalized_path):
        return "fixture"

    file_name = Path(normalized_path).name
    if SECRET_DOCUMENTATION_PATH_RE.search(normalized_path) or SECRET_DOCUMENTATION_FILE_RE.search(file_name):
        return "documentation"

    return "active"


def split_email_matches_by_confidence(matches: list[str]) -> tuple[list[str], list[str]]:
    high_confidence: list[str] = []
    low_confidence: list[str] = []

    for item in matches:
        rel_path, snippet = extract_email_match_context(item)
        if is_low_confidence_email_context(rel_path, snippet):
            low_confidence.append(item)
        else:
            high_confidence.append(item)

    return high_confidence, low_confidence


def extract_personal_path_literals(text: str) -> list[str]:
    if not text:
        return []

    findings: list[str] = []
    seen: set[str] = set()
    for pattern in PERSONAL_PATH_LITERAL_PATTERNS:
        for match in pattern.finditer(text):
            candidate = match.group(0).strip().strip("`\"'()[]{}")
            candidate = candidate.rstrip(".,;:")
            if not candidate or candidate in seen:
                continue
            if any(existing.endswith(candidate) for existing in seen):
                continue
            nested = [existing for existing in seen if candidate.endswith(existing)]
            for existing in nested:
                seen.remove(existing)
                findings.remove(existing)
            seen.add(candidate)
            findings.append(candidate)
    return findings


def split_unexpected_emails_by_origin_ownership(
    unexpected_emails: list[str],
    origin_url: str | None,
    allowed_remote_owners: set[str] | list[str],
) -> tuple[list[str], list[str]]:
    if not unexpected_emails:
        return [], []

    normalized_owners = {
        owner.strip().lower()
        for owner in allowed_remote_owners
        if owner and owner.strip()
    }
    origin_owner = parse_github_remote_owner(origin_url or "")

    if not origin_url or not origin_owner or not normalized_owners:
        return list(unexpected_emails), []
    if origin_owner and origin_owner.lower() in normalized_owners:
        return list(unexpected_emails), []
    return [], list(unexpected_emails)


def _redact_low_confidence_secret_assignment(match: re.Match[str]) -> str:
    quote = match.group("quote") or ""
    closing_quote = quote if quote else ""
    return f"{match.group('key')}{match.group('sep')}{quote}{REDACTED_SECRET}{closing_quote}"


def redact_sensitive_text(value: str) -> str:
    text = str(value)
    text = SECRET_CONTENT_RE.sub(REDACTED_SECRET, text)
    text = LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE.sub(_redact_low_confidence_secret_assignment, text)
    # Handle escaped Windows paths often seen inside JSON string literals.
    text = re.sub(r"C:\\\\Users\\\\[^\\\s]+", r"C:\\\\Users\\\\<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(
        r"C:\\\\Documents and Settings\\\\[^\\\s]+",
        r"C:\\\\Documents and Settings\\\\<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"AppData\\\\[^\\\s]+", r"AppData\\\\<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(r"C:\\Users\\[^\\\s]+", r"C:\\Users\\<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(
        r"C:\\Documents and Settings\\[^\\\s]+",
        r"C:\\Documents and Settings\\<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"/Users/[^/\s]+", "/Users/<redacted>", text)
    text = re.sub(r"/home/[^/\s]+", "/home/<redacted>", text)
    text = re.sub(r"AppData\\[^\\\s]+", r"AppData\\<redacted>", text, flags=re.IGNORECASE)
    text = EMAIL_RE.sub(REDACTED_EMAIL, text)
    return text


def _redact_email_list(emails: list[str]) -> list[str]:
    if not emails:
        return []
    return [REDACTED_EMAIL for _ in emails]


def _redact_identity_list(items: list[str]) -> list[str]:
    if not items:
        return []
    return [REDACTED_IDENTITY_TOKEN for _ in items]


def _redact_text_list(items: list[str]) -> list[str]:
    return [redact_sensitive_text(item) for item in items]


def sanitize_report_for_export(report: RepoReport) -> dict[str, object]:
    payload = dict(report.__dict__)
    payload["path"] = redact_sensitive_text(report.path)
    payload["origin_url"] = redact_sensitive_text(report.origin_url) if report.origin_url else None
    payload["upstream_url"] = redact_sensitive_text(report.upstream_url) if report.upstream_url else None
    payload["clean_status"] = redact_sensitive_text(report.clean_status or "")
    payload["author_emails"] = _redact_email_list(report.author_emails)
    payload["committer_emails"] = _redact_email_list(report.committer_emails)
    payload["author_identity_tokens"] = _redact_identity_list(report.author_identity_tokens)
    payload["committer_identity_tokens"] = _redact_identity_list(report.committer_identity_tokens)
    payload["unexpected_emails"] = _redact_email_list(report.unexpected_emails)
    payload["unexpected_emails_owned_repo"] = _redact_email_list(report.unexpected_emails_owned_repo)
    payload["unexpected_emails_third_party_repo"] = _redact_email_list(
        report.unexpected_emails_third_party_repo
    )
    payload["unexpected_identity_tokens"] = _redact_identity_list(report.unexpected_identity_tokens)
    payload["unexpected_identity_tokens_owned_repo"] = _redact_identity_list(
        report.unexpected_identity_tokens_owned_repo
    )
    payload["unexpected_identity_tokens_third_party_repo"] = _redact_identity_list(
        report.unexpected_identity_tokens_third_party_repo
    )
    payload["tracked_secret_matches"] = _redact_text_list(report.tracked_secret_matches)
    payload["tracked_secret_high_confidence"] = _redact_text_list(
        report.tracked_secret_high_confidence
    )
    payload["tracked_secret_low_confidence"] = _redact_text_list(report.tracked_secret_low_confidence)
    payload["tracked_secret_fixture_matches"] = _redact_text_list(
        report.tracked_secret_fixture_matches
    )
    payload["tracked_secret_documentation_matches"] = _redact_text_list(
        report.tracked_secret_documentation_matches
    )
    payload["tracked_path_matches"] = _redact_text_list(report.tracked_path_matches)
    payload["tracked_email_matches"] = _redact_text_list(report.tracked_email_matches)
    payload["tracked_email_high_confidence"] = _redact_text_list(report.tracked_email_high_confidence)
    payload["tracked_email_low_confidence"] = _redact_text_list(report.tracked_email_low_confidence)
    payload["tracked_secret_files"] = _redact_text_list(report.tracked_secret_files)
    payload["history_secret_matches"] = _redact_text_list(report.history_secret_matches)
    payload["history_secret_high_confidence"] = _redact_text_list(
        report.history_secret_high_confidence
    )
    payload["history_secret_low_confidence"] = _redact_text_list(report.history_secret_low_confidence)
    payload["history_secret_fixture_matches"] = _redact_text_list(
        report.history_secret_fixture_matches
    )
    payload["history_secret_documentation_matches"] = _redact_text_list(
        report.history_secret_documentation_matches
    )
    payload["history_path_matches"] = _redact_text_list(report.history_path_matches)
    payload["history_email_matches"] = _redact_text_list(report.history_email_matches)
    payload["history_email_high_confidence"] = _redact_text_list(report.history_email_high_confidence)
    payload["history_email_low_confidence"] = _redact_text_list(report.history_email_low_confidence)
    payload["history_secret_files"] = _redact_text_list(report.history_secret_files)
    payload["git_metadata_secret_matches"] = _redact_text_list(report.git_metadata_secret_matches)
    payload["git_metadata_secret_low_confidence"] = _redact_text_list(
        report.git_metadata_secret_low_confidence
    )
    payload["history_sensitive_added"] = _redact_text_list(report.history_sensitive_added)
    payload["history_sensitive_deleted"] = _redact_text_list(report.history_sensitive_deleted)
    payload["secret_file_candidates"] = _redact_text_list(report.secret_file_candidates)
    payload["secret_file_autopurge_candidates"] = _redact_text_list(report.secret_file_autopurge_candidates)
    payload["secret_file_manual_review_candidates"] = _redact_text_list(report.secret_file_manual_review_candidates)
    payload["secret_history_purge_paths"] = _redact_text_list(report.secret_history_purge_paths)
    payload["tracked_but_ignored"] = _redact_text_list(report.tracked_but_ignored)
    payload["gitignore_missing_patterns"] = _redact_text_list(report.gitignore_missing_patterns)
    payload["exfil_code_indicators"] = _redact_text_list(report.exfil_code_indicators)
    payload["github_hardening_findings"] = _redact_text_list(report.github_hardening_findings)
    payload["github_hardening_warnings"] = _redact_text_list(report.github_hardening_warnings)
    payload["backups_created"] = _redact_text_list(report.backups_created)
    payload["fix_actions"] = _redact_text_list(report.fix_actions)
    payload["fix_errors"] = _redact_text_list(report.fix_errors)
    payload["execution_errors"] = _redact_text_list(report.execution_errors)
    payload["fsck_output"] = _redact_text_list(report.fsck_output)
    return payload


def validate_fix_preconditions(report: RepoReport) -> list[str]:
    issues: list[str] = []
    if repo_has_dirty_worktree(report.clean_status):
        issues.append(
            "automatic fix blocked: working tree is not clean; commit, stash, or discard local edits before remediation"
        )
    if not report.fsck_ok:
        issues.append("automatic fix blocked: git fsck failed; resolve repository integrity issues first")
    if report.execution_errors:
        issues.append(
            "automatic fix blocked: audit completed with execution errors; re-run after resolving lock, timeout, or git/runtime failures"
        )
    return issues


def build_fix_preflight_summary(config: GuardRunConfig, repos: list[Path]) -> list[str]:
    if not config.fix:
        return []

    lines = [
        "[PREVIEW] Fix mode preflight summary",
        f"[PREVIEW] repositories targeted: {len(repos)}",
        f"[PREVIEW] dry_run={config.dry_run} push={config.push}",
        f"[PREVIEW] audit_litellm_incident={config.audit_litellm_incident}",
        f"[PREVIEW] audit_github_hardening={config.audit_github_hardening}",
        f"[PREVIEW] rewrite_personal_paths={config.rewrite_personal_paths}",
        f"[PREVIEW] explicit replace-text file={bool(config.replace_text_file)}",
        f"[PREVIEW] low-confidence email mode: {config.low_confidence_email_mode}",
        f"[PREVIEW] confirm_each_repo_fix={config.confirm_each_repo_fix}",
        "[PREVIEW] potential destructive actions: history rewrite, file untracking, force push",
    ]

    if config.allowed_remote_owners:
        owners = ", ".join(sorted(set(config.allowed_remote_owners)))
        lines.append(f"[PREVIEW] allowed remote owners: {owners}")
    elif not config.allow_non_owner_push and config.push:
        lines.append("[PREVIEW] push owner check active with no explicit allowlist")

    return lines


def email_decision_context(report: RepoReport) -> tuple[int, int, int, int, int, int]:
    owned_unexpected = len(
        report.unexpected_emails_owned_repo
        if report.email_ownership_evaluated
        else report.unexpected_emails
    )
    third_party_unexpected = len(report.unexpected_emails_third_party_repo)
    owned_unexpected_identity_tokens = len(
        report.unexpected_identity_tokens_owned_repo
        if report.email_ownership_evaluated
        else report.unexpected_identity_tokens
    )
    third_party_unexpected_identity_tokens = len(report.unexpected_identity_tokens_third_party_repo)
    high_conf = len(
        report.tracked_email_high_confidence + report.history_email_high_confidence
        if report.email_confidence_evaluated
        else report.tracked_email_matches + report.history_email_matches
    )
    low_conf = len(report.tracked_email_low_confidence + report.history_email_low_confidence)
    return (
        owned_unexpected,
        third_party_unexpected,
        owned_unexpected_identity_tokens,
        third_party_unexpected_identity_tokens,
        high_conf,
        low_conf,
    )


def email_remediation_decision(report: RepoReport) -> tuple[str, str]:
    (
        owned_unexpected,
        third_party_unexpected,
        owned_unexpected_identity_tokens,
        third_party_unexpected_identity_tokens,
        high_conf,
        low_conf,
    ) = email_decision_context(report)
    low_blocking = report.low_confidence_email_mode == "blocking"

    if (
        owned_unexpected
        or owned_unexpected_identity_tokens
        or high_conf
        or (low_blocking and low_conf)
    ):
        if low_blocking and low_conf and not (
            owned_unexpected or owned_unexpected_identity_tokens or high_conf
        ):
            return (
                "RECOMMENDED",
                "Blocking mode active: low-confidence email findings require explicit review/remediation.",
            )
        return (
            "RECOMMENDED",
            "Authorize commit identity remediation for owned-repo or malformed metadata findings first.",
        )

    if low_conf or third_party_unexpected or third_party_unexpected_identity_tokens:
        return (
            "REVIEW",
            "Informational commit-identity findings only; review samples before authorizing broad remediation.",
        )

    return ("SKIP", "No commit identity remediation action needed for this repository.")


def repo_user_guidance(report: RepoReport) -> tuple[str, str, str, str]:
    email_status, email_message = email_remediation_decision(report)
    (
        owned_unexpected,
        _third_party_unexpected,
        owned_unexpected_identity_tokens,
        _third_party_unexpected_identity_tokens,
        high_conf,
        low_conf,
    ) = email_decision_context(report)
    low_blocking = report.low_confidence_email_mode == "blocking"
    litellm_severity = classify_litellm_incident_severity(report)
    worktree_dirty = repo_has_dirty_worktree(report.clean_status)

    if report.execution_errors:
        return (
            "IMMEDIATE",
            "Repository execution failed before the audit/fix flow completed.",
            "Possible consequence: results may be incomplete, stale, or skipped for this repository.",
            "Suggestion: review execution_errors for lock, timeout, or git/runtime failures, then re-run once the repository is stable.",
        )

    if report.fix_errors:
        return (
            "IMMEDIATE",
            "Requested remediation did not complete successfully.",
            "Possible consequence: repository state may be only partially remediated, or push/rewrite steps may have failed.",
            "Suggestion: review fix_errors, verify repository state manually, and re-run audit/fix after resolving the underlying issue.",
        )

    if litellm_severity in {"CRITICAL", "HIGH"}:
        return (
            "IMMEDIATE",
            "Critical supply-chain risk: LiteLLM compromise indicators were detected.",
            "Possible consequence: malicious package initialization or compromised dependencies in runtime/CI workflows.",
            "Suggestion: isolate affected environments, remove compromised versions, rotate secrets, and verify package provenance before redeploy.",
        )

    if litellm_severity == "MEDIUM":
        return (
            "PRIORITY",
            "Medium supply-chain risk: LiteLLM references were detected without direct compromise evidence.",
            "Possible consequence: potential exposure if vulnerable versions were installed temporarily in local or CI environments.",
            "Suggestion: verify resolved versions in lockfiles/environments and run targeted incident checks for IoCs.",
        )

    if worktree_dirty:
        return (
            "PRIORITY",
            "Medium risk: working tree is not clean.",
            "Possible consequence: publication decisions may be made against uncommitted or unpublished content.",
            "Suggestion: commit, stash, or discard local changes before relying on audit/fix results.",
        )

    has_secret_risk = bool(
        report.tracked_secret_matches
        or report.history_secret_matches
        or report.git_metadata_secret_matches
        or report.secret_file_candidates
        or report.history_sensitive_added
        or report.history_sensitive_deleted
    )
    has_path_risk = bool(report.tracked_path_matches or report.history_path_matches)
    has_identity_risk = bool(
        owned_unexpected
        or owned_unexpected_identity_tokens
        or high_conf
        or (low_blocking and low_conf)
    )

    if has_secret_risk:
        return (
            "IMMEDIATE",
            "High risk: secret indicators were detected.",
            "Possible consequence: credential leakage and unauthorized access if history is published.",
            "Suggestion: run fix in dry-run, review preview, then authorize secret purge/history rewrite.",
        )

    if has_identity_risk:
        return (
            "PRIORITY",
            "Medium-high risk: non-owner or malformed commit identity values are likely exposed in owned repository history/content.",
            "Possible consequence: personal identity exposure and compliance/privacy issues.",
            f"Suggestion: {email_message}",
        )

    if has_path_risk:
        return (
            "PRIORITY",
            "Medium risk: local/personal paths were detected.",
            "Possible consequence: host/user structure disclosure and unnecessary attack-surface context.",
            "Suggestion: review samples and authorize path-focused cleanup if repository will be public.",
        )

    if (
        report.tracked_secret_low_confidence
        or report.history_secret_low_confidence
        or report.git_metadata_secret_low_confidence
    ):
        return (
            "REVIEW",
            "Advisory review: generic secret-like assignments were detected.",
            "Possible consequence: a real credential may be hidden among noisy examples if not classified.",
            "Suggestion: classify each low-confidence secret finding as confirmed leak, fixture, safe documentation, or false positive before remediation.",
        )

    if report.exfil_code_indicators:
        return (
            "REVIEW",
            "Advisory review: outbound/exfil indicators were detected.",
            "Possible consequence: unexpected outbound behavior could disclose repository data or operator context if published unchecked.",
            "Suggestion: review each cited network-capable code path manually. This signal does not change PASS/FAIL by default.",
        )

    if report.github_hardening_findings:
        return (
            "REVIEW",
            "Advisory review: GitHub repository settings need hardening before public release.",
            "Possible consequence: direct pushes, weak workflow permissions, or missing review/security controls may remain active after publication.",
            "Suggestion: review github_hardening_findings, apply the remote settings manually, and re-run with --audit-github-hardening.",
        )

    if report.github_hardening_warnings:
        return (
            "REVIEW",
            "Advisory review: GitHub hardening audit was partial or could not authenticate.",
            "Possible consequence: repository settings may still have unaudited gaps even if local content checks passed.",
            "Suggestion: set REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN, or authenticate GitHub CLI with `gh auth login`, then re-run --audit-github-hardening.",
        )

    if email_status == "REVIEW":
        return (
            "REVIEW",
            "Low risk: commit identity findings look informational/noisy.",
            "Possible consequence: alert fatigue if remediated blindly.",
            f"Suggestion: {email_message}",
        )

    return (
        "SKIP",
        "No relevant privacy risk requiring remediation was detected.",
        "Possible consequence: none expected for this category.",
        "Suggestion: no remediation action required.",
    )


def classify_repo_severity(report: RepoReport) -> tuple[str, int, list[str]]:
    score = 0
    highlights: list[str] = []
    (
        owned_unexpected_count,
        third_party_unexpected_count,
        owned_unexpected_identity_token_count,
        third_party_unexpected_identity_token_count,
        high_conf_email_count,
        low_conf_email_count,
    ) = email_decision_context(report)
    low_confidence_blocking = report.low_confidence_email_mode == "blocking"
    litellm_severity = classify_litellm_incident_severity(report)
    worktree_dirty = repo_has_dirty_worktree(report.clean_status)

    if report.execution_errors:
        score = max(score, 85)
        highlights.append("Repository execution failed or was blocked")
    if report.fix_errors:
        score = max(score, 80)
        highlights.append("Remediation execution failed")
    if worktree_dirty:
        score = max(score, 55)
        highlights.append("Working tree contains uncommitted changes")
    if litellm_severity == "CRITICAL":
        score = max(score, 100)
        highlights.append("LiteLLM incident critical indicators detected (IoC or 1.82.8 evidence)")
    elif litellm_severity == "HIGH":
        score = max(score, 85)
        highlights.append("LiteLLM incident high-risk evidence detected (1.82.7)")
    elif litellm_severity == "MEDIUM":
        score = max(score, 50)
        highlights.append("LiteLLM references found; verify installed versions and provenance")

    if report.tracked_secret_matches or report.history_secret_matches or report.git_metadata_secret_matches:
        score = max(score, 100)
        highlights.append("Secret-like patterns found in tracked content, history, or Git metadata")
    if report.tracked_secret_low_confidence or report.history_secret_low_confidence:
        highlights.append("Low-confidence secret assignments require manual review (informational)")
    if report.git_metadata_secret_low_confidence:
        highlights.append("Low-confidence Git metadata secret indicators require manual review")
    if report.secret_file_candidates:
        score = max(score, 95)
        highlights.append("Secret file candidates detected")
    if report.history_sensitive_added or report.history_sensitive_deleted:
        score = max(score, 90)
        highlights.append("Sensitive filenames found in git history")
    if owned_unexpected_count:
        score = max(score, 75)
        highlights.append("Unexpected commit metadata emails in owned repository")
    if owned_unexpected_identity_token_count:
        score = max(score, 75)
        highlights.append("Malformed commit metadata identity tokens found in owned repository")
    if high_conf_email_count:
        score = max(score, 62)
        highlights.append("High-confidence non-owner email addresses found")
    if low_confidence_blocking and low_conf_email_count:
        score = max(score, 60)
        highlights.append("Low-confidence email findings are configured as blocking")
    if (not low_confidence_blocking) and low_conf_email_count:
        highlights.append("Low-confidence email findings are informational")
    if third_party_unexpected_count:
        highlights.append("Unexpected commit metadata emails in third-party repositories (informational)")
    if third_party_unexpected_identity_token_count:
        highlights.append("Malformed commit metadata identity tokens in third-party repositories (informational)")
    if report.tracked_path_matches or report.history_path_matches:
        score = max(score, 70)
        highlights.append("Personal/local path leakage detected")
    if report.tracked_but_ignored:
        score = max(score, 60)
        highlights.append("Ignored files are still tracked")
    if report.gitignore_missing_patterns:
        score = max(score, 40)
        highlights.append("Required .gitignore baseline is incomplete")
    if report.exfil_code_indicators:
        score = max(score, 20)
        highlights.append("Outbound/exfil heuristics require manual review (advisory)")
    if report.github_hardening_findings:
        score = max(score, 25)
        highlights.append("GitHub release hardening settings need manual follow-up (advisory)")
    if report.github_hardening_warnings:
        score = max(score, 10)
        highlights.append("GitHub release hardening audit was partial/incomplete")

    if score >= 90:
        return "HIGH", score, highlights
    if score >= 60:
        return "MEDIUM", score, highlights
    if report.status == "FAIL":
        if not highlights:
            highlights.append("Non-critical policy failures found")
        return "LOW", score, highlights
    return "OK", score, highlights


def classify_litellm_incident_severity(report: RepoReport) -> str:
    if report.litellm_incident_severity and report.litellm_incident_severity != "NONE":
        return report.litellm_incident_severity

    compromised_lines = report.litellm_compromised_reference_hits
    if report.litellm_ioc_hits or any(LITELLM_COMPROMISED_1828_RE.search(line) for line in compromised_lines):
        return "CRITICAL"
    if any(LITELLM_COMPROMISED_1827_RE.search(line) for line in compromised_lines):
        return "HIGH"
    if report.litellm_reference_hits or report.litellm_install_command_hits:
        return "MEDIUM"
    return "NONE"


def build_detected_findings_preview(report: RepoReport) -> list[str]:
    findings: list[str] = []

    def add(label: str, items: list[str], limit: int = 4) -> None:
        if not items:
            return
        for item in items[:limit]:
            findings.append(f"{label}: {item}")
        if len(items) > limit:
            findings.append(f"{label}: ... and {len(items) - limit} more")

    add("tracked secret", report.tracked_secret_matches)
    add("history secret", report.history_secret_matches)
    add("git metadata secret", report.git_metadata_secret_matches)
    add("tracked secret low confidence", report.tracked_secret_low_confidence)
    add("history secret low confidence", report.history_secret_low_confidence)
    add("tracked secret fixture", report.tracked_secret_fixture_matches)
    add("history secret fixture", report.history_secret_fixture_matches)
    add("tracked secret safe documentation", report.tracked_secret_documentation_matches)
    add("history secret safe documentation", report.history_secret_documentation_matches)
    add("secret file candidate", report.secret_file_candidates)
    add("tracked path", report.tracked_path_matches)
    add("history path", report.history_path_matches)
    add("tracked email", report.tracked_email_high_confidence)
    add("history email", report.history_email_high_confidence)
    add("commit identity token", report.unexpected_identity_tokens)
    add("tracked but ignored", report.tracked_but_ignored)
    add("history sensitive add", report.history_sensitive_added)
    add("history sensitive delete", report.history_sensitive_deleted)
    add("exfil advisory", report.exfil_code_indicators)
    add("github advisory", report.github_hardening_findings)
    add("github audit warning", report.github_hardening_warnings)
    add("litellm reference", report.litellm_reference_hits)
    add("litellm compromised", report.litellm_compromised_reference_hits)
    add("litellm ioc", report.litellm_ioc_hits)
    add("execution error", report.execution_errors)
    return findings


def build_planned_removals_preview(report: RepoReport) -> list[str]:
    planned: list[str] = []

    if report.secret_history_purge_paths:
        for path in report.secret_history_purge_paths[:8]:
            planned.append(f"history delete path: {path}")
        if len(report.secret_history_purge_paths) > 8:
            planned.append(
                f"history delete path: ... and {len(report.secret_history_purge_paths) - 8} more"
            )

    if report.tracked_but_ignored:
        for path in report.tracked_but_ignored[:8]:
            planned.append(f"stop tracking path: {path}")
        if len(report.tracked_but_ignored) > 8:
            planned.append(f"stop tracking path: ... and {len(report.tracked_but_ignored) - 8} more")

    if report.history_sensitive_added or report.history_sensitive_deleted:
        planned.append(
            "history delete by sensitive filename regex is eligible (.env, keys, id_rsa, pycache/pyc)"
        )

    return planned


def report_contains_sensitive_findings(report: RepoReport) -> bool:
    return bool(
        report.tracked_secret_matches
        or report.history_secret_matches
        or report.git_metadata_secret_matches
        or report.tracked_secret_low_confidence
        or report.history_secret_low_confidence
        or report.git_metadata_secret_low_confidence
        or report.tracked_secret_fixture_matches
        or report.history_secret_fixture_matches
        or report.tracked_secret_documentation_matches
        or report.history_secret_documentation_matches
        or report.secret_file_candidates
        or report.unexpected_emails
        or report.unexpected_identity_tokens
        or report.tracked_email_matches
        or report.history_email_matches
        or report.tracked_path_matches
        or report.history_path_matches
    )


def render_html_report(
    reports: list[RepoReport],
    artifacts: RunArtifacts,
    root_path: Path,
    policy_path: Path,
    run_settings: dict[str, str],
    finished_at: datetime,
    optional_supply_chain_payload: dict[str, object] | None = None,
) -> str:
    esc = html.escape
    total = len(reports)
    passed = sum(1 for item in reports if item.status == "PASS")
    failed = total - passed

    reason_counts: dict[str, int] = {}
    for rep in reports:
        for reason in rep.failures:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    ordered_reasons = sorted(reason_counts.items(), key=lambda entry: (-entry[1], entry[0]))

    repo_severity_data: list[tuple[RepoReport, str, int, list[str]]] = []
    for rep in reports:
        sev_label, sev_score, highlights = classify_repo_severity(rep)
        repo_severity_data.append((rep, sev_label, sev_score, highlights))
    repo_severity_data.sort(key=lambda item: (-item[2], item[0].name.lower()))

    high_risk_repos = [item for item in repo_severity_data if item[1] == "HIGH"]

    def render_lines(items: list[str], limit: int = 8) -> str:
        if not items:
            return '<div class="empty">No findings in this category.</div>'
        trimmed = items[:limit]
        content = "".join(f"<li><code>{esc(redact_sensitive_text(line))}</code></li>" for line in trimmed)
        suffix = ""
        if len(items) > limit:
            suffix = f'<div class="more">Showing {limit} of {len(items)} entries.</div>'
        return f"<ul class=\"finding-list\">{content}</ul>{suffix}"

    reason_rows = "".join(
        f"<tr><td>{esc(reason)}</td><td class=\"num\">{count}</td></tr>"
        for reason, count in ordered_reasons
    )
    if not reason_rows:
        reason_rows = '<tr><td class="empty" colspan="2">No failure reasons recorded.</td></tr>'

    settings_rows = "".join(
        f"<tr><td>{esc(key)}</td><td><code>{esc(redact_sensitive_text(value))}</code></td></tr>"
        for key, value in sorted(run_settings.items(), key=lambda item: item[0])
    )

    high_cards = ""
    for rep, _label, _score, highlights in high_risk_repos:
        detail = "".join(f"<li>{esc(item)}</li>" for item in highlights)
        high_cards += (
            "<article class=\"high-card\">"
            f"<h4>{esc(rep.name)}</h4>"
            f"<p>Status: <strong>{esc(rep.status)}</strong> | Failures: <strong>{len(rep.failures)}</strong></p>"
            f"<ul>{detail}</ul>"
            "</article>"
        )
    if not high_cards:
        high_cards = '<div class="empty">No HIGH severity repositories in this run.</div>'

    supply_chain_panel = ""
    if optional_supply_chain_payload:
        global_severity = str(optional_supply_chain_payload.get("severity", "NONE")).upper()
        global_severity_css = {
            "CRITICAL": "sev-high",
            "HIGH": "sev-high",
            "MEDIUM": "sev-medium",
            "LOW": "sev-low",
            "NONE": "sev-ok",
        }.get(global_severity, "sev-low")
        critical_evidence = [
            str(item) for item in optional_supply_chain_payload.get("critical_evidence", []) if str(item)
        ]
        high_evidence = [
            str(item) for item in optional_supply_chain_payload.get("high_evidence", []) if str(item)
        ]
        medium_evidence = [
            str(item) for item in optional_supply_chain_payload.get("medium_evidence", []) if str(item)
        ]
        python_probes = optional_supply_chain_payload.get("python_probes", [])
        probe_rows = ""
        if isinstance(python_probes, list):
            for probe in python_probes:
                if not isinstance(probe, dict):
                    continue
                probe_rows += (
                    "<tr>"
                    f"<td><code>{esc(redact_sensitive_text(str(probe.get('python', '-'))))}</code></td>"
                    f"<td>{esc(str(probe.get('installed', False)))}</td>"
                    f"<td>{esc(str(probe.get('version', '-')))}</td>"
                    f"<td><code>{esc(redact_sensitive_text(str(probe.get('location', '-'))))}</code></td>"
                    "</tr>"
                )
        if not probe_rows:
            probe_rows = '<tr><td class="empty" colspan="4">No python environment probes recorded.</td></tr>'

        supply_chain_panel = (
            '<section class="panel">'
            '<h2>Supply-chain incident audit (LiteLLM)</h2>'
            f'<p><strong>Global severity:</strong> <span class="sev-pill {global_severity_css}">{esc(global_severity)}</span></p>'
            '<div class="detail-grid">'
            '<section><h5>Critical evidence</h5>'
            f'{render_lines(critical_evidence, limit=12)}'
            '</section>'
            '<section><h5>High evidence</h5>'
            f'{render_lines(high_evidence, limit=12)}'
            '</section>'
            '</div>'
            '<div class="detail-grid">'
            '<section><h5>Medium evidence</h5>'
            f'{render_lines(medium_evidence, limit=12)}'
            '</section>'
            '<section><h5>Python environment probes</h5>'
            '<div class="table-wrap"><table>'
            '<tr><th>Python</th><th>LiteLLM installed</th><th>Version</th><th>Location</th></tr>'
            f'{probe_rows}'
            '</table></div>'
            '</section>'
            '</div>'
            '</section>'
        )

    repo_rows = ""
    repo_details = ""
    for rep, sev_label, _sev_score, highlights in repo_severity_data:
        decision_status, decision_message = email_remediation_decision(rep)
        guidance_level, guidance_risk, guidance_consequence, guidance_suggestion = repo_user_guidance(rep)
        owned_unexpected = (
            rep.unexpected_emails_owned_repo
            if rep.email_ownership_evaluated
            else rep.unexpected_emails
        )
        third_party_unexpected = (
            rep.unexpected_emails_third_party_repo if rep.email_ownership_evaluated else []
        )
        owned_unexpected_identity_tokens = (
            rep.unexpected_identity_tokens_owned_repo
            if rep.email_ownership_evaluated
            else rep.unexpected_identity_tokens
        )
        third_party_unexpected_identity_tokens = (
            rep.unexpected_identity_tokens_third_party_repo if rep.email_ownership_evaluated else []
        )
        tracked_email_high_confidence = (
            rep.tracked_email_high_confidence
            if rep.email_confidence_evaluated
            else rep.tracked_email_matches
        )
        tracked_email_low_confidence = (
            rep.tracked_email_low_confidence if rep.email_confidence_evaluated else []
        )
        history_email_high_confidence = (
            rep.history_email_high_confidence
            if rep.email_confidence_evaluated
            else rep.history_email_matches
        )
        history_email_low_confidence = (
            rep.history_email_low_confidence if rep.email_confidence_evaluated else []
        )

        sev_class = f"sev-{sev_label.lower()}"
        repo_rows += (
            "<tr>"
            f"<td>{esc(rep.name)}</td>"
            f"<td><span class=\"sev-pill {sev_class}\">{esc(sev_label)}</span></td>"
            f"<td>{esc(rep.status)}</td>"
            f"<td>{esc(classify_litellm_incident_severity(rep))}</td>"
            f"<td class=\"num\">{len(rep.failures)}</td>"
            f"<td class=\"num\">{len(rep.tracked_secret_matches) + len(rep.history_secret_matches) + len(rep.git_metadata_secret_matches)}</td>"
            f"<td class=\"num\">{len(rep.secret_file_candidates)}</td>"
            f"<td class=\"num\">{len(owned_unexpected)}</td>"
            f"<td class=\"num\">{len(owned_unexpected_identity_tokens)}</td>"
            f"<td class=\"num\">{len(rep.exfil_code_indicators)}</td>"
            f"<td class=\"num\">{len(rep.github_hardening_findings)}</td>"
            f"<td class=\"num\">{len(rep.litellm_ioc_hits)}</td>"
            f"<td class=\"num\">{len(rep.gitignore_missing_patterns)}</td>"
            "</tr>"
        )

        highlights_html = "".join(f"<li>{esc(item)}</li>" for item in highlights)
        if not highlights_html:
            highlights_html = "<li>No highlight details.</li>"

        failures_html = "".join(f"<li>{esc(item)}</li>" for item in rep.failures)
        if not failures_html:
            failures_html = "<li>No failures.</li>"

        detected_preview = build_detected_findings_preview(rep)
        planned_removals_preview = build_planned_removals_preview(rep)
        if not planned_removals_preview:
            planned_removals_preview = [
                "No deletion/untracking action is planned for current run settings."
            ]

        details_metrics = (
            "<table class=\"metrics\">"
            "<tr><th>Metric</th><th class=\"num\">Value</th></tr>"
            f"<tr><td>low_confidence_email_mode</td><td>{esc(rep.low_confidence_email_mode)}</td></tr>"
            f"<tr><td>unexpected_emails_total</td><td class=\"num\">{len(rep.unexpected_emails)}</td></tr>"
            f"<tr><td>unexpected_emails_owned_repo</td><td class=\"num\">{len(owned_unexpected)}</td></tr>"
            f"<tr><td>unexpected_emails_third_party_repo</td><td class=\"num\">{len(third_party_unexpected)}</td></tr>"
            f"<tr><td>unexpected_identity_tokens_total</td><td class=\"num\">{len(rep.unexpected_identity_tokens)}</td></tr>"
            f"<tr><td>unexpected_identity_tokens_owned_repo</td><td class=\"num\">{len(owned_unexpected_identity_tokens)}</td></tr>"
            f"<tr><td>unexpected_identity_tokens_third_party_repo</td><td class=\"num\">{len(third_party_unexpected_identity_tokens)}</td></tr>"
            f"<tr><td>tracked_secret_matches</td><td class=\"num\">{len(rep.tracked_secret_matches)}</td></tr>"
            f"<tr><td>tracked_secret_high_confidence</td><td class=\"num\">{len(rep.tracked_secret_high_confidence)}</td></tr>"
            f"<tr><td>tracked_secret_low_confidence</td><td class=\"num\">{len(rep.tracked_secret_low_confidence)}</td></tr>"
            f"<tr><td>tracked_secret_fixture_matches</td><td class=\"num\">{len(rep.tracked_secret_fixture_matches)}</td></tr>"
            f"<tr><td>tracked_secret_documentation_matches</td><td class=\"num\">{len(rep.tracked_secret_documentation_matches)}</td></tr>"
            f"<tr><td>history_secret_matches</td><td class=\"num\">{len(rep.history_secret_matches)}</td></tr>"
            f"<tr><td>history_secret_high_confidence</td><td class=\"num\">{len(rep.history_secret_high_confidence)}</td></tr>"
            f"<tr><td>history_secret_low_confidence</td><td class=\"num\">{len(rep.history_secret_low_confidence)}</td></tr>"
            f"<tr><td>history_secret_fixture_matches</td><td class=\"num\">{len(rep.history_secret_fixture_matches)}</td></tr>"
            f"<tr><td>history_secret_documentation_matches</td><td class=\"num\">{len(rep.history_secret_documentation_matches)}</td></tr>"
            f"<tr><td>git_metadata_secret_matches</td><td class=\"num\">{len(rep.git_metadata_secret_matches)}</td></tr>"
            f"<tr><td>git_metadata_secret_low_confidence</td><td class=\"num\">{len(rep.git_metadata_secret_low_confidence)}</td></tr>"
            f"<tr><td>secret_file_candidates</td><td class=\"num\">{len(rep.secret_file_candidates)}</td></tr>"
            f"<tr><td>tracked_path_matches</td><td class=\"num\">{len(rep.tracked_path_matches)}</td></tr>"
            f"<tr><td>history_path_matches</td><td class=\"num\">{len(rep.history_path_matches)}</td></tr>"
            f"<tr><td>tracked_email_matches</td><td class=\"num\">{len(rep.tracked_email_matches)}</td></tr>"
            f"<tr><td>tracked_email_high_confidence</td><td class=\"num\">{len(tracked_email_high_confidence)}</td></tr>"
            f"<tr><td>tracked_email_low_confidence</td><td class=\"num\">{len(tracked_email_low_confidence)}</td></tr>"
            f"<tr><td>history_email_matches</td><td class=\"num\">{len(rep.history_email_matches)}</td></tr>"
            f"<tr><td>history_email_high_confidence</td><td class=\"num\">{len(history_email_high_confidence)}</td></tr>"
            f"<tr><td>history_email_low_confidence</td><td class=\"num\">{len(history_email_low_confidence)}</td></tr>"
            f"<tr><td>history_sensitive_added</td><td class=\"num\">{len(rep.history_sensitive_added)}</td></tr>"
            f"<tr><td>history_sensitive_deleted</td><td class=\"num\">{len(rep.history_sensitive_deleted)}</td></tr>"
            f"<tr><td>tracked_but_ignored</td><td class=\"num\">{len(rep.tracked_but_ignored)}</td></tr>"
            f"<tr><td>gitignore_missing_patterns</td><td class=\"num\">{len(rep.gitignore_missing_patterns)}</td></tr>"
            f"<tr><td>exfil_code_indicators</td><td class=\"num\">{len(rep.exfil_code_indicators)}</td></tr>"
            f"<tr><td>github_hardening_checked</td><td>{esc(str(rep.github_hardening_checked))}</td></tr>"
            f"<tr><td>github_hardening_findings</td><td class=\"num\">{len(rep.github_hardening_findings)}</td></tr>"
            f"<tr><td>github_hardening_warnings</td><td class=\"num\">{len(rep.github_hardening_warnings)}</td></tr>"
            f"<tr><td>litellm_incident_severity</td><td>{esc(classify_litellm_incident_severity(rep))}</td></tr>"
            f"<tr><td>litellm_reference_hits</td><td class=\"num\">{len(rep.litellm_reference_hits)}</td></tr>"
            f"<tr><td>litellm_compromised_reference_hits</td><td class=\"num\">{len(rep.litellm_compromised_reference_hits)}</td></tr>"
            f"<tr><td>litellm_install_command_hits</td><td class=\"num\">{len(rep.litellm_install_command_hits)}</td></tr>"
            f"<tr><td>litellm_ioc_hits</td><td class=\"num\">{len(rep.litellm_ioc_hits)}</td></tr>"
            f"<tr><td>execution_errors</td><td class=\"num\">{len(rep.execution_errors)}</td></tr>"
            "</table>"
        )

        detail_sections = (
            "<div class=\"detail-grid\">"
            "<section><h5>User guidance</h5>"
            f"<p><strong>{esc(guidance_level)}</strong> - {esc(guidance_risk)}</p>"
            f"<p><strong>Possible consequence:</strong> {esc(guidance_consequence)}</p>"
            f"<p><strong>Suggestion:</strong> {esc(guidance_suggestion)}</p>"
            "</section>"
            "<section><h5>Email remediation decision</h5>"
            f"<p><strong>{esc(decision_status)}</strong> - {esc(decision_message)}</p>"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Detected findings (explicit preview)</h5>"
            f"{render_lines(detected_preview, limit=12)}"
            "</section>"
            "<section><h5>Planned deletions/untracking (explicit preview)</h5>"
            f"{render_lines(planned_removals_preview, limit=12)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>LiteLLM references (sample)</h5>"
            f"{render_lines(rep.litellm_reference_hits)}"
            "</section>"
            "<section><h5>LiteLLM IoCs (sample)</h5>"
            f"{render_lines(rep.litellm_ioc_hits)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Failure reasons</h5>"
            f"<ul>{failures_html}</ul></section>"
            "<section><h5>Severity highlights</h5>"
            f"<ul>{highlights_html}</ul></section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Tracked secret matches (sample)</h5>"
            f"{render_lines(rep.tracked_secret_matches)}"
            "</section>"
            "<section><h5>History secret matches (sample)</h5>"
            f"{render_lines(rep.history_secret_matches)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Low-confidence secret assignments (tracked)</h5>"
            f"{render_lines(rep.tracked_secret_low_confidence)}"
            "</section>"
            "<section><h5>Low-confidence secret assignments (history)</h5>"
            f"{render_lines(rep.history_secret_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Secret fixtures/examples (safe)</h5>"
            f"{render_lines(rep.tracked_secret_fixture_matches + rep.history_secret_fixture_matches)}"
            "</section>"
            "<section><h5>Secret documentation examples (safe)</h5>"
            f"{render_lines(rep.tracked_secret_documentation_matches + rep.history_secret_documentation_matches)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Git metadata secret matches</h5>"
            f"{render_lines(rep.git_metadata_secret_matches)}"
            "</section>"
            "<section><h5>Git metadata low-confidence secret indicators</h5>"
            f"{render_lines(rep.git_metadata_secret_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Secret file candidates</h5>"
            f"{render_lines(rep.secret_file_candidates)}"
            "</section>"
            "<section><h5>Unexpected commit emails (owned repositories)</h5>"
            f"{render_lines(owned_unexpected)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Malformed commit identity tokens (owned repositories)</h5>"
            f"{render_lines(owned_unexpected_identity_tokens)}"
            "</section>"
            "<section><h5>Unexpected commit emails (third-party repositories)</h5>"
            f"{render_lines(third_party_unexpected)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Malformed commit identity tokens (third-party repositories)</h5>"
            f"{render_lines(third_party_unexpected_identity_tokens)}"
            "</section>"
            "<section><h5>Exfil indicators (advisory sample)</h5>"
            f"{render_lines(rep.exfil_code_indicators)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>GitHub hardening findings (advisory sample)</h5>"
            f"{render_lines(rep.github_hardening_findings)}"
            "</section>"
            "<section><h5>GitHub hardening audit warnings</h5>"
            f"{render_lines(rep.github_hardening_warnings)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Path leaks in history (sample)</h5>"
            f"{render_lines(rep.history_path_matches)}"
            "</section>"
            "<section><h5>Path leaks in tracked files (sample)</h5>"
            f"{render_lines(rep.tracked_path_matches)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Email matches in tracked files (high confidence)</h5>"
            f"{render_lines(tracked_email_high_confidence)}"
            "</section>"
            "<section><h5>Email matches in tracked files (low confidence)</h5>"
            f"{render_lines(tracked_email_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Email leaks in history (high confidence)</h5>"
            f"{render_lines(history_email_high_confidence)}"
            "</section>"
            "<section><h5>Email leaks in history (low confidence)</h5>"
            f"{render_lines(history_email_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Ignore and history filename issues</h5>"
            f"{render_lines(rep.gitignore_missing_patterns + rep.history_sensitive_added + rep.history_sensitive_deleted)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Execution errors</h5>"
            f"{render_lines(rep.execution_errors)}"
            "</section>"
            "<section><h5>Fix errors</h5>"
            f"{render_lines(rep.fix_errors)}"
            "</section>"
            "</div>"
            "<section><h5>Metrics snapshot</h5>"
            f"{details_metrics}</section>"
        )

        repo_details += (
            "<details class=\"repo-detail\">"
            f"<summary>{esc(rep.name)} | severity {esc(sev_label)} | status {esc(rep.status)}</summary>"
            f"<p class=\"meta\">path: <code>{esc(redact_sensitive_text(rep.path))}</code></p>"
            f"<p class=\"meta\">origin: <code>{esc(redact_sensitive_text(rep.origin_url or '-'))}</code></p>"
            f"<p class=\"meta\">upstream: <code>{esc(redact_sensitive_text(rep.upstream_url or '-'))}</code></p>"
            f"{detail_sections}"
            "</details>"
        )

    duration = finished_at - artifacts.started_at
    duration_seconds = max(duration.total_seconds(), 0.0)

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Repo Privacy Guardian Audit Report - {esc(artifacts.run_id)}</title>
  <style>
    :root {{
      --bg: #f6f8fc;
      --surface: #ffffff;
      --text: #17233a;
      --muted: #4d5a73;
      --line: #d6deeb;
      --ok: #1e8e5a;
      --low: #a66a00;
      --med: #d95f02;
      --high: #b00020;
      --accent: #005bbb;
      --shadow: 0 10px 28px rgba(23, 35, 58, 0.08);
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0f172a;
        --surface: #1e293b;
        --text: #e2ecf6;
        --muted: #94a3b8;
        --line: #334155;
        --ok: #34d399;
        --low: #fbbf24;
        --med: #fb923c;
        --high: #f87171;
        --accent: #38bdf8;
        --shadow: 0 10px 28px rgba(0, 0, 0, 0.4);
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      background: radial-gradient(circle at top right, #dde8ff 0%, var(--bg) 42%);
      color: var(--text);
      line-height: 1.45;
    }}
    @media (prefers-color-scheme: dark) {{
      body {{
        background: radial-gradient(circle at top right, #1e293b 0%, var(--bg) 42%);
      }}
    }}
    .container {{ max-width: 1280px; margin: 0 auto; padding: 22px; }}
    .hero {{
      background: linear-gradient(125deg, #0f3c78 0%, #005bbb 55%, #2a7de1 100%);
      color: #fff;
      border-radius: 16px;
      padding: 24px;
      box-shadow: var(--shadow);
    }}
    .hero h1 {{ margin: 0 0 10px; font-size: 1.65rem; }}
    .hero p {{ margin: 6px 0; opacity: 0.95; }}
    .grid {{ display: grid; gap: 14px; margin-top: 18px; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); }}
    .card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 14px; box-shadow: var(--shadow); }}
    .card h3 {{ margin: 0 0 6px; font-size: 0.95rem; color: var(--muted); font-weight: 600; }}
    .metric {{ font-size: 1.8rem; font-weight: 700; margin: 0; }}
    .metric.fail {{ color: var(--high); }}
    .metric.pass {{ color: var(--ok); }}
    section {{ margin-top: 18px; }}
    h2 {{ margin: 0 0 10px; font-size: 1.18rem; }}
    h4 {{ margin: 0 0 8px; }}
    .panel {{ background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 14px; box-shadow: var(--shadow); }}
    .table-wrap {{ width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }}
    .table-wrap table {{ width: 100%; border-collapse: collapse; min-width: 520px; }}
    .table-wrap.matrix table {{ min-width: 980px; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ background: #eef3fb; font-weight: 700; }}
    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .sev-pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.82rem; font-weight: 700; }}
    .sev-high {{ background: #ffe4e8; color: var(--high); }}
    .sev-medium {{ background: #fff1de; color: var(--med); }}
    .sev-low {{ background: #fff8df; color: var(--low); }}
    .sev-ok {{ background: #dff6e9; color: var(--ok); }}
    .high-card {{ border: 1px solid #f3b7bf; background: #fff0f3; border-radius: 10px; padding: 12px; margin-bottom: 10px; }}
    .repo-detail {{ border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; margin-bottom: 10px; background: var(--surface); box-shadow: var(--shadow); }}
    .repo-detail summary {{ cursor: pointer; font-weight: 700; }}
    .meta {{ margin: 8px 0 0; color: var(--muted); }}
    .detail-grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); margin-top: 10px; }}
    .finding-list {{ margin: 0; padding-left: 18px; }}
    .finding-list code {{ white-space: pre-wrap; word-break: break-word; }}
    code {{ background: #f1f5ff; color: #1b2f55; border-radius: 4px; padding: 1px 4px; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }}
    .more, .empty {{ margin-top: 8px; color: var(--muted); font-style: italic; }}
    @media (prefers-color-scheme: dark) {{
      th {{ background: #0f172a; border-bottom-color: #334155; }}
      code {{ background: #0f172a; color: #bae6fd; }}
      .sev-high {{ background: #450a0a; color: var(--high); }}
      .sev-medium {{ background: #431407; color: var(--med); }}
      .sev-low {{ background: #422006; color: var(--low); }}
      .sev-ok {{ background: #064e3b; color: var(--ok); }}
      .high-card {{ border-color: #7f1d1d; background: #450a0a; }}
    }}
    @media (max-width: 760px) {{
      .container {{ padding: 12px; }}
      .hero {{ padding: 16px; }}
      th, td {{ padding: 8px; }}
            .table-wrap.matrix table {{ min-width: 820px; }}
    }}
  </style>
</head>
<body>
  <div class=\"container\">
    <header class=\"hero\">
      <h1>Repository Privacy Audit Report</h1>
      <p><strong>Run ID:</strong> {esc(artifacts.run_id)}</p>
      <p><strong>Started:</strong> {esc(artifacts.started_at.strftime('%Y-%m-%d %H:%M:%S'))} | <strong>Finished:</strong> {esc(finished_at.strftime('%Y-%m-%d %H:%M:%S'))} | <strong>Duration:</strong> {duration_seconds:.2f}s</p>
            <p><strong>Root:</strong> <code>{esc(redact_sensitive_text(str(root_path)))}</code></p>
            <p><strong>Policy:</strong> <code>{esc(redact_sensitive_text(str(policy_path)))}</code></p>
            <p><strong>Artifacts:</strong> <code>{esc(redact_sensitive_text(str(artifacts.run_dir)))}</code></p>
    </header>

    <section class=\"grid\">
      <article class=\"card\"><h3>Total repositories</h3><p class=\"metric\">{total}</p></article>
      <article class=\"card\"><h3>PASS</h3><p class=\"metric pass\">{passed}</p></article>
      <article class=\"card\"><h3>FAIL</h3><p class=\"metric fail\">{failed}</p></article>
            <article class=\"card\"><h3>HIGH severity repos</h3><p class=\"metric fail\">{len(high_risk_repos)}</p></article>
    </section>

    <section class=\"panel\">
      <h2>Execution settings</h2>
      <div class=\"table-wrap\">
        <table>
          <tr><th>Setting</th><th>Value</th></tr>
          {settings_rows}
        </table>
      </div>
    </section>

    <section class=\"panel\">
            <h2>High severity focus</h2>
      {high_cards}
    </section>

        {supply_chain_panel}

    <section class=\"panel\">
      <h2>Failure reason frequency</h2>
      <div class=\"table-wrap\">
        <table>
          <tr><th>Reason</th><th class=\"num\">Repos</th></tr>
          {reason_rows}
        </table>
      </div>
    </section>

    <section class=\"panel\">
      <h2>Repository matrix</h2>
      <div class=\"table-wrap matrix\">
        <table>
          <tr>
            <th>Repository</th>
            <th>Severity</th>
            <th>Status</th>
                        <th>LiteLLM Incident</th>
            <th class=\"num\">Failures</th>
            <th class=\"num\">Secret matches</th>
            <th class=\"num\">Secret file candidates</th>
            <th class=\"num\">Unexpected emails (owned repo)</th>
            <th class=\"num\">Identity tokens (owned repo)</th>
            <th class=\"num\">Exfil indicators</th>
            <th class=\"num\">GitHub findings</th>
            <th class=\"num\">LiteLLM IoCs</th>
            <th class=\"num\">Missing .gitignore rules</th>
          </tr>
          {repo_rows}
        </table>
      </div>
    </section>

    <section>
      <h2>Repository details</h2>
      {repo_details}
    </section>
  </div>
</body>
</html>
"""


def persist_run_outputs(
    reports: list[RepoReport],
    artifacts: RunArtifacts,
    root_path: Path,
    policy_path: Path,
    run_settings: dict[str, str],
    logger: Callable[[str], None],
    optional_json_export: str | None = None,
    optional_supply_chain_payload: dict[str, object] | None = None,
) -> None:
    artifact_helpers.persist_run_outputs(
        reports=reports,
        artifacts=artifacts,
        root_path=root_path,
        policy_path=policy_path,
        run_settings=run_settings,
        logger=logger,
        sanitize_report_for_export=sanitize_report_for_export,
        render_html_report=render_html_report,
        write_private_text_file=write_private_text_file,
        report_contains_sensitive_findings=report_contains_sensitive_findings,
        resolve_optional_json_export_path=resolve_optional_json_export_path,
        optional_json_export=optional_json_export,
        optional_supply_chain_payload=optional_supply_chain_payload,
        now_factory=datetime.now,
    )


def open_html_report_in_browser(
    html_path: Path,
    logger: Callable[[str], None],
) -> None:
    if not html_path.exists():
        return

    try:
        opened = bool(webbrowser.open(html_path.resolve().as_uri()))
    except Exception as exc:
        logger(f"[WARN] Could not open HTML report automatically: {exc}")
        return

    if opened:
        logger(f"[INFO] Opened HTML report in browser: {html_path}")
    else:
        logger(f"[WARN] Browser did not open automatically. Open report manually: {html_path}")


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
    }


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
    state_tracker = RunStateTracker(artifacts.state_path, artifacts=artifacts, config=config)

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
    guard = RepoPublicationGuard(**guard_kwargs)
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
        state_tracker.update(phase="preflight")
        git_ok, git_error = probe_git_available()
        if not git_ok:
            logger(f"[ERROR] {git_error}")
            exit_code = EXIT_RUNTIME_ERROR
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
            if config.low_confidence_email_mode == "blocking":
                logger("[INFO] Email policy: low-confidence findings are blocking.")
            else:
                logger("[INFO] Email policy: low-confidence findings are informational.")
            if config.audit_github_hardening:
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
                remote_no_targets_error: str | None = None
                if config.github_owner:
                    state_tracker.update(phase="github-discovery")
                    try:
                        repos, clone_failure_reports, remote_temp_root, remote_no_targets_error = (
                            prepare_github_remote_audit_repositories(config, logger)
                        )
                        for failure_report in clone_failure_reports:
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
                            repo_lock = acquire_repo_lock(repo)
                        logger(f"[AUDIT] {repo_name}")
                        report = guard.audit_repo(repo)

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
                                fixed = guard.apply_fixes(repo, report)
                                logger(f"[RE-AUDIT] {repo_name}")
                                report = guard.audit_repo(repo)
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

                    report.finalize()
                    reports.append(report)
                    completed_repo_iterations += 1
                    print_report(report, logger)
                    state_tracker.update(
                        phase="fixing" if config.fix else "auditing",
                        current_repository="",
                        completed_repositories=len(reports),
                        total_repositories=total_repositories,
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
            persist_kwargs: dict[str, object] = {
                "reports": reports,
                "artifacts": artifacts,
                "root_path": config.root,
                "policy_path": config.policy,
                "run_settings": run_settings,
                "logger": logger,
                "optional_json_export": config.report_json,
                "optional_supply_chain_payload": supply_chain_payload,
            }

            persist_params = inspect.signature(persist_run_outputs).parameters
            if "optional_supply_chain_payload" not in persist_params:
                persist_kwargs.pop("optional_supply_chain_payload", None)
            persist_run_outputs(**persist_kwargs)
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
                removed, cleanup_error = remove_private_temp_tree(
                    remote_temp_root,
                    required_prefix="repo-privacy-guardian-github-",
                )
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
) -> GuardRunConfig:
    normalized_owner_emails = normalize_text_values(owner_emails)
    normalized_allowed_remote_owners = normalize_text_values(allowed_remote_owners)
    inferred_owner = infer_github_username_from_noreply(noreply_email)
    if inferred_owner and inferred_owner not in normalized_allowed_remote_owners:
        normalized_allowed_remote_owners.append(inferred_owner)

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
        low_confidence_email_mode=low_confidence_email_mode,
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
    payload: dict[str, object] = {
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


class GuiApp:  # pragma: no cover
    def __init__(self) -> None:
        tk, messagebox, filedialog, ctk, tcl_error = load_gui_runtime()

        self._gui_settings_path = default_gui_settings_path()
        self._gui_settings = load_gui_settings(self._gui_settings_path)
        self._gui_locale = normalize_gui_locale(gui_setting_str(self._gui_settings, "gui_locale", GUI_LOCALE_DEFAULT))
        self._gui_appearance = normalize_gui_appearance(
            gui_setting_str(self._gui_settings, "gui_appearance", GUI_APPEARANCE_DEFAULT)
        )
        ctk.set_appearance_mode(self._gui_appearance)
        ctk.set_default_color_theme("blue")

        self.tk = tk
        self.ctk = ctk
        self.messagebox = messagebox
        self.filedialog = filedialog
        try:
            self.root = ctk.CTk()
        except tcl_error as exc:
            raise RuntimeError(
                "GUI mode could not initialize Tk. "
                "On Linux desktop, install python3-tk and start from a graphical session. "
                "Otherwise, use the CLI."
            ) from exc
        self._gui_asset_images = self._load_gui_assets()
        self._gui_themed_asset_images: dict[tuple[str, str, str], object] = {}
        self._gui_button_asset_images = self._load_gui_button_assets()
        self._set_window_icon()
        self.root.title("Repo Privacy Guardian")
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        window_w = min(max(int(screen_w * 0.92), 1180), 1620)
        window_h = min(max(int(screen_h * 0.9), 760), 980)
        window_x = max((screen_w - window_w) // 2, 0)
        window_y = max((screen_h - window_h) // 2, 0)
        self._top_stack_width_threshold = 1220
        self._options_stack_width_threshold = 1220
        self._results_stack_width_threshold = 1240
        self.root.geometry(f"{window_w}x{window_h}+{window_x}+{window_y}")
        self.root.minsize(min(1180, screen_w), min(700, screen_h))
        self.root.maxsize(screen_w, screen_h)

        available_families: set[str] | None = None
        try:
            available_families = {
                str(name)
                for name in self.root.tk.call("font", "families")
                if isinstance(name, str)
            }
        except Exception:
            available_families = None

        font_options = gui_font_candidates()
        self._ui_font_family = choose_gui_font_family(font_options["ui"], available_families)
        self._mono_font_family = choose_gui_font_family(font_options["mono"], available_families)
        self._configure_gui_theme_palette()
        self.root.configure(fg_color=self._page_bg)

        self.locale_var = tk.StringVar(value=gui_locale_label(self._gui_locale))
        self.appearance_var = tk.StringVar(value=gui_appearance_label(self._gui_appearance, self._current_locale()))
        self._localized_config_targets: list[tuple[object, str, str, dict[str, object]]] = []
        self._locale_menu = None
        self._appearance_menu = None
        setup_completed = gui_setting_bool(self._gui_settings, "setup_completed", False)
        self._setup_completed = setup_completed

        self.root_var = tk.StringVar(value=gui_setting_str(self._gui_settings, "root", str(default_root_dir())))
        self.policy_var = tk.StringVar(value=gui_setting_str(self._gui_settings, "policy", str(DEFAULT_POLICY)))
        self.noreply_var = tk.StringVar(value=DEFAULT_NOREPLY)
        self.placeholder_var = tk.StringVar(value=DEFAULT_PLACEHOLDER)
        self.owner_name_var = tk.StringVar(value="Owner")
        self.owner_emails_var = tk.StringVar(value="")
        self.allowed_remote_owners_var = tk.StringVar(value="")
        self.git_user_name_var = tk.StringVar(value="Owner")
        self.git_user_email_var = tk.StringVar(value=DEFAULT_NOREPLY)
        self.report_dir_var = tk.StringVar(
            value=gui_setting_str(self._gui_settings, "report_dir", str(default_results_dir()))
        )
        self.report_json_var = tk.StringVar(value=gui_setting_str(self._gui_settings, "report_json", ""))
        self.replace_text_file_var = tk.StringVar(value="")
        self.max_matches_var = tk.StringVar(value=gui_setting_str(self._gui_settings, "max_matches", "50"))
        self.github_owner_var = tk.StringVar(value=gui_setting_str(self._gui_settings, "github_owner", ""))
        self.github_repo_filters_var = tk.StringVar(
            value=gui_setting_str(self._gui_settings, "github_repo_filters", "")
        )
        self.github_jobs_var = tk.StringVar(value=gui_setting_str(self._gui_settings, "github_jobs", "4"))

        self.public_only_var = tk.BooleanVar(
            value=gui_setting_bool(self._gui_settings, "public_only", GUI_DEFAULT_PUBLIC_ONLY)
        )
        self.github_include_forks_var = tk.BooleanVar(
            value=gui_setting_bool(self._gui_settings, "github_include_forks", False)
        )
        self.github_fast_var = tk.BooleanVar(value=gui_setting_bool(self._gui_settings, "github_fast", False))
        self.push_var = tk.BooleanVar(value=False)
        self.redact_var = tk.BooleanVar(value=False)
        self.rewrite_personal_paths_var = tk.BooleanVar(value=False)
        self.purge_detected_secret_files_var = tk.BooleanVar(value=False)
        self.purge_all_detected_secret_files_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=gui_setting_bool(self._gui_settings, "dry_run", False))
        self.low_confidence_blocking_var = tk.BooleanVar(
            value=gui_setting_bool(self._gui_settings, "low_confidence_blocking", False)
        )
        self.audit_litellm_incident_var = tk.BooleanVar(
            value=gui_setting_bool(self._gui_settings, "audit_litellm_incident", False)
        )
        self.audit_github_hardening_var = tk.BooleanVar(
            value=gui_setting_bool(self._gui_settings, "audit_github_hardening", False)
        )
        self.open_report_var = tk.BooleanVar(value=gui_setting_bool(self._gui_settings, "open_report", False))
        self.confirm_each_repo_fix_var = tk.BooleanVar(value=True)
        self.allow_non_owner_push_var = tk.BooleanVar(value=False)
        self.audit_github_hardening_var.trace_add("write", self._on_audit_github_hardening_toggled)
        self.github_owner_var.trace_add("write", self._on_github_remote_controls_changed)
        self.github_repo_filters_var.trace_add("write", self._on_github_remote_controls_changed)
        self._purge_safe_checkbox = None
        self._purge_risky_checkbox = None
        self._allowed_remote_owner_entry = None
        self._audit_button = None
        self._cancel_button = None
        self._repair_button = None
        self._run_in_progress = False
        self._active_cancel_token: CancellationToken | None = None
        self._repair_ready = False
        self._repair_button_text_key = "lock_repair_default"
        self._repair_button_text_kwargs: dict[str, object] = {}
        self._repair_lock_reason_key: str | None = "lock_repair_default"
        self._repair_button_text = self._t("lock_repair_default")
        self._repair_cooldown_seconds = 10
        self._repair_cooldown_remaining = 0
        self._repair_cooldown_after_id = None
        self._last_audit_reports_payload: list[dict[str, object]] = []
        self._last_audit_selection_signature: tuple[str, ...] | None = None
        self._flow_tabs = None
        self._workflow_strip = None
        self._workflow_strip_visible = True
        self._audit_tab_name = self._t("tab_audit")
        self._reports_tab_name = self._t("tab_reports")
        self._prompts_tab_name = self._t("tab_prompts")
        self._settings_tab_name = self._t("tab_settings")
        self._repair_tab_name = self._t("tab_repair")
        self._setup_settings_visible = not setup_completed
        self._setup_settings_toggle_button = None
        self._setup_settings_hint_label = None
        self._setup_settings_frame = None
        self._settings_status_label = None
        self._repo_drop_hint_label = None
        self._dnd_command_names: list[str] = []
        self._advanced_identity_visible = False
        self._advanced_identity_toggle_button = None
        self._advanced_identity_hint_label = None
        self._identity_card = None
        self._repair_tab_block_overlay = None
        self._repair_tab_block_label = None
        self._repair_tab_block_steps: list[object] = []
        self._identity_actions = None
        self._identity_action_buttons: list[object] = []
        self._compact_identity_actions_layout = False
        self._results_row = None
        self._repos_card = None
        self._output_card = None
        self._compact_results_layout = False
        self._repo_summary_label = None
        self._repo_empty_state = None
        self._repo_empty_state_title_label = None
        self._repo_empty_state_body_label = None
        self._repo_empty_state_hint_label = None
        self._repo_empty_reason: str | None = None
        self._repo_items: list[tuple[str, str]] = []
        self._select_all_button = None
        self._clear_selection_button = None
        self._refresh_button = None
        self._repair_status_label = None
        self._repair_status_panel = None
        self._repair_status_badge = None
        self._repair_gate_note_label = None
        self._last_run_artifacts: artifact_helpers.RunArtifacts | None = None
        self._last_run_exit_code: int | None = None
        self._last_run_action = ""
        self._reports_status_badge = None
        self._reports_summary_label = None
        self._reports_paths_label = None
        self._reports_action_buttons: list[object] = []
        self._prompt_cards_frame = None
        self._header_visual_label = None
        self._reports_visual_label = None
        self._prompts_visual_label = None
        self._repo_empty_state_visual_label = None
        self._repo_scrollbar = None
        self._output_empty_state_label = None
        self._repair_gate_visual_label = None
        self._repair_options_visible = False
        self._repair_options_toggle_button = None
        self._repair_options_hint_label = None
        self._repair_options_card = None

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        app = ctk.CTkScrollableFrame(
            self.root,
            fg_color=self._page_bg,
            corner_radius=0,
            border_width=0,
            scrollbar_fg_color=self._scrollbar_track,
            scrollbar_button_color=self._scrollbar_thumb,
            scrollbar_button_hover_color=self._scrollbar_hover,
        )
        app.grid(row=0, column=0, sticky="nsew")
        app.grid_columnconfigure(0, weight=1)
        self._app_frame = app

        header = ctk.CTkFrame(app, fg_color=self._header_fg, corner_radius=18)
        header.grid(row=0, column=0, sticky="we", padx=16, pady=(10, 8))
        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(1, weight=0)
        self._localize_widget(ctk.CTkLabel(
            header,
            text=self._t("header_title"),
            font=self._font(24, bold=True),
            text_color="#F8FAFC",
        ), "text", "header_title").grid(row=0, column=0, sticky="w", padx=18, pady=(12, 0))
        self._localize_widget(ctk.CTkLabel(
            header,
            text=self._t("header_subtitle"),
            font=self._font(13),
            text_color="#D8FFF3",
        ), "text", "header_subtitle").grid(row=1, column=0, sticky="w", padx=18, pady=(2, 8))

        workflow_strip = ctk.CTkFrame(header, fg_color="transparent")
        workflow_strip.grid(row=2, column=0, sticky="w", padx=18, pady=(0, 14))
        self._workflow_strip = workflow_strip
        workflow_items = [
            "workflow_audit",
            "workflow_review",
            "workflow_repair",
            "workflow_parity",
        ]
        for idx, label_key in enumerate(workflow_items):
            self._localize_widget(ctk.CTkLabel(
                workflow_strip,
                text=self._t(label_key),
                height=26,
                corner_radius=13,
                fg_color=self._header_chip_fg,
                text_color=self._header_chip_text,
                font=self._font(11, bold=True),
                padx=12,
            ), "text", label_key).grid(row=0, column=idx, sticky="w", padx=(0, 8))
        self._header_visual_label = self._make_asset_label(
            header,
            "header-watermark.png",
            background=self._header_fg,
        )
        if self._header_visual_label is not None:
            self._header_visual_label.grid(row=0, column=1, rowspan=3, sticky="e", padx=(8, 12), pady=8)

        flow_tabs = ctk.CTkTabview(
            app,
            fg_color=self._tabview_fg,
            corner_radius=14,
            segmented_button_fg_color=self._tab_segment_fg,
            segmented_button_selected_color=self._tab_selected_fg,
            segmented_button_selected_hover_color=self._tab_selected_hover,
            segmented_button_unselected_color=self._tab_unselected_fg,
            segmented_button_unselected_hover_color=self._tab_unselected_hover,
            text_color=self._text_heading,
        )
        flow_tabs.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 4))
        flow_tabs.add(self._audit_tab_name)
        flow_tabs.add(self._reports_tab_name)
        flow_tabs.add(self._prompts_tab_name)
        flow_tabs.add(self._settings_tab_name)
        flow_tabs.add(self._repair_tab_name)
        self._flow_tabs = flow_tabs

        audit_tab = flow_tabs.tab(self._audit_tab_name)
        reports_tab = flow_tabs.tab(self._reports_tab_name)
        prompts_tab = flow_tabs.tab(self._prompts_tab_name)
        settings_tab = flow_tabs.tab(self._settings_tab_name)
        repair_tab = flow_tabs.tab(self._repair_tab_name)
        audit_tab.grid_columnconfigure(0, weight=1)
        audit_tab.grid_rowconfigure(1, weight=1)
        reports_tab.grid_columnconfigure(0, weight=1)
        prompts_tab.grid_columnconfigure(0, weight=1)
        settings_tab.grid_columnconfigure(0, weight=1)
        repair_tab.grid_columnconfigure(0, weight=1)

        audit_target_card = ctk.CTkFrame(
            audit_tab,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        audit_target_card.grid(row=0, column=0, sticky="we", padx=10, pady=(8, 8))
        audit_target_card.grid_columnconfigure(1, weight=1)
        self._localize_widget(ctk.CTkLabel(
            audit_target_card,
            text=self._t("audit_target"),
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "audit_target").grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(12, 4))
        self._localize_widget(ctk.CTkLabel(
            audit_target_card,
            text=self._t("audit_target_body"),
            justify="left",
            anchor="w",
            wraplength=1100,
            font=self._font(12),
            text_color=self._text_muted,
        ), "text", "audit_target_body").grid(row=1, column=0, columnspan=3, sticky="we", padx=14, pady=(0, 8))
        self._add_directory_field(
            audit_target_card,
            row=2,
            label_key="repositories_root",
            variable=self.root_var,
            title_key="choose_repositories_root",
            tooltip_key="repositories_root",
        )
        audit_settings_row = ctk.CTkFrame(audit_target_card, fg_color="transparent")
        audit_settings_row.grid(row=3, column=0, columnspan=3, sticky="we", padx=14, pady=(6, 12))
        audit_settings_row.grid_columnconfigure(0, weight=1)
        self._localize_widget(ctk.CTkLabel(
            audit_settings_row,
            text=self._t("recommended_path_body"),
            justify="left",
            anchor="w",
            wraplength=860,
            font=self._font(11),
            text_color=self._text_muted,
        ), "text", "recommended_path_body").grid(row=0, column=0, sticky="we")
        settings_shortcut = ctk.CTkButton(
            audit_settings_row,
            text=self._t("open_settings_tab"),
            command=lambda: self._set_active_flow_tab(self._settings_tab_name),
            width=150,
            height=32,
            corner_radius=8,
            **self._button_asset_options("icon-settings.png"),
            **self._secondary_button_options(),
        )
        self._localize_widget(settings_shortcut, "text", "open_settings_tab")
        self._bind_tooltip_key(settings_shortcut, "open_settings_tab")
        settings_shortcut.grid(row=0, column=1, sticky="e", padx=(12, 0))

        settings_intro = ctk.CTkFrame(settings_tab, fg_color="transparent")
        settings_intro.grid(row=0, column=0, sticky="we", padx=10, pady=(8, 0))
        settings_intro.grid_columnconfigure(0, weight=1)
        self._localize_widget(ctk.CTkLabel(
            settings_intro,
            text=self._t("settings_companion_title"),
            font=self._font(18, bold=True),
            text_color=self._text_heading,
        ), "text", "settings_companion_title").grid(row=0, column=0, sticky="w")
        self._localize_widget(ctk.CTkLabel(
            settings_intro,
            text=self._t("settings_companion_body"),
            justify="left",
            anchor="w",
            wraplength=1100,
            font=self._font(12),
            text_color=self._text_muted,
        ), "text", "settings_companion_body").grid(row=1, column=0, sticky="we", pady=(2, 8))

        top_row = ctk.CTkFrame(settings_tab, fg_color="transparent")
        top_row.grid(row=1, column=0, sticky="we", padx=10, pady=(0, 8))
        top_row.grid_columnconfigure(0, weight=2)
        top_row.grid_columnconfigure(1, weight=1)
        self._top_row = top_row

        settings_card = ctk.CTkFrame(
            top_row,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        settings_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        settings_card.grid_columnconfigure(1, weight=1)
        self._settings_card = settings_card
        self._localize_widget(ctk.CTkLabel(
            settings_card,
            text=self._t("setup_settings"),
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "setup_settings").grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(12, 8))

        quick_start = ctk.CTkFrame(
            settings_card,
            fg_color=self._success_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._success_panel_border,
        )
        quick_start.grid(row=1, column=0, columnspan=3, sticky="we", padx=14, pady=(0, 10))
        quick_start.grid_columnconfigure(1, weight=1)
        self._localize_widget(ctk.CTkLabel(
            quick_start,
            text=self._t("setup_settings"),
            height=28,
            corner_radius=14,
            fg_color=self._primary_button_fg,
            text_color="#F8FAFC",
            font=self._font(11, bold=True),
            padx=12,
        ), "text", "setup_settings").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self._localize_widget(ctk.CTkLabel(
            quick_start,
            text=self._t("settings_status"),
            justify="left",
            anchor="w",
            wraplength=820,
            font=self._font(12),
            text_color=self._text_body,
        ), "text", "settings_status").grid(row=0, column=1, sticky="we", padx=(0, 10), pady=10)

        row = 2
        self._add_directory_field(
            settings_card,
            row=row,
            label_key="repositories_root",
            variable=self.root_var,
            title_key="choose_repositories_root",
            tooltip_key="repositories_root",
        )

        row += 1
        setup_toggle_row = ctk.CTkFrame(
            settings_card,
            fg_color=self._surface_alt,
            corner_radius=10,
            border_width=1,
            border_color=self._card_border,
        )
        setup_toggle_row.grid(row=row, column=0, columnspan=3, sticky="we", padx=14, pady=(6, 12))
        setup_toggle_row.grid_columnconfigure(0, weight=1)
        self._setup_settings_hint_label = ctk.CTkLabel(
            setup_toggle_row,
            text=self._t("setup_initial_hint"),
            justify="left",
            anchor="w",
            wraplength=760,
            font=self._font(11),
            text_color=self._text_muted,
        )
        self._localize_widget(self._setup_settings_hint_label, "text", "setup_initial_hint")
        self._setup_settings_hint_label.grid(row=0, column=0, sticky="we", padx=12, pady=10)
        self._setup_settings_toggle_button = ctk.CTkButton(
            setup_toggle_row,
            text=self._t("hide_settings"),
            command=self._toggle_setup_settings,
            width=170,
            height=32,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._bind_tooltip_key(self._setup_settings_toggle_button, "settings_toggle")
        self._setup_settings_toggle_button.grid(row=0, column=1, sticky="e", padx=(8, 12), pady=10)

        row += 1
        setup_settings_frame = ctk.CTkFrame(
            settings_card,
            fg_color=self._surface_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._card_border,
        )
        setup_settings_frame.grid(row=row, column=0, columnspan=3, sticky="we", padx=14, pady=(0, 12))
        setup_settings_frame.grid_columnconfigure(1, weight=1)
        self._setup_settings_frame = setup_settings_frame

        self._localize_widget(ctk.CTkLabel(
            setup_settings_frame,
            text=self._t("setup_settings"),
            font=self._font(14, bold=True),
            text_color=self._text_heading,
        ), "text", "setup_settings").grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(12, 4))
        self._settings_status_label = ctk.CTkLabel(
            setup_settings_frame,
            text=self._t("settings_status"),
            justify="left",
            anchor="w",
            wraplength=880,
            font=self._font(11),
            text_color=self._text_muted,
        )
        self._localize_widget(self._settings_status_label, "text", "settings_status")
        self._settings_status_label.grid(row=1, column=0, columnspan=3, sticky="we", padx=14, pady=(0, 8))

        settings_row = 2
        self._make_field_label(
            setup_settings_frame,
            text_key="gui_language",
            tooltip_key="gui_language",
        ).grid(row=settings_row, column=0, sticky="w", padx=(14, 8), pady=4)
        self._locale_menu = ctk.CTkOptionMenu(
            setup_settings_frame,
            variable=self.locale_var,
            values=[label for _locale, label in GUI_LOCALE_OPTIONS],
            command=self._on_gui_locale_selected,
            height=32,
            corner_radius=8,
            fg_color=self._secondary_button_fg,
            button_color=self._support_button_fg,
            button_hover_color=self._support_button_hover,
            text_color=self._secondary_button_text,
        )
        self._bind_tooltip_key(self._locale_menu, "gui_language")
        self._locale_menu.grid(row=settings_row, column=1, sticky="w", pady=4)

        settings_row += 1
        self._make_field_label(
            setup_settings_frame,
            text_key="gui_appearance",
            tooltip_key="gui_appearance",
        ).grid(row=settings_row, column=0, sticky="w", padx=(14, 8), pady=4)
        self._appearance_menu = ctk.CTkOptionMenu(
            setup_settings_frame,
            variable=self.appearance_var,
            values=[label for _appearance, label in gui_appearance_options(self._current_locale())],
            command=self._on_gui_appearance_selected,
            height=32,
            corner_radius=8,
            fg_color=self._secondary_button_fg,
            button_color=self._support_button_fg,
            button_hover_color=self._support_button_hover,
            text_color=self._secondary_button_text,
        )
        self._bind_tooltip_key(self._appearance_menu, "gui_appearance")
        self._appearance_menu.grid(row=settings_row, column=1, sticky="w", pady=4)

        settings_row += 1
        self._add_file_field(
            setup_settings_frame,
            row=settings_row,
            label_key="policy_file",
            variable=self.policy_var,
            title_key="choose_policy_file",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
            tooltip_key="policy_file",
        )

        settings_row += 1
        self._add_directory_field(
            setup_settings_frame,
            row=settings_row,
            label_key="audit_results_folder",
            variable=self.report_dir_var,
            title_key="choose_results_folder",
            tooltip_key="audit_results_folder",
        )

        settings_row += 1
        self._add_save_file_field(
            setup_settings_frame,
            row=settings_row,
            label_key="optional_json_copy",
            variable=self.report_json_var,
            title_key="choose_json_copy",
            default_extension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            tooltip_key="optional_json_copy",
        )

        settings_row += 1
        github_remote_card = ctk.CTkFrame(
            setup_settings_frame,
            fg_color=self._info_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._info_panel_border,
        )
        github_remote_card.grid(row=settings_row, column=0, columnspan=3, sticky="we", padx=14, pady=(4, 10))
        github_remote_card.grid_columnconfigure(1, weight=1)
        github_remote_card.grid_columnconfigure(3, weight=1)
        self._make_field_label(
            github_remote_card,
            text_key="github_owner",
            tooltip_key="github_owner",
        ).grid(row=0, column=0, sticky="w", padx=(12, 8), pady=(10, 4))
        github_owner_entry = ctk.CTkEntry(
            github_remote_card,
            textvariable=self.github_owner_var,
            height=32,
            corner_radius=8,
            placeholder_text=self._t("github_owner_placeholder"),
        )
        self._localize_widget(github_owner_entry, "placeholder_text", "github_owner_placeholder")
        self._bind_tooltip_key(github_owner_entry, "github_owner")
        github_owner_entry.grid(row=0, column=1, sticky="we", padx=(0, 12), pady=(10, 4))
        self._make_field_label(
            github_remote_card,
            text_key="remote_repo_filters",
            tooltip_key="github_repo_filters",
        ).grid(row=0, column=2, sticky="w", padx=(0, 8), pady=(10, 4))
        github_filter_entry = ctk.CTkEntry(
            github_remote_card,
            textvariable=self.github_repo_filters_var,
            height=32,
            corner_radius=8,
            placeholder_text=self._t("remote_repo_filters_placeholder"),
        )
        self._localize_widget(github_filter_entry, "placeholder_text", "remote_repo_filters_placeholder")
        self._bind_tooltip_key(github_filter_entry, "github_repo_filters")
        github_filter_entry.grid(row=0, column=3, sticky="we", padx=(0, 12), pady=(10, 4))
        self._make_field_label(
            github_remote_card,
            text_key="clone_workers",
            tooltip_key="github_clone_workers",
        ).grid(row=1, column=0, sticky="w", padx=(12, 8), pady=(4, 10))
        github_jobs_entry = ctk.CTkEntry(
            github_remote_card,
            textvariable=self.github_jobs_var,
            width=90,
            height=32,
            corner_radius=8,
        )
        self._bind_tooltip_key(github_jobs_entry, "github_clone_workers")
        github_jobs_entry.grid(row=1, column=1, sticky="w", padx=(0, 12), pady=(4, 10))
        github_include_forks_checkbox = ctk.CTkCheckBox(
            github_remote_card,
            text=self._t("include_forks"),
            variable=self.github_include_forks_var,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._localize_widget(github_include_forks_checkbox, "text", "include_forks")
        self._bind_tooltip_key(github_include_forks_checkbox, "github_include_forks")
        github_include_forks_checkbox.grid(row=1, column=2, sticky="w", padx=(0, 12), pady=(4, 10))
        github_fast_checkbox = ctk.CTkCheckBox(
            github_remote_card,
            text=self._t("fast_shallow_clone"),
            variable=self.github_fast_var,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._localize_widget(github_fast_checkbox, "text", "fast_shallow_clone")
        self._bind_tooltip_key(github_fast_checkbox, "github_fast")
        github_fast_checkbox.grid(row=1, column=3, sticky="w", padx=(0, 12), pady=(4, 10))

        settings_row += 1
        self._make_field_label(
            setup_settings_frame,
            text_key="max_findings",
            tooltip_key="max_findings",
        ).grid(row=settings_row, column=0, sticky="w", padx=(14, 8), pady=(4, 12))
        max_matches_entry = ctk.CTkEntry(
            setup_settings_frame,
            textvariable=self.max_matches_var,
            width=100,
            height=32,
            corner_radius=8,
        )
        self._bind_tooltip_key(max_matches_entry, "max_findings")
        max_matches_entry.grid(row=settings_row, column=1, sticky="w", pady=(4, 12))
        self._localize_widget(ctk.CTkLabel(
            setup_settings_frame,
            text=self._t("settings_persist_note"),
            justify="left",
            anchor="w",
            wraplength=760,
            font=self._font(11),
            text_color=self._text_muted,
        ), "text", "settings_persist_note").grid(row=settings_row + 1, column=0, columnspan=3, sticky="we", padx=14, pady=(0, 8))

        setup_actions = ctk.CTkFrame(setup_settings_frame, fg_color="transparent")
        setup_actions.grid(row=settings_row + 2, column=0, columnspan=3, sticky="we", padx=14, pady=(0, 10))
        setup_actions.grid_columnconfigure(0, weight=1)
        save_setup_button = ctk.CTkButton(
            setup_actions,
            text=self._t("save_setup"),
            command=self.save_setup_clicked,
            width=140,
            height=32,
            corner_radius=8,
            fg_color=self._support_button_fg,
            hover_color=self._support_button_hover,
        )
        self._localize_widget(save_setup_button, "text", "save_setup")
        self._bind_tooltip_key(save_setup_button, "save_setup")
        save_setup_button.grid(row=0, column=1, sticky="e")

        advanced_identity_row = ctk.CTkFrame(
            setup_settings_frame,
            fg_color=self._surface_alt,
            corner_radius=10,
            border_width=1,
            border_color=self._card_border,
        )
        advanced_identity_row.grid(row=settings_row + 3, column=0, columnspan=3, sticky="we", padx=14, pady=(0, 12))
        advanced_identity_row.grid_columnconfigure(0, weight=1)
        self._advanced_identity_hint_label = ctk.CTkLabel(
            advanced_identity_row,
            text=self._t("advanced_identity_hidden"),
            justify="left",
            anchor="w",
            wraplength=760,
            font=self._font(11),
            text_color=self._text_muted,
        )
        self._advanced_identity_hint_label.grid(row=0, column=0, sticky="we", padx=12, pady=10)
        self._advanced_identity_toggle_button = ctk.CTkButton(
            advanced_identity_row,
            text=self._t("show_advanced_identity"),
            command=self._toggle_advanced_identity_settings,
            width=230,
            height=32,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._bind_tooltip_key(self._advanced_identity_toggle_button, "advanced_identity")
        self._advanced_identity_toggle_button.grid(row=0, column=1, sticky="e", padx=(8, 12), pady=10)

        profile_card = ctk.CTkFrame(
            top_row,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        profile_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        profile_card.grid_columnconfigure(1, weight=1)
        self._profile_card = profile_card
        self._compact_top_layout = False

        self._localize_widget(ctk.CTkLabel(
            profile_card,
            text=self._t("owner_profile"),
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "owner_profile").grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(12, 8))
        self._localize_widget(ctk.CTkLabel(
            profile_card,
            text=self._t("owner_profile_body"),
            justify="left",
            anchor="w",
            wraplength=440,
            font=self._font(11),
            text_color=self._text_muted,
        ), "text", "owner_profile_body").grid(row=1, column=0, columnspan=2, sticky="we", padx=14, pady=(0, 6))

        row = 2
        self._make_field_label(profile_card, text_key="noreply_email", tooltip_key="noreply_email").grid(
            row=row,
            column=0,
            sticky="w",
            padx=(14, 8),
            pady=4,
        )
        noreply_entry = ctk.CTkEntry(profile_card, textvariable=self.noreply_var, height=32, corner_radius=8)
        self._bind_tooltip_key(noreply_entry, "noreply_email")
        noreply_entry.grid(
            row=row,
            column=1,
            sticky="we",
            padx=(0, 14),
            pady=4,
        )

        row += 1
        self._make_field_label(profile_card, text_key="placeholder_email", tooltip_key="placeholder_email").grid(
            row=row,
            column=0,
            sticky="w",
            padx=(14, 8),
            pady=4,
        )
        placeholder_entry = ctk.CTkEntry(profile_card, textvariable=self.placeholder_var, height=32, corner_radius=8)
        self._bind_tooltip_key(placeholder_entry, "placeholder_email")
        placeholder_entry.grid(
            row=row,
            column=1,
            sticky="we",
            padx=(0, 14),
            pady=4,
        )

        row += 1
        self._make_field_label(profile_card, text_key="owner_name", tooltip_key="owner_name").grid(
            row=row,
            column=0,
            sticky="w",
            padx=(14, 8),
            pady=4,
        )
        owner_name_entry = ctk.CTkEntry(profile_card, textvariable=self.owner_name_var, height=32, corner_radius=8)
        self._bind_tooltip_key(owner_name_entry, "owner_name")
        owner_name_entry.grid(
            row=row,
            column=1,
            sticky="we",
            padx=(0, 14),
            pady=4,
        )

        row += 1
        self._make_field_label(
            profile_card,
            text_key="private_emails_to_replace",
            tooltip_key="owner_emails",
        ).grid(row=row, column=0, sticky="w", padx=(14, 8), pady=(4, 12))
        owner_emails_entry = ctk.CTkEntry(profile_card, textvariable=self.owner_emails_var, height=32, corner_radius=8)
        self._bind_tooltip_key(owner_emails_entry, "owner_emails")
        owner_emails_entry.grid(
            row=row,
            column=1,
            sticky="we",
            padx=(0, 14),
            pady=(4, 12),
        )

        identity_card = ctk.CTkFrame(
            audit_tab,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        identity_card.grid(row=1, column=0, sticky="we", padx=10, pady=(10, 8))
        identity_card.grid_columnconfigure(1, weight=1)
        self._localize_widget(ctk.CTkLabel(
            identity_card,
            text=self._t("optional_git_identity"),
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "optional_git_identity").grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(12, 8))

        self._make_field_label(identity_card, text_key="git_user_name", tooltip_key="git_user_name").grid(
            row=1,
            column=0,
            sticky="w",
            padx=(14, 8),
            pady=4,
        )
        git_user_name_entry = ctk.CTkEntry(identity_card, textvariable=self.git_user_name_var, height=32, corner_radius=8)
        self._bind_tooltip_key(git_user_name_entry, "git_user_name")
        git_user_name_entry.grid(
            row=1,
            column=1,
            sticky="we",
            padx=(0, 14),
            pady=4,
        )

        self._make_field_label(
            identity_card,
            text_key="git_user_email",
            tooltip_key="git_user_email",
        ).grid(row=2, column=0, sticky="w", padx=(14, 8), pady=4)
        git_user_email_entry = ctk.CTkEntry(
            identity_card,
            textvariable=self.git_user_email_var,
            height=32,
            corner_radius=8,
        )
        self._bind_tooltip_key(git_user_email_entry, "git_user_email")
        git_user_email_entry.grid(
            row=2,
            column=1,
            sticky="we",
            padx=(0, 14),
            pady=4,
        )

        identity_actions = ctk.CTkFrame(identity_card, fg_color="transparent")
        identity_actions.grid(row=3, column=0, columnspan=2, sticky="we", padx=14, pady=(8, 4))
        identity_actions.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self._identity_actions = identity_actions
        identity_primary_global = ctk.CTkButton(
            identity_actions,
            text=self._t("apply_global_git_config"),
            command=self.apply_git_identity_global_clicked,
            height=32,
            corner_radius=8,
            fg_color=self._support_button_fg,
            hover_color=self._support_button_hover,
        )
        self._localize_widget(identity_primary_global, "text", "apply_global_git_config")
        self._bind_tooltip_key(identity_primary_global, "apply_global_git_config")
        identity_primary_global.grid(row=0, column=0, sticky="we", padx=(0, 6), pady=3)
        identity_primary_local = ctk.CTkButton(
            identity_actions,
            text=self._t("apply_local_git_config"),
            command=self.apply_git_identity_local_clicked,
            height=32,
            corner_radius=8,
            fg_color=self._support_button_fg,
            hover_color=self._support_button_hover,
        )
        self._localize_widget(identity_primary_local, "text", "apply_local_git_config")
        self._bind_tooltip_key(identity_primary_local, "apply_local_git_config")
        identity_primary_local.grid(row=0, column=1, sticky="we", padx=(6, 6), pady=3)
        identity_secondary_read = ctk.CTkButton(
            identity_actions,
            text=self._t("read_current_git_identity"),
            command=self.read_git_identity_clicked,
            height=32,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._localize_widget(identity_secondary_read, "text", "read_current_git_identity")
        self._bind_tooltip_key(identity_secondary_read, "read_current_git_identity")
        identity_secondary_read.grid(row=0, column=2, sticky="we", padx=(6, 6), pady=3)
        identity_secondary_settings = ctk.CTkButton(
            identity_actions,
            text=self._t("open_github_email_settings"),
            command=self.open_github_email_settings_clicked,
            height=32,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._localize_widget(identity_secondary_settings, "text", "open_github_email_settings")
        self._bind_tooltip_key(identity_secondary_settings, "open_github_email_settings")
        identity_secondary_settings.grid(row=0, column=3, sticky="we", padx=(6, 0), pady=3)
        self._identity_action_buttons = [
            identity_primary_global,
            identity_primary_local,
            identity_secondary_read,
            identity_secondary_settings,
        ]

        self._localize_widget(ctk.CTkLabel(
            identity_card,
            text=self._t("identity_help"),
            justify="left",
            anchor="w",
            wraplength=1200,
            font=self._font(12),
            text_color=self._text_body,
        ), "text", "identity_help").grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="we",
            padx=14,
            pady=(8, 12),
        )
        self._identity_card = identity_card
        self._set_advanced_identity_visibility(False)
        self._set_setup_settings_visibility(self._setup_settings_visible)

        self._build_reports_tab(reports_tab)
        self._build_prompts_tab(prompts_tab)

        repair_options_toggle = ctk.CTkFrame(
            repair_tab,
            fg_color=self._warning_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._warning_panel_border,
        )
        repair_options_toggle.grid(row=0, column=0, sticky="we", padx=10, pady=(8, 8))
        repair_options_toggle.grid_columnconfigure(0, weight=1)
        self._repair_options_hint_label = ctk.CTkLabel(
            repair_options_toggle,
            text=self._t("repair_advanced_hint_hidden"),
            justify="left",
            anchor="w",
            wraplength=860,
            font=self._font(11),
            text_color=self._warning_text,
        )
        self._localize_widget(self._repair_options_hint_label, "text", "repair_advanced_hint_hidden")
        self._repair_options_hint_label.grid(row=0, column=0, sticky="we", padx=12, pady=10)
        self._repair_options_toggle_button = ctk.CTkButton(
            repair_options_toggle,
            text=self._t("repair_advanced_toggle_show"),
            command=self._toggle_repair_options,
            width=230,
            height=32,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._bind_tooltip_key(self._repair_options_toggle_button, "repair_options_toggle")
        self._repair_options_toggle_button.grid(row=0, column=1, sticky="e", padx=(10, 12), pady=10)

        options_card = ctk.CTkFrame(
            repair_tab,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        options_card.grid(row=1, column=0, sticky="we", padx=10, pady=(0, 8))
        options_card.grid_columnconfigure(0, weight=1)
        options_card.grid_columnconfigure(1, weight=1)
        self._options_card = options_card
        self._repair_options_card = options_card
        self._localize_widget(ctk.CTkLabel(
            options_card,
            text=self._t("repair_plan_options"),
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "repair_plan_options").grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(12, 8))

        safe_options = ctk.CTkFrame(
            options_card,
            fg_color=self._success_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._success_panel_border,
        )
        safe_options.grid(row=1, column=0, sticky="nsew", padx=(14, 7), pady=(0, 12))
        safe_options.grid_columnconfigure(0, weight=1)
        safe_options.grid_columnconfigure(1, weight=0)
        self._safe_options_card = safe_options
        self._localize_widget(ctk.CTkLabel(
            safe_options,
            text=self._t("review_output_options"),
            font=self._font(13, bold=True),
            text_color=self._success_text,
        ), "text", "review_output_options").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        self._make_info_badge(
            safe_options,
            lambda: self._t("review_output_info"),
        ).grid(row=0, column=1, sticky="e", padx=(0, 12), pady=(10, 2))

        safe_items = [
            ("only_audit_public_remotes", self.public_only_var, "public_only"),
            ("redact_third_party_emails", self.redact_var, "redact_third_party_emails"),
            ("low_confidence_blocking", self.low_confidence_blocking_var, "low_confidence_blocking"),
            ("dry_run_preview", self.dry_run_var, "dry_run_preview"),
            ("audit_github_hardening", self.audit_github_hardening_var, "audit_github_hardening"),
            ("audit_litellm_incident", self.audit_litellm_incident_var, "audit_litellm_incident"),
            ("open_html_report", self.open_report_var, "open_html_report"),
            ("confirm_each_repo_fix", self.confirm_each_repo_fix_var, "confirm_each_repo_fix"),
        ]
        for idx, (label_key, var, tooltip_key) in enumerate(safe_items, start=1):
            checkbox = ctk.CTkCheckBox(
                safe_options,
                text=self._t(label_key),
                variable=var,
                font=self._font(12),
                text_color=self._text_body,
            )
            self._localize_widget(checkbox, "text", label_key)
            self._bind_tooltip_key(checkbox, tooltip_key)
            checkbox.grid(row=idx, column=0, sticky="w", padx=12, pady=4)
            self._make_info_badge_for(safe_options, tooltip_key).grid(row=idx, column=1, sticky="e", padx=(0, 12))

        destructive_options = ctk.CTkFrame(
            options_card,
            fg_color=self._warning_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._warning_panel_border,
        )
        destructive_options.grid(row=1, column=1, sticky="nsew", padx=(7, 14), pady=(0, 12))
        destructive_options.grid_columnconfigure(0, weight=1)
        destructive_options.grid_columnconfigure(1, weight=0)
        self._destructive_options_card = destructive_options
        self._compact_options_layout = False
        self._localize_widget(ctk.CTkLabel(
            destructive_options,
            text=self._t("repair_write_actions"),
            font=self._font(13, bold=True),
            text_color=self._warning_text,
        ), "text", "repair_write_actions").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))
        self._make_info_badge(
            destructive_options,
            lambda: self._t("repair_write_info"),
        ).grid(row=0, column=1, sticky="e", padx=(0, 12), pady=(10, 2))
        self._localize_widget(ctk.CTkLabel(
            destructive_options,
            text=self._t("repair_write_body"),
            font=self._font(11),
            text_color=self._warning_strong_text,
        ), "text", "repair_write_body").grid(row=1, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 8))

        self._rewrite_paths_checkbox = ctk.CTkCheckBox(
            destructive_options,
            text=self._t("rewrite_personal_paths"),
            variable=self.rewrite_personal_paths_var,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._localize_widget(self._rewrite_paths_checkbox, "text", "rewrite_personal_paths")
        self._bind_tooltip_key(self._rewrite_paths_checkbox, "rewrite_personal_paths")
        self._rewrite_paths_checkbox.grid(row=2, column=0, sticky="w", padx=12, pady=(0, 4))
        self._make_info_badge_for(destructive_options, "rewrite_personal_paths").grid(
            row=2,
            column=1,
            sticky="e",
            padx=(0, 12),
        )
        self._localize_widget(ctk.CTkLabel(
            destructive_options,
            text=self._t("rewrite_personal_paths_body"),
            font=self._font(11),
            text_color=self._warning_strong_text,
        ), "text", "rewrite_personal_paths_body").grid(row=3, column=0, columnspan=2, sticky="w", padx=36, pady=(0, 6))

        self._make_field_label(
            destructive_options,
            text_key="replace_text_rules",
            tooltip_key="replace_text_rules",
        ).grid(row=4, column=0, sticky="w", padx=12, pady=(4, 0))
        replace_text_row = ctk.CTkFrame(destructive_options, fg_color="transparent")
        replace_text_row.grid(row=5, column=0, columnspan=2, sticky="we", padx=12, pady=(2, 4))
        replace_text_row.grid_columnconfigure(0, weight=1)
        replace_text_entry = ctk.CTkEntry(
            replace_text_row,
            textvariable=self.replace_text_file_var,
            height=32,
            corner_radius=8,
        )
        self._bind_tooltip_key(replace_text_entry, "replace_text_rules")
        replace_text_entry.grid(row=0, column=0, sticky="we", padx=(0, 8))
        replace_text_button = ctk.CTkButton(
            replace_text_row,
            text=self._t("browse"),
            width=92,
            height=32,
            corner_radius=8,
            **self._secondary_button_options(),
            command=lambda: self._browse_existing_file(
                self.replace_text_file_var,
                title=self._t("choose_replace_text_file"),
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            ),
        )
        self._localize_widget(replace_text_button, "text", "browse")
        self._bind_tooltip_key(replace_text_button, "replace_text_rules")
        replace_text_button.grid(row=0, column=1)
        self._localize_widget(ctk.CTkLabel(
            destructive_options,
            text=self._t("replace_text_rules_body"),
            font=self._font(11),
            text_color=self._warning_strong_text,
        ), "text", "replace_text_rules_body").grid(row=6, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 6))

        self._push_checkbox = ctk.CTkCheckBox(
            destructive_options,
            text=self._t("force_push"),
            variable=self.push_var,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._localize_widget(self._push_checkbox, "text", "force_push")
        self._bind_tooltip_key(self._push_checkbox, "force_push")
        self._push_checkbox.grid(row=7, column=0, sticky="w", padx=12, pady=(0, 4))
        self._make_info_badge_for(destructive_options, "force_push").grid(row=7, column=1, sticky="e", padx=(0, 12))

        self._allow_non_owner_push_checkbox = ctk.CTkCheckBox(
            destructive_options,
            text=self._t("bypass_remote_owner_guardrail"),
            variable=self.allow_non_owner_push_var,
            command=self._on_allow_non_owner_push_toggled,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._localize_widget(self._allow_non_owner_push_checkbox, "text", "bypass_remote_owner_guardrail")
        self._bind_tooltip_key(self._allow_non_owner_push_checkbox, "bypass_remote_owner_guardrail")
        self._allow_non_owner_push_checkbox.grid(row=8, column=0, sticky="w", padx=12, pady=4)
        self._make_info_badge_for(destructive_options, "bypass_remote_owner_guardrail").grid(
            row=8,
            column=1,
            sticky="e",
            padx=(0, 12),
        )

        self._make_field_label(
            destructive_options,
            text_key="allowed_remote_owners",
            tooltip_key="allowed_remote_owners",
        ).grid(row=9, column=0, sticky="w", padx=12, pady=(4, 0))
        self._allowed_remote_owner_entry = ctk.CTkEntry(
            destructive_options,
            textvariable=self.allowed_remote_owners_var,
            height=32,
            corner_radius=8,
        )
        self._bind_tooltip_key(self._allowed_remote_owner_entry, "allowed_remote_owners")
        self._allowed_remote_owner_entry.grid(
            row=10,
            column=0,
            columnspan=2,
            sticky="we",
            padx=12,
            pady=(2, 4),
        )
        self._localize_widget(ctk.CTkLabel(
            destructive_options,
            text=self._t("allowed_remote_owners_body"),
            font=self._font(11),
            text_color=self._warning_strong_text,
        ), "text", "allowed_remote_owners_body").grid(row=11, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 6))

        self._purge_safe_checkbox = ctk.CTkCheckBox(
            destructive_options,
            text=self._t("purge_safe_secret_files"),
            variable=self.purge_detected_secret_files_var,
            command=self._on_purge_safe_toggled,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._localize_widget(self._purge_safe_checkbox, "text", "purge_safe_secret_files")
        self._bind_tooltip_key(self._purge_safe_checkbox, "purge_safe_secret_files")
        self._purge_safe_checkbox.grid(row=12, column=0, sticky="w", padx=12, pady=(0, 4))
        self._make_info_badge_for(destructive_options, "purge_safe_secret_files").grid(
            row=12,
            column=1,
            sticky="e",
            padx=(0, 12),
        )

        self._purge_risky_checkbox = ctk.CTkCheckBox(
            destructive_options,
            text=self._t("purge_risky_secret_files"),
            variable=self.purge_all_detected_secret_files_var,
            command=self._on_purge_risky_toggled,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._localize_widget(self._purge_risky_checkbox, "text", "purge_risky_secret_files")
        self._bind_tooltip_key(self._purge_risky_checkbox, "purge_risky_secret_files")
        self._purge_risky_checkbox.grid(row=13, column=0, sticky="w", padx=12, pady=4)
        self._make_info_badge_for(destructive_options, "purge_risky_secret_files").grid(
            row=13,
            column=1,
            sticky="e",
            padx=(0, 12),
        )
        self._localize_widget(ctk.CTkLabel(
            destructive_options,
            text=self._t("purge_body"),
            font=self._font(11),
            text_color=self._warning_strong_text,
        ), "text", "purge_body").grid(row=14, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 10))
        self._sync_purge_mode_controls()
        self._sync_push_guardrail_controls()
        self._set_repair_options_visibility(False)

        repair_actions_card = ctk.CTkFrame(
            repair_tab,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        repair_actions_card.grid(row=2, column=0, sticky="we", padx=10, pady=(0, 8))
        repair_actions_card.grid_columnconfigure(0, weight=1)
        self._localize_widget(ctk.CTkLabel(
            repair_actions_card,
            text=self._t("repair_flow"),
            font=self._font(14, bold=True),
            text_color=self._warning_text,
        ), "text", "repair_flow").grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))
        self._repair_status_panel = ctk.CTkFrame(
            repair_actions_card,
            fg_color=self._success_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._success_panel_border,
        )
        self._repair_status_panel.grid(row=1, column=0, sticky="we", padx=14, pady=(0, 8))
        self._repair_status_panel.grid_columnconfigure(1, weight=1)
        self._repair_status_badge = ctk.CTkLabel(
            self._repair_status_panel,
            text=self._t("audit_required"),
            height=28,
            corner_radius=14,
            fg_color=self._success_badge_fg,
            text_color=self._success_text,
            font=self._font(11, bold=True),
            padx=12,
        )
        self._repair_status_badge.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 6))
        self._localize_widget(ctk.CTkLabel(
            self._repair_status_panel,
            text=self._t("latest_audit_summary"),
            font=self._font(12, bold=True),
            text_color=self._info_text,
        ), "text", "latest_audit_summary").grid(row=0, column=1, sticky="w", padx=(0, 12), pady=(10, 6))
        self._repair_status_label = ctk.CTkLabel(
            self._repair_status_panel,
            text=self._t("no_audit_results"),
            justify="left",
            anchor="w",
            wraplength=1080,
            font=self._font(12),
            text_color=self._text_muted,
        )
        self._repair_status_label.grid(row=1, column=0, columnspan=2, sticky="we", padx=12, pady=(0, 12))
        repair_controls = ctk.CTkFrame(repair_actions_card, fg_color="transparent")
        repair_controls.grid(row=2, column=0, sticky="we", padx=14, pady=(0, 10))
        repair_controls.grid_columnconfigure(1, weight=1)
        self._repair_button = ctk.CTkButton(
            repair_controls,
            text=self._repair_button_text,
            command=lambda: self.run_clicked(run_fix=True),
            width=280,
            height=34,
            corner_radius=8,
            fg_color="#B45309",
            hover_color="#92400E",
            **self._button_asset_options("icon-repair.png"),
        )
        self._bind_tooltip_key(self._repair_button, "repair_button")
        self._repair_button.grid(row=0, column=0, sticky="w")
        self._repair_gate_note_label = ctk.CTkLabel(
            repair_controls,
            text=self._t("repair_stays_disabled"),
            justify="left",
            anchor="w",
            font=self._font(11),
            text_color=self._text_muted,
        )
        self._repair_gate_note_label.grid(row=0, column=1, sticky="w", padx=(10, 0), pady=6)

        blocker_overlay = ctk.CTkFrame(
            repair_tab,
            fg_color=self._surface_alt,
            corner_radius=10,
            border_width=1,
            border_color=self._card_border,
        )
        blocker_overlay.grid_columnconfigure(0, weight=1)
        blocker_overlay.grid_rowconfigure(0, weight=1)
        self._repair_tab_block_overlay = blocker_overlay

        blocker_card = ctk.CTkFrame(
            blocker_overlay,
            fg_color=self._white_panel_fg,
            corner_radius=14,
            border_width=1,
            border_color=self._card_border,
        )
        blocker_card.grid(row=0, column=0, padx=28, pady=(16, 14), sticky="n")
        blocker_card.grid_columnconfigure(0, weight=1)
        self._repair_gate_visual_label = self._make_asset_label(
            blocker_card,
            "repair-gate.png",
            background=self._white_panel_fg,
        )
        if self._repair_gate_visual_label is not None:
            self._repair_gate_visual_label.grid(row=0, column=0, padx=24, pady=(10, 0), sticky="ew")
        self._localize_widget(ctk.CTkLabel(
            blocker_card,
            text=self._t("repair_tab_locked"),
            justify="center",
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "repair_tab_locked").grid(row=1, column=0, padx=24, pady=(6, 6), sticky="ew")
        self._repair_tab_block_label = ctk.CTkLabel(
            blocker_card,
            text="",
            justify="center",
            font=self._font(12, bold=True),
            text_color=self._text_heading,
            wraplength=620,
        )
        self._repair_tab_block_label.grid(row=2, column=0, padx=24, pady=(0, 6), sticky="ew")
        self._localize_widget(ctk.CTkLabel(
            blocker_card,
            text=self._t("before_repair"),
            justify="center",
            font=self._font(11, bold=True),
            text_color=self._text_muted,
        ), "text", "before_repair").grid(row=3, column=0, padx=24, pady=(0, 4), sticky="ew")
        step_texts = [
            "repair_lock_step_1",
            "repair_lock_step_2",
            "repair_lock_step_3",
        ]
        self._repair_tab_block_steps = []
        for idx, step_key in enumerate(step_texts, start=4):
            step_label = ctk.CTkLabel(
                blocker_card,
                text=self._t(step_key),
                justify="left",
                anchor="w",
                wraplength=620,
                font=self._font(11),
                text_color=self._text_body,
            )
            self._localize_widget(step_label, "text", step_key)
            step_label.grid(row=idx, column=0, padx=24, pady=1, sticky="ew")
            self._repair_tab_block_steps.append(step_label)
        self._localize_widget(ctk.CTkButton(
            blocker_card,
            text=self._t("go_to_audit"),
            command=lambda: self._set_active_flow_tab(self._audit_tab_name),
            width=170,
            height=32,
            corner_radius=8,
            fg_color=self._primary_button_fg,
            hover_color=self._primary_button_hover,
            **self._button_asset_options("icon-audit.png"),
        ), "text", "go_to_audit").grid(row=7, column=0, pady=(10, 14))

        results_row = ctk.CTkFrame(audit_tab, fg_color="transparent")
        results_row.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 14))
        results_row.grid_columnconfigure(0, weight=1)
        results_row.grid_columnconfigure(1, weight=1)
        results_row.grid_rowconfigure(0, weight=1)
        self._results_row = results_row

        repos_card = ctk.CTkFrame(
            results_row,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        repos_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=0)
        repos_card.grid_columnconfigure(0, weight=1)
        repos_card.grid_columnconfigure(1, weight=0)
        repos_card.grid_rowconfigure(2, weight=1)
        self._repos_card = repos_card
        repo_header = ctk.CTkFrame(repos_card, fg_color="transparent")
        repo_header.grid(row=0, column=0, columnspan=2, sticky="we", padx=14, pady=(12, 6))
        repo_header.grid_columnconfigure(0, weight=1)
        repo_header.grid_columnconfigure(1, weight=0)
        self._localize_widget(ctk.CTkLabel(
            repo_header,
            text=self._t("repositories"),
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "repositories").grid(row=0, column=0, sticky="w")
        repo_actions = ctk.CTkFrame(repo_header, fg_color="transparent")
        repo_actions.grid(row=0, column=1, sticky="e")
        self._audit_button = ctk.CTkButton(
            repo_actions,
            text=self._t("run_audit"),
            command=lambda: self.run_clicked(run_fix=False),
            width=130,
            height=34,
            corner_radius=8,
            fg_color=self._primary_button_fg,
            hover_color=self._primary_button_hover,
            **self._button_asset_options("icon-audit.png"),
        )
        self._bind_tooltip_key(self._audit_button, "run_audit")
        self._audit_button.pack(side="left", padx=(0, 8))
        self._cancel_button = ctk.CTkButton(
            repo_actions,
            text=self._t("stop_after_current_step"),
            command=self.cancel_run_clicked,
            width=172,
            height=34,
            corner_radius=8,
            **self._button_asset_options("icon-stop.png"),
            **self._secondary_button_options(),
        )
        self._bind_tooltip_key(self._cancel_button, "stop_after_current_step")
        self._cancel_button.pack(side="left", padx=(0, 8))
        self._refresh_button = ctk.CTkButton(
            repo_actions,
            text=self._t("refresh"),
            height=34,
            width=120,
            corner_radius=8,
            command=self.refresh_repos,
            **self._button_asset_options("icon-refresh.png"),
            **self._secondary_button_options(),
        )
        self._localize_widget(self._refresh_button, "text", "refresh")
        self._bind_tooltip_key(self._refresh_button, "refresh_repos")
        self._refresh_button.pack(side="left")
        self._repo_summary_label = ctk.CTkLabel(
            repos_card,
            text=self._t("repo_summary_default"),
            justify="left",
            anchor="w",
            font=self._font(11),
            text_color=self._text_muted,
        )
        self._repo_summary_label.grid(row=1, column=0, columnspan=2, sticky="we", padx=14, pady=(0, 8))

        list_shell = ctk.CTkFrame(
            repos_card,
            fg_color=self._white_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._card_border,
        )
        list_shell.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=14, pady=(0, 8))
        list_shell.grid_columnconfigure(0, weight=1)
        list_shell.grid_rowconfigure(1, weight=1)
        self._repo_drop_hint_label = ctk.CTkLabel(
            list_shell,
            text=self._t("repo_drop_hint"),
            justify="left",
            anchor="w",
            font=self._font(11),
            text_color=self._text_muted,
        )
        self._bind_tooltip_key(self._repo_drop_hint_label, "repo_drop_area")
        self._repo_drop_hint_label.grid(row=0, column=0, sticky="we", padx=10, pady=(8, 0))
        self._make_info_badge_for(list_shell, "repo_drop_area").grid(row=0, column=1, sticky="e", padx=(0, 10), pady=(8, 0))

        self.repo_list = tk.Listbox(
            list_shell,
            selectmode=tk.EXTENDED,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            activestyle="none",
            background=self._list_fg,
            foreground=self._list_text,
            selectbackground=self._primary_button_fg,
            selectforeground=self._list_select_text,
            font=self._font(11),
        )
        self._bind_tooltip_key(self.repo_list, "repo_drop_area")
        self.repo_list.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=10)
        repo_scroll = ctk.CTkScrollbar(
            list_shell,
            orientation="vertical",
            command=self.repo_list.yview,
            fg_color=self._scrollbar_track,
            button_color=self._scrollbar_thumb,
            button_hover_color=self._scrollbar_hover,
        )
        self._repo_scrollbar = repo_scroll
        repo_scroll.grid(row=1, column=1, sticky="ns", padx=(8, 10), pady=10)
        self.repo_list.configure(yscrollcommand=repo_scroll.set)
        self.repo_list.bind("<<ListboxSelect>>", self._on_repo_selection_changed)
        self._enable_repo_drag_and_drop(list_shell, self.repo_list)
        self._repo_empty_state = ctk.CTkFrame(
            list_shell,
            fg_color=self._surface_alt,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        self._repo_empty_state.grid_columnconfigure(0, weight=1)
        self._repo_empty_state_visual_label = self._make_asset_label(
            self._repo_empty_state,
            "repo-dropzone.png",
            background=self._surface_alt,
        )
        if self._repo_empty_state_visual_label is not None:
            self._repo_empty_state_visual_label.grid(row=0, column=0, padx=18, pady=(14, 2), sticky="ew")
        self._repo_empty_state_title_label = ctk.CTkLabel(
            self._repo_empty_state,
            text=self._t("repo_targets_unavailable"),
            justify="center",
            anchor="center",
            font=self._font(14, bold=True),
            text_color=self._text_heading,
        )
        self._repo_empty_state_title_label.grid(row=1, column=0, padx=18, pady=(6, 4), sticky="ew")
        self._repo_empty_state_body_label = ctk.CTkLabel(
            self._repo_empty_state,
            text=self._t("choose_valid_root"),
            justify="center",
            anchor="center",
            font=self._font(12),
            text_color=self._text_muted,
            wraplength=420,
        )
        self._repo_empty_state_body_label.grid(row=2, column=0, padx=18, pady=(0, 6), sticky="ew")
        self._repo_empty_state_hint_label = ctk.CTkLabel(
            self._repo_empty_state,
            text=self._t("run_audit_available_hint"),
            justify="center",
            anchor="center",
            font=self._font(11),
            text_color=self._text_muted,
            wraplength=420,
        )
        self._repo_empty_state_hint_label.grid(row=3, column=0, padx=18, pady=(0, 16), sticky="ew")

        run_controls = ctk.CTkFrame(repos_card, fg_color="transparent")
        run_controls.grid(row=3, column=0, columnspan=2, sticky="w", padx=14, pady=(4, 12))
        self._select_all_button = ctk.CTkButton(
            run_controls,
            text=self._t("select_all"),
            command=self.select_all,
            width=120,
            height=34,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._localize_widget(self._select_all_button, "text", "select_all")
        self._bind_tooltip_key(self._select_all_button, "select_all_repos")
        self._select_all_button.pack(side="left", padx=8)
        self._clear_selection_button = ctk.CTkButton(
            run_controls,
            text=self._t("clear_selection"),
            command=self.clear_selection,
            width=120,
            height=34,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._localize_widget(self._clear_selection_button, "text", "clear_selection")
        self._bind_tooltip_key(self._clear_selection_button, "clear_selection")
        self._clear_selection_button.pack(side="left", padx=8)
        clear_log_button = ctk.CTkButton(
            run_controls,
            text=self._t("clear_log"),
            command=self.clear_output,
            width=120,
            height=34,
            corner_radius=8,
            **self._secondary_button_options(),
        )
        self._localize_widget(clear_log_button, "text", "clear_log")
        self._bind_tooltip_key(clear_log_button, "clear_log")
        clear_log_button.pack(side="left", padx=8)

        output_card = ctk.CTkFrame(
            results_row,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        output_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=0)
        output_card.grid_columnconfigure(0, weight=1)
        output_card.grid_rowconfigure(1, weight=1)
        self._output_card = output_card
        self._localize_widget(ctk.CTkLabel(
            output_card,
            text=self._t("execution_log"),
            font=self._font(16, bold=True),
            text_color=self._text_heading,
        ), "text", "execution_log").grid(row=0, column=0, sticky="w", padx=14, pady=(12, 8))
        self.output = ctk.CTkTextbox(
            output_card,
            fg_color=self._output_fg,
            text_color=self._output_text,
            corner_radius=10,
            border_width=0,
            wrap="word",
            font=self._font(10, mono=True),
        )
        self.output.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 12))
        self._output_empty_state_label = ctk.CTkLabel(
            output_card,
            text=self._t("execution_log_empty"),
            justify="center",
            anchor="center",
            wraplength=520,
            font=self._font(11),
            text_color=self._output_empty_text,
            fg_color=self._output_fg,
        )
        self._localize_widget(self._output_empty_state_label, "text", "execution_log_empty")
        self._set_output_empty_state(True)

        self.refresh_repos()
        self.root.bind("<Configure>", self._on_root_resize)
        self.root.after(0, self._apply_responsive_layout)
        self._lock_repair_until_next_audit()
        self._set_active_flow_tab(self._audit_tab_name)

    def _current_appearance(self) -> str:
        return normalize_gui_appearance(getattr(self, "_gui_appearance", GUI_APPEARANCE_DEFAULT))

    def _ensure_gui_theme_palette(self) -> None:
        if not hasattr(self, "_text_muted"):
            self._configure_gui_theme_palette()

    def _configure_gui_theme_palette(self) -> None:
        if self._current_appearance() == GUI_APPEARANCE_DARK:
            self._page_bg = "#0F1D22"
            self._surface_fg = "#15272D"
            self._surface_alt = "#102026"
            self._card_border = "#2E4A4F"
            self._text_heading = "#E8F5F2"
            self._text_body = "#D2E2DE"
            self._text_muted = "#98ADA9"
            self._header_fg = "#082F31"
            self._header_chip_fg = "#123F41"
            self._header_chip_border = "#2B6D69"
            self._header_chip_text = "#D8FFF3"
            self._primary_button_fg = "#14A096"
            self._primary_button_hover = "#0D7F78"
            self._support_button_fg = "#2D4250"
            self._support_button_hover = "#243541"
            self._secondary_button_fg = "#1B3036"
            self._secondary_button_hover = "#223D43"
            self._secondary_button_border = "#4B6A6E"
            self._secondary_button_text = "#E7F4F0"
            self._disabled_button_fg = "#3A4D55"
            self._disabled_button_text = "#A1B3B8"
            self._tabview_fg = "#112329"
            self._tab_segment_fg = "#263C42"
            self._tab_selected_fg = "#145C55"
            self._tab_selected_hover = "#1A7169"
            self._tab_unselected_fg = "#1A2F35"
            self._tab_unselected_hover = "#263C42"
            self._success_panel_fg = "#12342F"
            self._success_panel_border = "#2A6B5F"
            self._success_badge_fg = "#174B43"
            self._success_text = "#9BE9D7"
            self._pass_badge_fg = "#173F2E"
            self._pass_badge_text = "#86EFAC"
            self._info_panel_fg = "#122D3A"
            self._info_panel_border = "#315D76"
            self._info_text = "#B8D8EA"
            self._warning_panel_fg = "#3A2814"
            self._warning_panel_border = "#8A5A24"
            self._warning_text = "#F3C98B"
            self._warning_strong_text = "#F8D6A3"
            self._warning_badge_fg = "#4A3418"
            self._warning_badge_text = "#F8D6A3"
            self._repair_warning_badge_fg = "#5A3B1A"
            self._danger_text = "#F2A3A3"
            self._failure_badge_fg = "#4C1D1D"
            self._failure_badge_text = "#FCA5A5"
            self._white_panel_fg = "#172A30"
            self._white_panel_border = "#35545A"
            self._list_fg = "#0F1E24"
            self._list_text = "#E8F5F2"
            self._list_select_text = "#F8FAFC"
            self._output_fg = "#071116"
            self._output_text = "#DDEDEA"
            self._output_empty_text = "#789097"
            self._scrollbar_track = "#0F1D22"
            self._scrollbar_thumb = "#3A5960"
            self._scrollbar_hover = "#4C747B"
            return

        self._page_bg = "#EEF5F2"
        self._surface_fg = "#FBFEFC"
        self._surface_alt = "#F5FAF8"
        self._card_border = "#CFE0DA"
        self._text_heading = "#0B2F32"
        self._text_body = "#132F36"
        self._text_muted = "#526A70"
        self._header_fg = "#0B3D3F"
        self._header_chip_fg = "#144F4E"
        self._header_chip_border = "#2E7D75"
        self._header_chip_text = "#D8FFF3"
        self._primary_button_fg = "#0F766E"
        self._primary_button_hover = "#0B5F59"
        self._support_button_fg = "#334155"
        self._support_button_hover = "#1E293B"
        self._secondary_button_fg = "#F8FAFC"
        self._secondary_button_hover = "#E6F0EF"
        self._secondary_button_border = "#9AB6B2"
        self._secondary_button_text = "#123C3F"
        self._disabled_button_fg = "#B8C6D5"
        self._disabled_button_text = "#64748B"
        self._tabview_fg = "#F6FBF8"
        self._tab_segment_fg = "#DDEBE7"
        self._tab_selected_fg = "#D8F3EA"
        self._tab_selected_hover = "#C6E8DE"
        self._tab_unselected_fg = "#EEF5F2"
        self._tab_unselected_hover = "#DDEBE7"
        self._success_panel_fg = "#F2FBF8"
        self._success_panel_border = "#B9DDD3"
        self._success_badge_fg = "#D8F3EA"
        self._success_text = "#0F766E"
        self._pass_badge_fg = "#DCFCE7"
        self._pass_badge_text = "#166534"
        self._info_panel_fg = "#F6FAFE"
        self._info_panel_border = "#C9DDEE"
        self._info_text = "#173A5E"
        self._warning_panel_fg = "#FFF7ED"
        self._warning_panel_border = "#F5C58B"
        self._warning_text = "#7A3E05"
        self._warning_strong_text = "#8A4B10"
        self._warning_badge_fg = "#FEF3C7"
        self._warning_badge_text = "#92400E"
        self._repair_warning_badge_fg = "#FBD7A2"
        self._danger_text = "#7B1E1E"
        self._failure_badge_fg = "#FEE2E2"
        self._failure_badge_text = "#991B1B"
        self._white_panel_fg = "#FFFFFF"
        self._white_panel_border = self._card_border
        self._list_fg = "#FFFFFF"
        self._list_text = "#0F172A"
        self._list_select_text = "#F8FAFC"
        self._output_fg = "#0B1720"
        self._output_text = "#DDEDEA"
        self._output_empty_text = "#7F939C"
        self._scrollbar_track = "#EEF5F2"
        self._scrollbar_thumb = "#BCD2CD"
        self._scrollbar_hover = "#8EAEA8"

    def _font(self, size: int, *, bold: bool = False, mono: bool = False):
        family = self._mono_font_family if mono else self._ui_font_family
        return (family, size, "bold") if bold else (family, size)

    def _load_gui_assets(self) -> dict[str, object]:
        images: dict[str, object] = {}
        for filename in GUI_ASSET_FILENAMES:
            asset_path = gui_asset_path(filename)
            if asset_path is None:
                continue
            try:
                images[filename] = self.tk.PhotoImage(file=str(asset_path))
            except Exception:
                continue
        return images

    def _load_gui_button_assets(self) -> dict[str, object]:
        ctk_image = getattr(self.ctk, "CTkImage", None)
        if ctk_image is None:
            return {}

        try:
            from PIL import Image, ImageColor
        except Exception:
            return {}

        images: dict[str, object] = {}
        dark_icon_color = "#E7F4F0"
        for filename in GUI_ASSET_FILENAMES:
            if not filename.startswith("icon-"):
                continue
            asset_path = gui_asset_path(filename)
            if asset_path is None:
                continue
            try:
                with Image.open(asset_path) as source:
                    image = source.convert("RGBA").copy()
                dark_image = self._tint_gui_icon(image, ImageColor.getrgb(dark_icon_color))
                images[filename] = ctk_image(light_image=image, dark_image=dark_image, size=(24, 24))
            except Exception:
                continue
        return images

    def _tint_gui_icon(self, image, color: tuple[int, int, int]):
        try:
            from PIL import Image, ImageChops
        except Exception:
            return image

        source = image.convert("RGBA")
        luminance = source.convert("L")
        darkness_mask = Image.eval(luminance, lambda pixel: 255 - pixel)
        alpha_mask = ImageChops.multiply(darkness_mask, source.getchannel("A"))
        tinted = Image.new("RGBA", image.size, color + (0,))
        tinted.putalpha(alpha_mask)
        return tinted

    def _asset_image(self, filename: str, *, background: str | None = None):
        if (
            background
            and self._current_appearance() == GUI_APPEARANCE_DARK
            and filename in GUI_THEMEABLE_ASSET_FILENAMES
        ):
            cache_key = (filename, self._current_appearance(), background)
            cached_image = self._gui_themed_asset_images.get(cache_key)
            if cached_image is not None:
                return cached_image
            background_rgb = parse_hex_rgb(background)
            asset_path = gui_asset_path(filename)
            if background_rgb is not None and asset_path is not None:
                try:
                    from PIL import Image, ImageTk

                    with Image.open(asset_path) as source:
                        themed_source = blend_near_white_gui_asset_background(source, background_rgb)
                    themed_image = ImageTk.PhotoImage(themed_source)
                    self._gui_themed_asset_images[cache_key] = themed_image
                    return themed_image
                except Exception:
                    pass
        return self._gui_asset_images.get(filename)

    def _set_window_icon(self) -> None:
        icon = self._asset_image("app-icon.png")
        if icon is None:
            return
        try:
            self.root.iconphoto(True, icon)
        except Exception:
            pass

    def _make_asset_label(
        self,
        parent: object,
        filename: str,
        *,
        background: str,
    ):
        image = self._asset_image(filename, background=background)
        if image is None:
            return None
        return self.tk.Label(
            parent,
            image=image,
            background=background,
            borderwidth=0,
            highlightthickness=0,
            padx=0,
            pady=0,
        )

    def _button_asset_options(self, filename: str) -> dict[str, object]:
        image = self._gui_button_asset_images.get(filename)
        if image is None:
            return {}
        return {"image": image, "compound": "left"}

    def _secondary_button_options(self) -> dict[str, object]:
        return {
            "fg_color": self._secondary_button_fg,
            "hover_color": self._secondary_button_hover,
            "border_width": 1,
            "border_color": self._secondary_button_border,
            "text_color": self._secondary_button_text,
        }

    def _build_reports_tab(self, reports_tab) -> None:
        ctk = self.ctk
        reports_card = ctk.CTkFrame(
            reports_tab,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        reports_card.grid(row=0, column=0, sticky="we", padx=10, pady=(8, 8))
        reports_card.grid_columnconfigure(0, weight=1)
        reports_card.grid_columnconfigure(1, weight=0)
        self._localize_widget(ctk.CTkLabel(
            reports_card,
            text=self._t("reports_dashboard"),
            font=self._font(18, bold=True),
            text_color=self._text_heading,
        ), "text", "reports_dashboard").grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        self._localize_widget(ctk.CTkLabel(
            reports_card,
            text=self._t("reports_dashboard_body"),
            justify="left",
            anchor="w",
            wraplength=1120,
            font=self._font(12),
            text_color=self._text_muted,
        ), "text", "reports_dashboard_body").grid(row=1, column=0, sticky="we", padx=14, pady=(0, 10))
        self._reports_visual_label = self._make_asset_label(
            reports_card,
            "reports-evidence.png",
            background=self._surface_fg,
        )
        if self._reports_visual_label is not None:
            self._reports_visual_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=(8, 14), pady=(10, 4))

        status_row = ctk.CTkFrame(
            reports_card,
            fg_color=self._success_panel_fg,
            corner_radius=10,
            border_width=1,
            border_color=self._success_panel_border,
        )
        status_row.grid(row=2, column=0, columnspan=2, sticky="we", padx=14, pady=(0, 10))
        status_row.grid_columnconfigure(1, weight=1)
        self._reports_status_badge = ctk.CTkLabel(
            status_row,
            text=self._t("last_run"),
            height=28,
            corner_radius=14,
            fg_color=self._success_badge_fg,
            text_color=self._success_text,
            font=self._font(11, bold=True),
            padx=12,
        )
        self._reports_status_badge.grid(row=0, column=0, sticky="w", padx=12, pady=(10, 6))
        self._localize_widget(ctk.CTkLabel(
            status_row,
            text=self._t("latest_artifacts"),
            font=self._font(12, bold=True),
            text_color=self._text_heading,
        ), "text", "latest_artifacts").grid(row=0, column=1, sticky="w", padx=(0, 12), pady=(10, 6))
        self._reports_summary_label = ctk.CTkLabel(
            status_row,
            text=self._t("last_run_none"),
            justify="left",
            anchor="w",
            wraplength=980,
            font=self._font(12),
            text_color=self._text_body,
        )
        self._reports_summary_label.grid(row=1, column=0, columnspan=2, sticky="we", padx=12, pady=(0, 8))
        self._reports_paths_label = ctk.CTkLabel(
            status_row,
            text=self._t("latest_artifacts_none"),
            justify="left",
            anchor="w",
            wraplength=980,
            font=self._font(11, mono=True),
            text_color=self._text_muted,
        )
        self._reports_paths_label.grid(row=2, column=0, columnspan=2, sticky="we", padx=12, pady=(0, 12))

        actions = ctk.CTkFrame(reports_card, fg_color="transparent")
        actions.grid(row=3, column=0, columnspan=2, sticky="w", padx=14, pady=(0, 12))
        report_actions = [
            ("open_html_report_action", "icon-report.png", lambda: self._open_last_artifact("html")),
            ("open_json_report_action", "icon-report.png", lambda: self._open_last_artifact("json")),
            ("open_run_log_action", "icon-open.png", lambda: self._open_last_artifact("log")),
            ("open_artifacts_folder_action", "icon-folder.png", lambda: self._open_last_artifact("folder")),
        ]
        self._reports_action_buttons = []
        for idx, (text_key, icon_filename, command) in enumerate(report_actions):
            button = ctk.CTkButton(
                actions,
                text=self._t(text_key),
                command=command,
                height=32,
                corner_radius=8,
                **self._button_asset_options(icon_filename),
                **self._secondary_button_options(),
            )
            self._localize_widget(button, "text", text_key)
            self._bind_tooltip_key(button, "reports_tab")
            button.grid(row=0, column=idx, sticky="w", padx=(0, 8))
            self._reports_action_buttons.append(button)
        self._refresh_reports_tab()

    def _build_prompts_tab(self, prompts_tab) -> None:
        ctk = self.ctk
        prompts_card = ctk.CTkFrame(
            prompts_tab,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        prompts_card.grid(row=0, column=0, sticky="we", padx=10, pady=(8, 8))
        prompts_card.grid_columnconfigure(0, weight=1)
        prompts_card.grid_columnconfigure(1, weight=0)
        self._localize_widget(ctk.CTkLabel(
            prompts_card,
            text=self._t("prompts_library"),
            font=self._font(18, bold=True),
            text_color=self._text_heading,
        ), "text", "prompts_library").grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        self._localize_widget(ctk.CTkLabel(
            prompts_card,
            text=self._t("prompts_library_body"),
            justify="left",
            anchor="w",
            wraplength=1120,
            font=self._font(12),
            text_color=self._text_muted,
        ), "text", "prompts_library_body").grid(row=1, column=0, sticky="we", padx=14, pady=(0, 10))
        self._prompts_visual_label = self._make_asset_label(
            prompts_card,
            "prompts-workflow.png",
            background=self._surface_fg,
        )
        if self._prompts_visual_label is not None:
            self._prompts_visual_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=(8, 14), pady=(10, 4))
        self._prompt_cards_frame = ctk.CTkFrame(prompts_card, fg_color="transparent")
        self._prompt_cards_frame.grid(row=2, column=0, columnspan=2, sticky="we", padx=14, pady=(0, 12))
        self._prompt_cards_frame.grid_columnconfigure((0, 1), weight=1)
        self._refresh_prompt_cards()

    def _refresh_prompt_cards(self) -> None:
        cards_frame = getattr(self, "_prompt_cards_frame", None)
        if cards_frame is None:
            return
        for child in cards_frame.winfo_children():
            child.destroy()

        repo_root = Path(__file__).resolve().parent
        for idx, prompt in enumerate(prompt_helpers.agentic_prompt_cards(self._current_locale())):
            row = idx // 2
            column = idx % 2
            card = self.ctk.CTkFrame(
                cards_frame,
                fg_color=self._surface_alt,
                corner_radius=10,
                border_width=1,
                border_color=self._card_border,
            )
            card.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 8 if column == 0 else 0), pady=(0, 8))
            card.grid_columnconfigure(0, weight=1)
            self.ctk.CTkLabel(
                card,
                text=prompt.title,
                font=self._font(14, bold=True),
                text_color=self._text_heading,
                anchor="w",
                justify="left",
            ).grid(row=0, column=0, sticky="we", padx=12, pady=(10, 2))
            self.ctk.CTkLabel(
                card,
                text=prompt.description,
                font=self._font(11),
                text_color=self._text_muted,
                anchor="w",
                justify="left",
                wraplength=500,
            ).grid(row=1, column=0, sticky="we", padx=12, pady=(0, 8))
            self.ctk.CTkLabel(
                card,
                text=f"{self._t('prompt_command')}: {prompt.command}",
                font=self._font(10, mono=True),
                text_color=self._text_body,
                anchor="w",
                justify="left",
                wraplength=520,
            ).grid(row=2, column=0, sticky="we", padx=12, pady=(0, 8))

            actions = self.ctk.CTkFrame(card, fg_color="transparent")
            actions.grid(row=3, column=0, sticky="w", padx=12, pady=(0, 12))
            copy_prompt_button = self.ctk.CTkButton(
                actions,
                text=self._t("copy_prompt"),
                command=lambda item=prompt: self._copy_prompt_to_clipboard(item),
                height=30,
                corner_radius=8,
                fg_color=self._primary_button_fg,
                hover_color=self._primary_button_hover,
                **self._button_asset_options("icon-copy.png"),
            )
            self._bind_tooltip_key(copy_prompt_button, "copy_prompt")
            copy_prompt_button.grid(row=0, column=0, sticky="w", padx=(0, 8))
            copy_command_button = self.ctk.CTkButton(
                actions,
                text=self._t("copy_command"),
                command=lambda item=prompt: self._copy_text_to_clipboard(item.command, self._t("prompt_command_copied")),
                height=30,
                corner_radius=8,
                **self._button_asset_options("icon-copy.png"),
                **self._secondary_button_options(),
            )
            self._bind_tooltip_key(copy_command_button, "copy_prompt_command")
            copy_command_button.grid(row=0, column=1, sticky="w", padx=(0, 8))
            open_prompt_button = self.ctk.CTkButton(
                actions,
                text=self._t("open_prompt"),
                command=lambda item=prompt: self._open_prompt_file(item, repo_root),
                height=30,
                corner_radius=8,
                **self._button_asset_options("icon-open.png"),
                **self._secondary_button_options(),
            )
            self._bind_tooltip_key(open_prompt_button, "open_prompt_file")
            open_prompt_button.grid(row=0, column=2, sticky="w")

    def _copy_text_to_clipboard(self, text: str, success_message: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
            self.log(f"[INFO] {success_message}")
        except Exception as exc:
            self.log(f"[WARN] Clipboard copy failed: {exc}")

    def _copy_prompt_to_clipboard(self, prompt: prompt_helpers.AgenticPrompt) -> None:
        repo_root = Path(__file__).resolve().parent
        try:
            text = prompt_helpers.read_prompt_text(prompt, repo_root)
        except Exception as exc:
            self.log(f"[WARN] Unable to read prompt file: {exc}")
            return
        self._copy_text_to_clipboard(text, self._t("prompt_copied"))

    def _open_prompt_file(self, prompt: prompt_helpers.AgenticPrompt, repo_root: Path) -> None:
        try:
            self._open_local_path(prompt.path(repo_root))
        except Exception as exc:
            self.log(f"[WARN] {self._t('prompt_open_failed', error=exc)}")

    def _open_local_path(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(path)
        opened = bool(webbrowser.open(path.resolve().as_uri()))
        if not opened:
            raise RuntimeError(f"local opener returned false for {path}")

    def _open_last_artifact(self, kind: str) -> None:
        artifacts = getattr(self, "_last_run_artifacts", None)
        if artifacts is None:
            self.log(f"[INFO] {self._t('latest_artifacts_none')}")
            return
        targets = {
            "html": artifacts.html_path,
            "json": artifacts.json_path,
            "log": artifacts.log_path,
            "folder": artifacts.run_dir,
        }
        target = targets.get(kind)
        if target is None:
            return
        try:
            self._open_local_path(target)
        except Exception as exc:
            self.log(f"[WARN] Could not open {target}: {exc}")

    def _refresh_reports_tab(self) -> None:
        badge = getattr(self, "_reports_status_badge", None)
        summary_label = getattr(self, "_reports_summary_label", None)
        paths_label = getattr(self, "_reports_paths_label", None)
        artifacts = getattr(self, "_last_run_artifacts", None)
        if badge is None or summary_label is None or paths_label is None:
            return
        if artifacts is None:
            badge.configure(text=self._t("last_run"), fg_color=self._success_badge_fg, text_color=self._success_text)
            summary_label.configure(text=self._t("last_run_none"))
            paths_label.configure(text=self._t("latest_artifacts_none"))
            for button in getattr(self, "_reports_action_buttons", []):
                button.configure(state="disabled")
            return

        failed = sum(1 for item in self._last_audit_reports_payload if item.get("status") == "FAIL")
        exit_code = getattr(self, "_last_run_exit_code", None)
        if failed or exit_code == EXIT_POLICY_FAILED:
            badge_text = "FAIL"
            badge_fg = self._failure_badge_fg
            badge_text_color = self._failure_badge_text
        elif exit_code == EXIT_RUNTIME_ERROR:
            badge_text = "ERROR"
            badge_fg = self._failure_badge_fg
            badge_text_color = self._failure_badge_text
        elif exit_code == EXIT_ABORTED:
            badge_text = "ABORTED"
            badge_fg = self._warning_badge_fg
            badge_text_color = self._warning_badge_text
        else:
            badge_text = "PASS/REVIEW"
            badge_fg = self._pass_badge_fg
            badge_text_color = self._pass_badge_text

        summary = self._build_repair_status_summary(self._last_audit_reports_payload)
        if not self._last_audit_reports_payload:
            summary = self._t("last_run_none") if exit_code is None else f"{self._last_run_action or 'run'} finished with exit code {exit_code}."
        badge.configure(text=badge_text, fg_color=badge_fg, text_color=badge_text_color)
        summary_label.configure(text=summary)
        paths_label.configure(
            text=(
                f"run_dir: {artifacts.run_dir}\n"
                f"report.json: {artifacts.json_path}\n"
                f"report.html: {artifacts.html_path}\n"
                f"run.log: {artifacts.log_path}\n"
                f"run_state.json: {artifacts.state_path}"
            )
        )
        for button in getattr(self, "_reports_action_buttons", []):
            button.configure(state="normal")

    def _remember_last_run_artifacts(
        self,
        artifacts: artifact_helpers.RunArtifacts,
        *,
        run_fix: bool,
        exit_code: int,
        reports_payload: list[dict[str, object]],
    ) -> None:
        self._last_run_artifacts = artifacts
        self._last_run_exit_code = exit_code
        self._last_run_action = self._t("action_repair" if run_fix else "action_audit")
        if reports_payload:
            self._last_audit_reports_payload = reports_payload
        self._refresh_reports_tab()

    def _set_repair_options_visibility(self, visible: bool) -> None:
        self._repair_options_visible = visible
        card = getattr(self, "_repair_options_card", None)
        if card is not None:
            if visible:
                card.grid()
            else:
                card.grid_remove()
        button = getattr(self, "_repair_options_toggle_button", None)
        if button is not None:
            button.configure(text=self._t("repair_advanced_toggle_hide" if visible else "repair_advanced_toggle_show"))
        hint = getattr(self, "_repair_options_hint_label", None)
        if hint is not None:
            hint.configure(text=self._t("repair_advanced_hint_visible" if visible else "repair_advanced_hint_hidden"))

    def _toggle_repair_options(self) -> None:
        self._set_repair_options_visibility(not getattr(self, "_repair_options_visible", False))

    def _current_locale(self) -> str:
        return normalize_gui_locale(getattr(self, "_gui_locale", GUI_LOCALE_DEFAULT))

    def _t(self, key: str, **kwargs: object) -> str:
        locale = self._current_locale()
        catalog = GUI_UI_TEXT_BY_LOCALE.get(locale, GUI_UI_TEXT_BY_LOCALE[GUI_LOCALE_DEFAULT])
        template = catalog.get(key, GUI_UI_TEXT_BY_LOCALE[GUI_LOCALE_DEFAULT][key])
        return template.format(**kwargs) if kwargs else template

    def _configure_localized_widget(
        self,
        widget: object,
        option: str,
        key: str,
        kwargs: dict[str, object],
    ) -> None:
        configure = getattr(widget, "configure", None)
        if configure is None:
            return
        configure(**{option: self._t(key, **kwargs)})

    def _localize_widget(self, widget, option: str, key: str, **kwargs: object):
        self._configure_localized_widget(widget, option, key, kwargs)
        targets = getattr(self, "_localized_config_targets", None)
        if targets is not None:
            targets.append((widget, option, key, dict(kwargs)))
        return widget

    def _refresh_localized_widgets(self) -> None:
        for widget, option, key, kwargs in list(getattr(self, "_localized_config_targets", [])):
            self._configure_localized_widget(widget, option, key, kwargs)

    def _refresh_locale_menu(self) -> None:
        locale_var = getattr(self, "locale_var", None)
        if locale_var is not None:
            locale_var.set(gui_locale_label(self._current_locale()))
        locale_menu = getattr(self, "_locale_menu", None)
        if locale_menu is not None:
            try:
                locale_menu.configure(values=[label for _locale, label in GUI_LOCALE_OPTIONS])
                locale_menu.set(gui_locale_label(self._current_locale()))
            except Exception:
                pass

    def _refresh_appearance_menu(self) -> None:
        appearance_var = getattr(self, "appearance_var", None)
        if appearance_var is not None:
            appearance_var.set(gui_appearance_label(self._current_appearance(), self._current_locale()))
        appearance_menu = getattr(self, "_appearance_menu", None)
        if appearance_menu is not None:
            try:
                appearance_menu.configure(
                    values=[label for _appearance, label in gui_appearance_options(self._current_locale())]
                )
                appearance_menu.set(gui_appearance_label(self._current_appearance(), self._current_locale()))
            except Exception:
                pass

    def _refresh_flow_tab_locale(self) -> None:
        flow_tabs = getattr(self, "_flow_tabs", None)
        if flow_tabs is None:
            return
        desired_audit_name = self._t("tab_audit")
        desired_reports_name = self._t("tab_reports")
        desired_prompts_name = self._t("tab_prompts")
        desired_settings_name = self._t("tab_settings")
        desired_repair_name = self._t("tab_repair")
        current_audit_name = getattr(self, "_audit_tab_name", desired_audit_name)
        current_reports_name = getattr(self, "_reports_tab_name", desired_reports_name)
        current_prompts_name = getattr(self, "_prompts_tab_name", desired_prompts_name)
        current_settings_name = getattr(self, "_settings_tab_name", desired_settings_name)
        current_repair_name = getattr(self, "_repair_tab_name", desired_repair_name)
        active_tab = None
        try:
            active_tab = flow_tabs.get()
        except Exception:
            active_tab = None
        try:
            if current_audit_name != desired_audit_name:
                flow_tabs.rename(current_audit_name, desired_audit_name)
                self._audit_tab_name = desired_audit_name
            if current_reports_name != desired_reports_name:
                flow_tabs.rename(current_reports_name, desired_reports_name)
                self._reports_tab_name = desired_reports_name
            if current_prompts_name != desired_prompts_name:
                flow_tabs.rename(current_prompts_name, desired_prompts_name)
                self._prompts_tab_name = desired_prompts_name
            if current_settings_name != desired_settings_name:
                flow_tabs.rename(current_settings_name, desired_settings_name)
                self._settings_tab_name = desired_settings_name
            if current_repair_name != desired_repair_name:
                flow_tabs.rename(current_repair_name, desired_repair_name)
                self._repair_tab_name = desired_repair_name
            if hasattr(flow_tabs, "_name_list"):
                flow_tabs._name_list = [  # noqa: SLF001 - CustomTkinter rename preserves visual order but appends internally.
                    desired_audit_name,
                    desired_reports_name,
                    desired_prompts_name,
                    desired_settings_name,
                    desired_repair_name,
                ]
        except Exception:
            self._audit_tab_name = desired_audit_name
            self._reports_tab_name = desired_reports_name
            self._prompts_tab_name = desired_prompts_name
            self._settings_tab_name = desired_settings_name
            self._repair_tab_name = desired_repair_name
            return
        if active_tab == current_repair_name:
            self._set_active_flow_tab(desired_repair_name)
        elif active_tab == current_audit_name:
            self._set_active_flow_tab(desired_audit_name)
        elif active_tab == current_reports_name:
            self._set_active_flow_tab(desired_reports_name)
        elif active_tab == current_prompts_name:
            self._set_active_flow_tab(desired_prompts_name)
        elif active_tab == current_settings_name:
            self._set_active_flow_tab(desired_settings_name)

    def _apply_gui_locale(self) -> None:
        self._refresh_locale_menu()
        self._refresh_appearance_menu()
        self._refresh_flow_tab_locale()
        self._refresh_localized_widgets()
        self._refresh_prompt_cards()
        self._refresh_reports_tab()
        self._refresh_repair_locale_state()
        self._set_repair_options_visibility(getattr(self, "_repair_options_visible", False))
        self._set_setup_settings_visibility(getattr(self, "_setup_settings_visible", True))
        self._set_advanced_identity_visibility(getattr(self, "_advanced_identity_visible", False))
        self._update_repair_gate_note()
        if getattr(self, "_run_in_progress", False):
            self._update_repo_summary()
            self._update_run_buttons_state()
            return
        if getattr(self, "repo_list", None) is None:
            return
        selected = self._selected_repo_names()
        self.refresh_repos()
        self._select_repo_values(selected)

    def _on_gui_locale_selected(self, selected_label: str) -> None:
        self._gui_locale = gui_locale_from_label(selected_label)
        self._apply_gui_locale()
        self._save_gui_setup_settings(setup_completed=bool(getattr(self, "_setup_completed", False)))

    def _on_gui_appearance_selected(self, selected_label: str) -> None:
        self._gui_appearance = gui_appearance_from_label(selected_label)
        self._refresh_appearance_menu()
        self._save_gui_setup_settings(setup_completed=bool(getattr(self, "_setup_completed", False)))
        self.log(f"[INFO] GUI theme saved as {self._current_appearance()}. Restart the GUI to apply it.")

    def _tooltip_text(self, key: str) -> str:
        catalog = GUI_TOOLTIP_TEXT_BY_LOCALE.get(self._current_locale(), GUI_TOOLTIP_TEXT)
        return catalog.get(key, GUI_TOOLTIP_TEXT[key])

    def _bind_tooltip_key(self, widget, key: str):
        self._bind_tooltip(widget, lambda: self._tooltip_text(key))
        return widget

    def _make_info_badge_for(self, parent, key: str):
        return self._make_info_badge(parent, lambda: self._tooltip_text(key))

    def _make_field_label(
        self,
        parent,
        *,
        text: str | None = None,
        text_key: str | None = None,
        tooltip_key: str | None = None,
    ):
        shell = self.ctk.CTkFrame(parent, fg_color="transparent")
        label_text = self._t(text_key) if text_key else (text or "")
        label = self.ctk.CTkLabel(shell, text=label_text, font=self._font(12), text_color=self._text_body)
        if text_key:
            self._localize_widget(label, "text", text_key)
        label.pack(side="left")
        if tooltip_key:
            self._bind_tooltip_key(label, tooltip_key)
            self._make_info_badge_for(shell, tooltip_key).pack(side="left", padx=(6, 0))
        return shell

    def _dialog_initial_dir(self, current_value: str) -> str:
        raw_value = current_value.strip()
        if not raw_value:
            return str(default_root_dir())

        candidate = Path(raw_value).expanduser()
        if candidate.exists():
            return str(candidate if candidate.is_dir() else candidate.parent)

        if candidate.suffix:
            return str(candidate.parent if candidate.parent.exists() else default_root_dir())

        return str(candidate if candidate.parent.exists() else default_root_dir())

    def _browse_directory(self, target_var, *, title: str) -> None:
        selected = self.filedialog.askdirectory(
            title=title,
            initialdir=self._dialog_initial_dir(target_var.get()),
            mustexist=False,
        )
        if selected:
            target_var.set(selected)

    def _browse_existing_file(self, target_var, *, title: str, filetypes) -> None:
        selected = self.filedialog.askopenfilename(
            title=title,
            initialdir=self._dialog_initial_dir(target_var.get()),
            filetypes=filetypes,
        )
        if selected:
            target_var.set(selected)

    def _browse_save_file(
        self,
        target_var,
        *,
        title: str,
        default_extension: str,
        filetypes,
    ) -> None:
        selected = self.filedialog.asksaveasfilename(
            title=title,
            initialdir=self._dialog_initial_dir(target_var.get()),
            defaultextension=default_extension,
            filetypes=filetypes,
        )
        if selected:
            target_var.set(selected)

    def _add_directory_field(
        self,
        parent,
        *,
        row: int,
        label: str | None = None,
        label_key: str | None = None,
        variable,
        title: str | None = None,
        title_key: str | None = None,
        tooltip_key: str | None = None,
    ) -> None:
        self._make_field_label(parent, text=label, text_key=label_key, tooltip_key=tooltip_key).grid(
            row=row,
            column=0,
            sticky="w",
            padx=(14, 8),
            pady=4,
        )
        entry = self.ctk.CTkEntry(parent, textvariable=variable, height=32, corner_radius=8)
        if tooltip_key:
            self._bind_tooltip_key(entry, tooltip_key)
        entry.grid(
            row=row,
            column=1,
            sticky="we",
            padx=(0, 8),
            pady=4,
        )
        button = self.ctk.CTkButton(
            parent,
            text=self._t("browse"),
            width=92,
            height=32,
            corner_radius=8,
            **self._button_asset_options("icon-folder.png"),
            **self._secondary_button_options(),
            command=lambda: self._browse_directory(variable, title=self._t(title_key) if title_key else (title or "")),
        )
        self._localize_widget(button, "text", "browse")
        if tooltip_key:
            self._bind_tooltip_key(button, tooltip_key)
        button.grid(row=row, column=2, padx=(0, 14), pady=4)

    def _add_file_field(
        self,
        parent,
        *,
        row: int,
        label: str | None = None,
        label_key: str | None = None,
        variable,
        title: str | None = None,
        title_key: str | None = None,
        filetypes,
        tooltip_key: str | None = None,
    ) -> None:
        self._make_field_label(parent, text=label, text_key=label_key, tooltip_key=tooltip_key).grid(
            row=row,
            column=0,
            sticky="w",
            padx=(14, 8),
            pady=4,
        )
        entry = self.ctk.CTkEntry(parent, textvariable=variable, height=32, corner_radius=8)
        if tooltip_key:
            self._bind_tooltip_key(entry, tooltip_key)
        entry.grid(
            row=row,
            column=1,
            sticky="we",
            padx=(0, 8),
            pady=4,
        )
        button = self.ctk.CTkButton(
            parent,
            text=self._t("browse"),
            width=92,
            height=32,
            corner_radius=8,
            **self._button_asset_options("icon-open.png"),
            **self._secondary_button_options(),
            command=lambda: self._browse_existing_file(
                variable,
                title=self._t(title_key) if title_key else (title or ""),
                filetypes=filetypes,
            ),
        )
        self._localize_widget(button, "text", "browse")
        if tooltip_key:
            self._bind_tooltip_key(button, tooltip_key)
        button.grid(row=row, column=2, padx=(0, 14), pady=4)

    def _add_save_file_field(
        self,
        parent,
        *,
        row: int,
        label: str | None = None,
        label_key: str | None = None,
        variable,
        title: str | None = None,
        title_key: str | None = None,
        default_extension: str,
        filetypes,
        tooltip_key: str | None = None,
    ) -> None:
        self._make_field_label(parent, text=label, text_key=label_key, tooltip_key=tooltip_key).grid(
            row=row,
            column=0,
            sticky="w",
            padx=(14, 8),
            pady=4,
        )
        entry = self.ctk.CTkEntry(parent, textvariable=variable, height=32, corner_radius=8)
        if tooltip_key:
            self._bind_tooltip_key(entry, tooltip_key)
        entry.grid(
            row=row,
            column=1,
            sticky="we",
            padx=(0, 8),
            pady=4,
        )
        button = self.ctk.CTkButton(
            parent,
            text=self._t("save_as"),
            width=92,
            height=32,
            corner_radius=8,
            **self._button_asset_options("icon-folder.png"),
            **self._secondary_button_options(),
            command=lambda: self._browse_save_file(
                variable,
                title=self._t(title_key) if title_key else (title or ""),
                default_extension=default_extension,
                filetypes=filetypes,
            ),
        )
        self._localize_widget(button, "text", "save_as")
        if tooltip_key:
            self._bind_tooltip_key(button, tooltip_key)
        button.grid(row=row, column=2, padx=(0, 14), pady=4)

    def _get_logical_window_width(self) -> int:
        geometry = self.root.wm_geometry().split("+", maxsplit=1)[0]
        width_text = geometry.split("x", maxsplit=1)[0]
        try:
            width = int(width_text)
        except ValueError:
            width = self.root.winfo_width()

        scale = 1.0
        try:
            scale = float(self.ctk.ScalingTracker.get_window_scaling(self.root))
        except Exception:
            pass

        safe_scale = scale if scale > 0 else 1.0
        return int(round(width / safe_scale))

    def _on_root_resize(self, event) -> None:
        del event
        self._apply_responsive_layout()

    def _apply_responsive_layout(self) -> None:
        width = self._get_logical_window_width()
        self._apply_header_flow_layout(compact=width <= self._top_stack_width_threshold)
        self._apply_top_layout(compact=width <= self._top_stack_width_threshold)
        self._apply_identity_actions_layout(compact=width <= self._top_stack_width_threshold)
        self._apply_options_layout(compact=width <= self._options_stack_width_threshold)
        self._apply_results_layout(compact=width <= self._results_stack_width_threshold)

    def _apply_header_flow_layout(self, compact: bool) -> None:
        if self._workflow_strip is None:
            return
        visible = not compact
        if visible == self._workflow_strip_visible:
            return
        self._workflow_strip_visible = visible
        try:
            header_visual = getattr(self, "_header_visual_label", None)
            if visible:
                self._workflow_strip.grid()
                if header_visual is not None:
                    header_visual.grid()
                return
            self._workflow_strip.grid_remove()
            if header_visual is not None:
                header_visual.grid_remove()
        except Exception:
            return

    def _current_gui_settings_payload(self, *, setup_completed: bool) -> dict[str, object]:
        return {
            "setup_completed": setup_completed,
            "gui_locale": self._current_locale(),
            "gui_appearance": self._current_appearance(),
            "root": self.root_var.get().strip(),
            "policy": self.policy_var.get().strip(),
            "report_dir": self.report_dir_var.get().strip(),
            "report_json": self.report_json_var.get().strip(),
            "max_matches": self.max_matches_var.get().strip(),
            "github_owner": self.github_owner_var.get().strip(),
            "github_repo_filters": self.github_repo_filters_var.get().strip(),
            "github_jobs": self.github_jobs_var.get().strip(),
            "public_only": bool(self.public_only_var.get()),
            "github_include_forks": bool(self.github_include_forks_var.get()),
            "github_fast": bool(self.github_fast_var.get()),
            "dry_run": bool(self.dry_run_var.get()),
            "low_confidence_blocking": bool(self.low_confidence_blocking_var.get()),
            "audit_litellm_incident": bool(self.audit_litellm_incident_var.get()),
            "audit_github_hardening": bool(self.audit_github_hardening_var.get()),
            "open_report": bool(self.open_report_var.get()),
        }

    def _save_gui_setup_settings(self, *, setup_completed: bool) -> bool:
        settings_path = getattr(self, "_gui_settings_path", None)
        if settings_path is None:
            return False
        try:
            save_gui_settings(
                settings_path,
                self._current_gui_settings_payload(setup_completed=setup_completed),
            )
        except Exception as exc:
            try:
                self.log(f"[WARN] GUI setup settings could not be saved: {exc}")
            except Exception:
                pass
            return False
        self._setup_completed = setup_completed
        return True

    def save_setup_clicked(self) -> None:
        if self._save_gui_setup_settings(setup_completed=True):
            self.log(f"[INFO] GUI setup saved to {self._gui_settings_path}")
            self._set_setup_settings_visibility(False)

    def _toggle_setup_settings(self) -> None:
        self._set_setup_settings_visibility(not self._setup_settings_visible)

    def _setup_settings_hint_text(self, visible: bool) -> str:
        if visible:
            return self._t("setup_hint_open")
        try:
            github_owner = self._github_owner_value()
        except Exception:
            github_owner = None
        if github_owner:
            return self._t("setup_hint_remote", github_owner=github_owner)
        return self._t("setup_hint_hidden")

    def _set_setup_settings_visibility(self, visible: bool) -> None:
        self._setup_settings_visible = visible

        toggle_button = getattr(self, "_setup_settings_toggle_button", None)
        if toggle_button is not None:
            toggle_button.configure(text=self._t("hide_settings" if visible else "open_settings"))

        hint_label = getattr(self, "_setup_settings_hint_label", None)
        if hint_label is not None:
            hint_label.configure(text=self._setup_settings_hint_text(visible))

        frame = getattr(self, "_setup_settings_frame", None)
        if frame is not None:
            if visible:
                frame.grid()
            else:
                frame.grid_remove()

    def _toggle_advanced_identity_settings(self) -> None:
        self._set_advanced_identity_visibility(not self._advanced_identity_visible)

    def _set_advanced_identity_visibility(self, visible: bool) -> None:
        self._advanced_identity_visible = visible

        toggle_button = getattr(self, "_advanced_identity_toggle_button", None)
        if toggle_button is not None:
            toggle_button.configure(text=self._t("hide_advanced_identity" if visible else "show_advanced_identity"))

        hint_label = getattr(self, "_advanced_identity_hint_label", None)
        if hint_label is not None:
            hint_label.configure(text=self._t("advanced_identity_visible" if visible else "advanced_identity_hidden"))

        identity_card = getattr(self, "_identity_card", None)
        if identity_card is not None:
            if visible:
                identity_card.grid(row=1, column=0, sticky="we", padx=10, pady=(10, 8))
            else:
                identity_card.grid_remove()

        self._apply_top_layout(
            compact=getattr(self, "_compact_top_layout", False),
            force=True,
        )

    def _apply_top_layout(self, compact: bool, *, force: bool = False) -> None:
        if not force and compact == self._compact_top_layout:
            return

        self._compact_top_layout = compact
        advanced_visible = bool(getattr(self, "_advanced_identity_visible", True))
        if compact:
            self._top_row.grid_columnconfigure(0, weight=1)
            self._top_row.grid_columnconfigure(1, weight=1)
            self._settings_card.grid_configure(
                row=0,
                column=0,
                columnspan=2,
                padx=0,
                pady=(0, 8),
                sticky="we",
            )
            if advanced_visible:
                self._profile_card.grid_configure(
                    row=1,
                    column=0,
                    columnspan=2,
                    padx=0,
                    pady=(8, 0),
                    sticky="we",
                )
            else:
                self._profile_card.grid_remove()
            return

        self._top_row.grid_columnconfigure(0, weight=2)
        self._top_row.grid_columnconfigure(1, weight=1)
        if advanced_visible:
            self._settings_card.grid_configure(
                row=0,
                column=0,
                columnspan=1,
                padx=(0, 8),
                pady=0,
                sticky="nsew",
            )
            self._profile_card.grid_configure(
                row=0,
                column=1,
                columnspan=1,
                padx=(8, 0),
                pady=0,
                sticky="nsew",
            )
            return

        self._settings_card.grid_configure(
            row=0,
            column=0,
            columnspan=2,
            padx=0,
            pady=0,
            sticky="nsew",
        )
        self._profile_card.grid_remove()

    def _apply_identity_actions_layout(self, compact: bool) -> None:
        if compact == self._compact_identity_actions_layout:
            return
        if self._identity_actions is None or len(self._identity_action_buttons) != 4:
            return

        self._compact_identity_actions_layout = compact
        buttons = self._identity_action_buttons

        if compact:
            self._identity_actions.grid_columnconfigure((0, 1), weight=1)
            self._identity_actions.grid_columnconfigure((2, 3), weight=0)
            buttons[0].grid_configure(row=0, column=0, padx=(0, 6), pady=3)
            buttons[1].grid_configure(row=0, column=1, padx=(6, 0), pady=3)
            buttons[2].grid_configure(row=1, column=0, padx=(0, 6), pady=3)
            buttons[3].grid_configure(row=1, column=1, padx=(6, 0), pady=3)
            return

        self._identity_actions.grid_columnconfigure((0, 1, 2, 3), weight=1)
        buttons[0].grid_configure(row=0, column=0, padx=(0, 6), pady=3)
        buttons[1].grid_configure(row=0, column=1, padx=(6, 6), pady=3)
        buttons[2].grid_configure(row=0, column=2, padx=(6, 6), pady=3)
        buttons[3].grid_configure(row=0, column=3, padx=(6, 0), pady=3)

    def _apply_options_layout(self, compact: bool) -> None:
        if compact == self._compact_options_layout:
            return

        self._compact_options_layout = compact
        if compact:
            self._safe_options_card.grid_configure(row=1, column=0, padx=14, pady=(0, 8), sticky="we")
            self._destructive_options_card.grid_configure(
                row=2,
                column=0,
                padx=14,
                pady=(0, 12),
                sticky="we",
            )
            return

        self._safe_options_card.grid_configure(row=1, column=0, padx=(14, 7), pady=(0, 12), sticky="nsew")
        self._destructive_options_card.grid_configure(
            row=1,
            column=1,
            padx=(7, 14),
            pady=(0, 12),
            sticky="nsew",
        )

    def _apply_results_layout(self, compact: bool) -> None:
        if compact == self._compact_results_layout:
            return

        self._compact_results_layout = compact
        if self._results_row is None or self._repos_card is None or self._output_card is None:
            return

        if compact:
            self._results_row.grid_columnconfigure(0, weight=1)
            self._results_row.grid_columnconfigure(1, weight=0)
            self._repos_card.grid_configure(row=0, column=0, padx=0, pady=(0, 8), sticky="nsew")
            self._output_card.grid_configure(row=1, column=0, padx=0, pady=(8, 0), sticky="nsew")
            return

        self._results_row.grid_columnconfigure(0, weight=1)
        self._results_row.grid_columnconfigure(1, weight=1)
        self._repos_card.grid_configure(row=0, column=0, padx=(0, 8), pady=0, sticky="nsew")
        self._output_card.grid_configure(row=0, column=1, padx=(8, 0), pady=0, sticky="nsew")

    def _set_active_flow_tab(self, tab_name: str) -> None:
        if self._flow_tabs is None:
            return
        try:
            self._select_flow_tab_without_delayed_cleanup(tab_name)
            app_frame = getattr(self, "_app_frame", None)
            parent_canvas = getattr(app_frame, "_parent_canvas", None)
            if parent_canvas is not None:
                parent_canvas.yview_moveto(0)
        except Exception:
            pass

    def _select_flow_tab_without_delayed_cleanup(self, tab_name: str) -> None:
        flow_tabs = getattr(self, "_flow_tabs", None)
        if flow_tabs is None:
            return
        try:
            tab_dict = getattr(flow_tabs, "_tab_dict", {})
            if tab_name not in tab_dict:
                return
            current_name = getattr(flow_tabs, "_current_name", "")
            if current_name in tab_dict and current_name != tab_name:
                tab_dict[current_name].grid_forget()
            flow_tabs._current_name = tab_name  # noqa: SLF001 - avoids CTkTabview.set() delayed grid cleanup.
            segmented_button = getattr(flow_tabs, "_segmented_button", None)
            if segmented_button is not None:
                segmented_button.set(tab_name)
            flow_tabs._set_grid_current_tab()  # noqa: SLF001
            flow_tabs._grid_forget_all_tabs(exclude_name=tab_name)  # noqa: SLF001
        except Exception:
            return

    def _set_output_empty_state(self, visible: bool) -> None:
        label = getattr(self, "_output_empty_state_label", None)
        output = getattr(self, "output", None)
        if label is None or output is None:
            return
        if visible:
            label.place(in_=output, relx=0.5, rely=0.5, anchor="center")
            label.lift()
            return
        label.place_forget()

    def _set_repair_status(
        self,
        message: str,
        *,
        text_color: str | None = None,
        badge_text: str = "Audit required",
        panel_fg: str | None = None,
        panel_border: str | None = None,
        badge_fg: str | None = None,
        badge_text_color: str | None = None,
    ) -> None:
        repair_status_label = getattr(self, "_repair_status_label", None)
        if repair_status_label is None:
            return
        text_color = text_color or self._text_muted
        panel_fg = panel_fg or self._success_panel_fg
        panel_border = panel_border or self._success_panel_border
        badge_fg = badge_fg or self._success_badge_fg
        badge_text_color = badge_text_color or self._success_text
        repair_status_label.configure(text=message, text_color=text_color)
        repair_status_panel = getattr(self, "_repair_status_panel", None)
        if repair_status_panel is not None:
            repair_status_panel.configure(fg_color=panel_fg, border_color=panel_border)
        repair_status_badge = getattr(self, "_repair_status_badge", None)
        if repair_status_badge is not None:
            repair_status_badge.configure(
                text=badge_text,
                fg_color=badge_fg,
                text_color=badge_text_color,
            )

    def _set_repo_empty_state(
        self,
        visible: bool,
        message: str | None = None,
        *,
        reason: str | None = None,
    ) -> None:
        repo_empty_state = getattr(self, "_repo_empty_state", None)
        if repo_empty_state is None:
            return
        self._ensure_gui_theme_palette()
        if not visible:
            self._repo_empty_reason = None
            try:
                self.repo_list.configure(state="normal")
            except Exception:
                pass
            repo_empty_state.place_forget()
            return
        self._repo_empty_reason = reason or "no_repos"
        title_label = getattr(self, "_repo_empty_state_title_label", None)
        body_label = getattr(self, "_repo_empty_state_body_label", None)
        hint_label = getattr(self, "_repo_empty_state_hint_label", None)

        palette = {
            "invalid_root": {
                "title": self._t("repo_empty_invalid_root_title"),
                "fg": self._warning_panel_fg,
                "border": self._warning_panel_border,
                "title_color": self._warning_text,
                "body_color": self._warning_strong_text,
                "hint": self._t("repo_empty_invalid_root_hint"),
            },
            "no_repos": {
                "title": self._t("repo_empty_no_repos_title"),
                "fg": self._info_panel_fg,
                "border": self._info_panel_border,
                "title_color": self._info_text,
                "body_color": self._text_muted,
                "hint": self._t("repo_empty_no_repos_hint"),
            },
            "github_remote": {
                "title": self._t("repo_empty_github_remote_title"),
                "fg": self._success_panel_fg,
                "border": self._success_panel_border,
                "title_color": self._success_text,
                "body_color": self._text_muted,
                "hint": self._t("repo_empty_github_remote_hint"),
            },
        }
        theme = palette.get(self._repo_empty_reason, palette["no_repos"])
        repo_empty_state.configure(fg_color=theme["fg"], border_color=theme["border"])
        visual_label = getattr(self, "_repo_empty_state_visual_label", None)
        if visual_label is not None:
            visual_label.configure(background=theme["fg"])
        if title_label is not None:
            title_label.configure(text=theme["title"], text_color=theme["title_color"])
        if body_label is not None and message:
            body_label.configure(text=message, text_color=theme["body_color"])
        if hint_label is not None:
            hint_label.configure(text=theme["hint"], text_color=self._text_muted)
        try:
            self.repo_list.configure(state="disabled")
        except Exception:
            pass
        repo_empty_state.place(relx=0.5, rely=0.5, relwidth=0.82, anchor="center")
        try:
            repo_empty_state.lift()
        except Exception:
            pass

    def _set_repo_drop_hint(self, message: str) -> None:
        label = getattr(self, "_repo_drop_hint_label", None)
        if label is not None:
            label.configure(text=message)

    def _enable_repo_drag_and_drop(self, *widgets: object) -> None:
        try:
            from tkinterdnd2 import DND_FILES, TkinterDnD

            TkinterDnD._require(self.root)
        except Exception as exc:
            self._set_repo_drop_hint(self._t("repo_drop_unavailable", error=exc))
            return

        def _drop(raw_data: str) -> str:
            self._handle_repo_drop(raw_data)
            return "copy"

        def _copy_action(*_args: object) -> str:
            return "copy"

        for widget in widgets:
            try:
                widget.tk.call("tkdnd::drop_target", "register", widget._w, DND_FILES)
                drop_command = self.root.register(_drop)
                enter_command = self.root.register(_copy_action)
                self._dnd_command_names.extend([drop_command, enter_command])
                widget.tk.call("bind", widget._w, "<<Drop>>", f"{drop_command} %D")
                widget.tk.call("bind", widget._w, "<<DropEnter>>", enter_command)
                widget.tk.call("bind", widget._w, "<<DropPosition>>", enter_command)
            except Exception as exc:
                self._set_repo_drop_hint(self._t("repo_drop_registration_failed", error=exc))
                return

        self._set_repo_drop_hint(self._t("repo_drop_ready"))

    def _handle_repo_drop(self, raw_data: str) -> None:
        if getattr(self, "_run_in_progress", False):
            self.log("[INFO] Drag-and-drop is disabled while a run is in progress.")
            return

        splitter = getattr(getattr(self.root, "tk", None), "splitlist", None)
        paths = parse_tk_drop_paths(raw_data, splitter=splitter)
        target_root, selected_values, error = resolve_dropped_repository_targets(paths)
        if error or target_root is None:
            self.log(f"[WARN] Repository drop ignored: {error or 'no usable paths'}")
            return

        if self._github_owner_value():
            self.github_owner_var.set("")
            self.log("[INFO] Cleared GitHub owner/org remote audit because local repositories were dropped.")

        self.root_var.set(str(target_root))
        self.refresh_repos()
        self._select_repo_values(selected_values)
        selected_text = "all detected repositories" if not selected_values else ", ".join(selected_values)
        self.log(f"[INFO] Repository drop loaded Root: {target_root} ({selected_text}).")
        self._save_gui_setup_settings(setup_completed=True)
        self._set_setup_settings_visibility(False)

    def _select_repo_values(self, selected_values: list[str]) -> None:
        if not selected_values or not self._repo_items:
            return
        wanted = set(selected_values)
        self.repo_list.selection_clear(0, "end")
        for index, (_label, value) in enumerate(self._repo_items):
            if value in wanted:
                self.repo_list.selection_set(index)
        self._update_repo_summary()

    def _update_repo_summary(self) -> None:
        repo_summary_label = getattr(self, "_repo_summary_label", None)
        if repo_summary_label is None:
            return

        github_owner = self._github_owner_value()
        if github_owner:
            repo_summary_label.configure(
                text=self._t(
                    "repo_summary_remote",
                    github_owner=github_owner,
                    filter_text=self._github_remote_filter_text(),
                )
            )
            return

        total = len(self._repo_items)
        selected = len(self.repo_list.curselection())
        includes_current_root = any(value == "." for _label, value in self._repo_items)

        if total == 0:
            if getattr(self, "_repo_empty_reason", None) == "invalid_root":
                repo_summary_label.configure(text=self._t("repo_summary_invalid_root"))
            else:
                repo_summary_label.configure(text=self._t("repo_summary_no_repos"))
            return

        repo_word = self._t("repo_word_singular" if total == 1 else "repo_word_plural")
        selected_text = (
            self._t("no_repos_selected")
            if selected == 0
            else self._t("selected_count", count=selected)
        )
        root_hint = self._t("current_root_available") if includes_current_root else ""
        repo_summary_label.configure(
            text=self._t(
                "repo_summary_targets",
                total=total,
                repo_word=repo_word,
                selected_text=selected_text,
                root_hint=root_hint,
            )
        )

    def _report_item_count(self, payload: dict[str, object], *keys: str) -> int:
        return sum(len(self._report_list(payload, key)) for key in keys)

    def _manual_review_signal_count(self, payload: dict[str, object]) -> int:
        return self._report_item_count(
            payload,
            "tracked_secret_low_confidence",
            "history_secret_low_confidence",
            "git_metadata_secret_low_confidence",
            "tracked_email_low_confidence",
            "history_email_low_confidence",
            "exfil_code_indicators",
            "github_hardening_findings",
            "github_hardening_warnings",
            "secret_file_manual_review_candidates",
        )

    def _safe_context_count(self, payload: dict[str, object]) -> int:
        return self._report_item_count(
            payload,
            "tracked_secret_fixture_matches",
            "history_secret_fixture_matches",
            "tracked_secret_documentation_matches",
            "history_secret_documentation_matches",
        )

    def _build_repair_status_summary(self, reports_payload: list[dict[str, object]]) -> str:
        total = len(reports_payload)
        if total == 0:
            return self._t("no_audit_results")

        passed = sum(1 for item in reports_payload if item.get("status") == "PASS")
        failed = sum(1 for item in reports_payload if item.get("status") == "FAIL")
        blocking_categories = sum(self._report_item_count(item, "failures") for item in reports_payload)
        manual_review_signals = sum(self._manual_review_signal_count(item) for item in reports_payload)
        safe_context = sum(self._safe_context_count(item) for item in reports_payload)
        names = [str(item.get("name")) for item in reports_payload[:3] if item.get("name")]
        label = ", ".join(names)
        if total > len(names):
            label += f", +{total - len(names)} more"

        detail_parts: list[str] = []
        if blocking_categories:
            detail_parts.append(
                self._t(
                    "blocking_category_singular" if blocking_categories == 1 else "blocking_category_plural",
                    count=blocking_categories,
                )
            )
        if manual_review_signals:
            detail_parts.append(
                self._t(
                    "manual_signal_singular" if manual_review_signals == 1 else "manual_signal_plural",
                    count=manual_review_signals,
                )
            )
        if safe_context:
            detail_parts.append(
                self._t(
                    "fixture_match_singular" if safe_context == 1 else "fixture_match_plural",
                    count=safe_context,
                )
            )
        detail_text = (" " + "; ".join(detail_parts) + ".") if detail_parts else ""

        if failed:
            return self._t(
                "last_audit_failed",
                label=label,
                failed=failed,
                passed=passed,
                detail_text=detail_text,
            )

        if manual_review_signals:
            return self._t(
                "last_audit_passed_manual",
                label=label,
                detail_text=detail_text,
            )

        return self._t(
            "last_audit_passed",
            label=label,
            detail_text=detail_text,
        )

    def _set_repair_tab_visual_lock(self, locked: bool, reason: str | None = None) -> None:
        if self._repair_tab_block_overlay is None:
            return

        if not locked:
            self._repair_tab_block_overlay.grid_forget()
            self._repair_tab_block_overlay.place_forget()
            return

        if self._repair_tab_block_label is not None:
            lock_reason = reason or self._t("repair_lock_default_reason")
            self._repair_tab_block_label.configure(
                text=self._t("repair_lock_message", reason=lock_reason)
            )

        self._repair_tab_block_overlay.place_forget()
        self._repair_tab_block_overlay.grid(row=0, column=0, rowspan=3, sticky="nsew", padx=0, pady=0)
        self._repair_tab_block_overlay.lift()

    def _make_info_badge(self, parent, message: str | Callable[[], str]):
        badge = self.ctk.CTkLabel(
            parent,
            text="i",
            width=22,
            height=22,
            corner_radius=11,
            fg_color=self._success_badge_fg,
            text_color=self._success_text,
            font=self._font(12, bold=True),
        )
        self._bind_tooltip(badge, message)
        return badge

    def _bind_tooltip(self, widget, message: str | Callable[[], str]) -> None:
        state = {"tip": None}

        def _show(_event) -> None:
            if state["tip"] is not None:
                return
            resolved_message = message() if callable(message) else message

            tip = self.tk.Toplevel(self.root)
            tip.wm_overrideredirect(True)
            try:
                tip.attributes("-topmost", True)
            except Exception:
                pass

            frame = self.ctk.CTkFrame(
                tip,
                fg_color="#0F172A",
                border_color="#1F4D79",
                border_width=1,
                corner_radius=8,
            )
            frame.pack(fill="both", expand=True)
            self.ctk.CTkLabel(
                frame,
                text=resolved_message,
                justify="left",
                anchor="w",
                wraplength=360,
                font=self._font(11),
                text_color="#E2ECF6",
            ).pack(padx=10, pady=8)

            x = widget.winfo_rootx() + widget.winfo_width() + 8
            y = widget.winfo_rooty() - 2
            tip.geometry(f"+{x}+{y}")
            state["tip"] = tip

        def _hide(_event) -> None:
            tip = state["tip"]
            if tip is not None:
                tip.destroy()
                state["tip"] = None

        widget.bind("<Enter>", _show, add="+")
        widget.bind("<Leave>", _hide, add="+")
        widget.bind("<ButtonPress-1>", _hide, add="+")

    def _sync_purge_mode_controls(self) -> None:
        safe_selected = self.purge_detected_secret_files_var.get()
        risky_selected = self.purge_all_detected_secret_files_var.get()

        if self._purge_safe_checkbox is not None:
            self._purge_safe_checkbox.configure(state="disabled" if risky_selected else "normal")
        if self._purge_risky_checkbox is not None:
            self._purge_risky_checkbox.configure(state="disabled" if safe_selected else "normal")

    def _on_purge_safe_toggled(self) -> None:
        if self.purge_detected_secret_files_var.get():
            self.purge_all_detected_secret_files_var.set(False)
        self._sync_purge_mode_controls()

    def _on_purge_risky_toggled(self) -> None:
        if self.purge_all_detected_secret_files_var.get():
            self.purge_detected_secret_files_var.set(False)
        self._sync_purge_mode_controls()

    def _sync_push_guardrail_controls(self) -> None:
        if self._allowed_remote_owner_entry is None:
            return
        state = "disabled" if self.allow_non_owner_push_var.get() else "normal"
        self._allowed_remote_owner_entry.configure(state=state)

    def _on_allow_non_owner_push_toggled(self) -> None:
        self._sync_push_guardrail_controls()

    def _offer_github_hardening_tooling_install(self) -> None:
        checks = build_github_optional_tooling_checks()
        accepted = prompt_gui_tooling_install(
            checks,
            self.log,
            blocking_only=False,
            title=self._t("install_github_tooling_title"),
            intro=self._t("install_github_tooling_intro"),
            confirm_question=self._t("install_github_tooling_confirm"),
        )
        if not accepted:
            return

        install_missing_tooling(checks, self.log)
        refreshed = build_github_optional_tooling_checks()
        github_check = next((check for check in refreshed if check.name == "github-auth"), None)
        if github_check and github_check.state == "warning" and not github_check.auto_install_command:
            self.messagebox.showinfo(
                self._t("github_auth_needed_title"),
                self._t("github_auth_needed_message"),
            )

    def _on_audit_github_hardening_toggled(self, *_args: object) -> None:
        if not self.audit_github_hardening_var.get():
            return
        self._offer_github_hardening_tooling_install()

    def _github_owner_value(self) -> str | None:
        variable = getattr(self, "github_owner_var", None)
        value = variable.get().strip() if variable is not None else ""
        return value or None

    def _github_repo_filters(self) -> list[str] | None:
        variable = getattr(self, "github_repo_filters_var", None)
        value = variable.get() if variable is not None else ""
        return normalize_csv_values(value) or None

    def _github_remote_filter_text(self) -> str:
        filters = self._github_repo_filters()
        if filters is None:
            return self._t("all_matching_repositories")
        key = "named_remote_repo_singular" if len(filters) == 1 else "named_remote_repo_plural"
        return self._t(key, count=len(filters))

    def _github_remote_state_message(self, github_owner: str) -> str:
        return self._t(
            "github_remote_state",
            filter_text=self._github_remote_filter_text(),
            github_owner=github_owner,
        )

    def _sync_remote_target_surface(self) -> bool:
        github_owner = self._github_owner_value()
        if not github_owner:
            return False
        try:
            self.repo_list.delete(0, "end")
        except Exception:
            pass
        self._repo_items = []
        self._set_repo_empty_state(
            True,
            self._github_remote_state_message(github_owner),
            reason="github_remote",
        )
        return True

    def _on_github_remote_controls_changed(self, *_args: object) -> None:
        if not self._sync_remote_target_surface():
            if getattr(self, "_repo_empty_reason", None) == "github_remote":
                self.refresh_repos()
        self._update_repo_summary()
        self._update_run_buttons_state()

    def _selection_signature(self, selected: list[str] | None) -> tuple[str, ...] | None:
        if selected is None:
            return None
        return tuple(sorted(selected))

    def _run_selection_signature(
        self,
        selected: list[str] | None,
        *,
        github_owner: str | None,
    ) -> tuple[str, ...] | None:
        if not github_owner:
            return self._selection_signature(selected)
        filters = self._selection_signature(selected) or ()
        return ("github-owner", github_owner.lower(), *filters)

    def _cancel_repair_cooldown(self) -> None:
        if self._repair_cooldown_after_id is None:
            return
        try:
            self.root.after_cancel(self._repair_cooldown_after_id)
        except Exception:
            pass
        self._repair_cooldown_after_id = None

    def _update_repair_gate_note(self) -> None:
        note_label = getattr(self, "_repair_gate_note_label", None)
        if note_label is None:
            return
        self._ensure_gui_theme_palette()
        if getattr(self, "_repair_ready", False):
            text_key = "repair_ready_note"
            text_color = self._pass_badge_text
        elif getattr(self, "_last_audit_reports_payload", []):
            text_key = "repair_review_pending_note"
            text_color = self._warning_text
        else:
            text_key = "repair_stays_disabled"
            text_color = self._text_muted
        note_label.configure(text=self._t(text_key), text_color=text_color)

    def _update_run_buttons_state(self) -> None:
        audit_button = getattr(self, "_audit_button", None)
        if audit_button is not None:
            has_targets = bool(getattr(self, "_repo_items", []))
            has_remote_target = self._github_owner_value() is not None
            audit_disabled = self._run_in_progress or not (has_targets or has_remote_target)
            primary_fg = getattr(self, "_primary_button_fg", "#0F766E")
            primary_hover = getattr(self, "_primary_button_hover", "#0B5F59")
            disabled_fg = getattr(self, "_disabled_button_fg", "#B8C6D5")
            disabled_text = getattr(self, "_disabled_button_text", "#64748B")
            audit_button.configure(
                text=self._t("run_audit" if (has_targets or has_remote_target) else "audit_unavailable"),
                state="disabled" if audit_disabled else "normal",
                fg_color=disabled_fg if audit_disabled else primary_fg,
                hover_color=disabled_fg if audit_disabled else primary_hover,
                text_color_disabled=disabled_text,
            )

        cancel_button = getattr(self, "_cancel_button", None)
        if cancel_button is not None:
            cancel_requested = bool(
                self._active_cancel_token and self._active_cancel_token.is_cancelled()
            )
            cancel_button.configure(
                text=self._t("stopping_after_current_step" if cancel_requested else "stop_after_current_step"),
                state="normal" if (self._run_in_progress and not cancel_requested) else "disabled",
            )

        self._update_repo_selection_controls()

        repair_button = getattr(self, "_repair_button", None)
        if repair_button is None:
            return

        state = "normal" if (self._repair_ready and not self._run_in_progress) else "disabled"
        repair_button.configure(state=state, text=self._repair_button_text)
        self._update_repair_gate_note()

    def _update_repo_selection_controls(self) -> None:
        has_targets = bool(getattr(self, "_repo_items", []))
        has_remote_target = self._github_owner_value() is not None
        run_in_progress = bool(getattr(self, "_run_in_progress", False))
        selection_state = "normal" if (has_targets and not run_in_progress and not has_remote_target) else "disabled"
        repo_list = getattr(self, "repo_list", None)
        if repo_list is not None:
            try:
                repo_list.configure(state=selection_state)
            except Exception:
                pass
        for button in (
            getattr(self, "_select_all_button", None),
            getattr(self, "_clear_selection_button", None),
        ):
            if button is not None:
                button.configure(state=selection_state)

        refresh_button = getattr(self, "_refresh_button", None)
        if refresh_button is not None:
            secondary_fg = getattr(self, "_secondary_button_fg", "#F8FAFC")
            secondary_hover = getattr(self, "_secondary_button_hover", "#E6F0EC")
            disabled_fg = getattr(self, "_disabled_button_fg", "#B8C6D5")
            disabled_text = getattr(self, "_disabled_button_text", "#64748B")
            refresh_button.configure(
                state="disabled" if run_in_progress else "normal",
                fg_color=disabled_fg if run_in_progress else secondary_fg,
                hover_color=disabled_fg if run_in_progress else secondary_hover,
                text_color_disabled=disabled_text,
            )

    def _set_repair_button_text_key(self, key: str | None, **kwargs: object) -> None:
        self._repair_button_text_key = key
        self._repair_button_text_kwargs = dict(kwargs)
        if key:
            self._repair_button_text = self._t(key, **kwargs)

    def _apply_repair_locked_status(self, reason_key: str | None, reason: str | None = None) -> None:
        self._ensure_gui_theme_palette()
        default_reason_key = "lock_repair_default"
        lock_reason = reason or self._t(reason_key or default_reason_key)
        is_default = (reason_key or default_reason_key) == default_reason_key
        self._set_repair_status(
            self._t("no_audit_results")
            if is_default
            else self._t("lock_repair_message", reason=lock_reason),
            text_color=self._text_muted,
            badge_text=self._t("audit_required" if is_default else "audit_again_required"),
        )
        self._set_repair_tab_visual_lock(True, lock_reason)

    def _refresh_repair_locale_state(self) -> None:
        key = getattr(self, "_repair_button_text_key", None)
        kwargs = getattr(self, "_repair_button_text_kwargs", {})
        if key:
            self._repair_button_text = self._t(key, **kwargs)

        lock_reason_key = getattr(self, "_repair_lock_reason_key", None)
        if (
            lock_reason_key
            and not getattr(self, "_repair_ready", False)
            and getattr(self, "_repair_cooldown_remaining", 0) == 0
        ):
            self._apply_repair_locked_status(lock_reason_key)

    def _lock_repair_until_next_audit(
        self,
        reason: str | None = None,
        *,
        reason_key: str | None = None,
    ) -> None:
        resolved_reason_key = reason_key or ("lock_repair_default" if reason is None else None)
        lock_reason = reason or self._t(resolved_reason_key or "lock_repair_default")
        self._cancel_repair_cooldown()
        self._repair_ready = False
        self._repair_cooldown_remaining = 0
        self._repair_lock_reason_key = resolved_reason_key
        if resolved_reason_key:
            self._set_repair_button_text_key(resolved_reason_key)
        else:
            self._repair_button_text_key = None
            self._repair_button_text_kwargs = {}
            self._repair_button_text = lock_reason
        self._apply_repair_locked_status(resolved_reason_key, lock_reason)
        self._update_run_buttons_state()

    def _start_repair_cooldown(
        self,
        reports_payload: list[dict[str, object]],
        selection_signature: tuple[str, ...] | None,
    ) -> None:
        self._last_audit_reports_payload = reports_payload
        self._last_audit_selection_signature = selection_signature

        if not reports_payload:
            self._lock_repair_until_next_audit(reason_key="lock_repair_no_results")
            return

        self._cancel_repair_cooldown()
        self._repair_ready = False
        self._repair_cooldown_remaining = self._repair_cooldown_seconds
        self._repair_lock_reason_key = None
        self._set_repair_button_text_key("repair_wait", seconds=self._repair_cooldown_remaining)
        self._set_repair_status(
            self._build_repair_status_summary(reports_payload)
            + self._t("repair_unlocks_after_review"),
            text_color=self._warning_text,
            badge_text=self._t("review_window"),
            panel_fg=self._warning_panel_fg,
            panel_border=self._warning_panel_border,
            badge_fg=self._repair_warning_badge_fg,
            badge_text_color=self._warning_text,
        )
        self._set_repair_tab_visual_lock(False)
        self._update_run_buttons_state()
        self.log(
            "[INFO] Repair unlocks in 10 seconds to enforce a minimum review window."
        )
        self._repair_cooldown_after_id = self.root.after(1000, self._tick_repair_cooldown)

    def _tick_repair_cooldown(self) -> None:
        self._repair_cooldown_after_id = None
        if self._repair_cooldown_remaining <= 1:
            self._repair_ready = True
            self._repair_cooldown_remaining = 0
            self._repair_lock_reason_key = None
            self._set_repair_button_text_key("repair")
            failed = sum(1 for item in self._last_audit_reports_payload if item.get("status") == "FAIL")
            self._set_repair_status(
                self._build_repair_status_summary(self._last_audit_reports_payload)
                + self._t("repair_now_available"),
                text_color=self._danger_text if failed else self._success_text,
                badge_text=self._t("repair_ready" if failed else "optional_cleanup"),
                panel_fg=self._warning_panel_fg if failed else self._success_panel_fg,
                panel_border=self._warning_panel_border if failed else self._success_panel_border,
                badge_fg=self._repair_warning_badge_fg if failed else self._pass_badge_fg,
                badge_text_color=self._warning_text if failed else self._pass_badge_text,
            )
            self._update_run_buttons_state()
            self.log("[INFO] Repair unlocked.")
            return

        self._repair_cooldown_remaining -= 1
        self._repair_lock_reason_key = None
        self._set_repair_button_text_key("repair_wait", seconds=self._repair_cooldown_remaining)
        self._set_repair_status(
            self._build_repair_status_summary(self._last_audit_reports_payload)
            + self._t("repair_unlocks_in", seconds=self._repair_cooldown_remaining),
            text_color=self._warning_text,
            badge_text=self._t("review_window"),
            panel_fg=self._warning_panel_fg,
            panel_border=self._warning_panel_border,
            badge_fg=self._repair_warning_badge_fg,
            badge_text_color=self._warning_text,
        )
        self._update_run_buttons_state()
        self._repair_cooldown_after_id = self.root.after(1000, self._tick_repair_cooldown)

    def _is_risky_repair_selected(self) -> bool:
        return bool(
            self.push_var.get()
            or self.purge_all_detected_secret_files_var.get()
            or self.allow_non_owner_push_var.get()
        )

    def _report_list(self, payload: dict[str, object], key: str) -> list[str]:
        value = payload.get(key)
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if isinstance(item, str)]

    def _build_repair_confirmation_text(self, selected_signature: tuple[str, ...] | None) -> str:
        risky_mode = self._is_risky_repair_selected()
        allowed_owners = normalize_csv_values(self.allowed_remote_owners_var.get())
        owners_text = ", ".join(allowed_owners) if allowed_owners else self._t("auto_owner")
        yes_text = self._t("yes")
        no_text = self._t("no")

        lines = [
            self._t("repair_plan_intro"),
            "",
            self._t("active_options"),
            self._t("plan_rewrite_paths", value=yes_text if self.rewrite_personal_paths_var.get() else no_text),
            self._t("plan_replace_text", value=self.replace_text_file_var.get().strip() or no_text),
            self._t("plan_purge_safe", value=yes_text if self.purge_detected_secret_files_var.get() else no_text),
            self._t("plan_purge_risky", value=yes_text if self.purge_all_detected_secret_files_var.get() else no_text),
            self._t("plan_force_push", value=yes_text if self.push_var.get() else no_text),
            self._t("plan_open_report", value=yes_text if self.open_report_var.get() else no_text),
            self._t("plan_confirm_each_repo", value=yes_text if self.confirm_each_repo_fix_var.get() else no_text),
            self._t("plan_allow_bypass", value=yes_text if self.allow_non_owner_push_var.get() else no_text),
            self._t("plan_allowed_owners", value=owners_text),
            "",
            self._t("repair_baseline_changes"),
            self._t("baseline_gitignore"),
            self._t("baseline_untrack"),
            self._t("baseline_rewrite"),
        ]

        if risky_mode:
            lines.extend(
                [
                    "",
                    self._t("risky_warning_1"),
                    self._t("risky_warning_2"),
                ]
            )

        lines.append("")
        lines.append(self._t("audited_findings_summary"))

        for rep in self._last_audit_reports_payload:
            name = str(rep.get("name", "(repo)"))
            status = str(rep.get("status", "UNKNOWN"))
            lines.append(self._t("repo_status_line", name=name, status=status))
            lines.append(self._t("blocking_categories_line", count=self._report_item_count(rep, "failures")))
            lines.append(self._t("manual_review_signals_line", count=self._manual_review_signal_count(rep)))
            safe_context_count = self._safe_context_count(rep)
            if safe_context_count:
                lines.append(self._t("fixture_context_line", count=safe_context_count))

            tracked_ignored = self._report_list(rep, "tracked_but_ignored")
            if tracked_ignored:
                lines.append(self._t("planned_untrack_line", count=len(tracked_ignored)))

            if self.rewrite_personal_paths_var.get():
                path_findings = self._report_list(rep, "tracked_path_matches") + self._report_list(
                    rep,
                    "history_path_matches",
                )
                lines.append(self._t("planned_path_rewrite_line", count=len(path_findings)))
            else:
                lines.append(self._t("personal_paths_disabled"))

            if self.purge_all_detected_secret_files_var.get():
                purge_targets = self._report_list(rep, "secret_file_candidates")
                lines.append(self._t("planned_purge_risky_line", count=len(purge_targets)))
                for item in purge_targets[:4]:
                    lines.append(f"    - {item}")
                if len(purge_targets) > 4:
                    lines.append(self._t("more_items", count=len(purge_targets) - 4))
            elif self.purge_detected_secret_files_var.get():
                purge_targets = self._report_list(rep, "secret_file_autopurge_candidates")
                lines.append(self._t("planned_purge_safe_line", count=len(purge_targets)))
                for item in purge_targets[:4]:
                    lines.append(f"    - {item}")
                if len(purge_targets) > 4:
                    lines.append(self._t("more_items", count=len(purge_targets) - 4))
            else:
                lines.append(self._t("secret_purge_disabled"))

        lines.extend(
            [
                "",
                self._t("continue_question"),
                self._t("rerun_if_changed"),
            ]
        )
        return "\n".join(lines)

    def _confirm_repair_run(self, selected_signature: tuple[str, ...] | None) -> bool:
        if not self._repair_ready:
            self.messagebox.showwarning(
                self._t("dialog_repair_locked_title"),
                self._t("dialog_repair_locked_review"),
            )
            return False

        if not self._last_audit_reports_payload:
            self.messagebox.showwarning(
                self._t("dialog_repair_locked_title"),
                self._t("dialog_repair_locked_no_results"),
            )
            return False

        if selected_signature != self._last_audit_selection_signature:
            self.messagebox.showwarning(
                self._t("dialog_new_audit_required_title"),
                self._t("dialog_new_audit_required"),
            )
            return False

        plan_message = self._build_repair_confirmation_text(selected_signature)
        confirmed = self.messagebox.askyesno(self._t("dialog_confirm_repair_title"), plan_message)
        if not confirmed:
            return False

        if self._is_risky_repair_selected():
            accepted = self.messagebox.askyesno(
                self._t("dialog_risk_title"),
                self._t("dialog_risk_message"),
            )
            if not accepted:
                return False

        return True

    def _on_gui_run_finished(
        self,
        run_fix: bool,
        selection_signature: tuple[str, ...] | None,
        reports_payload: list[dict[str, object]],
        exit_code: int,
    ) -> None:
        self._run_in_progress = False
        self._active_cancel_token = None
        if run_fix:
            self._lock_repair_until_next_audit(reason_key="lock_repair_run_again")
            self._set_active_flow_tab(self._repair_tab_name)
            return

        if exit_code == EXIT_ABORTED:
            self._lock_repair_until_next_audit(reason_key="lock_repair_cancelled")
            self._set_active_flow_tab(self._audit_tab_name)
            self.log("[INFO] Flow: audit cancelled. Run Audit again when you are ready to continue.")
            return

        if exit_code == EXIT_RUNTIME_ERROR:
            self._lock_repair_until_next_audit(reason_key="lock_repair_failed")
            self._set_active_flow_tab(self._audit_tab_name)
            self.log("[INFO] Flow: audit ended with an operational error. Repair remains locked.")
            return

        if selection_signature and selection_signature[0] == "github-owner":
            self._lock_repair_until_next_audit(reason_key="lock_repair_remote")
            self._set_active_flow_tab(self._reports_tab_name)
            self.log("[INFO] Flow: GitHub owner/org audit finished. Review artifacts in the Reports tab. Remote audit mode is audit-only.")
            return

        self._start_repair_cooldown(reports_payload, selection_signature)
        self._set_active_flow_tab(self._reports_tab_name)
        self.log("[INFO] Flow: audit finished. Review artifacts in the Reports tab, then continue to Repair only if needed.")

    def log(self, msg: str) -> None:
        self._set_output_empty_state(False)
        self.output.insert("end", msg + "\n")
        self.output.see("end")

    def clear_output(self) -> None:
        self.output.delete("1.0", "end")
        self._set_output_empty_state(True)

    def cancel_run_clicked(self) -> None:
        token = self._active_cancel_token
        if not self._run_in_progress or token is None:
            return
        if token.is_cancelled():
            return
        token.request_cancel()
        self.log(
            "[INFO] Cancellation requested. The current repository step will finish before the run stops."
        )
        self._update_run_buttons_state()

    def clear_selection(self) -> None:
        if not self._repo_items:
            return
        self.repo_list.selection_clear(0, "end")
        self._update_repo_summary()

    def select_all(self) -> None:
        if not self._repo_items:
            return
        self.repo_list.select_set(0, "end")
        self._update_repo_summary()

    def _on_repo_selection_changed(self, _event=None) -> None:
        self._update_repo_summary()

    def refresh_repos(self) -> None:
        if getattr(self, "_run_in_progress", False):
            self.log("[INFO] Refresh is disabled while a run is in progress.")
            return
        self.repo_list.delete(0, "end")
        self._repo_items = []
        if self._sync_remote_target_surface():
            self._update_repo_summary()
            self._update_run_buttons_state()
            return
        root = Path(self.root_var.get())
        root_error = validate_repository_root(root)
        if root_error:
            if root_error.startswith("Root folder does not exist:"):
                message = self._t("choose_valid_root")
            elif root_error.startswith("Root path is not a directory:"):
                message = self._t("choose_valid_root")
            else:
                message = f"{root_error}\n{self._t('choose_valid_root')}"
            self._set_repo_empty_state(
                True,
                message,
                reason="invalid_root",
            )
            self._update_repo_summary()
            self._update_run_buttons_state()
            return

        discovered, _skipped, discovery_error = discover_repository_targets(root, repo_filters=None)
        if discovery_error:
            self._set_repo_empty_state(
                True,
                f"{discovery_error}\n{self._t('choose_valid_root')}",
                reason="invalid_root",
            )
            self._update_repo_summary()
            self._update_run_buttons_state()
            return

        for repo in discovered:
            if repo == root:
                self._repo_items.append((f"{root.name} ({self._t('current_root_label')})", "."))
            else:
                self._repo_items.append((repo.name, repo.name))

        for label, _value in self._repo_items:
            self.repo_list.insert("end", label)

        if len(self._repo_items) == 1:
            self.repo_list.selection_set(0)

        self._set_repo_empty_state(
            not self._repo_items,
            self._t("repo_summary_no_repos"),
            reason="no_repos",
        )
        self._update_repo_summary()
        self._update_run_buttons_state()

    def _selected_repo_names(self) -> list[str]:
        return [self._repo_items[i][1] for i in self.repo_list.curselection() if i < len(self._repo_items)]

    def _read_identity_inputs(self) -> tuple[str, str]:
        user_name = self.git_user_name_var.get().strip()
        user_email = self.git_user_email_var.get().strip()
        return user_name, user_email

    def _handle_identity_validation(self, user_name: str, user_email: str) -> bool:
        errors = validate_git_identity_inputs(user_name, user_email)
        if not errors:
            return True
        self.messagebox.showerror(self._t("dialog_invalid_git_identity"), "\n".join(errors))
        return False

    def _show_identity_result(self, title: str, success: bool, message: str) -> None:
        if success:
            self.log(f"[INFO] {message}")
            self.messagebox.showinfo(title, message)
            return
        self.log(f"[ERROR] {message}")
        self.messagebox.showerror(title, message)

    def apply_git_identity_global_clicked(self) -> None:
        user_name, user_email = self._read_identity_inputs()
        if not self._handle_identity_validation(user_name, user_email):
            return

        confirmed = self.messagebox.askyesno(
            self._t("dialog_confirm_global_git_config"),
            self._t("dialog_confirm_global_git_config_message"),
        )
        if not confirmed:
            return

        ok, msg = apply_git_identity_config(
            scope="global",
            user_name=user_name,
            user_email=user_email,
            repo_path=None,
        )
        if ok:
            self.owner_name_var.set(user_name)
            self.noreply_var.set(user_email)
        self._show_identity_result(self._t("dialog_global_git_config"), ok, msg)

    def apply_git_identity_local_clicked(self) -> None:
        user_name, user_email = self._read_identity_inputs()
        if not self._handle_identity_validation(user_name, user_email):
            return

        repo_path, error = resolve_identity_repo_path(Path(self.root_var.get()), self._selected_repo_names())
        if error:
            self.messagebox.showwarning(self._t("dialog_local_git_config"), error)
            return

        ok, msg = apply_git_identity_config(
            scope="local",
            user_name=user_name,
            user_email=user_email,
            repo_path=repo_path,
        )
        if ok:
            self.owner_name_var.set(user_name)
            self.noreply_var.set(user_email)
        self._show_identity_result(self._t("dialog_local_git_config"), ok, msg)

    def read_git_identity_clicked(self) -> None:
        selected_repos = self._selected_repo_names()
        if len(selected_repos) > 1:
            self.messagebox.showwarning(
                self._t("dialog_read_git_identity"),
                self._t("dialog_read_git_identity_select_one"),
            )
            return

        repo_path: Path | None = None
        root = Path(self.root_var.get())
        if len(selected_repos) == 1:
            candidate = root / selected_repos[0]
            if not (candidate / ".git").exists():
                self.messagebox.showwarning(
                    self._t("dialog_read_git_identity"),
                    self._t("dialog_not_git_repo", candidate=candidate),
                )
                return
            repo_path = candidate
        elif (root / ".git").exists():
            repo_path = root

        config_values = read_git_identity_config(repo_path=repo_path)
        self.messagebox.showinfo(
            self._t("dialog_current_git_identity"),
            format_git_identity_status(config_values, repo_path),
        )
        self.log("[INFO] Read current Git identity configuration.")

    def open_github_email_settings_clicked(self) -> None:
        ok, msg = open_github_email_settings()
        self._show_identity_result(self._t("dialog_github_email_settings"), ok, msg)

    def run_clicked(self, run_fix: bool) -> None:
        if self._run_in_progress:
            self.messagebox.showinfo(
                self._t("dialog_run_in_progress"),
                self._t("dialog_run_in_progress_message"),
            )
            return

        self._set_active_flow_tab(self._repair_tab_name if run_fix else self._audit_tab_name)

        github_owner = self._github_owner_value()
        if run_fix and github_owner:
            self.messagebox.showwarning(
                self._t("dialog_remote_audit_only"),
                self._t("dialog_remote_audit_only_message"),
            )
            return

        if github_owner:
            repos_to_run = self._github_repo_filters()
        else:
            selected = self._selected_repo_names()
            repos_to_run = normalize_repo_filters(selected)
        selection_signature = self._run_selection_signature(repos_to_run, github_owner=github_owner)
        if repos_to_run is None and not github_owner:
            action_name = self._t("action_repair" if run_fix else "action_audit")
            run_all = self.messagebox.askyesno(
                self._t("dialog_run_all_title"),
                self._t("dialog_run_all_message", action_name=action_name),
            )
            if not run_all:
                return
            selection_signature = None

        if run_fix and not self._confirm_repair_run(selection_signature):
            return

        try:
            max_matches = parse_positive_int(self.max_matches_var.get().strip())
        except argparse.ArgumentTypeError:
            self.messagebox.showwarning(
                self._t("dialog_invalid_max_matches"),
                self._t("dialog_invalid_max_matches_message"),
            )
            return

        if github_owner:
            try:
                parse_positive_int(self.github_jobs_var.get().strip())
            except argparse.ArgumentTypeError:
                self.messagebox.showwarning(
                    self._t("dialog_invalid_github_jobs"),
                    self._t("dialog_invalid_github_jobs_message"),
                )
                return

        if not run_fix:
            self._lock_repair_until_next_audit(reason_key="lock_repair_in_progress")

        self._save_gui_setup_settings(setup_completed=True)
        self._set_setup_settings_visibility(False)

        self._run_in_progress = True
        self._active_cancel_token = CancellationToken()
        self._update_run_buttons_state()

        thread = threading.Thread(
            target=self._run_worker,
            args=(repos_to_run, max_matches, run_fix, selection_signature),
            daemon=True,
        )
        thread.start()

    def _run_worker(
        self,
        selected: list[str] | None,
        max_matches: int,
        run_fix: bool,
        selection_signature: tuple[str, ...] | None,
    ) -> None:
        try:
            root = Path(self.root_var.get())
            policy = Path(self.policy_var.get())
            owner_emails = normalize_csv_values(self.owner_emails_var.get())
            allowed_remote_owners = normalize_csv_values(self.allowed_remote_owners_var.get())
            requested_report_dir = self.report_dir_var.get().strip() or str(default_results_dir())
            enforced_results_dir, forced = enforce_results_dir(Path(requested_report_dir))
            report_json = self.report_json_var.get().strip() or None
            replace_text_file = self.replace_text_file_var.get().strip() or None
            github_owner = self._github_owner_value()
            github_jobs = parse_positive_int(self.github_jobs_var.get().strip()) if github_owner else 4

            def _ui_sink(message: str) -> None:
                def _emit() -> None:
                    self.log(message)

                self.root.after(0, _emit)

            artifacts = create_run_artifacts(enforced_results_dir)
            gui_logger = RunLogger(
                artifacts.log_path,
                sink=_ui_sink,
            )
            if forced:
                gui_logger(
                    f"[WARN] report-dir was forced to {default_results_dir()} to comply with mandatory Audit_Results policy"
                )
            gui_logger(f"[INFO] Run artifacts directory: {artifacts.run_dir}")
            gui_logger(f"[INFO] Run state manifest: {artifacts.state_path}")
            gui_logger(f"[INFO] GUI action: {'repair' if run_fix else 'audit'}")

            config = build_guard_run_config(
                mode="gui",
                root=root,
                policy=policy,
                repos=selected,
                public_only=self.public_only_var.get(),
                fix=run_fix,
                push=(run_fix and self.push_var.get()),
                dry_run=self.dry_run_var.get(),
                redact_third_party_emails=self.redact_var.get(),
                purge_detected_secret_files=(run_fix and self.purge_detected_secret_files_var.get()),
                purge_all_detected_secret_files=(run_fix and self.purge_all_detected_secret_files_var.get()),
                rewrite_personal_paths=(run_fix and self.rewrite_personal_paths_var.get()),
                low_confidence_email_mode=(
                    "blocking" if self.low_confidence_blocking_var.get() else "informational"
                ),
                owner_name=self.owner_name_var.get().strip() or "Owner",
                owner_emails=owner_emails,
                noreply_email=self.noreply_var.get().strip(),
                placeholder_email=self.placeholder_var.get().strip(),
                max_matches=max_matches,
                confirm_each_repo_fix=self.confirm_each_repo_fix_var.get(),
                open_report=self.open_report_var.get(),
                allow_non_owner_push=(run_fix and self.allow_non_owner_push_var.get()),
                allowed_remote_owners=allowed_remote_owners,
                replace_text_file=(replace_text_file if run_fix else None),
                report_json=report_json,
                github_owner=github_owner,
                github_include_forks=self.github_include_forks_var.get(),
                github_fast=self.github_fast_var.get(),
                github_jobs=github_jobs,
                audit_litellm_incident=self.audit_litellm_incident_var.get(),
                audit_github_hardening=self.audit_github_hardening_var.get(),
            )

            def _confirm_repo_fix(repo: Path, index: int, total: int) -> bool:
                result: dict[str, bool] = {"value": False}
                done = threading.Event()

                def _ask() -> None:
                    try:
                        result["value"] = bool(
                            self.messagebox.askyesno(
                                self._t("confirm_repo_repair_title"),
                                self._t(
                                    "confirm_repo_repair_message",
                                    index=index,
                                    total=total,
                                    repo_name=repo_display_name(repo),
                                ),
                            )
                        )
                    finally:
                        done.set()

                self.root.after(0, _ask)
                done.wait()
                return bool(result["value"])

            exit_code = execute_guard_pipeline(
                config=config,
                artifacts=artifacts,
                logger=gui_logger,
                results_dir=enforced_results_dir,
                require_confirmation=False,
                confirm_callback=None,
                confirm_repo_fix_callback=(
                    _confirm_repo_fix if run_fix and config.confirm_each_repo_fix else None
                ),
                cancel_callback=(
                    self._active_cancel_token.is_cancelled if self._active_cancel_token is not None else None
                ),
            )

            reports_payload: list[dict[str, object]] = []
            if not run_fix:
                try:
                    loaded = json.loads(artifacts.json_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, list):
                        reports_payload = [item for item in loaded if isinstance(item, dict)]
                except Exception:
                    reports_payload = []

            def _finish_ui() -> None:
                self._remember_last_run_artifacts(
                    artifacts,
                    run_fix=run_fix,
                    exit_code=exit_code,
                    reports_payload=reports_payload,
                )
                self._on_gui_run_finished(run_fix, selection_signature, reports_payload, exit_code)
                if exit_code != 0:
                    self.log(f"[INFO] Run finished with exit code: {exit_code}")

            self.root.after(0, _finish_ui)
        except Exception:
            error_trace = traceback.format_exc().strip()

            def _finish_ui_error() -> None:
                self.log("[ERROR] GUI worker failed unexpectedly.")
                self.log(error_trace)
                self._on_gui_run_finished(run_fix, selection_signature, [], EXIT_RUNTIME_ERROR)

            self.root.after(0, _finish_ui_error)

    def run(self) -> None:
        self.root.mainloop()


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
    artifacts = create_run_artifacts(enforced_results_dir)
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
