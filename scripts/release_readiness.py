#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import os
from os import PathLike
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import Repo_Privacy_Guardian as rpg  # noqa: E402


DEFAULT_TIMEOUTS = {
    "quick": 120,
    "test": 1200,
    "build": 900,
    "install": 900,
    "audit": 900,
}
DEPENDENCY_AUDIT_REQUIREMENT_FILES = (
    "config/requirements/requirements-dev.txt",
    "config/requirements/requirements-gui.txt",
    "config/requirements/requirements-remediation.txt",
)
RELEASE_BYTE_COMPILE_PATHS = (
    "Repo_Privacy_Guardian.py",
    "repo_privacy_guardian/__init__.py",
    "repo_privacy_guardian/agent_summary.py",
    "repo_privacy_guardian/artifacts.py",
    "repo_privacy_guardian/config.py",
    "repo_privacy_guardian/core.py",
    "repo_privacy_guardian/evidence_taxonomy.py",
    "repo_privacy_guardian/execution.py",
    "repo_privacy_guardian/gui/__init__.py",
    "repo_privacy_guardian/gui/app.py",
    "repo_privacy_guardian/gui/assets.py",
    "repo_privacy_guardian/gui/locale.py",
    "repo_privacy_guardian/gui/state.py",
    "repo_privacy_guardian/gui/theme.py",
    "repo_privacy_guardian/history_parsing.py",
    "repo_privacy_guardian/github.py",
    "repo_privacy_guardian/github_fix_guide.py",
    "repo_privacy_guardian/metrics.py",
    "repo_privacy_guardian/policy.py",
    "repo_privacy_guardian/prompts.py",
    "repo_privacy_guardian/redaction.py",
    "repo_privacy_guardian/remediation.py",
    "repo_privacy_guardian/report_diff.py",
    "repo_privacy_guardian/reporting.py",
    "repo_privacy_guardian/runtime.py",
    "repo_privacy_guardian/scanner.py",
    "repo_privacy_guardian/strict_profiles.py",
    "repo_privacy_guardian/suppressions.py",
    "repo_privacy_guardian/tooling.py",
    "repo_privacy_guardian_artifacts.py",
    "repo_privacy_guardian_github.py",
    "repo_privacy_guardian_prompts.py",
    "repo_privacy_guardian_runtime.py",
    "scripts/check_release_contract.py",
    "scripts/release_readiness.py",
    "scripts/visual_qa_gui.py",
)
BUILD_ARTIFACT_CLEANUP_ATTEMPTS = 5
BUILD_ARTIFACT_CLEANUP_RETRY_SECONDS = 1.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run local release-readiness checks for Repo Privacy Guardian.",
    )
    parser.add_argument(
        "--repo-root",
        default=str(REPO_ROOT),
        help="Repository root to validate. Defaults to the current checkout.",
    )
    parser.add_argument(
        "--skip-clean-build-artifacts",
        action="store_true",
        help="Do not remove stale dist/build/*.egg-info outputs before building.",
    )
    parser.add_argument(
        "--skip-gui-smoke",
        action="store_true",
        help="Skip the GUI smoke test.",
    )
    parser.add_argument(
        "--skip-self-audit",
        action="store_true",
        help="Skip the final self-audit run.",
    )
    parser.add_argument(
        "--skip-dependency-audit",
        action="store_true",
        help="Skip pip-audit vulnerability checks for pinned requirement files.",
    )
    parser.add_argument(
        "--self-audit-root",
        default=None,
        help="Root directory to pass to the self-audit command. Defaults to the parent of repo-root.",
    )
    parser.add_argument(
        "--self-audit-repo",
        default=None,
        help="Repository name to pass to the self-audit command. Defaults to the current repo directory name.",
    )
    return parser.parse_args(argv)


def log(message: str) -> None:
    print(f"[RELEASE-CHECK] {message}")


def run_command(
    cmd: list[str | PathLike[str]],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> None:
    log(f"Running: {subprocess.list2cmdline([str(part) for part in cmd])}")
    proc = subprocess.run(
        [str(part) for part in cmd],
        cwd=str(cwd),
        timeout=timeout,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def run_named_command(
    name: str,
    cmd: list[str | PathLike[str]],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str] | None = None,
) -> None:
    log(name)
    run_command(cmd, cwd=cwd, timeout=timeout, env=env)


def is_clean_worktree(repo_root: Path) -> bool:
    proc = subprocess.run(
        ["git", "status", "--short"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    return proc.returncode == 0 and not proc.stdout.strip()


def _validate_cleanup_target(repo_root: Path, target: Path) -> Path:
    resolved_root = repo_root.resolve()
    resolved_target = target.resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_root)
    except ValueError as exc:
        raise RuntimeError(f"Refusing to clean path outside repository root: {target}") from exc
    return resolved_target


def _path_has_existing_symlink_component(path: Path) -> bool:
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


def _remove_tree_if_present(repo_root: Path, target: Path) -> None:
    if _path_has_existing_symlink_component(target):
        raise RuntimeError(f"Refusing to recursively remove symlinked path: {target}")
    if not target.exists():
        return
    validated = _validate_cleanup_target(repo_root, target)
    if validated.is_symlink():
        raise RuntimeError(f"Refusing to recursively remove symlinked path: {validated}")
    log(f"Removing stale build output: {validated}")
    last_exc: OSError | None = None
    for attempt in range(1, BUILD_ARTIFACT_CLEANUP_ATTEMPTS + 1):
        try:
            shutil.rmtree(validated, ignore_errors=False)
            return
        except FileNotFoundError:
            return
        except PermissionError as exc:
            last_exc = exc
        except OSError as exc:
            if getattr(exc, "errno", None) not in {errno.EACCES, errno.EPERM, errno.EBUSY}:
                raise
            last_exc = exc

        if attempt >= BUILD_ARTIFACT_CLEANUP_ATTEMPTS:
            break
        log(
            f"Retrying stale build output cleanup ({attempt}/{BUILD_ARTIFACT_CLEANUP_ATTEMPTS}) after: {last_exc}"
        )
        time.sleep(BUILD_ARTIFACT_CLEANUP_RETRY_SECONDS)

    raise RuntimeError(f"Unable to remove stale build output after retries: {validated}") from last_exc


def remove_stale_build_outputs(repo_root: Path) -> None:
    for rel in ("dist", "build"):
        target = repo_root / rel
        _remove_tree_if_present(repo_root, target)

    for egg_info in repo_root.glob("*.egg-info"):
        _remove_tree_if_present(repo_root, egg_info)


def venv_python(venv_dir: Path) -> Path:
    candidate = venv_dir / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    if not candidate.exists():
        raise FileNotFoundError(f"Virtualenv python not found: {candidate}")
    return candidate


def venv_console(venv_dir: Path, name: str) -> Path:
    scripts_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")
    suffixes = [".exe", ".cmd", ".bat", ""] if os.name == "nt" else [""]
    for suffix in suffixes:
        candidate = scripts_dir / f"{name}{suffix}"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Console entrypoint not found for {name} in {scripts_dir}")


def install_smoke_for_artifact(repo_root: Path, artifact: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="rpg-release-check-") as temp_dir:
        venv_dir = Path(temp_dir) / "venv"
        run_command([sys.executable, "-m", "venv", str(venv_dir)], cwd=repo_root, timeout=DEFAULT_TIMEOUTS["install"])
        py = venv_python(venv_dir)
        run_command([py, "-m", "pip", "install", "--upgrade", "pip"], cwd=repo_root, timeout=DEFAULT_TIMEOUTS["install"])
        run_command([py, "-m", "pip", "install", str(artifact)], cwd=repo_root, timeout=DEFAULT_TIMEOUTS["install"])
        run_command([py, "-m", "pip", "check"], cwd=repo_root, timeout=DEFAULT_TIMEOUTS["quick"])
        run_command([venv_console(venv_dir, "repo-privacy-guardian"), "--help"], cwd=repo_root, timeout=DEFAULT_TIMEOUTS["quick"])
        run_command([py, "-m", "Repo_Privacy_Guardian", "--help"], cwd=repo_root, timeout=DEFAULT_TIMEOUTS["quick"])
        run_command(
            [
                py,
                "-c",
                "from pathlib import Path; import Repo_Privacy_Guardian as rpg; "
                "assert Path(rpg.DEFAULT_POLICY).exists(), rpg.DEFAULT_POLICY",
            ],
            cwd=repo_root,
            timeout=DEFAULT_TIMEOUTS["quick"],
        )


def latest_artifact(repo_root: Path, pattern: str) -> Path:
    matches = sorted((repo_root / "dist").glob(pattern))
    if not matches:
        raise FileNotFoundError(f"No build artifact matches {pattern}")
    return matches[-1]


def create_release_runtime_workspace() -> Path:
    runtime_dir = Path(tempfile.mkdtemp(prefix="rpg-release-runtime-"))
    log(f"Release runtime workspace: {runtime_dir}")
    return runtime_dir


def cleanup_release_runtime_workspace(runtime_dir: Path) -> None:
    removed, cleanup_error = rpg.remove_private_temp_tree(
        runtime_dir,
        required_prefix="rpg-release-runtime-",
    )
    if not removed:
        log(f"WARNING: could not remove release runtime workspace: {cleanup_error}")


def build_release_pytest_artifact_paths(runtime_dir: Path) -> tuple[Path, Path]:
    return runtime_dir / "pytest", runtime_dir / ".coverage"


def run_dependency_audits(repo_root: Path) -> None:
    for rel_path in DEPENDENCY_AUDIT_REQUIREMENT_FILES:
        run_named_command(
            f"Auditing Python dependencies ({rel_path})",
            [sys.executable, "-m", "pip_audit", "-r", rel_path],
            cwd=repo_root,
            timeout=DEFAULT_TIMEOUTS["quick"],
        )


def run_release_verification_steps(
    repo_root: Path,
    args: argparse.Namespace,
    *,
    runtime_dir: Path,
) -> None:
    pytest_base_temp, coverage_file = build_release_pytest_artifact_paths(runtime_dir)
    run_named_command(
        "CLI tooling preflight",
        [sys.executable, "-m", "Repo_Privacy_Guardian", "--check-tooling"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Checking release contract",
        [sys.executable, "scripts/check_release_contract.py"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Byte-compiling release Python surfaces",
        [
            sys.executable,
            "-m",
            "py_compile",
            *RELEASE_BYTE_COMPILE_PATHS,
        ],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Running ruff check",
        [sys.executable, "-m", "ruff", "check", "."],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Running pyright",
        ["pyright", "-p", "pyrightconfig.json"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    if args.skip_dependency_audit:
        log("Skipping dependency vulnerability audit by request.")
    else:
        run_dependency_audits(repo_root)
    run_named_command(
        "Running tracked pytest suite",
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--basetemp",
            str(pytest_base_temp),
            f"--cov-report=xml:{runtime_dir / 'coverage.xml'}",
        ],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["test"],
        env={
            **os.environ,
            "COVERAGE_FILE": str(coverage_file),
        },
    )
    run_named_command(
        "Running CLI smoke test",
        [sys.executable, "tests/release_smoke_cli.py"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    if args.skip_gui_smoke:
        log("Skipping GUI smoke by request.")
    else:
        run_named_command(
            "Running GUI smoke test",
            [sys.executable, "tests/release_smoke_gui.py"],
            cwd=repo_root,
            timeout=DEFAULT_TIMEOUTS["quick"],
        )
    run_named_command(
        "Checking module help",
        [sys.executable, "-m", "Repo_Privacy_Guardian", "--help"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Checking direct script help",
        [sys.executable, "Repo_Privacy_Guardian.py", "--help"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Building wheel and sdist",
        [sys.executable, "-m", "build"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["build"],
    )


def maybe_run_self_audit(repo_root: Path, args: argparse.Namespace) -> None:
    if args.skip_self_audit:
        log("Skipping self-audit by request.")
        return
    if not is_clean_worktree(repo_root):
        log("Skipping self-audit because the worktree is not clean yet. Commit or stash changes, then re-run for a final PASS/FAIL check.")
        return

    audit_root = Path(args.self_audit_root) if args.self_audit_root else repo_root.parent
    audit_repo = args.self_audit_repo or repo_root.name
    cmd = [
        sys.executable,
        "-m",
        "Repo_Privacy_Guardian",
        "--root",
        str(audit_root),
        "--repos",
        audit_repo,
        "--dry-run",
        "--yes",
    ]
    if rpg.resolve_github_hardening_token():
        cmd.append("--audit-github-hardening")
    else:
        log("GitHub hardening auth is not available; self-audit will run without remote hardening checks.")
    run_command(cmd, cwd=repo_root, timeout=DEFAULT_TIMEOUTS["audit"])


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = Path(args.repo_root).resolve()

    if repo_root != REPO_ROOT.resolve():
        raise SystemExit(f"--repo-root must point at this checkout for now: {REPO_ROOT}")

    log(f"Repository root: {repo_root}")
    if not args.skip_clean_build_artifacts:
        remove_stale_build_outputs(repo_root)
    runtime_dir = create_release_runtime_workspace()
    try:
        run_release_verification_steps(repo_root, args, runtime_dir=runtime_dir)
        install_smoke_for_artifact(repo_root, latest_artifact(repo_root, "*.whl"))
        install_smoke_for_artifact(repo_root, latest_artifact(repo_root, "*.tar.gz"))
        maybe_run_self_audit(repo_root, args)
    finally:
        cleanup_release_runtime_workspace(runtime_dir)
    log("Release-readiness checks completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
