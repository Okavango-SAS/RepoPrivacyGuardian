#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import Repo_Privacy_Guardian as rpg


DEFAULT_TIMEOUTS = {
    "quick": 120,
    "test": 1200,
    "build": 900,
    "install": 900,
    "audit": 900,
}


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
    cmd: list[str],
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
    )
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def run_named_command(
    name: str,
    cmd: list[str],
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
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    return proc.returncode == 0 and not proc.stdout.strip()


def remove_stale_build_outputs(repo_root: Path) -> None:
    for rel in ("dist", "build"):
        target = repo_root / rel
        if target.exists():
            log(f"Removing stale build output: {target}")
            shutil.rmtree(target, ignore_errors=True)

    for egg_info in repo_root.glob("*.egg-info"):
        if egg_info.exists():
            log(f"Removing stale egg-info output: {egg_info}")
            shutil.rmtree(egg_info, ignore_errors=True)


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


def run_release_verification_steps(repo_root: Path, args: argparse.Namespace) -> None:
    run_named_command(
        "CLI tooling preflight",
        [sys.executable, "-m", "Repo_Privacy_Guardian", "--check-tooling"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Byte-compiling the main module",
        [sys.executable, "-m", "py_compile", "Repo_Privacy_Guardian.py"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["quick"],
    )
    run_named_command(
        "Running tracked pytest suite",
        [sys.executable, "-m", "pytest", "-q"],
        cwd=repo_root,
        timeout=DEFAULT_TIMEOUTS["test"],
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

    run_release_verification_steps(repo_root, args)

    install_smoke_for_artifact(repo_root, latest_artifact(repo_root, "*.whl"))
    install_smoke_for_artifact(repo_root, latest_artifact(repo_root, "*.tar.gz"))
    maybe_run_self_audit(repo_root, args)
    log("Release-readiness checks completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
