from __future__ import annotations

from collections.abc import Callable
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import Repo_Privacy_Guardian as rpg


BASELINE = rpg.render_ignore_baseline()


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"Command failed: {cmd}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    return proc


def resolve_cli_command(
    *,
    repo_root: Path = REPO_ROOT,
    scripts_dir: Path | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> list[str]:
    resolved_scripts_dir = scripts_dir or Path(sys.executable).resolve().parent
    cli_candidates = [
        resolved_scripts_dir / "repo-privacy-guardian.exe",
        resolved_scripts_dir / "repo-privacy-guardian",
    ]
    cli = next((str(path) for path in cli_candidates if path.exists()), None)
    if not cli:
        cli = which("repo-privacy-guardian")
    if cli:
        return [cli]

    direct_script = repo_root / "Repo_Privacy_Guardian.py"
    if direct_script.exists():
        return [sys.executable, str(direct_script)]

    return [sys.executable, "-m", "Repo_Privacy_Guardian"]


def main() -> int:
    workspace = Path.cwd()
    root = Path(tempfile.mkdtemp(prefix="rpg-smoke-"))
    results = workspace / "Audit_Results" / "ci-smoke"
    shutil.rmtree(results, ignore_errors=True)
    try:
        repo = root / "smoke-repo"
        run(["git", "init", "-b", "main", str(repo)])
        run(["git", "-C", str(repo), "config", "user.name", "Repo Owner"])
        run(
            [
                "git",
                "-C",
                str(repo),
                "config",
                "user.email",
                "12345+repoowner@users.noreply.github.com",
            ]
        )
        (repo / ".gitignore").write_text(BASELINE, encoding="utf-8")
        (repo / "README.md").write_text("# smoke\n", encoding="utf-8")
        run(["git", "-C", str(repo), "add", "-A"])
        run(["git", "-C", str(repo), "commit", "-m", "baseline"])

        cli_cmd = resolve_cli_command()
        proc = subprocess.run(
            [
                *cli_cmd,
                "--root",
                str(root),
                "--repos",
                "smoke-repo",
                "--report-dir",
                str(results),
                "--yes",
            ],
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            raise SystemExit(
                f"CLI smoke failed with exit code {proc.returncode}\n"
                f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            )

        run_dirs = sorted([p for p in results.iterdir() if p.is_dir()])
        if not run_dirs:
            raise SystemExit("CLI smoke did not create a report directory.")

        payload = json.loads((run_dirs[-1] / "report.json").read_text(encoding="utf-8"))[0]
        if payload["status"] != "PASS":
            raise SystemExit(f"Unexpected smoke status: {payload['status']}")
        return 0
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(results, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
