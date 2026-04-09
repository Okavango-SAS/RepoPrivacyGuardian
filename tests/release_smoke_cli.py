from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


BASELINE = "\n".join(
    [
        ".venv/",
        "__pycache__/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".env",
        ".env.*",
        "wsa-config.local.yaml",
        "Audit_Results/",
        "sessions/*",
        "artifacts/",
        "exports/",
        "*.log",
        "*.tmp",
        "*.bak",
        ".vscode/",
        ".idea/",
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
        "",
    ]
)


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

        scripts_dir = Path(sys.executable).resolve().parent
        cli_candidates = [
            scripts_dir / "repo-privacy-guardian.exe",
            scripts_dir / "repo-privacy-guardian",
        ]
        cli = next((str(path) for path in cli_candidates if path.exists()), None)
        if not cli:
            cli = shutil.which("repo-privacy-guardian")
        if not cli:
            raise SystemExit("repo-privacy-guardian entry point is not available.")

        proc = subprocess.run(
            [
                cli,
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
