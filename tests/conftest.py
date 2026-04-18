from __future__ import annotations

import subprocess
import sys
from functools import lru_cache
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@lru_cache(maxsize=1)
def _tracked_test_files() -> set[str]:
    try:
        out = subprocess.check_output(
            ["git", "ls-files", "tests"],
            cwd=REPO_ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return set()

    return {
        line.strip().replace("\\", "/")
        for line in out.splitlines()
        if line.strip()
    }


def pytest_ignore_collect(collection_path, config):  # type: ignore[no-untyped-def]
    del config
    path = Path(str(collection_path))
    if path.suffix != ".py" or not path.name.startswith("test_"):
        return False

    try:
        rel = path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return False

    tracked = _tracked_test_files()
    if not tracked:
        return False

    return rel.startswith("tests/") and rel not in tracked
