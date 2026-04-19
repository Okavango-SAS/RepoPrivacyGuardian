from __future__ import annotations

import sys
import traceback
from pathlib import Path


def bootstrap_repo_root(
    *,
    script_path: str | Path = __file__,
    path_list: list[str] | None = None,
) -> Path:
    repo_root = Path(script_path).resolve().parents[1]
    target_path_list = sys.path if path_list is None else path_list
    repo_root_text = str(repo_root)
    if repo_root_text not in target_path_list:
        target_path_list.insert(0, repo_root_text)
    return repo_root


REPO_ROOT = bootstrap_repo_root()

import Repo_Privacy_Guardian as rpg  # noqa: E402


def main() -> int:
    try:
        app = rpg.GuiApp()
        app.root.after(100, app.root.update_idletasks)
        app.root.after(250, app.root.destroy)
        app.run()
        return 0
    except Exception as exc:  # pragma: no cover - exercised in CI smoke
        raise SystemExit(f"GUI smoke failed: {exc}\n{traceback.format_exc()}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
