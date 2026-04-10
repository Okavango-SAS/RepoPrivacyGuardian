from __future__ import annotations

import traceback

import Repo_Privacy_Guardian as rpg


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
