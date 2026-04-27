from __future__ import annotations

import sys
import json
import os
import tempfile
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
        with tempfile.TemporaryDirectory() as temp_dir:
            settings_path = Path(temp_dir) / "gui_settings.json"
            settings_path.write_text(
                json.dumps(
                    {
                        "schema_version": rpg.GUI_SETTINGS_SCHEMA_VERSION,
                        "setup_completed": False,
                        "gui_locale": rpg.GUI_LOCALE_ES_419,
                    }
                ),
                encoding="utf-8",
            )
            os.environ[rpg.GUI_SETTINGS_ENV_VAR] = str(settings_path)
            app = rpg.GuiApp()
            assert app._current_locale() == rpg.GUI_LOCALE_ES_419
            assert getattr(app._flow_tabs, "_name_list", []) == [
                "1. Auditar",
                "2. Reportes",
                "3. Prompts",
                "4. Configuración",
                "5. Reparar",
            ]
            app._on_gui_locale_selected("English")
            assert app._current_locale() == rpg.GUI_LOCALE_DEFAULT
            assert getattr(app._flow_tabs, "_name_list", []) == [
                "1. Audit",
                "2. Reports",
                "3. Prompts",
                "4. Settings",
                "5. Repair",
            ]
            app.root.after(100, app.root.update_idletasks)
            app.root.after(250, app.root.destroy)
            app.run()
        return 0
    except Exception as exc:  # pragma: no cover - exercised in CI smoke
        raise SystemExit(f"GUI smoke failed: {exc}\n{traceback.format_exc()}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
