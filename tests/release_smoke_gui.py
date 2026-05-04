from __future__ import annotations

import sys
import json
import os
import tempfile
import traceback
from datetime import datetime
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
from repo_privacy_guardian_artifacts import RunArtifacts  # noqa: E402


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
                        "gui_appearance": rpg.GUI_APPEARANCE_LIGHT,
                    }
                ),
                encoding="utf-8",
            )
            os.environ[rpg.GUI_SETTINGS_ENV_VAR] = str(settings_path)
            app = rpg.GuiApp()
            app.root.update_idletasks()
            app.root.update()
            assert app._current_locale() == rpg.GUI_LOCALE_ES_419
            assert app._current_appearance() == rpg.GUI_APPEARANCE_LIGHT
            assert getattr(app._flow_tabs, "_name_list", []) == [
                "1. Auditar",
                "2. Reportes",
                "3. Instrucciones",
                "4. Configuración",
                "5. Reparar",
            ]
            assert app._audit_button.cget("text") == app._t("run_audit")
            assert app._audit_button.cget("state") == "normal"
            assert app._agent_prompts_shortcut.cget("text") == app._t("open_agent_prompts_tab")
            assert app._refresh_button.cget("fg_color") == app._secondary_button_fg
            assert getattr(app._app_frame._scrollbar, "_button_color", None) == app._scrollbar_thumb
            assert getattr(app._repo_scrollbar, "_button_color", None) == app._scrollbar_thumb
            assert app._appearance_menu.cget("values") == ["Claro", "Oscuro"]
            assert app._output_empty_state_label.winfo_viewable()
            app.log("[INFO] GUI smoke log")
            app.root.update_idletasks()
            app.root.update()
            assert not app._output_empty_state_label.winfo_viewable()
            app.clear_output()
            app.root.update_idletasks()
            app.root.update()
            assert app._output_empty_state_label.winfo_viewable()
            assert app._repair_button.cget("text") == app._t("lock_repair_default")
            assert app._repair_button.cget("state") == "disabled"
            assert app._repair_status_label.cget("text") == app._t("no_audit_results")
            app._set_active_flow_tab(app._reports_tab_name)
            app.root.update_idletasks()
            app.root.update()
            assert app._reports_go_audit_button.cget("text") == app._t("go_to_audit")
            assert app._reports_go_audit_button.winfo_viewable()
            assert not app._reports_agent_handoff_button.winfo_viewable()
            assert app._reports_status_badge.winfo_viewable()
            assert app._reports_paths_label.winfo_viewable()
            assert all(button.cget("state") == "disabled" for button in app._reports_action_buttons)
            assert not any(button.winfo_viewable() for button in app._reports_action_buttons)
            run_dir = REPO_ROOT / "Audit_Results" / "gui-smoke-handoff"
            app._remember_last_run_artifacts(
                RunArtifacts(
                    run_id="run-artifacts",
                    run_dir=run_dir,
                    json_path=run_dir / "report.json",
                    log_path=run_dir / "run.log",
                    html_path=run_dir / "report.html",
                    state_path=run_dir / "run_state.json",
                    started_at=datetime.now(),
                ),
                run_fix=False,
                exit_code=rpg.EXIT_OK,
                reports_payload=[],
            )
            app.root.update_idletasks()
            app.root.update()
            assert not app._reports_go_audit_button.winfo_viewable()
            assert app._reports_agent_handoff_button.cget("text") == app._t("copy_agent_handoff")
            assert app._reports_agent_handoff_button.winfo_viewable()
            assert all(button.cget("state") == "normal" for button in app._reports_action_buttons)
            assert all(button.winfo_viewable() for button in app._reports_action_buttons)
            assert "Audit_Results/gui-smoke-handoff/report.json" in app._reports_paths_label.cget("text")
            assert str(REPO_ROOT) not in app._reports_paths_label.cget("text")
            handoff_text = app._build_agent_handoff_text()
            assert handoff_text is not None
            assert "Audit_Results/gui-smoke-handoff/report.json" in handoff_text
            assert "No pegues secretos crudos" in handoff_text
            app._last_run_artifacts = None
            app._refresh_reports_tab()
            app.root.update_idletasks()
            app.root.update()
            assert app._reports_go_audit_button.winfo_viewable()
            assert not app._reports_agent_handoff_button.winfo_viewable()
            assert not any(button.winfo_viewable() for button in app._reports_action_buttons)
            app._set_active_flow_tab(app._prompts_tab_name)
            app.root.update_idletasks()
            app.root.update()
            assert len(app._prompt_cards_frame.winfo_children()) == 4
            assert app._prompt_cards_frame.winfo_viewable()
            app._set_active_flow_tab(app._repair_tab_name)
            app.root.update_idletasks()
            app.root.update()
            assert app._repair_tab_block_overlay.winfo_viewable()
            assert all(step.winfo_viewable() for step in app._repair_tab_block_steps)
            app._on_gui_locale_selected("English")
            assert app._current_locale() == rpg.GUI_LOCALE_DEFAULT
            assert getattr(app._flow_tabs, "_name_list", []) == [
                "1. Audit",
                "2. Reports",
                "3. Prompts",
                "4. Settings",
                "5. Repair",
            ]
            assert app._audit_button.cget("text") == app._t("run_audit")
            assert app._audit_button.cget("state") == "normal"
            assert app._agent_prompts_shortcut.cget("text") == app._t("open_agent_prompts_tab")
            assert app._refresh_button.cget("fg_color") == app._secondary_button_fg
            assert getattr(app._app_frame._scrollbar, "_button_color", None) == app._scrollbar_thumb
            assert getattr(app._repo_scrollbar, "_button_color", None) == app._scrollbar_thumb
            assert app._appearance_menu.cget("values") == ["Light", "Dark"]
            assert app._output_empty_state_label.cget("text") == app._t("execution_log_empty")
            app._set_active_flow_tab(app._audit_tab_name)
            app.root.update_idletasks()
            app.root.update()
            assert app._output_empty_state_label.winfo_viewable()
            assert app._repair_button.cget("text") == app._t("lock_repair_default")
            assert app._repair_button.cget("state") == "disabled"
            assert app._repair_status_label.cget("text") == app._t("no_audit_results")
            app._set_active_flow_tab(app._reports_tab_name)
            app.root.update_idletasks()
            app.root.update()
            assert app._reports_go_audit_button.cget("text") == app._t("go_to_audit")
            assert app._reports_go_audit_button.winfo_viewable()
            assert app._reports_agent_handoff_button.cget("text") == app._t("copy_agent_handoff")
            assert not app._reports_agent_handoff_button.winfo_viewable()
            assert app._reports_status_badge.winfo_viewable()
            assert app._reports_paths_label.winfo_viewable()
            assert all(button.cget("state") == "disabled" for button in app._reports_action_buttons)
            assert not any(button.winfo_viewable() for button in app._reports_action_buttons)
            app._set_active_flow_tab(app._prompts_tab_name)
            app.root.update_idletasks()
            app.root.update()
            assert len(app._prompt_cards_frame.winfo_children()) == 4
            assert app._prompt_cards_frame.winfo_viewable()
            app._set_active_flow_tab(app._repair_tab_name)
            app.root.update_idletasks()
            app.root.update()
            assert app._repair_tab_block_overlay.winfo_viewable()
            assert all(step.winfo_viewable() for step in app._repair_tab_block_steps)
            app.root.after(100, app.root.update_idletasks)
            app.root.after(250, app.root.destroy)
            app.run()
        return 0
    except Exception as exc:  # pragma: no cover - exercised in CI smoke
        raise SystemExit(f"GUI smoke failed: {exc}\n{traceback.format_exc()}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
