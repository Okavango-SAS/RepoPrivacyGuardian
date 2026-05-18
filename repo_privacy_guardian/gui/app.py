"""Desktop GUI coordinator."""

from __future__ import annotations

import argparse
import json
import os
import threading
import traceback
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, cast

from repo_privacy_guardian.gui import assets as gui_asset_helpers
from repo_privacy_guardian.gui import state as gui_state_helpers
from repo_privacy_guardian.gui import theme as gui_theme_helpers
from repo_privacy_guardian.gui import window as gui_window_helpers

if TYPE_CHECKING:
    from repo_privacy_guardian.core import (
        DEFAULT_NOREPLY,
        DEFAULT_PLACEHOLDER,
        DEFAULT_POLICY,
        EXIT_ABORTED,
        EXIT_OK,
        EXIT_POLICY_FAILED,
        EXIT_RUNTIME_ERROR,
        GUI_APPEARANCE_DARK,
        GUI_APPEARANCE_DEFAULT,
        GUI_APPEARANCE_LIGHT,
        GUI_APPEARANCE_SYSTEM,
        GUI_ASSET_FILENAMES,
        GUI_DEFAULT_PUBLIC_ONLY,
        GUI_LOCALE_DEFAULT,
        GUI_LOCALE_OPTIONS,
        GUI_THEMEABLE_ASSET_FILENAMES,
        GUI_TOOLTIP_TEXT,
        GUI_TOOLTIP_TEXT_BY_LOCALE,
        GUI_UI_TEXT_BY_LOCALE,
        CancellationToken,
        RunLogger,
        apply_git_identity_config,
        artifact_helpers,
        blend_near_white_gui_asset_background,
        build_github_optional_tooling_checks,
        build_guard_run_config,
        choose_gui_font_family,
        compare_report_files,
        create_run_artifacts,
        default_gui_settings_path,
        default_results_dir,
        default_root_dir,
        discover_repository_targets,
        enforce_results_dir,
        execute_guard_pipeline,
        find_previous_report_json,
        format_git_identity_status,
        format_report_diff_summary,
        gui_appearance_from_label,
        gui_appearance_label,
        gui_appearance_options,
        gui_asset_path,
        gui_font_candidates,
        gui_locale_from_label,
        gui_locale_label,
        gui_setting_bool,
        gui_setting_str,
        install_missing_tooling,
        load_gui_runtime,
        load_gui_settings,
        normalize_csv_values,
        normalize_gui_appearance,
        normalize_gui_locale,
        normalize_repo_filters,
        open_github_email_settings,
        parse_hex_rgb,
        parse_positive_int,
        parse_tk_drop_paths,
        prompt_gui_tooling_install,
        prompt_helpers,
        read_git_identity_config,
        redact_sensitive_text,
        repo_display_name,
        resolve_dropped_repository_targets,
        resolve_identity_repo_path,
        save_gui_settings,
        source_tree_root,
        strict_profiles,
        validate_git_identity_inputs,
        validate_repository_root,
    )


class GuiApp:  # pragma: no cover
    def __init__(self) -> None:
        _sync_gui_public_overrides()
        tk, messagebox, filedialog, ctk, tcl_error = load_gui_runtime()

        self._gui_settings_path = default_gui_settings_path()
        self._gui_settings = load_gui_settings(self._gui_settings_path)
        self._gui_locale = normalize_gui_locale(gui_setting_str(self._gui_settings, "gui_locale", GUI_LOCALE_DEFAULT))
        self._gui_appearance = normalize_gui_appearance(
            gui_setting_str(self._gui_settings, "gui_appearance", GUI_APPEARANCE_DEFAULT)
        )
        gui_window_helpers.configure_ctk_theme(ctk, self._gui_appearance)

        self.tk = tk
        self.ctk = ctk
        self.messagebox = messagebox
        self.filedialog = filedialog
        self.root = gui_window_helpers.create_root(ctk, tcl_error)
        self._sync_ctk_system_appearance_probe()
        self._gui_asset_manager = self._create_gui_asset_manager()
        self._gui_asset_images = self._load_gui_assets()
        self._gui_themed_asset_images = self._gui_asset_manager.themed_asset_images
        self._gui_button_asset_images = self._load_gui_button_assets()
        self._gui_info_badges: list[object] = []
        self._gui_asset_labels = self._gui_asset_manager.asset_labels
        self._fixed_theme_options: list[dict[str, object]] = []
        self._effective_gui_appearance = GUI_APPEARANCE_LIGHT
        self._appearance_mode_callback_registered = False
        self._set_window_icon()
        gui_window_helpers.configure_root_window(self.root)
        self._top_stack_width_threshold = 1220
        self._options_stack_width_threshold = 1220
        self._results_stack_width_threshold = 1240
        self._prompts_stack_width_threshold = 1240

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
        self.strict_profile_var = tk.StringVar(
            value=gui_setting_str(self._gui_settings, "strict_profile", "default") or "default"
        )
        self.suppressions_file_var = tk.StringVar(
            value=gui_setting_str(self._gui_settings, "suppressions", "")
        )

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
        self.accept_github_admin_bypass_var = tk.BooleanVar(
            value=gui_setting_bool(self._gui_settings, "accept_github_admin_bypass", False)
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
        self._repo_empty_state_action_button = None
        self._repo_empty_reason: str | None = None
        self._repo_items: list[tuple[str, str]] = []
        self._select_all_button = None
        self._clear_selection_button = None
        self._refresh_button = None
        self._agent_prompts_shortcut = None
        self._repair_status_label = None
        self._repair_status_panel = None
        self._repair_status_badge = None
        self._repair_gate_note_label = None
        self._last_run_artifacts: artifact_helpers.RunArtifacts | None = None
        self._last_run_exit_code: int | None = None
        self._last_run_action = ""
        self._gui_warnings: list[str] = []
        self._gui_debug_warnings = os.environ.get("REPO_PRIVACY_GUARDIAN_GUI_DEBUG", "").lower() in {
            "1",
            "true",
            "yes",
        }
        self._reports_status_badge = None
        self._reports_summary_label = None
        self._reports_paths_label = None
        self._reports_next_action_badge = None
        self._reports_next_action_label = None
        self._reports_agent_steps_frame = None
        self._reports_agent_step_labels: list[object] = []
        self._reports_open_prompts_button = None
        self._reports_go_audit_button = None
        self._reports_agent_handoff_button = None
        self._reports_action_buttons: list[object] = []
        self._reports_decision_layout_signature: tuple[object, ...] | None = None
        self._compact_reports_decision_layout = False
        self._compact_reports_actions_layout = False
        self._prompt_cards_frame = None
        self._prompt_card_widgets: list[object] = []
        self._prompt_card_stage_labels: list[object] = []
        self._prompt_card_column_count = 2
        self._prompts_workflow_guide = None
        self._prompts_workflow_title_label = None
        self._prompts_workflow_body_label = None
        self._prompts_workflow_info_badge = None
        self._gui_destroying = False
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
        self._safe_options_card = None
        self._destructive_options_card = None

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
        heading_specs = gui_state_helpers.gui_section_heading_specs()
        panel_specs = gui_state_helpers.gui_panel_specs()
        text_specs = gui_state_helpers.gui_text_label_specs()

        header = ctk.CTkFrame(app, fg_color=self._header_fg, corner_radius=18)
        header.grid(row=0, column=0, sticky="we", padx=16, pady=(10, 8))
        header.grid_columnconfigure(0, weight=1)
        header.grid_columnconfigure(1, weight=0)
        self._add_section_heading(header, heading_specs["header"])
        self._add_text_label(header, text_specs["header_subtitle"])

        workflow_strip = ctk.CTkFrame(header, fg_color="transparent")
        workflow_strip.grid(row=2, column=0, sticky="w", padx=18, pady=(0, 14))
        self._workflow_strip = workflow_strip
        workflow_items = gui_state_helpers.header_workflow_chip_label_specs()
        for label_spec in workflow_items:
            self._add_text_label(workflow_strip, label_spec)
        self._make_info_badge_for(workflow_strip, "workflow_overview").grid(
            row=0,
            column=len(workflow_items),
            sticky="w",
            padx=(2, 0),
        )
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
        self._add_section_heading(audit_target_card, heading_specs["audit_target"])
        self._add_text_label(audit_target_card, text_specs["audit_target_body"])
        self._add_path_field(
            audit_target_card,
            gui_state_helpers.repositories_root_path_field_spec(row=2),
        )
        audit_settings_row = ctk.CTkFrame(audit_target_card, fg_color="transparent")
        audit_settings_row.grid(row=3, column=0, columnspan=3, sticky="we", padx=14, pady=(6, 12))
        audit_settings_row.grid_columnconfigure(0, weight=1)
        self._add_text_label(audit_settings_row, text_specs["recommended_path_body"])
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
        settings_shortcut.grid(row=1, column=2, sticky="e", padx=(8, 0))
        agent_prompts_shortcut = ctk.CTkButton(
            audit_settings_row,
            text=self._t("open_agent_prompts_tab"),
            command=lambda: self._set_active_flow_tab(self._prompts_tab_name),
            width=150,
            height=32,
            corner_radius=8,
            **self._button_asset_options("icon-copy.png"),
            **self._secondary_button_options(),
        )
        self._agent_prompts_shortcut = agent_prompts_shortcut
        self._localize_widget(agent_prompts_shortcut, "text", "open_agent_prompts_tab")
        self._bind_tooltip_key(agent_prompts_shortcut, "open_agent_prompts_tab")
        agent_prompts_shortcut.grid(row=1, column=1, sticky="e", padx=(12, 0))

        settings_intro = ctk.CTkFrame(settings_tab, fg_color="transparent")
        settings_intro.grid(row=0, column=0, sticky="we", padx=10, pady=(8, 0))
        settings_intro.grid_columnconfigure(0, weight=1)
        self._add_section_heading(settings_intro, heading_specs["settings_companion"])
        self._add_text_label(settings_intro, text_specs["settings_companion_body"])

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
        self._add_section_heading(settings_card, heading_specs["setup_settings_card"])

        quick_start = self._make_panel(settings_card, panel_specs["setup_quick_start"])
        self._add_text_label(quick_start, text_specs["setup_quick_start_badge"])
        self._add_text_label(quick_start, text_specs["setup_quick_start_status"])

        row = 2
        self._add_path_field(
            settings_card,
            gui_state_helpers.repositories_root_path_field_spec(row=row),
        )

        row += 1
        settings_panel_specs = gui_state_helpers.gui_panel_specs(setup_toggle_row=row)
        setup_toggle_row = self._make_panel(settings_card, settings_panel_specs["setup_toggle"])
        self._add_text_label(setup_toggle_row, text_specs["setup_initial_hint"])
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
        settings_panel_specs = gui_state_helpers.gui_panel_specs(setup_settings_row=row)
        setup_settings_frame = self._make_panel(settings_card, settings_panel_specs["setup_settings_frame"])

        self._add_section_heading(setup_settings_frame, heading_specs["setup_settings_inner"])
        self._add_text_label(setup_settings_frame, text_specs["settings_status"])

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
        policy_row = settings_row

        settings_row += 1
        results_row = settings_row

        settings_row += 1
        json_row = settings_row

        setup_path_specs = {
            spec.label_key: spec
            for spec in gui_state_helpers.setup_path_field_specs(
                policy_row=policy_row,
                results_row=results_row,
                json_row=json_row,
                suppression_row=json_row + 2,
            )
        }
        self._add_path_field(setup_settings_frame, setup_path_specs["policy_file"])
        self._add_path_field(setup_settings_frame, setup_path_specs["audit_results_folder"])
        self._add_path_field(setup_settings_frame, setup_path_specs["optional_json_copy"])

        settings_row += 1
        self._make_field_label(
            setup_settings_frame,
            text_key="strict_profile",
            tooltip_key="strict_profile",
        ).grid(row=settings_row, column=0, sticky="w", padx=(14, 8), pady=4)
        strict_profile_menu = ctk.CTkOptionMenu(
            setup_settings_frame,
            variable=self.strict_profile_var,
            values=["default", *strict_profiles.STRICT_PROFILE_CHOICES],
            height=32,
            corner_radius=8,
            fg_color=self._secondary_button_fg,
            button_color=self._support_button_fg,
            button_hover_color=self._support_button_hover,
            text_color=self._secondary_button_text,
        )
        self._bind_tooltip_key(strict_profile_menu, "strict_profile")
        strict_profile_menu.grid(row=settings_row, column=1, sticky="w", pady=4)
        self._make_info_badge_for(setup_settings_frame, "strict_profile").grid(
            row=settings_row,
            column=2,
            sticky="w",
            padx=(8, 14),
            pady=4,
        )

        settings_row += 1
        self._add_path_field(setup_settings_frame, setup_path_specs["suppression_file"])

        settings_row += 1
        settings_panel_specs = gui_state_helpers.gui_panel_specs(github_remote_row=settings_row)
        github_remote_card = self._make_panel(setup_settings_frame, settings_panel_specs["github_remote"])
        for entry_spec in gui_state_helpers.github_remote_entry_field_specs():
            self._add_entry_field(github_remote_card, entry_spec)
        for option_spec in gui_state_helpers.github_remote_option_checkbox_specs():
            self._make_option_checkbox(github_remote_card, option_spec)

        settings_row += 1
        self._add_entry_field(
            setup_settings_frame,
            gui_state_helpers.max_findings_entry_field_spec(row=settings_row),
        )
        self._add_text_label(
            setup_settings_frame,
            gui_state_helpers.gui_text_label_specs(settings_persist_note_row=settings_row + 1)[
                "settings_persist_note"
            ],
        )

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

        settings_panel_specs = gui_state_helpers.gui_panel_specs(advanced_identity_row=settings_row + 3)
        advanced_identity_row = self._make_panel(
            setup_settings_frame,
            settings_panel_specs["advanced_identity_toggle"],
        )
        self._add_text_label(advanced_identity_row, text_specs["advanced_identity_hint"])
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

        self._add_section_heading(profile_card, heading_specs["owner_profile"])
        self._add_text_label(profile_card, text_specs["owner_profile_body"])

        for entry_spec in gui_state_helpers.owner_profile_entry_field_specs(start_row=2):
            self._add_entry_field(profile_card, entry_spec)

        identity_card = ctk.CTkFrame(
            audit_tab,
            fg_color=self._surface_fg,
            corner_radius=12,
            border_width=1,
            border_color=self._card_border,
        )
        identity_card.grid(row=1, column=0, sticky="we", padx=10, pady=(10, 8))
        identity_card.grid_columnconfigure(1, weight=1)
        self._add_text_label(identity_card, text_specs["optional_git_identity"])

        for entry_spec in gui_state_helpers.git_identity_entry_field_specs():
            self._add_entry_field(identity_card, entry_spec)

        identity_actions = ctk.CTkFrame(identity_card, fg_color="transparent")
        identity_actions.grid(row=3, column=0, columnspan=2, sticky="we", padx=14, pady=(8, 4))
        identity_actions.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self._identity_actions = identity_actions
        self._identity_action_buttons = [
            self._make_action_button(identity_actions, spec)
            for spec in gui_state_helpers.identity_action_button_specs()
        ]

        self._add_text_label(identity_card, text_specs["identity_help"])
        self._identity_card = identity_card
        self._set_advanced_identity_visibility(False)
        self._set_setup_settings_visibility(self._setup_settings_visible)

        self._build_reports_tab(reports_tab)
        self._build_prompts_tab(prompts_tab)

        repair_options_toggle = self._make_panel(repair_tab, panel_specs["repair_options_toggle"])
        self._add_text_label(repair_options_toggle, text_specs["repair_options_hint"])
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
        self._add_section_heading(options_card, heading_specs["repair_options"])

        safe_options = self._make_panel(options_card, panel_specs["repair_review_options"])
        self._add_text_label(safe_options, text_specs["review_output_options"])
        self._make_info_badge(
            safe_options,
            lambda: self._t("review_output_info"),
        ).grid(row=0, column=1, sticky="e", padx=(0, 12), pady=(10, 2))

        for option_spec in gui_state_helpers.repair_review_option_checkbox_specs():
            self._make_option_checkbox(safe_options, option_spec)

        destructive_options = self._make_panel(options_card, panel_specs["repair_write_options"])
        self._compact_options_layout = False
        self._add_text_label(destructive_options, text_specs["repair_write_actions"])
        self._make_info_badge(
            destructive_options,
            lambda: self._t("repair_write_info"),
        ).grid(row=0, column=1, sticky="e", padx=(0, 12), pady=(10, 2))
        self._add_text_label(destructive_options, text_specs["repair_write_body"])

        repair_write_specs = {
            spec.text_key: spec
            for spec in gui_state_helpers.repair_write_option_checkbox_specs()
        }
        self._make_option_checkbox(destructive_options, repair_write_specs["rewrite_personal_paths"])
        self._add_text_label(destructive_options, text_specs["rewrite_personal_paths_body"])

        self._add_path_field(
            destructive_options,
            gui_state_helpers.repair_replace_text_path_field_spec(),
        )
        self._add_text_label(destructive_options, text_specs["replace_text_rules_body"])

        self._make_option_checkbox(destructive_options, repair_write_specs["force_push"])
        self._make_option_checkbox(
            destructive_options,
            repair_write_specs["bypass_remote_owner_guardrail"],
        )

        self._add_entry_field(
            destructive_options,
            gui_state_helpers.repair_allowed_remote_owner_entry_field_spec(),
        )
        self._add_text_label(destructive_options, text_specs["allowed_remote_owners_body"])

        self._make_option_checkbox(destructive_options, repair_write_specs["purge_safe_secret_files"])
        self._make_option_checkbox(destructive_options, repair_write_specs["purge_risky_secret_files"])
        self._add_text_label(destructive_options, text_specs["purge_body"])
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
        self._add_section_heading(repair_actions_card, heading_specs["repair_flow"])
        repair_status_panel = self._make_panel(repair_actions_card, panel_specs["repair_status"])
        self._add_text_label(repair_status_panel, text_specs["repair_status_badge"])
        self._add_text_label(repair_status_panel, text_specs["latest_audit_summary"])
        self._add_text_label(repair_status_panel, text_specs["repair_status_body"])
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
        self._add_text_label(repair_controls, text_specs["repair_gate_note"])

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
        self._add_text_label(blocker_card, text_specs["repair_tab_locked"])
        self._repair_tab_block_label = ctk.CTkLabel(
            blocker_card,
            text="",
            justify="center",
            font=self._font(12, bold=True),
            text_color=self._text_heading,
            wraplength=620,
        )
        self._repair_tab_block_label.grid(row=2, column=0, padx=24, pady=(0, 6), sticky="ew")
        self._add_text_label(blocker_card, text_specs["before_repair"])
        self._repair_tab_block_steps = []
        for step_spec in gui_state_helpers.repair_lock_step_label_specs():
            self._repair_tab_block_steps.append(self._add_text_label(blocker_card, step_spec))
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
        self._add_section_heading(repo_header, heading_specs["repositories"])
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
        self._add_text_label(repos_card, text_specs["repo_summary"])

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
        self._add_text_label(list_shell, text_specs["repo_drop_hint"])
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
        self._add_text_label(self._repo_empty_state, text_specs["repo_empty_title"])
        self._add_text_label(self._repo_empty_state, text_specs["repo_empty_body"])
        self._add_text_label(self._repo_empty_state, text_specs["repo_empty_hint"])
        self._repo_empty_state_action_button = ctk.CTkButton(
            self._repo_empty_state,
            text=self._t("repo_empty_choose_root_action"),
            command=self._choose_root_from_empty_state,
            width=150,
            height=32,
            corner_radius=8,
            **self._button_asset_options("icon-folder.png"),
            **self._secondary_button_options(),
        )
        self._localize_widget(self._repo_empty_state_action_button, "text", "repo_empty_choose_root_action")
        self._bind_tooltip_key(self._repo_empty_state_action_button, "repositories_root")
        self._repo_empty_state_action_button.grid(row=4, column=0, padx=18, pady=(0, 16))

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
        self._add_section_heading(output_card, heading_specs["execution_log"])
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
        self._add_text_label(self.output, text_specs["output_empty"])
        self._set_output_empty_state(True)

        self.refresh_repos()
        self.root.bind("<Configure>", self._on_root_resize)
        self.root.bind("<Destroy>", self._on_root_destroy, add="+")
        self._register_appearance_mode_callback()
        self.root.after(0, self._apply_responsive_layout)
        self._lock_repair_until_next_audit()
        self._set_active_flow_tab(self._audit_tab_name)

    def _current_appearance(self) -> str:
        return normalize_gui_appearance(getattr(self, "_gui_appearance", GUI_APPEARANCE_DEFAULT))

    def _resolved_effective_appearance(self) -> str:
        selected = self._current_appearance()
        if selected != GUI_APPEARANCE_SYSTEM:
            return selected
        try:
            mode = str(self.ctk.get_appearance_mode()).strip().lower()
        except Exception:
            mode = ""
        if mode.startswith("dark"):
            return GUI_APPEARANCE_DARK
        return GUI_APPEARANCE_LIGHT

    def _effective_appearance(self) -> str:
        return normalize_gui_appearance(
            getattr(self, "_effective_gui_appearance", self._resolved_effective_appearance())
        )

    def _ensure_gui_theme_palette(self) -> None:
        if not hasattr(self, "_text_muted"):
            self._configure_gui_theme_palette()

    def _configure_gui_theme_palette(self) -> None:
        self._effective_gui_appearance = self._resolved_effective_appearance()
        if self._effective_appearance() == GUI_APPEARANCE_DARK:
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

    def _create_gui_asset_manager(self) -> gui_asset_helpers.GuiAssetManager:
        return gui_asset_helpers.GuiAssetManager(
            tk=self.tk,
            ctk=self.ctk,
            root=self.root,
            asset_filenames=lambda: GUI_ASSET_FILENAMES,
            themeable_asset_filenames=lambda: GUI_THEMEABLE_ASSET_FILENAMES,
            asset_path=lambda filename: gui_asset_path(filename),
            parse_hex_rgb=lambda color: parse_hex_rgb(color),
            blend_themeable_asset_background=lambda image, background_rgb: blend_near_white_gui_asset_background(
                image,
                background_rgb,
            ),
            effective_appearance=self._effective_appearance,
            dark_appearance=lambda: GUI_APPEARANCE_DARK,
            theme_attrs=lambda: vars(self),
            record_warning=self._record_gui_warning,
        )

    def _gui_asset_manager_for_use(self) -> gui_asset_helpers.GuiAssetManager:
        manager = getattr(self, "_gui_asset_manager", None)
        if not isinstance(manager, gui_asset_helpers.GuiAssetManager):
            manager = self._create_gui_asset_manager()
            self._gui_asset_manager = manager
        if hasattr(self, "_gui_asset_images"):
            manager.asset_images = self._gui_asset_images
        if hasattr(self, "_gui_themed_asset_images"):
            manager.themed_asset_images = self._gui_themed_asset_images
        if hasattr(self, "_gui_button_asset_images"):
            manager.button_asset_images = self._gui_button_asset_images
        if hasattr(self, "_gui_asset_labels"):
            manager.asset_labels = self._gui_asset_labels
        return manager

    def _load_gui_assets(self) -> dict[str, object]:
        return self._gui_asset_manager_for_use().load_asset_images()

    def _load_gui_button_assets(self) -> dict[str, object]:
        return self._gui_asset_manager_for_use().load_button_asset_images()

    def _tint_gui_icon(self, image, color: tuple[int, int, int]):
        return gui_asset_helpers.tint_gui_icon(image, color)

    def _asset_image(self, filename: str, *, background: str | None = None):
        return self._gui_asset_manager_for_use().image(filename, background=background)

    def _set_window_icon(self) -> None:
        self._gui_asset_manager_for_use().set_window_icon()

    def _theme_token_name_for_color(self, color: str) -> str | None:
        return self._gui_asset_manager_for_use().theme_token_name_for_color(color)

    def _make_asset_label(
        self,
        parent: object,
        filename: str,
        *,
        background: str,
    ) -> Any:
        return self._gui_asset_manager_for_use().make_label(parent, filename, background=background)

    def _button_asset_options(self, filename: str) -> dict[str, object]:
        return self._gui_asset_manager_for_use().button_options(filename)

    def _secondary_button_options(self) -> dict[str, object]:
        return {
            "fg_color": self._secondary_button_fg,
            "hover_color": self._secondary_button_hover,
            "border_width": 1,
            "border_color": self._secondary_button_border,
            "text_color": self._secondary_button_text,
        }

    def _sync_ctk_system_appearance_probe(self) -> None:
        gui_window_helpers.sync_ctk_system_appearance_probe(
            self.ctk,
            current_appearance=self._current_appearance(),
            system_appearance=GUI_APPEARANCE_SYSTEM,
            record_warning=self._record_gui_warning,
        )

    def _register_appearance_mode_callback(self) -> None:
        self._appearance_mode_callback_registered = gui_window_helpers.register_appearance_mode_callback(
            self.ctk,
            callback=self._on_ctk_appearance_mode_changed,
            root=self.root,
            already_registered=getattr(self, "_appearance_mode_callback_registered", False),
            record_warning=self._record_gui_warning,
        )

    def _unregister_appearance_mode_callback(self) -> None:
        self._appearance_mode_callback_registered = gui_window_helpers.unregister_appearance_mode_callback(
            self.ctk,
            callback=self._on_ctk_appearance_mode_changed,
            was_registered=getattr(self, "_appearance_mode_callback_registered", False),
            record_warning=self._record_gui_warning,
        )

    def _on_ctk_appearance_mode_changed(self, _mode_name: str) -> None:
        if not gui_window_helpers.should_apply_appearance_mode_change(
            gui_destroying=getattr(self, "_gui_destroying", False),
        ):
            return
        self._apply_effective_gui_theme()

    def _theme_palette_snapshot(self) -> dict[str, str]:
        return gui_theme_helpers.theme_palette_snapshot_from_attrs(vars(self))

    def _preferred_theme_token_for_option(
        self,
        option: str,
        token_names: list[str],
        *,
        sibling_values: dict[str, object],
        old_palette: dict[str, str],
    ) -> str | None:
        return gui_theme_helpers.preferred_theme_token_for_option(
            option,
            token_names,
            sibling_values=sibling_values,
            old_palette=old_palette,
        )

    def _translate_theme_color(
        self,
        value: object,
        option: str,
        *,
        old_palette: dict[str, str],
        new_palette: dict[str, str],
        sibling_values: dict[str, object],
    ) -> object | None:
        return gui_theme_helpers.translate_theme_color(
            value,
            option,
            old_palette=old_palette,
            new_palette=new_palette,
            sibling_values=sibling_values,
        )

    def _iter_theme_widgets(self):
        seen: set[int] = set()

        def walk(widget):
            widget_id = id(widget)
            if widget_id in seen:
                return
            seen.add(widget_id)
            yield widget
            try:
                children = widget.winfo_children()
            except Exception:
                children = []
            for child in children:
                yield from walk(child)

        yield from walk(self.root)

    def _apply_theme_to_widget(self, widget: object, old_palette: dict[str, str], new_palette: dict[str, str]) -> None:
        sibling_values: dict[str, object] = {}
        dynamic_widget = cast(Any, widget)
        for option in gui_theme_helpers.THEME_TRANSLATABLE_OPTIONS:
            try:
                sibling_values[option] = dynamic_widget.cget(option)
            except Exception:
                continue
        updates = gui_theme_helpers.theme_option_updates(
            sibling_values,
            old_palette=old_palette,
            new_palette=new_palette,
        )
        if not updates:
            return
        try:
            dynamic_widget.configure(**updates)
        except Exception as exc:
            self._record_gui_warning("bulk theme update failed", exc)
            for option, translated in updates.items():
                try:
                    dynamic_widget.configure(**{option: translated})
                except Exception as item_exc:
                    self._record_gui_warning(f"theme option update failed ({option})", item_exc)

    def _configure_asset_label_image(self, label: object, filename: str, background: str) -> None:
        self._gui_asset_manager_for_use().configure_label_image(label, filename, background)

    def _refresh_gui_asset_labels(self) -> None:
        self._gui_asset_manager_for_use().refresh_labels()

    def _register_fixed_theme_option(self, widget: object, option: str, value: object) -> None:
        self._fixed_theme_options.append({"widget": widget, "option": option, "value": value})

    def _refresh_fixed_theme_options(self) -> None:
        for item in list(getattr(self, "_fixed_theme_options", [])):
            widget = item.get("widget")
            option = item.get("option")
            value = item.get("value")
            if widget is None or not isinstance(option, str):
                continue
            try:
                widget.configure(**{option: value})
            except Exception as exc:
                self._record_gui_warning(f"fixed theme option update failed ({option})", exc)

    def _configure_theme_widget(
        self,
        widget: object | None,
        updates: dict[str, str],
        warning_context: str | None,
    ) -> None:
        if widget is None:
            return
        try:
            cast(Any, widget).configure(**updates)
        except Exception as exc:
            if warning_context is not None:
                self._record_gui_warning(warning_context, exc)

    def _apply_theme_to_special_widgets(self) -> None:
        special_updates = gui_theme_helpers.special_widget_theme_updates(self._theme_palette_snapshot())
        self._configure_theme_widget(
            self.root,
            special_updates["root"],
            "root theme update failed",
        )
        app_frame = getattr(self, "_app_frame", None)
        self._configure_theme_widget(
            app_frame,
            special_updates["app_frame"],
            "scrollable frame theme update failed",
        )
        flow_tabs = getattr(self, "_flow_tabs", None)
        if flow_tabs is not None:
            self._configure_theme_widget(flow_tabs, special_updates["flow_tabs"], None)
            segmented_button = getattr(flow_tabs, "_segmented_button", None)
            self._configure_theme_widget(
                segmented_button,
                special_updates["flow_segmented_button"],
                "tab segmented button theme update failed",
            )
        repo_scrollbar = getattr(self, "_repo_scrollbar", None)
        self._configure_theme_widget(
            repo_scrollbar,
            special_updates["repo_scrollbar"],
            "repository scrollbar theme update failed",
        )
        repo_list = getattr(self, "repo_list", None)
        self._configure_theme_widget(
            repo_list,
            special_updates["repo_list"],
            "repository list theme update failed",
        )
        output = getattr(self, "output", None)
        self._configure_theme_widget(
            output,
            special_updates["output"],
            "output theme update failed",
        )
        output_empty_state_label = getattr(self, "_output_empty_state_label", None)
        self._configure_theme_widget(
            output_empty_state_label,
            special_updates["output_empty_state_label"],
            "output empty-state theme update failed",
        )
        self._refresh_fixed_theme_options()

    def _refresh_theme_dependent_state(self) -> None:
        if getattr(self, "_repo_empty_reason", None):
            body_label = getattr(self, "_repo_empty_state_body_label", None)
            try:
                message = body_label.cget("text") if body_label is not None else None
            except Exception:
                message = None
            self._set_repo_empty_state(True, message, reason=getattr(self, "_repo_empty_reason", None))
        self._refresh_reports_tab()
        self._refresh_repair_locale_state()
        self._update_repair_gate_note()
        self._sync_purge_mode_controls()
        self._sync_push_guardrail_controls()
        if getattr(self, "repo_list", None) is not None:
            self._update_run_buttons_state()

    def _apply_effective_gui_theme(self, *, force: bool = False) -> None:
        old_effective = getattr(self, "_effective_gui_appearance", None)
        resolved_effective = self._resolved_effective_appearance()
        if not force and old_effective == resolved_effective:
            return
        old_palette = self._theme_palette_snapshot() if hasattr(self, "_text_muted") else {}
        self._effective_gui_appearance = resolved_effective
        self._configure_gui_theme_palette()
        new_palette = self._theme_palette_snapshot()
        if old_palette and getattr(self, "root", None) is not None:
            for widget in self._iter_theme_widgets():
                self._apply_theme_to_widget(widget, old_palette, new_palette)
            self._apply_theme_to_special_widgets()
            self._refresh_gui_asset_labels()
            self._refresh_theme_dependent_state()

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
        heading_specs = gui_state_helpers.gui_section_heading_specs()
        panel_specs = gui_state_helpers.gui_panel_specs()
        text_specs = gui_state_helpers.gui_text_label_specs()
        self._add_section_heading(reports_card, heading_specs["reports_dashboard"])
        self._add_text_label(reports_card, text_specs["reports_dashboard_body"])
        self._reports_visual_label = self._make_asset_label(
            reports_card,
            "reports-evidence.png",
            background=self._surface_fg,
        )
        if self._reports_visual_label is not None:
            self._reports_visual_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=(8, 14), pady=(10, 4))

        status_row = self._make_panel(reports_card, panel_specs["reports_status"])
        self._add_text_label(status_row, text_specs["reports_status_badge"])
        self._add_text_label(status_row, text_specs["latest_artifacts"])
        self._make_info_badge_for(status_row, "latest_artifacts_section").grid(
            row=0,
            column=2,
            sticky="e",
            padx=(0, 12),
            pady=(10, 6),
        )
        self._add_text_label(status_row, text_specs["reports_summary"])
        self._add_text_label(status_row, text_specs["reports_paths"])

        decision_row = self._make_panel(reports_card, panel_specs["reports_decision"])
        self._add_text_label(decision_row, text_specs["reports_next_action_badge"])
        self._add_text_label(decision_row, text_specs["reports_next_action"])
        self._make_info_badge_for(decision_row, "next_action_section").grid(
            row=0,
            column=2,
            sticky="e",
            padx=(0, 12),
            pady=(10, 8),
        )
        self._reports_agent_steps_frame = ctk.CTkFrame(decision_row, fg_color="transparent")
        self._reports_agent_steps_frame.grid(row=1, column=0, columnspan=3, sticky="we", padx=12, pady=(0, 10))
        self._reports_agent_steps_frame.grid_columnconfigure(0, weight=1)
        self._reports_agent_steps_frame.grid_columnconfigure(1, weight=1)
        self._reports_agent_steps_frame.grid_columnconfigure(2, weight=1)
        self._reports_agent_step_labels = []
        for step_spec in gui_state_helpers.reports_agent_step_label_specs():
            self._reports_agent_step_labels.append(self._add_text_label(self._reports_agent_steps_frame, step_spec))
        self._reports_open_prompts_button = self._make_action_button(
            decision_row,
            gui_state_helpers.reports_decision_action_button_spec(),
        )

        actions = ctk.CTkFrame(reports_card, fg_color="transparent")
        actions.grid(row=4, column=0, columnspan=2, sticky="w", padx=14, pady=(0, 12))
        primary_report_specs = gui_state_helpers.reports_primary_action_button_specs()
        self._reports_go_audit_button = self._make_action_button(actions, primary_report_specs[0])
        self._reports_agent_handoff_button = self._make_action_button(actions, primary_report_specs[1])
        self._reports_action_buttons = [
            self._make_action_button(actions, spec)
            for spec in gui_state_helpers.report_artifact_action_button_specs()
        ]
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
        heading_specs = gui_state_helpers.gui_section_heading_specs()
        panel_specs = gui_state_helpers.gui_panel_specs()
        text_specs = gui_state_helpers.gui_text_label_specs()
        self._add_section_heading(prompts_card, heading_specs["prompts_library"])
        self._add_text_label(prompts_card, text_specs["prompts_library_body"])
        self._prompts_visual_label = self._make_asset_label(
            prompts_card,
            "prompts-workflow.png",
            background=self._surface_fg,
        )
        if self._prompts_visual_label is not None:
            self._prompts_visual_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=(8, 14), pady=(10, 4))
        workflow_guide = self._make_panel(prompts_card, panel_specs["prompts_workflow"])
        self._add_text_label(workflow_guide, text_specs["prompts_workflow_title"])
        workflow_info_badge = self._make_info_badge_for(workflow_guide, "agent_workflow_section")
        self._prompts_workflow_info_badge = workflow_info_badge
        self._add_text_label(workflow_guide, text_specs["prompts_workflow_body"])
        self._apply_prompts_workflow_layout(compact=self._prompt_card_columns_for_width(self._get_logical_window_width()) == 1)
        self._prompt_cards_frame = ctk.CTkFrame(prompts_card, fg_color="transparent")
        self._prompt_cards_frame.grid(row=3, column=0, columnspan=2, sticky="we", padx=14, pady=(0, 12))
        self._refresh_prompt_cards()

    def _prompt_card_columns_for_width(self, width: int) -> int:
        threshold = int(getattr(self, "_prompts_stack_width_threshold", 1240))
        return 1 if width <= threshold else 2

    def _prompt_card_text_wraplength(self, columns: int, *, mono: bool = False) -> int:
        if columns > 1:
            return 520 if mono else 500
        width = self._get_logical_window_width()
        return max(520, min(900, width - (140 if mono else 170)))

    def _prompt_metadata_text(self, prompt_id: str, prefix: str) -> str:
        key = f"{prefix}_{prompt_id}"
        if key not in GUI_UI_TEXT_BY_LOCALE[GUI_LOCALE_DEFAULT]:
            return ""
        return self._t(key)

    def _refresh_prompt_cards(self) -> None:
        cards_frame = getattr(self, "_prompt_cards_frame", None)
        if cards_frame is None:
            return
        for child in cards_frame.winfo_children():
            child.destroy()
        self._prompt_card_widgets = []
        self._prompt_card_stage_labels = []

        columns = self._prompt_card_columns_for_width(self._get_logical_window_width())
        body_wraplength = self._prompt_card_text_wraplength(columns)
        command_wraplength = self._prompt_card_text_wraplength(columns, mono=True)

        repo_root = source_tree_root()
        for idx, prompt in enumerate(prompt_helpers.agentic_prompt_cards(self._current_locale())):
            card_spec = gui_state_helpers.prompt_card_presentation_spec(
                index=idx,
                stage_text=self._prompt_metadata_text(prompt.prompt_id, "prompt_stage"),
                title=prompt.title,
                description=prompt.description,
                best_for_text=self._prompt_metadata_text(prompt.prompt_id, "prompt_best_for"),
                command_label=self._t("prompt_command"),
                command=prompt.command,
                body_wraplength=body_wraplength,
                command_wraplength=command_wraplength,
            )
            card = self.ctk.CTkFrame(
                cards_frame,
                fg_color=self._theme_color_role(card_spec.fg_color_role),
                corner_radius=card_spec.corner_radius,
                border_width=card_spec.border_width,
                border_color=self._theme_color_role(card_spec.border_color_role),
            )
            self._prompt_card_widgets.append(card)
            for column_config in card_spec.column_configs:
                card.grid_columnconfigure(column_config.column, weight=column_config.weight)
            self._prompt_card_stage_labels.append(self._add_literal_text_label(card, card_spec.stage_label))
            self._add_literal_text_label(card, card_spec.title_label)
            self._add_literal_text_label(card, card_spec.description_label)
            self._add_literal_text_label(card, card_spec.best_for_label)
            self._add_literal_text_label(card, card_spec.command_label)

            actions = self.ctk.CTkFrame(card, fg_color="transparent")
            actions.grid(**card_spec.actions_grid.kwargs)
            for action_spec in gui_state_helpers.prompt_card_action_button_specs():
                self._make_action_button(actions, action_spec, prompt=prompt, repo_root=repo_root)
        self._apply_prompt_cards_layout(columns)

    def _apply_prompt_cards_layout(self, columns: int) -> None:
        cards_frame = getattr(self, "_prompt_cards_frame", None)
        if cards_frame is None:
            return
        safe_columns = 1 if columns <= 1 else 2
        self._prompt_card_column_count = safe_columns
        for column_index in range(2):
            cards_frame.grid_columnconfigure(column_index, weight=1 if column_index < safe_columns else 0)
        for idx, card in enumerate(getattr(self, "_prompt_card_widgets", [])):
            row = idx // safe_columns
            column = idx % safe_columns
            if safe_columns == 1:
                padx = (0, 0)
            else:
                padx = (0 if column == 0 else 8, 8 if column == 0 else 0)
            card.grid(row=row, column=column, sticky="nsew", padx=padx, pady=(0, 8))

    def _copy_text_to_clipboard(self, text: str, success_message: str) -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update_idletasks()
            self.log(f"[INFO] {success_message}")
        except Exception as exc:
            self.log(f"[WARN] Clipboard copy failed: {exc}")

    def _copy_prompt_to_clipboard(self, prompt: prompt_helpers.AgenticPrompt) -> None:
        repo_root = source_tree_root()
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

    def _compare_previous_report_to_latest(self) -> None:
        artifacts = getattr(self, "_last_run_artifacts", None)
        if artifacts is None:
            self.log(f"[INFO] {self._t('latest_artifacts_none')}")
            return
        previous_report = find_previous_report_json(artifacts.json_path)
        if previous_report is None:
            self.log(f"[INFO] {self._t('report_diff_no_previous')}")
            return
        try:
            diff = compare_report_files(
                previous_report,
                artifacts.json_path,
                before_label=self._artifact_handoff_path(previous_report),
                after_label=self._artifact_handoff_path(artifacts.json_path),
            )
            summary = format_report_diff_summary(diff)
        except Exception as exc:
            self.log(f"[WARN] {self._t('report_diff_failed', error=exc)}")
            return
        for line in summary.splitlines():
            self.log(line)
        self._copy_text_to_clipboard(summary, self._t("report_diff_copied"))

    def _artifact_handoff_path(self, path: Path) -> str:
        repo_root = source_tree_root()
        try:
            return path.resolve().relative_to(repo_root).as_posix()
        except ValueError:
            return redact_sensitive_text(str(path))

    def _reports_summary_counts(self, reports_payload: list[dict[str, object]] | None = None) -> dict[str, int]:
        payload = getattr(self, "_last_audit_reports_payload", []) if reports_payload is None else reports_payload
        return {
            "total": len(payload),
            "passed": sum(1 for item in payload if item.get("status") == "PASS"),
            "failed": sum(1 for item in payload if item.get("status") == "FAIL"),
            "blocking": sum(self._report_item_count(item, "failures") for item in payload),
            "manual": sum(self._manual_review_signal_count(item) for item in payload),
            "fixture": sum(self._safe_context_count(item) for item in payload),
        }

    def _reports_status_label(self, counts: dict[str, int], exit_code: int | None) -> str:
        return gui_state_helpers.reports_status_label(
            counts,
            exit_code,
            exit_policy_failed=EXIT_POLICY_FAILED,
            exit_runtime_error=EXIT_RUNTIME_ERROR,
            exit_aborted=EXIT_ABORTED,
        )

    def _reports_next_action_key(self, counts: dict[str, int], exit_code: int | None, has_artifacts: bool) -> str:
        return gui_state_helpers.reports_next_action_key(
            counts,
            exit_code,
            has_artifacts=has_artifacts,
            exit_ok=EXIT_OK,
            exit_policy_failed=EXIT_POLICY_FAILED,
            exit_runtime_error=EXIT_RUNTIME_ERROR,
            exit_aborted=EXIT_ABORTED,
        )

    def _refresh_reports_decision_panel(self) -> None:
        next_action_label = getattr(self, "_reports_next_action_label", None)
        if next_action_label is None:
            return
        artifacts = getattr(self, "_last_run_artifacts", None)
        counts = self._reports_summary_counts()
        exit_code = getattr(self, "_last_run_exit_code", None)
        visibility_state = gui_state_helpers.reports_action_visibility_state(has_artifacts=artifacts is not None)
        next_action_label.configure(
            text=self._t(self._reports_next_action_key(counts, exit_code, artifacts is not None))
        )
        steps_frame = getattr(self, "_reports_agent_steps_frame", None)
        prompts_button = getattr(self, "_reports_open_prompts_button", None)
        if steps_frame is not None:
            if visibility_state.show_decision_steps:
                steps_frame.grid()
            else:
                steps_frame.grid_remove()
        if prompts_button is not None:
            if visibility_state.show_prompts_button:
                prompts_button.grid()
            else:
                prompts_button.grid_remove()
        if artifacts is None:
            return
        self._reports_decision_layout_signature = None
        self._apply_reports_decision_layout(compact=bool(getattr(self, "_compact_reports_decision_layout", False)))

    def _build_agent_handoff_text(self) -> str | None:
        artifacts = getattr(self, "_last_run_artifacts", None)
        if artifacts is None:
            return None
        counts = self._reports_summary_counts()
        exit_code = getattr(self, "_last_run_exit_code", None)
        status_label = self._reports_status_label(counts, exit_code)
        next_action = self._t(self._reports_next_action_key(counts, exit_code, True))
        return self._t(
            "agent_handoff_prompt",
            status_label=status_label,
            repo_count=counts["total"],
            blocking_count=counts["blocking"],
            manual_count=counts["manual"],
            fixture_count=counts["fixture"],
            next_action=next_action,
            agent_summary_path=self._artifact_handoff_path(
                artifacts.agent_summary_path or artifacts.run_dir / "agent_summary.json"
            ),
            json_path=self._artifact_handoff_path(artifacts.json_path),
            html_path=self._artifact_handoff_path(artifacts.html_path),
            log_path=self._artifact_handoff_path(artifacts.log_path),
            state_path=self._artifact_handoff_path(artifacts.state_path),
        )

    def _copy_agent_handoff_to_clipboard(self) -> None:
        text = self._build_agent_handoff_text()
        if text is None:
            self.log(f"[INFO] {self._t('latest_artifacts_none')}")
            return
        self._copy_text_to_clipboard(text, self._t("agent_handoff_copied"))

    def _refresh_reports_tab(self) -> None:
        badge = getattr(self, "_reports_status_badge", None)
        summary_label = getattr(self, "_reports_summary_label", None)
        paths_label = getattr(self, "_reports_paths_label", None)
        artifacts = getattr(self, "_last_run_artifacts", None)
        if badge is None or summary_label is None or paths_label is None:
            return
        go_audit_button = getattr(self, "_reports_go_audit_button", None)
        agent_handoff_button = getattr(self, "_reports_agent_handoff_button", None)
        counts = self._reports_summary_counts()
        exit_code = getattr(self, "_last_run_exit_code", None)
        artifact_paths_text = ""
        if artifacts is not None:
            artifact_paths_text = gui_state_helpers.report_artifact_paths_text(
                run_dir=self._artifact_handoff_path(artifacts.run_dir),
                json_path=self._artifact_handoff_path(artifacts.json_path),
                agent_summary_path=self._artifact_handoff_path(
                    artifacts.agent_summary_path or artifacts.run_dir / "agent_summary.json"
                ),
                html_path=self._artifact_handoff_path(artifacts.html_path),
                log_path=self._artifact_handoff_path(artifacts.log_path),
                state_path=self._artifact_handoff_path(artifacts.state_path),
            )
        presentation_state = gui_state_helpers.reports_run_presentation_state(
            has_artifacts=artifacts is not None,
            counts=counts,
            exit_code=exit_code,
            run_action=self._last_run_action,
            artifact_paths_text=artifact_paths_text,
            repair_summary_text=self._build_repair_status_summary(self._last_audit_reports_payload),
            empty_badge_text=self._t("last_run"),
            empty_summary_text=self._t("last_run_none"),
            empty_paths_text=self._t("latest_artifacts_none"),
            exit_ok=EXIT_OK,
            exit_policy_failed=EXIT_POLICY_FAILED,
            exit_runtime_error=EXIT_RUNTIME_ERROR,
            exit_aborted=EXIT_ABORTED,
        )
        visibility_state = presentation_state.visibility
        self._refresh_reports_decision_panel()
        badge.configure(
            text=presentation_state.badge_text,
            fg_color=self._theme_color_role(presentation_state.badge_fg_color_role),
            text_color=self._theme_color_role(presentation_state.badge_text_color_role),
        )
        summary_label.configure(text=presentation_state.summary_text)
        paths_label.configure(text=presentation_state.paths_text)
        if artifacts is None:
            if go_audit_button is not None and visibility_state.show_go_audit_button:
                go_audit_button.grid(**gui_state_helpers.reports_primary_action_button_specs()[0].grid.kwargs)
            if agent_handoff_button is not None:
                agent_handoff_button.grid_remove()
            for button in getattr(self, "_reports_action_buttons", []):
                button.grid_remove()
                button.configure(state=visibility_state.artifact_button_state)
            return

        if go_audit_button is not None and not visibility_state.show_go_audit_button:
            go_audit_button.grid_remove()
        compact_actions = bool(getattr(self, "_compact_reports_actions_layout", False))
        artifact_buttons = list(getattr(self, "_reports_action_buttons", []))
        action_layout_state = gui_state_helpers.reports_action_layout_state(
            compact=compact_actions,
            artifact_button_count=len(artifact_buttons),
        )
        if agent_handoff_button is not None and visibility_state.show_agent_handoff_button:
            agent_handoff_button.grid(**action_layout_state.agent_handoff_grid.kwargs)
        for button, button_grid in zip(artifact_buttons, action_layout_state.artifact_button_grids, strict=True):
            button.grid_configure(**button_grid.kwargs)

        for button in getattr(self, "_reports_action_buttons", []):
            button.configure(state=visibility_state.artifact_button_state)

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
        visibility_state = gui_state_helpers.repair_options_visibility_state(visible=visible)
        self._repair_options_visible = visibility_state.visible
        card = getattr(self, "_repair_options_card", None)
        if card is not None:
            if visibility_state.visible:
                card.grid()
            else:
                card.grid_remove()
        button = getattr(self, "_repair_options_toggle_button", None)
        if button is not None:
            button.configure(text=self._t(visibility_state.toggle_text_key))
        hint = getattr(self, "_repair_options_hint_label", None)
        if hint is not None:
            hint.configure(text=self._t(visibility_state.hint_text_key, **visibility_state.hint_kwargs))

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
        try:
            self.ctk.set_appearance_mode(self._current_appearance())
        except Exception:
            pass
        self._sync_ctk_system_appearance_probe()
        self._apply_effective_gui_theme(force=True)
        self._refresh_appearance_menu()
        self._save_gui_setup_settings(setup_completed=bool(getattr(self, "_setup_completed", False)))
        self.log(f"[INFO] GUI theme applied as {self._current_appearance()} ({self._effective_appearance()} effective).")

    def _tooltip_text(self, key: str) -> str:
        catalog = GUI_TOOLTIP_TEXT_BY_LOCALE.get(self._current_locale(), GUI_TOOLTIP_TEXT)
        return catalog.get(key, GUI_TOOLTIP_TEXT[key])

    def _bind_tooltip_key(self, widget, key: str):
        self._bind_tooltip(widget, lambda: self._tooltip_text(key))
        return widget

    def _make_info_badge_for(self, parent, key: str):
        return self._make_info_badge(parent, lambda: self._tooltip_text(key))

    def _theme_color_role(self, role: str) -> str:
        colors = {
            "body": self._text_body,
            "card_border": self._card_border,
            "failure_badge": self._failure_badge_fg,
            "failure_badge_text": self._failure_badge_text,
            "fixed_header_light": "#F8FAFC",
            "fixed_header_subtitle": "#D8FFF3",
            "header_chip": self._header_chip_fg,
            "header_chip_text": self._header_chip_text,
            "heading": self._text_heading,
            "info": self._info_text,
            "info_panel": self._info_panel_fg,
            "info_panel_border": self._info_panel_border,
            "muted": self._text_muted,
            "output": self._output_fg,
            "output_empty": self._output_empty_text,
            "pass_badge": self._pass_badge_fg,
            "pass_badge_text": self._pass_badge_text,
            "primary_button": self._primary_button_fg,
            "success": self._success_text,
            "success_badge": self._success_badge_fg,
            "success_panel": self._success_panel_fg,
            "success_panel_border": self._success_panel_border,
            "surface": self._surface_fg,
            "surface_alt": self._surface_alt,
            "transparent": "transparent",
            "warning": self._warning_text,
            "warning_badge": self._warning_badge_fg,
            "warning_badge_text": self._warning_badge_text,
            "warning_panel": self._warning_panel_fg,
            "warning_panel_border": self._warning_panel_border,
            "warning_strong": self._warning_strong_text,
            "white_panel": self._white_panel_fg,
        }
        if role not in colors:
            raise ValueError(f"Unknown GUI theme color role: {role}")
        return colors[role]

    def _make_panel(self, parent, spec: gui_state_helpers.PanelSpec):
        panel = self.ctk.CTkFrame(
            parent,
            fg_color=self._theme_color_role(spec.fg_color_role),
            corner_radius=spec.corner_radius,
            border_width=spec.border_width,
            border_color=self._theme_color_role(spec.border_color_role),
        )
        panel.grid(**spec.grid.kwargs)
        for config in spec.column_configs:
            panel.grid_columnconfigure(config.column, weight=config.weight)
        for config in spec.row_configs:
            panel.grid_rowconfigure(config.column, weight=config.weight)
        if spec.widget_attr:
            setattr(self, spec.widget_attr, panel)
        return panel

    def _add_text_label(self, parent, spec: gui_state_helpers.TextLabelSpec):
        label_options: dict[str, object] = {
            "text": self._t(spec.text_key),
            "font": self._font(spec.font_size, bold=spec.bold, mono=spec.mono),
            "text_color": self._theme_color_role(spec.text_color_role),
            "justify": spec.justify,
        }
        if spec.anchor is not None:
            label_options["anchor"] = spec.anchor
        if spec.wraplength is not None:
            label_options["wraplength"] = spec.wraplength
        if spec.height is not None:
            label_options["height"] = spec.height
        if spec.corner_radius is not None:
            label_options["corner_radius"] = spec.corner_radius
        if spec.fg_color_role is not None:
            label_options["fg_color"] = self._theme_color_role(spec.fg_color_role)
        if spec.padx is not None:
            label_options["padx"] = spec.padx

        label = self.ctk.CTkLabel(parent, **label_options)
        if spec.fixed_text_color:
            self._register_fixed_theme_option(label, "text_color", self._theme_color_role(spec.text_color_role))
        if spec.localize:
            self._localize_widget(label, "text", spec.text_key)
        if spec.tooltip_key:
            self._bind_tooltip_key(label, spec.tooltip_key)
        if spec.grid is not None:
            label.grid(**spec.grid.kwargs)
        if spec.widget_attr:
            setattr(self, spec.widget_attr, label)
        return label

    def _add_literal_text_label(self, parent, spec: gui_state_helpers.LiteralTextLabelSpec):
        label_options: dict[str, object] = {
            "text": spec.text,
            "font": self._font(spec.font_size, bold=spec.bold, mono=spec.mono),
            "text_color": self._theme_color_role(spec.text_color_role),
        }
        if spec.justify is not None:
            label_options["justify"] = spec.justify
        if spec.anchor is not None:
            label_options["anchor"] = spec.anchor
        if spec.wraplength is not None:
            label_options["wraplength"] = spec.wraplength
        if spec.height is not None:
            label_options["height"] = spec.height
        if spec.corner_radius is not None:
            label_options["corner_radius"] = spec.corner_radius
        if spec.fg_color_role is not None:
            label_options["fg_color"] = self._theme_color_role(spec.fg_color_role)
        if spec.padx is not None:
            label_options["padx"] = spec.padx
        label = self.ctk.CTkLabel(parent, **label_options)
        label.grid(**spec.grid.kwargs)
        return label

    def _add_section_heading(self, parent, spec: gui_state_helpers.SectionHeadingSpec):
        heading = self._make_section_heading(
            parent,
            text_key=spec.text_key,
            tooltip_key=spec.tooltip_key,
            font_size=spec.font_size,
            text_color=self._theme_color_role(spec.text_color_role),
            fixed_text_color=spec.fixed_text_color,
        )
        heading.grid(**spec.grid.kwargs)
        return heading

    def _make_section_heading(
        self,
        parent,
        *,
        text_key: str,
        tooltip_key: str,
        font_size: int = 16,
        text_color: str | None = None,
        fixed_text_color: bool = False,
    ):
        shell = self.ctk.CTkFrame(parent, fg_color="transparent")
        label = self.ctk.CTkLabel(
            shell,
            text=self._t(text_key),
            font=self._font(font_size, bold=True),
            text_color=text_color or self._text_heading,
        )
        if fixed_text_color:
            self._register_fixed_theme_option(label, "text_color", text_color or self._text_heading)
        self._localize_widget(label, "text", text_key)
        self._bind_tooltip_key(label, tooltip_key)
        label.pack(side="left")
        self._make_info_badge_for(shell, tooltip_key).pack(side="left", padx=(8, 0))
        return shell

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

    def _make_option_checkbox(
        self,
        parent,
        spec: gui_state_helpers.OptionCheckboxSpec,
    ):
        options: dict[str, object] = {}
        if spec.command_attr:
            options["command"] = getattr(self, spec.command_attr)
        checkbox = self.ctk.CTkCheckBox(
            parent,
            text=self._t(spec.text_key),
            variable=getattr(self, spec.variable_attr),
            font=self._font(12),
            text_color=self._text_body,
            **options,
        )
        self._localize_widget(checkbox, "text", spec.text_key)
        self._bind_tooltip_key(checkbox, spec.tooltip_key)
        checkbox.grid(**spec.grid.kwargs)
        if spec.widget_attr:
            setattr(self, spec.widget_attr, checkbox)
        if spec.info_badge:
            self._make_info_badge_for(parent, spec.tooltip_key).grid(
                row=spec.grid.row,
                column=1,
                sticky="e",
                padx=(0, 12),
            )
        return checkbox

    def _action_button_style_options(self, style: gui_state_helpers.ActionButtonStyle) -> dict[str, object]:
        if style == "primary":
            return {
                "fg_color": self._primary_button_fg,
                "hover_color": self._primary_button_hover,
            }
        if style == "support":
            return {
                "fg_color": self._support_button_fg,
                "hover_color": self._support_button_hover,
            }
        return self._secondary_button_options()

    def _action_button_command(
        self,
        spec: gui_state_helpers.ActionButtonSpec,
        *,
        prompt: prompt_helpers.AgenticPrompt | None = None,
        repo_root: Path | None = None,
    ) -> Callable[[], None]:
        if spec.command_kind == "method":
            if spec.command_attr is None:
                raise ValueError(f"Action button {spec.text_key} is missing command_attr")
            return cast(Callable[[], None], getattr(self, spec.command_attr))
        if spec.command_kind == "flow_tab":
            command_arg = spec.command_arg
            if command_arg is None:
                raise ValueError(f"Action button {spec.text_key} is missing command_arg")
            return lambda: self._set_active_flow_tab(getattr(self, command_arg))
        if spec.command_kind == "artifact":
            command_arg = spec.command_arg
            if command_arg is None:
                raise ValueError(f"Action button {spec.text_key} is missing command_arg")
            return lambda: self._open_last_artifact(command_arg)
        if spec.command_kind == "prompt_copy":
            if prompt is None:
                raise ValueError(f"Action button {spec.text_key} is missing prompt")
            return lambda: self._copy_prompt_to_clipboard(prompt)
        if spec.command_kind == "prompt_command_copy":
            if prompt is None:
                raise ValueError(f"Action button {spec.text_key} is missing prompt")
            return lambda: self._copy_text_to_clipboard(prompt.command, self._t("prompt_command_copied"))
        if prompt is None or repo_root is None:
            raise ValueError(f"Action button {spec.text_key} is missing prompt or repo_root")
        return lambda: self._open_prompt_file(prompt, repo_root)

    def _make_action_button(
        self,
        parent,
        spec: gui_state_helpers.ActionButtonSpec,
        *,
        prompt: prompt_helpers.AgenticPrompt | None = None,
        repo_root: Path | None = None,
    ):
        button_options: dict[str, object] = {}
        if spec.icon:
            button_options.update(self._button_asset_options(spec.icon))
        button_options.update(self._action_button_style_options(spec.style))
        button = self.ctk.CTkButton(
            parent,
            text=self._t(spec.text_key),
            command=self._action_button_command(spec, prompt=prompt, repo_root=repo_root),
            height=spec.height,
            corner_radius=8,
            **button_options,
        )
        if spec.localize:
            self._localize_widget(button, "text", spec.text_key)
        self._bind_tooltip_key(button, spec.tooltip_key)
        button.grid(**spec.grid.kwargs)
        if spec.widget_attr:
            setattr(self, spec.widget_attr, button)
        return button

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

    def _browse_directory(self, target_var, *, title: str, mustexist: bool = False) -> bool:
        selected = self.filedialog.askdirectory(
            title=title,
            initialdir=self._dialog_initial_dir(target_var.get()),
            mustexist=mustexist,
        )
        if selected:
            target_var.set(selected)
            return True
        return False

    def _on_root_directory_selected(self) -> None:
        self.refresh_repos()
        self._save_gui_setup_settings(setup_completed=True)

    def _choose_root_from_empty_state(self) -> None:
        if self._browse_directory(
            self.root_var,
            title=self._t("choose_repositories_root"),
            mustexist=True,
        ):
            self._on_root_directory_selected()

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

    def _add_entry_field(
        self,
        parent,
        spec: gui_state_helpers.EntryFieldSpec,
    ):
        variable = getattr(self, spec.variable_attr)
        self._make_field_label(
            parent,
            text_key=spec.text_key,
            tooltip_key=spec.tooltip_key,
        ).grid(**spec.label_grid.kwargs)

        entry_options: dict[str, object] = {}
        if spec.width is not None:
            entry_options["width"] = spec.width
        if spec.placeholder_key is not None:
            entry_options["placeholder_text"] = self._t(spec.placeholder_key)
        entry = self.ctk.CTkEntry(
            parent,
            textvariable=variable,
            height=32,
            corner_radius=8,
            **entry_options,
        )
        if spec.placeholder_key is not None:
            self._localize_widget(entry, "placeholder_text", spec.placeholder_key)
        self._bind_tooltip_key(entry, spec.tooltip_key)
        entry.grid(**spec.entry_grid.kwargs)
        if spec.widget_attr:
            setattr(self, spec.widget_attr, entry)
        return entry

    def _add_path_field(
        self,
        parent,
        spec: gui_state_helpers.PathFieldSpec,
    ) -> None:
        variable = getattr(self, spec.variable_attr)
        self._make_field_label(
            parent,
            text_key=spec.label_key,
            tooltip_key=spec.tooltip_key,
        ).grid(**spec.label_grid.kwargs)

        field_parent = parent
        if spec.row_frame_grid is not None:
            row_frame = self.ctk.CTkFrame(parent, fg_color="transparent")
            row_frame.grid(**spec.row_frame_grid.kwargs)
            if spec.row_frame_weight_column is not None:
                row_frame.grid_columnconfigure(spec.row_frame_weight_column, weight=1)
            field_parent = row_frame

        entry = self.ctk.CTkEntry(field_parent, textvariable=variable, height=32, corner_radius=8)
        self._bind_tooltip_key(entry, spec.tooltip_key)
        entry.grid(**spec.entry_grid.kwargs)

        button_options: dict[str, object] = {}
        if spec.button_icon:
            button_options.update(self._button_asset_options(spec.button_icon))
        button_options.update(self._secondary_button_options())
        button = self.ctk.CTkButton(
            field_parent,
            text=self._t(spec.button_text_key),
            width=92,
            height=32,
            corner_radius=8,
            **button_options,
            command=lambda: self._run_path_field_dialog(spec, variable),
        )
        self._localize_widget(button, "text", spec.button_text_key)
        self._bind_tooltip_key(button, spec.tooltip_key)
        button.grid(**spec.button_grid.kwargs)

    def _run_path_field_dialog(self, spec: gui_state_helpers.PathFieldSpec, variable) -> None:
        title = self._t(spec.title_key)
        if spec.kind == "directory":
            on_select = getattr(self, spec.on_select_attr) if spec.on_select_attr else None
            self._handle_directory_browse(variable, title=title, on_select=on_select)
            return
        if spec.kind == "existing_file":
            self._browse_existing_file(variable, title=title, filetypes=list(spec.filetypes))
            return
        if spec.default_extension is None:
            raise ValueError(f"Path field {spec.label_key} is missing default_extension")
        self._browse_save_file(
            variable,
            title=title,
            default_extension=spec.default_extension,
            filetypes=list(spec.filetypes),
        )

    def _handle_directory_browse(
        self,
        target_var,
        *,
        title: str,
        on_select: Callable[[], None] | None = None,
    ) -> None:
        if self._browse_directory(target_var, title=title) and on_select is not None:
            on_select()

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
        return max(0, int(round(width / safe_scale)))

    def _on_root_resize(self, event) -> None:
        del event
        if getattr(self, "_gui_destroying", False):
            return
        self._apply_responsive_layout()

    def _on_root_destroy(self, event) -> None:
        if getattr(event, "widget", None) is self.root:
            self._gui_destroying = True
            self._unregister_appearance_mode_callback()

    def _apply_responsive_layout(self) -> None:
        if getattr(self, "_gui_destroying", False):
            return
        width = self._get_logical_window_width()
        self._apply_header_flow_layout(compact=width <= self._top_stack_width_threshold)
        self._apply_top_layout(compact=width <= self._top_stack_width_threshold)
        self._apply_identity_actions_layout(compact=width <= self._top_stack_width_threshold)
        self._apply_options_layout(compact=width <= self._options_stack_width_threshold)
        self._apply_results_layout(compact=width <= self._results_stack_width_threshold)
        self._apply_reports_decision_layout(compact=width <= self._results_stack_width_threshold)
        self._apply_reports_actions_layout(compact=width <= self._results_stack_width_threshold)
        prompt_columns = self._prompt_card_columns_for_width(width)
        self._apply_prompts_workflow_layout(compact=prompt_columns == 1)
        if prompt_columns != getattr(self, "_prompt_card_column_count", 2):
            self._apply_prompt_cards_layout(prompt_columns)

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
        except Exception as exc:
            self._record_gui_warning("header flow layout update failed", exc)
            return

    def _apply_prompts_workflow_layout(self, compact: bool) -> None:
        guide = getattr(self, "_prompts_workflow_guide", None)
        title_label = getattr(self, "_prompts_workflow_title_label", None)
        body_label = getattr(self, "_prompts_workflow_body_label", None)
        info_badge = getattr(self, "_prompts_workflow_info_badge", None)
        visual_label = getattr(self, "_prompts_visual_label", None)
        layout_state = gui_state_helpers.prompts_workflow_layout_state(compact=compact)
        try:
            if guide is not None:
                for column_config in layout_state.column_configs:
                    guide.grid_columnconfigure(column_config.column, weight=column_config.weight)
            if title_label is not None:
                title_label.grid(**layout_state.title_grid.kwargs)
            if info_badge is not None:
                info_badge.grid(**layout_state.info_badge_grid.kwargs)
            if body_label is not None:
                body_label.grid(**layout_state.body_grid.kwargs)
                body_label.configure(wraplength=layout_state.body_wraplength)
            if visual_label is not None:
                if layout_state.visual_visible:
                    visual_label.grid()
                else:
                    visual_label.grid_remove()
        except Exception as exc:
            self._record_gui_warning("prompts workflow layout update failed", exc)
            return

    def _gui_var_str(self, attr_name: str, default: str = "") -> str:
        var = getattr(self, attr_name, None)
        if var is None:
            return default
        try:
            value = var.get()
        except Exception:
            return default
        return str(value).strip()

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
            "strict_profile": self._gui_var_str("strict_profile_var", "default"),
            "suppressions": self._gui_var_str("suppressions_file_var", ""),
            "public_only": bool(self.public_only_var.get()),
            "github_include_forks": bool(self.github_include_forks_var.get()),
            "github_fast": bool(self.github_fast_var.get()),
            "dry_run": bool(self.dry_run_var.get()),
            "low_confidence_blocking": bool(self.low_confidence_blocking_var.get()),
            "audit_litellm_incident": bool(self.audit_litellm_incident_var.get()),
            "audit_github_hardening": bool(self.audit_github_hardening_var.get()),
            "accept_github_admin_bypass": bool(self.accept_github_admin_bypass_var.get()),
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
        visibility_state = self._setup_settings_visibility_state(visible)
        return self._t(visibility_state.hint_text_key, **visibility_state.hint_kwargs)

    def _setup_settings_visibility_state(self, visible: bool) -> gui_state_helpers.CollapsibleSectionState:
        try:
            github_owner = self._github_owner_value()
        except Exception:
            github_owner = None
        return gui_state_helpers.setup_settings_visibility_state(visible=visible, github_owner=github_owner)

    def _set_setup_settings_visibility(self, visible: bool) -> None:
        visibility_state = self._setup_settings_visibility_state(visible)
        self._setup_settings_visible = visibility_state.visible

        toggle_button = getattr(self, "_setup_settings_toggle_button", None)
        if toggle_button is not None:
            toggle_button.configure(text=self._t(visibility_state.toggle_text_key))

        hint_label = getattr(self, "_setup_settings_hint_label", None)
        if hint_label is not None:
            hint_label.configure(text=self._t(visibility_state.hint_text_key, **visibility_state.hint_kwargs))

        frame = getattr(self, "_setup_settings_frame", None)
        if frame is not None:
            if visibility_state.visible:
                frame.grid()
            else:
                frame.grid_remove()

    def _toggle_advanced_identity_settings(self) -> None:
        self._set_advanced_identity_visibility(not self._advanced_identity_visible)

    def _set_advanced_identity_visibility(self, visible: bool) -> None:
        visibility_state = gui_state_helpers.advanced_identity_visibility_state(visible=visible)
        self._advanced_identity_visible = visibility_state.visible

        toggle_button = getattr(self, "_advanced_identity_toggle_button", None)
        if toggle_button is not None:
            toggle_button.configure(text=self._t(visibility_state.toggle_text_key))

        hint_label = getattr(self, "_advanced_identity_hint_label", None)
        if hint_label is not None:
            hint_label.configure(text=self._t(visibility_state.hint_text_key, **visibility_state.hint_kwargs))

        identity_card = getattr(self, "_identity_card", None)
        if identity_card is not None:
            if visibility_state.visible:
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
        buttons = [cast(Any, button) for button in self._identity_action_buttons]
        layout_state = gui_state_helpers.identity_actions_layout_state(compact=compact)

        for column_config in layout_state.column_configs:
            self._identity_actions.grid_columnconfigure(column_config.column, weight=column_config.weight)
        for button, button_grid in zip(buttons, layout_state.button_grids, strict=True):
            button.grid_configure(**button_grid.kwargs)

    def _apply_options_layout(self, compact: bool) -> None:
        if compact == self._compact_options_layout:
            return

        safe_options_card = getattr(self, "_safe_options_card", None)
        destructive_options_card = getattr(self, "_destructive_options_card", None)
        if safe_options_card is None or destructive_options_card is None:
            return

        self._compact_options_layout = compact
        safe_options_card = cast(Any, safe_options_card)
        destructive_options_card = cast(Any, destructive_options_card)
        if compact:
            safe_options_card.grid_configure(row=1, column=0, padx=14, pady=(0, 8), sticky="we")
            destructive_options_card.grid_configure(
                row=2,
                column=0,
                padx=14,
                pady=(0, 12),
                sticky="we",
            )
            return

        safe_options_card.grid_configure(row=1, column=0, padx=(14, 7), pady=(0, 12), sticky="nsew")
        destructive_options_card.grid_configure(
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

    def _apply_reports_actions_layout(self, compact: bool) -> None:
        if compact == getattr(self, "_compact_reports_actions_layout", False):
            return

        self._compact_reports_actions_layout = compact
        self._refresh_reports_tab()

    def _apply_reports_decision_layout(self, compact: bool) -> None:
        steps_frame = getattr(self, "_reports_agent_steps_frame", None)
        step_labels = list(getattr(self, "_reports_agent_step_labels", []))
        prompts_button = getattr(self, "_reports_open_prompts_button", None)
        if steps_frame is None or len(step_labels) != 3:
            return

        layout_signature = (
            compact,
            id(steps_frame),
            *(id(label) for label in step_labels),
            id(prompts_button),
        )
        if layout_signature == getattr(self, "_reports_decision_layout_signature", None):
            return

        layout_state = gui_state_helpers.reports_decision_layout_state(compact=compact)
        try:
            self._compact_reports_decision_layout = layout_state.compact
            for column_config in layout_state.column_configs:
                steps_frame.grid_columnconfigure(column_config.column, weight=column_config.weight)
            for label, label_grid in zip(step_labels, layout_state.step_label_grids, strict=True):
                label.grid_configure(**label_grid.kwargs)
            if prompts_button is not None and self._widget_is_grid_managed(prompts_button):
                prompts_button.grid_configure(sticky=layout_state.prompts_button_sticky)
            self._reports_decision_layout_signature = layout_signature
        except Exception as exc:
            self._reports_decision_layout_signature = None
            self._record_gui_warning("reports decision layout update failed", exc)
            return

    @staticmethod
    def _widget_is_grid_managed(widget: object) -> bool:
        try:
            return cast(Any, widget).winfo_manager() == "grid"
        except Exception:
            return True

    def _set_active_flow_tab(self, tab_name: str) -> None:
        if self._flow_tabs is None:
            return
        try:
            self._select_flow_tab_without_delayed_cleanup(tab_name)
            app_frame = getattr(self, "_app_frame", None)
            parent_canvas = getattr(app_frame, "_parent_canvas", None)
            if parent_canvas is not None:
                parent_canvas.yview_moveto(0)
        except Exception as exc:
            self._record_gui_warning("flow tab selection failed", exc)

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
        except Exception as exc:
            self._record_gui_warning("tab view direct selection failed", exc)
            return

    def _set_output_empty_state(self, visible: bool) -> None:
        label = getattr(self, "_output_empty_state_label", None)
        output = getattr(self, "output", None)
        if label is None or output is None:
            return
        if visible:
            label.place(relx=0.5, rely=0.5, anchor="center")
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
        presentation_state = gui_state_helpers.repo_empty_presentation_state(
            reason=reason,
            body_text=message or "",
        )
        self._repo_empty_reason = presentation_state.reason
        title_label = getattr(self, "_repo_empty_state_title_label", None)
        body_label = getattr(self, "_repo_empty_state_body_label", None)
        hint_label = getattr(self, "_repo_empty_state_hint_label", None)
        action_button = getattr(self, "_repo_empty_state_action_button", None)

        panel_fg = self._theme_color_role(presentation_state.fg_color_role)
        repo_empty_state.configure(
            fg_color=panel_fg,
            border_color=self._theme_color_role(presentation_state.border_color_role),
        )
        visual_label = getattr(self, "_repo_empty_state_visual_label", None)
        if visual_label is not None:
            self._configure_asset_label_image(visual_label, "repo-dropzone.png", panel_fg)
        if title_label is not None:
            title_label.configure(
                text=self._t(presentation_state.title_key),
                text_color=self._theme_color_role(presentation_state.title_color_role),
            )
        if body_label is not None and presentation_state.body_text:
            body_label.configure(
                text=presentation_state.body_text,
                text_color=self._theme_color_role(presentation_state.body_color_role),
            )
        if hint_label is not None:
            hint_label.configure(
                text=self._t(presentation_state.hint_key),
                text_color=self._theme_color_role(presentation_state.hint_color_role),
            )
        if action_button is not None:
            if presentation_state.show_action_button:
                action_button.configure(
                    text=self._t(presentation_state.action_text_key),
                    state=presentation_state.action_state,
                )
                action_button.grid()
            else:
                action_button.grid_remove()
        try:
            self.repo_list.configure(state="disabled")
        except Exception:
            pass
        repo_empty_state.place(**presentation_state.place.kwargs)
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
            dynamic_widget = cast(Any, widget)
            try:
                dynamic_widget.tk.call("tkdnd::drop_target", "register", dynamic_widget._w, DND_FILES)
                drop_command = self.root.register(_drop)
                enter_command = self.root.register(_copy_action)
                self._dnd_command_names.extend([drop_command, enter_command])
                dynamic_widget.tk.call("bind", dynamic_widget._w, "<<Drop>>", f"{drop_command} %D")
                dynamic_widget.tk.call("bind", dynamic_widget._w, "<<DropEnter>>", enter_command)
                dynamic_widget.tk.call("bind", dynamic_widget._w, "<<DropPosition>>", enter_command)
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
        return gui_state_helpers.report_item_count(payload, *keys)

    def _manual_review_signal_count(self, payload: dict[str, object]) -> int:
        return gui_state_helpers.manual_review_signal_count(payload)

    def _safe_context_count(self, payload: dict[str, object]) -> int:
        return gui_state_helpers.safe_context_count(payload)

    def _build_repair_status_summary(self, reports_payload: list[dict[str, object]]) -> str:
        return gui_state_helpers.build_repair_status_summary(reports_payload, self._t)

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
        badges = getattr(self, "_gui_info_badges", None)
        if isinstance(badges, list):
            badges.append(badge)
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

            tip.update_idletasks()
            tip_width = max(tip.winfo_reqwidth(), 1)
            tip_height = max(tip.winfo_reqheight(), 1)
            screen_width = max(self.root.winfo_screenwidth(), 1)
            screen_height = max(self.root.winfo_screenheight(), 1)
            x = widget.winfo_rootx() + widget.winfo_width() + 8
            y = widget.winfo_rooty() - 2
            if x + tip_width + 8 > screen_width:
                x = widget.winfo_rootx() - tip_width - 8
            if y + tip_height + 8 > screen_height:
                y = screen_height - tip_height - 8
            x = max(4, x)
            y = max(4, y)
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
        note_state = gui_state_helpers.repair_gate_note_state(
            repair_ready=bool(getattr(self, "_repair_ready", False)),
            has_audit_reports=bool(getattr(self, "_last_audit_reports_payload", [])),
        )
        text_color = {
            "ready": self._pass_badge_text,
            "review": self._warning_text,
            "locked": self._text_muted,
        }[note_state.tone]
        note_label.configure(text=self._t(note_state.text_key), text_color=text_color)

    def _update_run_buttons_state(self) -> None:
        audit_button = getattr(self, "_audit_button", None)
        if audit_button is not None:
            has_targets = bool(getattr(self, "_repo_items", []))
            has_remote_target = self._github_owner_value() is not None
            audit_state = gui_state_helpers.audit_button_state(
                run_in_progress=bool(self._run_in_progress),
                has_targets=has_targets,
                has_remote_target=has_remote_target,
            )
            primary_fg = getattr(self, "_primary_button_fg", "#0F766E")
            primary_hover = getattr(self, "_primary_button_hover", "#0B5F59")
            disabled_fg = getattr(self, "_disabled_button_fg", "#B8C6D5")
            disabled_text = getattr(self, "_disabled_button_text", "#64748B")
            audit_button.configure(
                text=self._t(audit_state.text_key),
                state=audit_state.widget_state,
                fg_color=disabled_fg if audit_state.disabled else primary_fg,
                hover_color=disabled_fg if audit_state.disabled else primary_hover,
                text_color_disabled=disabled_text,
            )

        cancel_button = getattr(self, "_cancel_button", None)
        if cancel_button is not None:
            cancel_requested = bool(
                self._active_cancel_token and self._active_cancel_token.is_cancelled()
            )
            cancel_state = gui_state_helpers.cancel_button_state(
                run_in_progress=bool(self._run_in_progress),
                cancel_requested=cancel_requested,
            )
            cancel_button.configure(
                text=self._t(cancel_state.text_key),
                state=cancel_state.widget_state,
            )

        self._update_repo_selection_controls()

        repair_button = getattr(self, "_repair_button", None)
        if repair_button is None:
            return

        repair_button.configure(
            state=gui_state_helpers.repair_button_state(
                repair_ready=bool(self._repair_ready),
                run_in_progress=bool(self._run_in_progress),
            ),
            text=self._repair_button_text,
        )
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

    def _record_gui_warning(self, context: str, exc: Exception | None = None) -> None:
        detail = f"{context}: {exc}" if exc is not None else context
        warning = redact_sensitive_text(detail)
        warnings = getattr(self, "_gui_warnings", None)
        if isinstance(warnings, list):
            warnings.append(warning)
            del warnings[:-50]
        if not getattr(self, "_gui_debug_warnings", False):
            return
        try:
            self.log(f"[WARN] GUI visual fallback: {warning}")
        except Exception:
            return

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
            strict_profile_raw = self._gui_var_str("strict_profile_var", "default")
            strict_profile = None if strict_profile_raw in {"", "default"} else strict_profile_raw
            suppressions_file = self._gui_var_str("suppressions_file_var", "") or None

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
                accept_github_admin_bypass=self.accept_github_admin_bypass_var.get(),
                agent_summary=False,
                strict_profile=strict_profile,
                suppressions=suppressions_file,
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
        gui_window_helpers.run_mainloop(self.root)


from repo_privacy_guardian import core as _core  # noqa: E402

_GUI_OVERRIDE_NAMES = (
    "CancellationToken",
    "DEFAULT_NOREPLY",
    "DEFAULT_PLACEHOLDER",
    "DEFAULT_POLICY",
    "EXIT_ABORTED",
    "EXIT_OK",
    "EXIT_POLICY_FAILED",
    "EXIT_RUNTIME_ERROR",
    "GUI_APPEARANCE_DARK",
    "GUI_APPEARANCE_DEFAULT",
    "GUI_APPEARANCE_LIGHT",
    "GUI_APPEARANCE_SYSTEM",
    "GUI_ASSET_FILENAMES",
    "GUI_DEFAULT_PUBLIC_ONLY",
    "GUI_LOCALE_DEFAULT",
    "GUI_LOCALE_OPTIONS",
    "GUI_THEMEABLE_ASSET_FILENAMES",
    "GUI_TOOLTIP_TEXT",
    "GUI_TOOLTIP_TEXT_BY_LOCALE",
    "GUI_UI_TEXT_BY_LOCALE",
    "Path",
    "RunLogger",
    "apply_git_identity_config",
    "argparse",
    "artifact_helpers",
    "blend_near_white_gui_asset_background",
    "build_github_optional_tooling_checks",
    "build_guard_run_config",
    "choose_gui_font_family",
    "compare_report_files",
    "create_run_artifacts",
    "default_gui_settings_path",
    "default_results_dir",
    "default_root_dir",
    "discover_repository_targets",
    "enforce_results_dir",
    "execute_guard_pipeline",
    "find_previous_report_json",
    "format_git_identity_status",
    "format_report_diff_summary",
    "gui_appearance_from_label",
    "gui_appearance_label",
    "gui_appearance_options",
    "gui_asset_path",
    "gui_font_candidates",
    "gui_locale_from_label",
    "gui_locale_label",
    "gui_setting_bool",
    "gui_setting_str",
    "install_missing_tooling",
    "json",
    "load_gui_runtime",
    "load_gui_settings",
    "normalize_csv_values",
    "normalize_gui_appearance",
    "normalize_gui_locale",
    "normalize_repo_filters",
    "open_github_email_settings",
    "os",
    "parse_hex_rgb",
    "parse_positive_int",
    "parse_tk_drop_paths",
    "prompt_gui_tooling_install",
    "prompt_helpers",
    "read_git_identity_config",
    "redact_sensitive_text",
    "repo_display_name",
    "resolve_dropped_repository_targets",
    "resolve_identity_repo_path",
    "save_gui_settings",
    "source_tree_root",
    "strict_profiles",
    "threading",
    "traceback",
    "validate_git_identity_inputs",
    "validate_repository_root",
    "webbrowser",
)


def _sync_gui_public_overrides() -> None:
    for name in _GUI_OVERRIDE_NAMES:
        globals()[name] = getattr(_core, name)


_sync_gui_public_overrides()


def _wrap_gui_method(method: Callable[..., Any]) -> Callable[..., Any]:
    def synced(self: object, *args: Any, **kwargs: Any) -> Any:
        _sync_gui_public_overrides()
        return method(self, *args, **kwargs)

    synced.__name__ = getattr(method, "__name__", "synced")
    synced.__doc__ = getattr(method, "__doc__", None)
    return synced


for _method_name, _method in list(GuiApp.__dict__.items()):
    if isinstance(_method, (staticmethod, classmethod)):
        continue
    if callable(_method) and not _method_name.startswith("__"):
        setattr(GuiApp, _method_name, _wrap_gui_method(_method))
