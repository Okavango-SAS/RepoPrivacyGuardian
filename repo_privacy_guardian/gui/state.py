"""Pure GUI state helpers for the Audit and Repair flow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal


WidgetState = Literal["normal", "disabled"]
RepairGateTone = Literal["locked", "review", "ready"]
PathFieldKind = Literal["directory", "existing_file", "save_file"]
ActionButtonStyle = Literal["primary", "secondary", "support"]
ActionCommandKind = Literal[
    "method",
    "flow_tab",
    "artifact",
    "prompt_copy",
    "prompt_command_copy",
    "prompt_open",
]
GridColumnTarget = int | tuple[int, ...]
GridPadding = int | tuple[int, int]


MANUAL_REVIEW_SIGNAL_KEYS = (
    "tracked_secret_low_confidence",
    "history_secret_low_confidence",
    "git_metadata_secret_low_confidence",
    "tracked_email_low_confidence",
    "history_email_low_confidence",
    "exfil_code_indicators",
    "github_hardening_findings",
    "github_hardening_warnings",
    "secret_file_manual_review_candidates",
)

SAFE_CONTEXT_KEYS = (
    "tracked_secret_fixture_matches",
    "history_secret_fixture_matches",
    "tracked_secret_documentation_matches",
    "history_secret_documentation_matches",
    "tracked_email_fixture_matches",
    "history_email_fixture_matches",
    "reviewed_network_indicators",
)


@dataclass(frozen=True)
class ButtonState:
    text_key: str
    widget_state: WidgetState

    @property
    def disabled(self) -> bool:
        return self.widget_state == "disabled"


@dataclass(frozen=True)
class RepairGateNoteState:
    text_key: str
    tone: RepairGateTone


@dataclass(frozen=True)
class CollapsibleSectionState:
    visible: bool
    toggle_text_key: str
    hint_text_key: str
    hint_text_kwargs: tuple[tuple[str, object], ...] = ()

    @property
    def hint_kwargs(self) -> dict[str, object]:
        return dict(self.hint_text_kwargs)


@dataclass(frozen=True)
class GridColumnConfig:
    column: GridColumnTarget
    weight: int


@dataclass(frozen=True)
class WidgetGridConfig:
    row: int
    column: int
    sticky: str
    padx: GridPadding = 0
    pady: GridPadding = 0
    columnspan: int | None = None

    @property
    def kwargs(self) -> dict[str, object]:
        values: dict[str, object] = {
            "row": self.row,
            "column": self.column,
            "sticky": self.sticky,
            "padx": self.padx,
            "pady": self.pady,
        }
        if self.columnspan is not None:
            values["columnspan"] = self.columnspan
        return values


@dataclass(frozen=True)
class OptionCheckboxSpec:
    text_key: str
    variable_attr: str
    tooltip_key: str
    grid: WidgetGridConfig
    widget_attr: str | None = None
    command_attr: str | None = None
    info_badge: bool = False


@dataclass(frozen=True)
class PathFieldSpec:
    kind: PathFieldKind
    label_key: str
    variable_attr: str
    title_key: str
    tooltip_key: str
    label_grid: WidgetGridConfig
    entry_grid: WidgetGridConfig
    button_grid: WidgetGridConfig
    button_text_key: str
    button_icon: str | None
    filetypes: tuple[tuple[str, str], ...] = ()
    default_extension: str | None = None
    on_select_attr: str | None = None
    row_frame_grid: WidgetGridConfig | None = None
    row_frame_weight_column: int | None = None


@dataclass(frozen=True)
class ActionButtonSpec:
    text_key: str
    tooltip_key: str
    command_kind: ActionCommandKind
    grid: WidgetGridConfig
    style: ActionButtonStyle = "secondary"
    icon: str | None = None
    command_attr: str | None = None
    command_arg: str | None = None
    widget_attr: str | None = None
    height: int = 32
    localize: bool = True


@dataclass(frozen=True)
class ReportsDecisionLayoutState:
    compact: bool
    column_configs: tuple[GridColumnConfig, ...]
    step_label_grids: tuple[WidgetGridConfig, WidgetGridConfig, WidgetGridConfig]
    prompts_button_sticky: str


@dataclass(frozen=True)
class PromptsWorkflowLayoutState:
    compact: bool
    column_configs: tuple[GridColumnConfig, GridColumnConfig, GridColumnConfig]
    title_grid: WidgetGridConfig
    info_badge_grid: WidgetGridConfig
    body_grid: WidgetGridConfig
    body_wraplength: int
    visual_visible: bool


@dataclass(frozen=True)
class ReportsActionVisibilityState:
    show_decision_steps: bool
    show_prompts_button: bool
    show_go_audit_button: bool
    show_agent_handoff_button: bool
    show_artifact_buttons: bool
    artifact_button_state: WidgetState


@dataclass(frozen=True)
class IdentityActionsLayoutState:
    compact: bool
    column_configs: tuple[GridColumnConfig, ...]
    button_grids: tuple[WidgetGridConfig, WidgetGridConfig, WidgetGridConfig, WidgetGridConfig]


@dataclass(frozen=True)
class ReportsActionLayoutState:
    compact: bool
    agent_handoff_grid: WidgetGridConfig
    artifact_button_grids: tuple[WidgetGridConfig, ...]


Translate = Callable[..., str]


def report_list(payload: dict[str, object], key: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def report_item_count(payload: dict[str, object], *keys: str) -> int:
    return sum(len(report_list(payload, key)) for key in keys)


def manual_review_signal_count(payload: dict[str, object]) -> int:
    return report_item_count(payload, *MANUAL_REVIEW_SIGNAL_KEYS)


def safe_context_count(payload: dict[str, object]) -> int:
    return report_item_count(payload, *SAFE_CONTEXT_KEYS)


def build_repair_status_summary(
    reports_payload: list[dict[str, object]],
    translate: Translate,
) -> str:
    total = len(reports_payload)
    if total == 0:
        return translate("no_audit_results")

    passed = sum(1 for item in reports_payload if item.get("status") == "PASS")
    failed = sum(1 for item in reports_payload if item.get("status") == "FAIL")
    blocking_categories = sum(report_item_count(item, "failures") for item in reports_payload)
    manual_review_signals = sum(manual_review_signal_count(item) for item in reports_payload)
    safe_context = sum(safe_context_count(item) for item in reports_payload)
    names = [str(item.get("name")) for item in reports_payload[:3] if item.get("name")]
    label = ", ".join(names)
    if total > len(names):
        label += f", +{total - len(names)} more"

    detail_parts: list[str] = []
    if blocking_categories:
        detail_parts.append(
            translate(
                "blocking_category_singular" if blocking_categories == 1 else "blocking_category_plural",
                count=blocking_categories,
            )
        )
    if manual_review_signals:
        detail_parts.append(
            translate(
                "manual_signal_singular" if manual_review_signals == 1 else "manual_signal_plural",
                count=manual_review_signals,
            )
        )
    if safe_context:
        detail_parts.append(
            translate(
                "fixture_match_singular" if safe_context == 1 else "fixture_match_plural",
                count=safe_context,
            )
        )
    detail_text = (" " + "; ".join(detail_parts) + ".") if detail_parts else ""

    if failed:
        return translate(
            "last_audit_failed",
            label=label,
            failed=failed,
            passed=passed,
            detail_text=detail_text,
        )

    if manual_review_signals:
        return translate(
            "last_audit_passed_manual",
            label=label,
            detail_text=detail_text,
        )

    return translate(
        "last_audit_passed",
        label=label,
        detail_text=detail_text,
    )


def audit_button_state(
    *,
    run_in_progress: bool,
    has_targets: bool,
    has_remote_target: bool,
) -> ButtonState:
    has_any_target = has_targets or has_remote_target
    disabled = run_in_progress or not has_any_target
    return ButtonState(
        text_key="run_audit" if has_any_target else "audit_unavailable",
        widget_state="disabled" if disabled else "normal",
    )


def cancel_button_state(
    *,
    run_in_progress: bool,
    cancel_requested: bool,
) -> ButtonState:
    return ButtonState(
        text_key="stopping_after_current_step" if cancel_requested else "stop_after_current_step",
        widget_state="normal" if (run_in_progress and not cancel_requested) else "disabled",
    )


def repair_button_state(
    *,
    repair_ready: bool,
    run_in_progress: bool,
) -> WidgetState:
    return "normal" if repair_ready and not run_in_progress else "disabled"


def repair_gate_note_state(
    *,
    repair_ready: bool,
    has_audit_reports: bool,
) -> RepairGateNoteState:
    if repair_ready:
        return RepairGateNoteState(text_key="repair_ready_note", tone="ready")
    if has_audit_reports:
        return RepairGateNoteState(text_key="repair_review_pending_note", tone="review")
    return RepairGateNoteState(text_key="repair_stays_disabled", tone="locked")


def setup_settings_visibility_state(
    *,
    visible: bool,
    github_owner: str | None,
) -> CollapsibleSectionState:
    if visible:
        return CollapsibleSectionState(
            visible=True,
            toggle_text_key="hide_settings",
            hint_text_key="setup_hint_open",
        )
    if github_owner:
        return CollapsibleSectionState(
            visible=False,
            toggle_text_key="open_settings",
            hint_text_key="setup_hint_remote",
            hint_text_kwargs=(("github_owner", github_owner),),
        )
    return CollapsibleSectionState(
        visible=False,
        toggle_text_key="open_settings",
        hint_text_key="setup_hint_hidden",
    )


def repair_options_visibility_state(*, visible: bool) -> CollapsibleSectionState:
    return CollapsibleSectionState(
        visible=visible,
        toggle_text_key="repair_advanced_toggle_hide" if visible else "repair_advanced_toggle_show",
        hint_text_key="repair_advanced_hint_visible" if visible else "repair_advanced_hint_hidden",
    )


def standard_path_field_spec(
    *,
    kind: PathFieldKind,
    row: int,
    label_key: str,
    variable_attr: str,
    title_key: str,
    tooltip_key: str,
    filetypes: tuple[tuple[str, str], ...] = (),
    default_extension: str | None = None,
    on_select_attr: str | None = None,
) -> PathFieldSpec:
    return PathFieldSpec(
        kind=kind,
        label_key=label_key,
        variable_attr=variable_attr,
        title_key=title_key,
        tooltip_key=tooltip_key,
        label_grid=WidgetGridConfig(row=row, column=0, sticky="w", padx=(14, 8), pady=4),
        entry_grid=WidgetGridConfig(row=row, column=1, sticky="we", padx=(0, 8), pady=4),
        button_grid=WidgetGridConfig(row=row, column=2, sticky="", padx=(0, 14), pady=4),
        button_text_key="save_as" if kind == "save_file" else "browse",
        button_icon="icon-open.png" if kind == "existing_file" else "icon-folder.png",
        filetypes=filetypes,
        default_extension=default_extension,
        on_select_attr=on_select_attr,
    )


def repositories_root_path_field_spec(*, row: int) -> PathFieldSpec:
    return standard_path_field_spec(
        kind="directory",
        row=row,
        label_key="repositories_root",
        variable_attr="root_var",
        title_key="choose_repositories_root",
        tooltip_key="repositories_root",
        on_select_attr="_on_root_directory_selected",
    )


def setup_path_field_specs(
    *,
    policy_row: int,
    results_row: int,
    json_row: int,
    suppression_row: int,
) -> tuple[PathFieldSpec, ...]:
    return (
        standard_path_field_spec(
            kind="existing_file",
            row=policy_row,
            label_key="policy_file",
            variable_attr="policy_var",
            title_key="choose_policy_file",
            tooltip_key="policy_file",
            filetypes=(("Markdown files", "*.md"), ("All files", "*.*")),
        ),
        standard_path_field_spec(
            kind="directory",
            row=results_row,
            label_key="audit_results_folder",
            variable_attr="report_dir_var",
            title_key="choose_results_folder",
            tooltip_key="audit_results_folder",
        ),
        standard_path_field_spec(
            kind="save_file",
            row=json_row,
            label_key="optional_json_copy",
            variable_attr="report_json_var",
            title_key="choose_json_copy",
            tooltip_key="optional_json_copy",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
            default_extension=".json",
        ),
        standard_path_field_spec(
            kind="existing_file",
            row=suppression_row,
            label_key="suppression_file",
            variable_attr="suppressions_file_var",
            title_key="choose_suppression_file",
            tooltip_key="suppression_file",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        ),
    )


def repair_replace_text_path_field_spec() -> PathFieldSpec:
    return PathFieldSpec(
        kind="existing_file",
        label_key="replace_text_rules",
        variable_attr="replace_text_file_var",
        title_key="choose_replace_text_file",
        tooltip_key="replace_text_rules",
        label_grid=WidgetGridConfig(row=4, column=0, sticky="w", padx=12, pady=(4, 0)),
        entry_grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=(0, 8), pady=0),
        button_grid=WidgetGridConfig(row=0, column=1, sticky="", padx=0, pady=0),
        button_text_key="browse",
        button_icon=None,
        filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
        row_frame_grid=WidgetGridConfig(row=5, column=0, sticky="we", padx=12, pady=(2, 4), columnspan=2),
        row_frame_weight_column=0,
    )


def identity_action_button_specs() -> tuple[ActionButtonSpec, ...]:
    return (
        ActionButtonSpec(
            text_key="apply_global_git_config",
            tooltip_key="apply_global_git_config",
            command_kind="method",
            command_attr="apply_git_identity_global_clicked",
            style="support",
            grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=(0, 6), pady=3),
        ),
        ActionButtonSpec(
            text_key="apply_local_git_config",
            tooltip_key="apply_local_git_config",
            command_kind="method",
            command_attr="apply_git_identity_local_clicked",
            style="support",
            grid=WidgetGridConfig(row=0, column=1, sticky="we", padx=(6, 6), pady=3),
        ),
        ActionButtonSpec(
            text_key="read_current_git_identity",
            tooltip_key="read_current_git_identity",
            command_kind="method",
            command_attr="read_git_identity_clicked",
            style="secondary",
            grid=WidgetGridConfig(row=0, column=2, sticky="we", padx=(6, 6), pady=3),
        ),
        ActionButtonSpec(
            text_key="open_github_email_settings",
            tooltip_key="open_github_email_settings",
            command_kind="method",
            command_attr="open_github_email_settings_clicked",
            style="secondary",
            grid=WidgetGridConfig(row=0, column=3, sticky="we", padx=(6, 0), pady=3),
        ),
    )


def identity_actions_layout_state(*, compact: bool) -> IdentityActionsLayoutState:
    if compact:
        return IdentityActionsLayoutState(
            compact=True,
            column_configs=(
                GridColumnConfig(column=(0, 1), weight=1),
                GridColumnConfig(column=(2, 3), weight=0),
            ),
            button_grids=(
                WidgetGridConfig(row=0, column=0, sticky="we", padx=(0, 6), pady=3),
                WidgetGridConfig(row=0, column=1, sticky="we", padx=(6, 0), pady=3),
                WidgetGridConfig(row=1, column=0, sticky="we", padx=(0, 6), pady=3),
                WidgetGridConfig(row=1, column=1, sticky="we", padx=(6, 0), pady=3),
            ),
        )
    wide_specs = identity_action_button_specs()
    return IdentityActionsLayoutState(
        compact=False,
        column_configs=(GridColumnConfig(column=(0, 1, 2, 3), weight=1),),
        button_grids=(wide_specs[0].grid, wide_specs[1].grid, wide_specs[2].grid, wide_specs[3].grid),
    )


def reports_decision_action_button_spec() -> ActionButtonSpec:
    return ActionButtonSpec(
        text_key="open_agent_prompts_from_reports",
        tooltip_key="open_agent_prompts_tab",
        command_kind="flow_tab",
        command_arg="_prompts_tab_name",
        grid=WidgetGridConfig(row=2, column=0, sticky="e", padx=12, pady=(0, 12), columnspan=3),
        style="secondary",
        icon="icon-open.png",
        widget_attr="_reports_open_prompts_button",
    )


def reports_primary_action_button_specs() -> tuple[ActionButtonSpec, ActionButtonSpec]:
    return (
        ActionButtonSpec(
            text_key="go_to_audit",
            tooltip_key="run_audit",
            command_kind="flow_tab",
            command_arg="_audit_tab_name",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=(0, 8), pady=0),
            style="primary",
            icon="icon-audit.png",
            widget_attr="_reports_go_audit_button",
        ),
        ActionButtonSpec(
            text_key="copy_agent_handoff",
            tooltip_key="copy_agent_handoff",
            command_kind="method",
            command_attr="_copy_agent_handoff_to_clipboard",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=(0, 8), pady=0),
            style="primary",
            icon="icon-copy.png",
            widget_attr="_reports_agent_handoff_button",
        ),
    )


def report_artifact_action_button_specs() -> tuple[ActionButtonSpec, ...]:
    return (
        ActionButtonSpec(
            text_key="open_html_report_action",
            tooltip_key="reports_tab",
            command_kind="artifact",
            command_arg="html",
            grid=WidgetGridConfig(row=0, column=1, sticky="w", padx=(0, 8), pady=0),
            icon="icon-report.png",
        ),
        ActionButtonSpec(
            text_key="open_json_report_action",
            tooltip_key="reports_tab",
            command_kind="artifact",
            command_arg="json",
            grid=WidgetGridConfig(row=0, column=2, sticky="w", padx=(0, 8), pady=0),
            icon="icon-report.png",
        ),
        ActionButtonSpec(
            text_key="compare_previous_report_action",
            tooltip_key="compare_previous_report",
            command_kind="method",
            command_attr="_compare_previous_report_to_latest",
            grid=WidgetGridConfig(row=0, column=3, sticky="w", padx=(0, 8), pady=0),
            icon="icon-report.png",
        ),
        ActionButtonSpec(
            text_key="open_run_log_action",
            tooltip_key="reports_tab",
            command_kind="artifact",
            command_arg="log",
            grid=WidgetGridConfig(row=0, column=4, sticky="w", padx=(0, 8), pady=0),
            icon="icon-open.png",
        ),
        ActionButtonSpec(
            text_key="open_artifacts_folder_action",
            tooltip_key="reports_tab",
            command_kind="artifact",
            command_arg="folder",
            grid=WidgetGridConfig(row=0, column=5, sticky="w", padx=(0, 8), pady=0),
            icon="icon-folder.png",
        ),
    )


def reports_action_layout_state(*, compact: bool, artifact_button_count: int) -> ReportsActionLayoutState:
    if compact:
        return ReportsActionLayoutState(
            compact=True,
            agent_handoff_grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 6)),
            artifact_button_grids=tuple(
                WidgetGridConfig(row=1, column=idx, sticky="w", padx=(0, 8), pady=(2, 0))
                for idx in range(artifact_button_count)
            ),
        )
    return ReportsActionLayoutState(
        compact=False,
        agent_handoff_grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=(0, 8), pady=0),
        artifact_button_grids=tuple(
            WidgetGridConfig(row=0, column=idx + 1, sticky="w", padx=(0, 8), pady=0)
            for idx in range(artifact_button_count)
        ),
    )


def prompt_card_action_button_specs() -> tuple[ActionButtonSpec, ...]:
    return (
        ActionButtonSpec(
            text_key="copy_prompt",
            tooltip_key="copy_prompt",
            command_kind="prompt_copy",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=(0, 8), pady=0),
            style="primary",
            icon="icon-copy.png",
            height=30,
            localize=False,
        ),
        ActionButtonSpec(
            text_key="copy_command",
            tooltip_key="copy_prompt_command",
            command_kind="prompt_command_copy",
            grid=WidgetGridConfig(row=0, column=1, sticky="w", padx=(0, 8), pady=0),
            style="secondary",
            icon="icon-copy.png",
            height=30,
            localize=False,
        ),
        ActionButtonSpec(
            text_key="open_prompt",
            tooltip_key="open_prompt_file",
            command_kind="prompt_open",
            grid=WidgetGridConfig(row=0, column=2, sticky="w", padx=0, pady=0),
            style="secondary",
            icon="icon-open.png",
            height=30,
            localize=False,
        ),
    )


def github_remote_option_checkbox_specs() -> tuple[OptionCheckboxSpec, ...]:
    return (
        OptionCheckboxSpec(
            text_key="include_forks",
            variable_attr="github_include_forks_var",
            tooltip_key="github_include_forks",
            grid=WidgetGridConfig(
                row=1,
                column=2,
                sticky="w",
                padx=(0, 12),
                pady=(4, 10),
            ),
        ),
        OptionCheckboxSpec(
            text_key="fast_shallow_clone",
            variable_attr="github_fast_var",
            tooltip_key="github_fast",
            grid=WidgetGridConfig(
                row=1,
                column=3,
                sticky="w",
                padx=(0, 12),
                pady=(4, 10),
            ),
        ),
    )


def repair_review_option_checkbox_specs() -> tuple[OptionCheckboxSpec, ...]:
    items = (
        ("only_audit_public_remotes", "public_only_var", "public_only"),
        ("redact_third_party_emails", "redact_var", "redact_third_party_emails"),
        ("low_confidence_blocking", "low_confidence_blocking_var", "low_confidence_blocking"),
        ("dry_run_preview", "dry_run_var", "dry_run_preview"),
        ("audit_github_hardening", "audit_github_hardening_var", "audit_github_hardening"),
        ("accept_github_admin_bypass", "accept_github_admin_bypass_var", "accept_github_admin_bypass"),
        ("audit_litellm_incident", "audit_litellm_incident_var", "audit_litellm_incident"),
        ("open_html_report", "open_report_var", "open_html_report"),
        ("confirm_each_repo_fix", "confirm_each_repo_fix_var", "confirm_each_repo_fix"),
    )
    return tuple(
        OptionCheckboxSpec(
            text_key=text_key,
            variable_attr=variable_attr,
            tooltip_key=tooltip_key,
            grid=WidgetGridConfig(row=row, column=0, sticky="w", padx=12, pady=4),
            info_badge=True,
        )
        for row, (text_key, variable_attr, tooltip_key) in enumerate(items, start=1)
    )


def repair_write_option_checkbox_specs() -> tuple[OptionCheckboxSpec, ...]:
    return (
        OptionCheckboxSpec(
            text_key="rewrite_personal_paths",
            variable_attr="rewrite_personal_paths_var",
            tooltip_key="rewrite_personal_paths",
            grid=WidgetGridConfig(row=2, column=0, sticky="w", padx=12, pady=(0, 4)),
            widget_attr="_rewrite_paths_checkbox",
            info_badge=True,
        ),
        OptionCheckboxSpec(
            text_key="force_push",
            variable_attr="push_var",
            tooltip_key="force_push",
            grid=WidgetGridConfig(row=7, column=0, sticky="w", padx=12, pady=(0, 4)),
            widget_attr="_push_checkbox",
            info_badge=True,
        ),
        OptionCheckboxSpec(
            text_key="bypass_remote_owner_guardrail",
            variable_attr="allow_non_owner_push_var",
            tooltip_key="bypass_remote_owner_guardrail",
            grid=WidgetGridConfig(row=8, column=0, sticky="w", padx=12, pady=4),
            widget_attr="_allow_non_owner_push_checkbox",
            command_attr="_on_allow_non_owner_push_toggled",
            info_badge=True,
        ),
        OptionCheckboxSpec(
            text_key="purge_safe_secret_files",
            variable_attr="purge_detected_secret_files_var",
            tooltip_key="purge_safe_secret_files",
            grid=WidgetGridConfig(row=12, column=0, sticky="w", padx=12, pady=(0, 4)),
            widget_attr="_purge_safe_checkbox",
            command_attr="_on_purge_safe_toggled",
            info_badge=True,
        ),
        OptionCheckboxSpec(
            text_key="purge_risky_secret_files",
            variable_attr="purge_all_detected_secret_files_var",
            tooltip_key="purge_risky_secret_files",
            grid=WidgetGridConfig(row=13, column=0, sticky="w", padx=12, pady=4),
            widget_attr="_purge_risky_checkbox",
            command_attr="_on_purge_risky_toggled",
            info_badge=True,
        ),
    )


def advanced_identity_visibility_state(*, visible: bool) -> CollapsibleSectionState:
    return CollapsibleSectionState(
        visible=visible,
        toggle_text_key="hide_advanced_identity" if visible else "show_advanced_identity",
        hint_text_key="advanced_identity_visible" if visible else "advanced_identity_hidden",
    )


def reports_decision_layout_state(*, compact: bool) -> ReportsDecisionLayoutState:
    if compact:
        return ReportsDecisionLayoutState(
            compact=True,
            column_configs=(
                GridColumnConfig(column=0, weight=1),
                GridColumnConfig(column=(1, 2), weight=0),
            ),
            step_label_grids=(
                WidgetGridConfig(row=0, column=0, sticky="we", padx=0, pady=(0, 3)),
                WidgetGridConfig(row=1, column=0, sticky="we", padx=0, pady=(0, 3)),
                WidgetGridConfig(row=2, column=0, sticky="we", padx=0, pady=(0, 3)),
            ),
            prompts_button_sticky="w",
        )
    return ReportsDecisionLayoutState(
        compact=False,
        column_configs=(GridColumnConfig(column=(0, 1, 2), weight=1),),
        step_label_grids=(
            WidgetGridConfig(row=0, column=0, sticky="we", padx=(0, 8), pady=0),
            WidgetGridConfig(row=0, column=1, sticky="we", padx=(0, 8), pady=0),
            WidgetGridConfig(row=0, column=2, sticky="we", padx=(0, 0), pady=0),
        ),
        prompts_button_sticky="e",
    )


def prompts_workflow_layout_state(*, compact: bool) -> PromptsWorkflowLayoutState:
    return PromptsWorkflowLayoutState(
        compact=compact,
        column_configs=(
            GridColumnConfig(column=0, weight=1 if compact else 0),
            GridColumnConfig(column=1, weight=0 if compact else 1),
            GridColumnConfig(column=2, weight=0),
        ),
        title_grid=WidgetGridConfig(
            row=0,
            column=0,
            sticky="w",
            padx=10,
            pady=(10, 4) if compact else 10,
        ),
        info_badge_grid=WidgetGridConfig(
            row=0,
            column=1 if compact else 2,
            sticky="e",
            padx=(0, 10),
            pady=(10, 4) if compact else 10,
        ),
        body_grid=WidgetGridConfig(
            row=1 if compact else 0,
            column=0 if compact else 1,
            columnspan=2 if compact else 1,
            sticky="we",
            padx=10 if compact else (0, 10),
            pady=(0, 10) if compact else 10,
        ),
        body_wraplength=760 if compact else 1040,
        visual_visible=not compact,
    )


def reports_action_visibility_state(*, has_artifacts: bool) -> ReportsActionVisibilityState:
    return ReportsActionVisibilityState(
        show_decision_steps=has_artifacts,
        show_prompts_button=has_artifacts,
        show_go_audit_button=not has_artifacts,
        show_agent_handoff_button=has_artifacts,
        show_artifact_buttons=has_artifacts,
        artifact_button_state="normal" if has_artifacts else "disabled",
    )
