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
TextColorRole = str
FillColorRole = str
RepoEmptyReason = Literal["invalid_root", "no_repos", "github_remote"]


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
class WidgetPlaceConfig:
    relx: float
    rely: float
    relwidth: float
    anchor: str

    @property
    def kwargs(self) -> dict[str, object]:
        return {
            "relx": self.relx,
            "rely": self.rely,
            "relwidth": self.relwidth,
            "anchor": self.anchor,
        }


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
class EntryFieldSpec:
    text_key: str
    variable_attr: str
    tooltip_key: str
    label_grid: WidgetGridConfig
    entry_grid: WidgetGridConfig
    width: int | None = None
    placeholder_key: str | None = None
    widget_attr: str | None = None


@dataclass(frozen=True)
class SectionHeadingSpec:
    text_key: str
    tooltip_key: str
    grid: WidgetGridConfig
    font_size: int = 16
    text_color_role: TextColorRole = "heading"
    fixed_text_color: bool = False


@dataclass(frozen=True)
class TextLabelSpec:
    text_key: str
    grid: WidgetGridConfig | None
    font_size: int = 12
    bold: bool = False
    mono: bool = False
    text_color_role: TextColorRole = "body"
    fg_color_role: FillColorRole | None = None
    fixed_text_color: bool = False
    justify: str = "left"
    anchor: str | None = "w"
    wraplength: int | None = None
    height: int | None = None
    corner_radius: int | None = None
    padx: int | None = None
    tooltip_key: str | None = None
    widget_attr: str | None = None
    localize: bool = True


@dataclass(frozen=True)
class LiteralTextLabelSpec:
    text: str
    grid: WidgetGridConfig
    font_size: int = 12
    bold: bool = False
    mono: bool = False
    text_color_role: TextColorRole = "body"
    fg_color_role: FillColorRole | None = None
    justify: str | None = "left"
    anchor: str | None = "w"
    wraplength: int | None = None
    height: int | None = None
    corner_radius: int | None = None
    padx: int | None = None


@dataclass(frozen=True)
class PanelSpec:
    grid: WidgetGridConfig
    fg_color_role: FillColorRole
    border_color_role: FillColorRole
    corner_radius: int = 10
    border_width: int = 1
    column_configs: tuple[GridColumnConfig, ...] = ()
    row_configs: tuple[GridColumnConfig, ...] = ()
    widget_attr: str | None = None


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


@dataclass(frozen=True)
class RepoEmptyPresentationState:
    reason: RepoEmptyReason
    title_key: str
    body_text: str
    hint_key: str
    fg_color_role: FillColorRole
    border_color_role: FillColorRole
    title_color_role: TextColorRole
    body_color_role: TextColorRole
    hint_color_role: TextColorRole
    show_action_button: bool
    action_text_key: str
    action_state: WidgetState
    place: WidgetPlaceConfig


@dataclass(frozen=True)
class ReportsRunPresentationState:
    visibility: ReportsActionVisibilityState
    badge_text: str
    badge_fg_color_role: FillColorRole
    badge_text_color_role: TextColorRole
    summary_text: str
    paths_text: str
    next_action_key: str


@dataclass(frozen=True)
class PromptCardPresentationSpec:
    fg_color_role: FillColorRole
    border_color_role: FillColorRole
    corner_radius: int
    border_width: int
    column_configs: tuple[GridColumnConfig, ...]
    stage_label: LiteralTextLabelSpec
    title_label: LiteralTextLabelSpec
    description_label: LiteralTextLabelSpec
    best_for_label: LiteralTextLabelSpec
    command_label: LiteralTextLabelSpec
    actions_grid: WidgetGridConfig


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


def repo_empty_presentation_state(
    *,
    reason: str | None,
    body_text: str,
) -> RepoEmptyPresentationState:
    normalized_reason: RepoEmptyReason
    if reason == "invalid_root":
        normalized_reason = "invalid_root"
    elif reason == "github_remote":
        normalized_reason = "github_remote"
    else:
        normalized_reason = "no_repos"

    states = {
        "invalid_root": RepoEmptyPresentationState(
            reason="invalid_root",
            title_key="repo_empty_invalid_root_title",
            body_text=body_text,
            hint_key="repo_empty_invalid_root_hint",
            fg_color_role="warning_panel",
            border_color_role="warning_panel_border",
            title_color_role="warning",
            body_color_role="warning_strong",
            hint_color_role="muted",
            show_action_button=True,
            action_text_key="repo_empty_choose_root_action",
            action_state="normal",
            place=WidgetPlaceConfig(relx=0.5, rely=0.5, relwidth=0.82, anchor="center"),
        ),
        "no_repos": RepoEmptyPresentationState(
            reason="no_repos",
            title_key="repo_empty_no_repos_title",
            body_text=body_text,
            hint_key="repo_empty_no_repos_hint",
            fg_color_role="info_panel",
            border_color_role="info_panel_border",
            title_color_role="info",
            body_color_role="muted",
            hint_color_role="muted",
            show_action_button=True,
            action_text_key="repo_empty_choose_root_action",
            action_state="normal",
            place=WidgetPlaceConfig(relx=0.5, rely=0.5, relwidth=0.82, anchor="center"),
        ),
        "github_remote": RepoEmptyPresentationState(
            reason="github_remote",
            title_key="repo_empty_github_remote_title",
            body_text=body_text,
            hint_key="repo_empty_github_remote_hint",
            fg_color_role="success_panel",
            border_color_role="success_panel_border",
            title_color_role="success",
            body_color_role="muted",
            hint_color_role="muted",
            show_action_button=False,
            action_text_key="repo_empty_choose_root_action",
            action_state="disabled",
            place=WidgetPlaceConfig(relx=0.5, rely=0.5, relwidth=0.82, anchor="center"),
        ),
    }
    return states[normalized_reason]


def gui_section_heading_specs() -> dict[str, SectionHeadingSpec]:
    return {
        "header": SectionHeadingSpec(
            text_key="header_title",
            tooltip_key="workflow_overview",
            font_size=24,
            text_color_role="fixed_header_light",
            fixed_text_color=True,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=18, pady=(12, 0)),
        ),
        "audit_target": SectionHeadingSpec(
            text_key="audit_target",
            tooltip_key="audit_target_section",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 4), columnspan=3),
        ),
        "settings_companion": SectionHeadingSpec(
            text_key="settings_companion_title",
            tooltip_key="settings_section",
            font_size=18,
            grid=WidgetGridConfig(row=0, column=0, sticky="w"),
        ),
        "setup_settings_card": SectionHeadingSpec(
            text_key="setup_settings",
            tooltip_key="settings_section",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 8), columnspan=3),
        ),
        "setup_settings_inner": SectionHeadingSpec(
            text_key="setup_settings",
            tooltip_key="settings_section",
            font_size=14,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 4), columnspan=3),
        ),
        "owner_profile": SectionHeadingSpec(
            text_key="owner_profile",
            tooltip_key="owner_profile_section",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 8), columnspan=2),
        ),
        "repair_options": SectionHeadingSpec(
            text_key="repair_plan_options",
            tooltip_key="repair_options_section",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 8), columnspan=2),
        ),
        "repair_flow": SectionHeadingSpec(
            text_key="repair_flow",
            tooltip_key="repair_flow_section",
            font_size=14,
            text_color_role="warning",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(10, 4)),
        ),
        "repositories": SectionHeadingSpec(
            text_key="repositories",
            tooltip_key="repositories_section",
            grid=WidgetGridConfig(row=0, column=0, sticky="w"),
        ),
        "execution_log": SectionHeadingSpec(
            text_key="execution_log",
            tooltip_key="execution_log_section",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 8)),
        ),
        "reports_dashboard": SectionHeadingSpec(
            text_key="reports_dashboard",
            tooltip_key="reports_section",
            font_size=18,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 4)),
        ),
        "prompts_library": SectionHeadingSpec(
            text_key="prompts_library",
            tooltip_key="prompts_section",
            font_size=18,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 4)),
        ),
    }


def gui_panel_specs(
    *,
    setup_toggle_row: int = 0,
    setup_settings_row: int = 0,
    github_remote_row: int = 0,
    advanced_identity_row: int = 0,
) -> dict[str, PanelSpec]:
    return {
        "setup_quick_start": PanelSpec(
            fg_color_role="success_panel",
            border_color_role="success_panel_border",
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 10), columnspan=3),
            column_configs=(GridColumnConfig(column=1, weight=1),),
        ),
        "setup_toggle": PanelSpec(
            fg_color_role="surface_alt",
            border_color_role="card_border",
            grid=WidgetGridConfig(
                row=setup_toggle_row,
                column=0,
                sticky="we",
                padx=14,
                pady=(6, 12),
                columnspan=3,
            ),
            column_configs=(GridColumnConfig(column=0, weight=1),),
        ),
        "setup_settings_frame": PanelSpec(
            fg_color_role="surface",
            border_color_role="card_border",
            grid=WidgetGridConfig(
                row=setup_settings_row,
                column=0,
                sticky="we",
                padx=14,
                pady=(0, 12),
                columnspan=3,
            ),
            column_configs=(GridColumnConfig(column=1, weight=1),),
            widget_attr="_setup_settings_frame",
        ),
        "github_remote": PanelSpec(
            fg_color_role="info_panel",
            border_color_role="info_panel_border",
            grid=WidgetGridConfig(
                row=github_remote_row,
                column=0,
                sticky="we",
                padx=14,
                pady=(4, 10),
                columnspan=3,
            ),
            column_configs=(
                GridColumnConfig(column=1, weight=1),
                GridColumnConfig(column=3, weight=1),
            ),
        ),
        "advanced_identity_toggle": PanelSpec(
            fg_color_role="surface_alt",
            border_color_role="card_border",
            grid=WidgetGridConfig(
                row=advanced_identity_row,
                column=0,
                sticky="we",
                padx=14,
                pady=(0, 12),
                columnspan=3,
            ),
            column_configs=(GridColumnConfig(column=0, weight=1),),
        ),
        "repair_options_toggle": PanelSpec(
            fg_color_role="warning_panel",
            border_color_role="warning_panel_border",
            grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=10, pady=(8, 8)),
            column_configs=(GridColumnConfig(column=0, weight=1),),
        ),
        "repair_review_options": PanelSpec(
            fg_color_role="success_panel",
            border_color_role="success_panel_border",
            grid=WidgetGridConfig(row=1, column=0, sticky="nsew", padx=(14, 7), pady=(0, 12)),
            column_configs=(
                GridColumnConfig(column=0, weight=1),
                GridColumnConfig(column=1, weight=0),
            ),
            widget_attr="_safe_options_card",
        ),
        "repair_write_options": PanelSpec(
            fg_color_role="warning_panel",
            border_color_role="warning_panel_border",
            grid=WidgetGridConfig(row=1, column=1, sticky="nsew", padx=(7, 14), pady=(0, 12)),
            column_configs=(
                GridColumnConfig(column=0, weight=1),
                GridColumnConfig(column=1, weight=0),
            ),
            widget_attr="_destructive_options_card",
        ),
        "repair_status": PanelSpec(
            fg_color_role="success_panel",
            border_color_role="success_panel_border",
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 8)),
            column_configs=(GridColumnConfig(column=1, weight=1),),
            widget_attr="_repair_status_panel",
        ),
        "reports_status": PanelSpec(
            fg_color_role="success_panel",
            border_color_role="success_panel_border",
            grid=WidgetGridConfig(row=2, column=0, sticky="we", padx=14, pady=(0, 10), columnspan=2),
            column_configs=(
                GridColumnConfig(column=1, weight=1),
                GridColumnConfig(column=2, weight=0),
            ),
        ),
        "reports_decision": PanelSpec(
            fg_color_role="info_panel",
            border_color_role="info_panel_border",
            grid=WidgetGridConfig(row=3, column=0, sticky="we", padx=14, pady=(0, 10), columnspan=2),
            column_configs=(
                GridColumnConfig(column=1, weight=1),
                GridColumnConfig(column=2, weight=0),
            ),
        ),
        "prompts_workflow": PanelSpec(
            fg_color_role="info_panel",
            border_color_role="info_panel_border",
            grid=WidgetGridConfig(row=2, column=0, sticky="we", padx=14, pady=(0, 12), columnspan=2),
            column_configs=(GridColumnConfig(column=1, weight=1),),
            widget_attr="_prompts_workflow_guide",
        ),
    }


def gui_text_label_specs(*, settings_persist_note_row: int = 0) -> dict[str, TextLabelSpec]:
    return {
        "header_subtitle": TextLabelSpec(
            text_key="header_subtitle",
            font_size=13,
            text_color_role="fixed_header_subtitle",
            fixed_text_color=True,
            grid=WidgetGridConfig(row=1, column=0, sticky="w", padx=18, pady=(2, 8)),
        ),
        "audit_target_body": TextLabelSpec(
            text_key="audit_target_body",
            font_size=12,
            text_color_role="muted",
            wraplength=1100,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 8), columnspan=3),
        ),
        "recommended_path_body": TextLabelSpec(
            text_key="recommended_path_body",
            font_size=11,
            text_color_role="muted",
            wraplength=860,
            grid=WidgetGridConfig(row=0, column=0, sticky="we", pady=(0, 8), columnspan=3),
        ),
        "settings_companion_body": TextLabelSpec(
            text_key="settings_companion_body",
            font_size=12,
            text_color_role="muted",
            wraplength=1100,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", pady=(2, 8)),
        ),
        "setup_quick_start_badge": TextLabelSpec(
            text_key="setup_settings",
            font_size=11,
            bold=True,
            height=28,
            corner_radius=14,
            fg_color_role="primary_button",
            text_color_role="fixed_header_light",
            fixed_text_color=True,
            padx=12,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=10, pady=10),
        ),
        "setup_quick_start_status": TextLabelSpec(
            text_key="settings_status",
            font_size=12,
            text_color_role="body",
            wraplength=820,
            grid=WidgetGridConfig(row=0, column=1, sticky="we", padx=(0, 10), pady=10),
        ),
        "setup_initial_hint": TextLabelSpec(
            text_key="setup_initial_hint",
            font_size=11,
            text_color_role="muted",
            wraplength=760,
            widget_attr="_setup_settings_hint_label",
            grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=12, pady=10),
        ),
        "settings_status": TextLabelSpec(
            text_key="settings_status",
            font_size=11,
            text_color_role="muted",
            wraplength=880,
            widget_attr="_settings_status_label",
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 8), columnspan=3),
        ),
        "settings_persist_note": TextLabelSpec(
            text_key="settings_persist_note",
            font_size=11,
            text_color_role="muted",
            wraplength=760,
            grid=WidgetGridConfig(
                row=settings_persist_note_row,
                column=0,
                sticky="we",
                padx=14,
                pady=(0, 8),
                columnspan=3,
            ),
        ),
        "advanced_identity_hint": TextLabelSpec(
            text_key="advanced_identity_hidden",
            font_size=11,
            text_color_role="muted",
            wraplength=760,
            widget_attr="_advanced_identity_hint_label",
            grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=12, pady=10),
        ),
        "owner_profile_body": TextLabelSpec(
            text_key="owner_profile_body",
            font_size=11,
            text_color_role="muted",
            wraplength=440,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 6), columnspan=2),
        ),
        "optional_git_identity": TextLabelSpec(
            text_key="optional_git_identity",
            font_size=16,
            bold=True,
            text_color_role="heading",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=14, pady=(12, 8), columnspan=2),
        ),
        "identity_help": TextLabelSpec(
            text_key="identity_help",
            font_size=12,
            text_color_role="body",
            wraplength=1200,
            grid=WidgetGridConfig(row=4, column=0, sticky="we", padx=14, pady=(8, 12), columnspan=2),
        ),
        "repair_options_hint": TextLabelSpec(
            text_key="repair_advanced_hint_hidden",
            font_size=11,
            text_color_role="warning",
            wraplength=860,
            widget_attr="_repair_options_hint_label",
            grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=12, pady=10),
        ),
        "review_output_options": TextLabelSpec(
            text_key="review_output_options",
            font_size=13,
            bold=True,
            text_color_role="success",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=12, pady=(10, 2)),
        ),
        "repair_write_actions": TextLabelSpec(
            text_key="repair_write_actions",
            font_size=13,
            bold=True,
            text_color_role="warning",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=12, pady=(10, 2)),
        ),
        "repair_write_body": TextLabelSpec(
            text_key="repair_write_body",
            font_size=11,
            text_color_role="warning_strong",
            grid=WidgetGridConfig(row=1, column=0, sticky="w", padx=12, pady=(0, 8), columnspan=2),
        ),
        "rewrite_personal_paths_body": TextLabelSpec(
            text_key="rewrite_personal_paths_body",
            font_size=11,
            text_color_role="warning_strong",
            grid=WidgetGridConfig(row=3, column=0, sticky="w", padx=36, pady=(0, 6), columnspan=2),
        ),
        "replace_text_rules_body": TextLabelSpec(
            text_key="replace_text_rules_body",
            font_size=11,
            text_color_role="warning_strong",
            grid=WidgetGridConfig(row=6, column=0, sticky="w", padx=12, pady=(0, 6), columnspan=2),
        ),
        "allowed_remote_owners_body": TextLabelSpec(
            text_key="allowed_remote_owners_body",
            font_size=11,
            text_color_role="warning_strong",
            grid=WidgetGridConfig(row=11, column=0, sticky="w", padx=12, pady=(0, 6), columnspan=2),
        ),
        "purge_body": TextLabelSpec(
            text_key="purge_body",
            font_size=11,
            text_color_role="warning_strong",
            grid=WidgetGridConfig(row=14, column=0, sticky="w", padx=12, pady=(0, 10), columnspan=2),
        ),
        "repair_status_badge": TextLabelSpec(
            text_key="audit_required",
            font_size=11,
            bold=True,
            height=28,
            corner_radius=14,
            fg_color_role="success_badge",
            text_color_role="success",
            padx=12,
            widget_attr="_repair_status_badge",
            localize=False,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=12, pady=(10, 6)),
        ),
        "latest_audit_summary": TextLabelSpec(
            text_key="latest_audit_summary",
            font_size=12,
            bold=True,
            text_color_role="info",
            grid=WidgetGridConfig(row=0, column=1, sticky="w", padx=(0, 12), pady=(10, 6)),
        ),
        "repair_status_body": TextLabelSpec(
            text_key="no_audit_results",
            font_size=12,
            text_color_role="muted",
            wraplength=1080,
            widget_attr="_repair_status_label",
            localize=False,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=12, pady=(0, 12), columnspan=2),
        ),
        "repair_gate_note": TextLabelSpec(
            text_key="repair_stays_disabled",
            font_size=11,
            text_color_role="muted",
            widget_attr="_repair_gate_note_label",
            localize=False,
            grid=WidgetGridConfig(row=0, column=1, sticky="w", padx=(10, 0), pady=6),
        ),
        "repair_tab_locked": TextLabelSpec(
            text_key="repair_tab_locked",
            font_size=16,
            bold=True,
            text_color_role="heading",
            justify="center",
            anchor=None,
            grid=WidgetGridConfig(row=1, column=0, sticky="ew", padx=24, pady=(6, 6)),
        ),
        "before_repair": TextLabelSpec(
            text_key="before_repair",
            font_size=11,
            bold=True,
            text_color_role="muted",
            justify="center",
            anchor=None,
            grid=WidgetGridConfig(row=3, column=0, sticky="ew", padx=24, pady=(0, 4)),
        ),
        "repo_summary": TextLabelSpec(
            text_key="repo_summary_default",
            font_size=11,
            text_color_role="muted",
            widget_attr="_repo_summary_label",
            localize=False,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 8), columnspan=2),
        ),
        "repo_drop_hint": TextLabelSpec(
            text_key="repo_drop_hint",
            font_size=11,
            text_color_role="muted",
            tooltip_key="repo_drop_area",
            widget_attr="_repo_drop_hint_label",
            grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=10, pady=(8, 0)),
        ),
        "repo_empty_title": TextLabelSpec(
            text_key="repo_targets_unavailable",
            font_size=14,
            bold=True,
            text_color_role="heading",
            justify="center",
            anchor="center",
            widget_attr="_repo_empty_state_title_label",
            localize=False,
            grid=WidgetGridConfig(row=1, column=0, sticky="ew", padx=18, pady=(6, 4)),
        ),
        "repo_empty_body": TextLabelSpec(
            text_key="choose_valid_root",
            font_size=12,
            text_color_role="muted",
            justify="center",
            anchor="center",
            wraplength=420,
            widget_attr="_repo_empty_state_body_label",
            localize=False,
            grid=WidgetGridConfig(row=2, column=0, sticky="ew", padx=18, pady=(0, 6)),
        ),
        "repo_empty_hint": TextLabelSpec(
            text_key="run_audit_available_hint",
            font_size=11,
            text_color_role="muted",
            justify="center",
            anchor="center",
            wraplength=420,
            widget_attr="_repo_empty_state_hint_label",
            localize=False,
            grid=WidgetGridConfig(row=3, column=0, sticky="ew", padx=18, pady=(0, 8)),
        ),
        "output_empty": TextLabelSpec(
            text_key="execution_log_empty",
            font_size=11,
            text_color_role="output_empty",
            fg_color_role="output",
            justify="center",
            anchor="center",
            wraplength=520,
            widget_attr="_output_empty_state_label",
            grid=None,
        ),
        "reports_dashboard_body": TextLabelSpec(
            text_key="reports_dashboard_body",
            font_size=12,
            text_color_role="muted",
            wraplength=1120,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 10)),
        ),
        "reports_status_badge": TextLabelSpec(
            text_key="last_run",
            font_size=11,
            bold=True,
            height=28,
            corner_radius=14,
            fg_color_role="success_badge",
            text_color_role="success",
            padx=12,
            widget_attr="_reports_status_badge",
            localize=False,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=12, pady=(10, 6)),
        ),
        "latest_artifacts": TextLabelSpec(
            text_key="latest_artifacts",
            font_size=12,
            bold=True,
            text_color_role="heading",
            tooltip_key="latest_artifacts_section",
            grid=WidgetGridConfig(row=0, column=1, sticky="w", padx=(0, 8), pady=(10, 6)),
        ),
        "reports_summary": TextLabelSpec(
            text_key="last_run_none",
            font_size=12,
            text_color_role="body",
            wraplength=980,
            widget_attr="_reports_summary_label",
            localize=False,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=12, pady=(0, 8), columnspan=2),
        ),
        "reports_paths": TextLabelSpec(
            text_key="latest_artifacts_none",
            font_size=11,
            mono=True,
            text_color_role="muted",
            wraplength=980,
            widget_attr="_reports_paths_label",
            localize=False,
            grid=WidgetGridConfig(row=2, column=0, sticky="we", padx=12, pady=(0, 12), columnspan=2),
        ),
        "reports_next_action_badge": TextLabelSpec(
            text_key="next_action",
            font_size=11,
            bold=True,
            height=28,
            corner_radius=14,
            fg_color_role="success_badge",
            text_color_role="success",
            padx=12,
            tooltip_key="next_action_section",
            widget_attr="_reports_next_action_badge",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=12, pady=(10, 8)),
        ),
        "reports_next_action": TextLabelSpec(
            text_key="next_action_run_audit",
            font_size=12,
            text_color_role="body",
            wraplength=900,
            tooltip_key="next_action_section",
            widget_attr="_reports_next_action_label",
            localize=False,
            grid=WidgetGridConfig(row=0, column=1, sticky="we", padx=(0, 8), pady=(10, 8)),
        ),
        "prompts_library_body": TextLabelSpec(
            text_key="prompts_library_body",
            font_size=12,
            text_color_role="muted",
            wraplength=1120,
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=14, pady=(0, 10)),
        ),
        "prompts_workflow_title": TextLabelSpec(
            text_key="agent_workflow_title",
            font_size=11,
            bold=True,
            height=28,
            corner_radius=14,
            fg_color_role="success_badge",
            text_color_role="success",
            padx=12,
            tooltip_key="agent_workflow_section",
            widget_attr="_prompts_workflow_title_label",
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=10, pady=10),
        ),
        "prompts_workflow_body": TextLabelSpec(
            text_key="agent_workflow_body",
            font_size=12,
            text_color_role="body",
            wraplength=1040,
            tooltip_key="agent_workflow_section",
            widget_attr="_prompts_workflow_body_label",
            grid=WidgetGridConfig(row=0, column=1, sticky="we", padx=(0, 10), pady=10),
        ),
    }


def header_workflow_chip_label_specs() -> tuple[TextLabelSpec, ...]:
    return tuple(
        TextLabelSpec(
            text_key=text_key,
            font_size=11,
            bold=True,
            height=26,
            corner_radius=13,
            fg_color_role="header_chip",
            text_color_role="header_chip_text",
            padx=12,
            grid=WidgetGridConfig(row=0, column=index, sticky="w", padx=(0, 8)),
        )
        for index, text_key in enumerate(
            (
                "workflow_audit",
                "workflow_review",
                "workflow_agent",
                "workflow_repair",
                "workflow_parity",
            )
        )
    )


def repair_lock_step_label_specs() -> tuple[TextLabelSpec, TextLabelSpec, TextLabelSpec]:
    return (
        TextLabelSpec(
            text_key="repair_lock_step_1",
            font_size=11,
            text_color_role="body",
            wraplength=620,
            grid=WidgetGridConfig(row=4, column=0, sticky="ew", padx=24, pady=1),
        ),
        TextLabelSpec(
            text_key="repair_lock_step_2",
            font_size=11,
            text_color_role="body",
            wraplength=620,
            grid=WidgetGridConfig(row=5, column=0, sticky="ew", padx=24, pady=1),
        ),
        TextLabelSpec(
            text_key="repair_lock_step_3",
            font_size=11,
            text_color_role="body",
            wraplength=620,
            grid=WidgetGridConfig(row=6, column=0, sticky="ew", padx=24, pady=1),
        ),
    )


def reports_agent_step_label_specs() -> tuple[TextLabelSpec, TextLabelSpec, TextLabelSpec]:
    return (
        TextLabelSpec(
            text_key="agent_step_evidence",
            font_size=11,
            bold=True,
            text_color_role="body",
            fg_color_role="transparent",
            padx=10,
            grid=WidgetGridConfig(row=0, column=0, sticky="we", padx=(0, 8)),
        ),
        TextLabelSpec(
            text_key="agent_step_copy",
            font_size=11,
            bold=True,
            text_color_role="body",
            fg_color_role="transparent",
            padx=10,
            grid=WidgetGridConfig(row=0, column=1, sticky="we", padx=(0, 8)),
        ),
        TextLabelSpec(
            text_key="agent_step_prompt",
            font_size=11,
            bold=True,
            text_color_role="body",
            fg_color_role="transparent",
            padx=10,
            grid=WidgetGridConfig(row=0, column=2, sticky="we", padx=(0, 0)),
        ),
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


def standard_entry_field_spec(
    *,
    row: int,
    text_key: str,
    variable_attr: str,
    tooltip_key: str,
    width: int | None = None,
    label_pady: GridPadding = 4,
    entry_pady: GridPadding = 4,
    placeholder_key: str | None = None,
) -> EntryFieldSpec:
    return EntryFieldSpec(
        text_key=text_key,
        variable_attr=variable_attr,
        tooltip_key=tooltip_key,
        label_grid=WidgetGridConfig(row=row, column=0, sticky="w", padx=(14, 8), pady=label_pady),
        entry_grid=WidgetGridConfig(row=row, column=1, sticky="we", padx=(0, 14), pady=entry_pady),
        width=width,
        placeholder_key=placeholder_key,
    )


def github_remote_entry_field_specs() -> tuple[EntryFieldSpec, EntryFieldSpec, EntryFieldSpec]:
    return (
        EntryFieldSpec(
            text_key="github_owner",
            variable_attr="github_owner_var",
            tooltip_key="github_owner",
            label_grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=(12, 8), pady=(10, 4)),
            entry_grid=WidgetGridConfig(row=0, column=1, sticky="we", padx=(0, 12), pady=(10, 4)),
            placeholder_key="github_owner_placeholder",
        ),
        EntryFieldSpec(
            text_key="remote_repo_filters",
            variable_attr="github_repo_filters_var",
            tooltip_key="github_repo_filters",
            label_grid=WidgetGridConfig(row=0, column=2, sticky="w", padx=(0, 8), pady=(10, 4)),
            entry_grid=WidgetGridConfig(row=0, column=3, sticky="we", padx=(0, 12), pady=(10, 4)),
            placeholder_key="remote_repo_filters_placeholder",
        ),
        EntryFieldSpec(
            text_key="clone_workers",
            variable_attr="github_jobs_var",
            tooltip_key="github_clone_workers",
            label_grid=WidgetGridConfig(row=1, column=0, sticky="w", padx=(12, 8), pady=(4, 10)),
            entry_grid=WidgetGridConfig(row=1, column=1, sticky="w", padx=(0, 12), pady=(4, 10)),
            width=90,
        ),
    )


def max_findings_entry_field_spec(*, row: int) -> EntryFieldSpec:
    return standard_entry_field_spec(
        row=row,
        text_key="max_findings",
        variable_attr="max_matches_var",
        tooltip_key="max_findings",
        width=100,
        label_pady=(4, 12),
        entry_pady=(4, 12),
    )


def owner_profile_entry_field_specs(*, start_row: int) -> tuple[EntryFieldSpec, ...]:
    items: tuple[tuple[str, str, str, GridPadding], ...] = (
        ("noreply_email", "noreply_var", "noreply_email", 4),
        ("placeholder_email", "placeholder_var", "placeholder_email", 4),
        ("owner_name", "owner_name_var", "owner_name", 4),
        ("private_emails_to_replace", "owner_emails_var", "owner_emails", (4, 12)),
    )
    return tuple(
        standard_entry_field_spec(
            row=start_row + index,
            text_key=text_key,
            variable_attr=variable_attr,
            tooltip_key=tooltip_key,
            label_pady=pady,
            entry_pady=pady,
        )
        for index, (text_key, variable_attr, tooltip_key, pady) in enumerate(items)
    )


def git_identity_entry_field_specs() -> tuple[EntryFieldSpec, EntryFieldSpec]:
    return (
        standard_entry_field_spec(
            row=1,
            text_key="git_user_name",
            variable_attr="git_user_name_var",
            tooltip_key="git_user_name",
        ),
        standard_entry_field_spec(
            row=2,
            text_key="git_user_email",
            variable_attr="git_user_email_var",
            tooltip_key="git_user_email",
        ),
    )


def repair_allowed_remote_owner_entry_field_spec() -> EntryFieldSpec:
    return EntryFieldSpec(
        text_key="allowed_remote_owners",
        variable_attr="allowed_remote_owners_var",
        tooltip_key="allowed_remote_owners",
        label_grid=WidgetGridConfig(row=9, column=0, sticky="w", padx=12, pady=(4, 0)),
        entry_grid=WidgetGridConfig(row=10, column=0, sticky="we", padx=12, pady=(2, 4), columnspan=2),
        widget_attr="_allowed_remote_owner_entry",
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
        ActionButtonSpec(
            text_key="cleanup_audit_results_action",
            tooltip_key="cleanup_audit_results",
            command_kind="method",
            command_attr="_cleanup_old_audit_results",
            grid=WidgetGridConfig(row=0, column=6, sticky="w", padx=(0, 8), pady=0),
            icon="icon-folder.png",
        ),
    )


def reports_action_layout_state(*, compact: bool, artifact_button_count: int) -> ReportsActionLayoutState:
    if compact:
        return ReportsActionLayoutState(
            compact=True,
            agent_handoff_grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 6)),
            artifact_button_grids=tuple(
                WidgetGridConfig(row=1 + (idx // 3), column=idx % 3, sticky="w", padx=(0, 8), pady=(2, 0))
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


def reports_status_label(
    counts: dict[str, int],
    exit_code: int | None,
    *,
    exit_policy_failed: int,
    exit_runtime_error: int,
    exit_aborted: int,
) -> str:
    if counts["failed"] or counts["blocking"] or exit_code == exit_policy_failed:
        return "FAIL"
    if exit_code == exit_runtime_error:
        return "ERROR"
    if exit_code == exit_aborted:
        return "ABORTED"
    if counts["manual"] or counts["total"] == 0:
        return "PASS/REVIEW"
    return "PASS"


def reports_next_action_key(
    counts: dict[str, int],
    exit_code: int | None,
    *,
    has_artifacts: bool,
    exit_ok: int,
    exit_policy_failed: int,
    exit_runtime_error: int,
    exit_aborted: int,
) -> str:
    if not has_artifacts:
        return "next_action_run_audit"
    if exit_code in {exit_runtime_error, exit_aborted}:
        return "next_action_error"
    if exit_code not in {None, exit_ok, exit_policy_failed}:
        return "next_action_error"
    if counts["failed"] or counts["blocking"] or exit_code == exit_policy_failed:
        return "next_action_failed"
    if counts["manual"]:
        return "next_action_manual"
    if counts["total"] == 0:
        return "next_action_review_artifacts"
    return "next_action_pass"


def reports_badge_color_roles(status_label: str) -> tuple[FillColorRole, TextColorRole]:
    if status_label in {"FAIL", "ERROR"}:
        return "failure_badge", "failure_badge_text"
    if status_label == "ABORTED":
        return "warning_badge", "warning_badge_text"
    return "pass_badge", "pass_badge_text"


def report_artifact_paths_text(
    *,
    run_dir: str,
    json_path: str,
    agent_summary_path: str,
    html_path: str,
    log_path: str,
    state_path: str,
) -> str:
    return (
        f"run_dir: {run_dir}\n"
        f"report.json: {json_path}\n"
        f"agent_summary.json: {agent_summary_path}\n"
        f"report.html: {html_path}\n"
        f"run.log: {log_path}\n"
        f"run_state.json: {state_path}"
    )


def reports_run_presentation_state(
    *,
    has_artifacts: bool,
    counts: dict[str, int],
    exit_code: int | None,
    run_action: str,
    artifact_paths_text: str,
    repair_summary_text: str,
    empty_badge_text: str,
    empty_summary_text: str,
    empty_paths_text: str,
    exit_ok: int,
    exit_policy_failed: int,
    exit_runtime_error: int,
    exit_aborted: int,
) -> ReportsRunPresentationState:
    visibility = reports_action_visibility_state(has_artifacts=has_artifacts)
    next_action = reports_next_action_key(
        counts,
        exit_code,
        has_artifacts=has_artifacts,
        exit_ok=exit_ok,
        exit_policy_failed=exit_policy_failed,
        exit_runtime_error=exit_runtime_error,
        exit_aborted=exit_aborted,
    )
    if not has_artifacts:
        return ReportsRunPresentationState(
            visibility=visibility,
            badge_text=empty_badge_text,
            badge_fg_color_role="success_badge",
            badge_text_color_role="success",
            summary_text=empty_summary_text,
            paths_text=empty_paths_text,
            next_action_key=next_action,
        )

    status_label = reports_status_label(
        counts,
        exit_code,
        exit_policy_failed=exit_policy_failed,
        exit_runtime_error=exit_runtime_error,
        exit_aborted=exit_aborted,
    )
    badge_fg_role, badge_text_role = reports_badge_color_roles(status_label)
    summary_text = repair_summary_text
    if counts["total"] == 0:
        summary_text = (
            empty_summary_text
            if exit_code is None
            else f"{run_action or 'run'} finished with exit code {exit_code}."
        )
    return ReportsRunPresentationState(
        visibility=visibility,
        badge_text=status_label,
        badge_fg_color_role=badge_fg_role,
        badge_text_color_role=badge_text_role,
        summary_text=summary_text,
        paths_text=artifact_paths_text,
        next_action_key=next_action,
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


def prompt_card_presentation_spec(
    *,
    index: int,
    stage_text: str,
    title: str,
    description: str,
    best_for_text: str,
    command_label: str,
    command: str,
    body_wraplength: int,
    command_wraplength: int,
) -> PromptCardPresentationSpec:
    return PromptCardPresentationSpec(
        fg_color_role="surface_alt",
        border_color_role="card_border",
        corner_radius=10,
        border_width=1,
        column_configs=(GridColumnConfig(column=0, weight=1),),
        stage_label=LiteralTextLabelSpec(
            text=f"{index + 1} / {stage_text}",
            font_size=10,
            bold=True,
            height=24,
            corner_radius=12,
            fg_color_role="success_badge",
            text_color_role="success",
            anchor="w",
            justify=None,
            padx=10,
            grid=WidgetGridConfig(row=0, column=0, sticky="w", padx=12, pady=(10, 4)),
        ),
        title_label=LiteralTextLabelSpec(
            text=title,
            font_size=14,
            bold=True,
            text_color_role="heading",
            grid=WidgetGridConfig(row=1, column=0, sticky="we", padx=12, pady=(0, 2)),
        ),
        description_label=LiteralTextLabelSpec(
            text=description,
            font_size=11,
            text_color_role="muted",
            wraplength=body_wraplength,
            grid=WidgetGridConfig(row=2, column=0, sticky="we", padx=12, pady=(0, 6)),
        ),
        best_for_label=LiteralTextLabelSpec(
            text=best_for_text,
            font_size=11,
            bold=True,
            text_color_role="body",
            wraplength=body_wraplength,
            grid=WidgetGridConfig(row=3, column=0, sticky="we", padx=12, pady=(0, 8)),
        ),
        command_label=LiteralTextLabelSpec(
            text=f"{command_label}: {command}",
            font_size=10,
            mono=True,
            text_color_role="body",
            wraplength=command_wraplength,
            grid=WidgetGridConfig(row=4, column=0, sticky="we", padx=12, pady=(0, 8)),
        ),
        actions_grid=WidgetGridConfig(row=5, column=0, sticky="w", padx=12, pady=(0, 12)),
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
