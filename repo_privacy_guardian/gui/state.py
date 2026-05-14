"""Pure GUI state helpers for the Audit and Repair flow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal


WidgetState = Literal["normal", "disabled"]
RepairGateTone = Literal["locked", "review", "ready"]


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


def advanced_identity_visibility_state(*, visible: bool) -> CollapsibleSectionState:
    return CollapsibleSectionState(
        visible=visible,
        toggle_text_key="hide_advanced_identity" if visible else "show_advanced_identity",
        hint_text_key="advanced_identity_visible" if visible else "advanced_identity_hidden",
    )
