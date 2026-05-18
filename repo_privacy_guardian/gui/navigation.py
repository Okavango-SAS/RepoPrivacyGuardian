"""GUI flow-tab navigation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FlowTabNames:
    audit: str
    reports: str
    prompts: str
    settings: str
    repair: str

    def ordered(self) -> list[str]:
        return [self.audit, self.reports, self.prompts, self.settings, self.repair]


def active_flow_tab_after_rename(
    active_tab: str | None,
    *,
    current: FlowTabNames,
    desired: FlowTabNames,
) -> str | None:
    if active_tab is None:
        return None
    replacements = dict(zip(current.ordered(), desired.ordered(), strict=True))
    return replacements.get(active_tab)


def rename_flow_tabs(flow_tabs: Any, *, current: FlowTabNames, desired: FlowTabNames) -> None:
    for current_name, desired_name in zip(current.ordered(), desired.ordered(), strict=True):
        if current_name != desired_name:
            flow_tabs.rename(current_name, desired_name)
    if hasattr(flow_tabs, "_name_list"):
        flow_tabs._name_list = desired.ordered()  # noqa: SLF001 - CTkTabview stores visual tab order here.


def select_flow_tab_without_delayed_cleanup(flow_tabs: Any, tab_name: str) -> bool:
    tab_dict = getattr(flow_tabs, "_tab_dict", {})
    if tab_name not in tab_dict:
        return False

    current_name = getattr(flow_tabs, "_current_name", "")
    if current_name in tab_dict and current_name != tab_name:
        tab_dict[current_name].grid_forget()

    flow_tabs._current_name = tab_name  # noqa: SLF001 - avoids CTkTabview.set() delayed grid cleanup.
    segmented_button = getattr(flow_tabs, "_segmented_button", None)
    if segmented_button is not None:
        segmented_button.set(tab_name)
    flow_tabs._set_grid_current_tab()  # noqa: SLF001
    flow_tabs._grid_forget_all_tabs(exclude_name=tab_name)  # noqa: SLF001
    return True
