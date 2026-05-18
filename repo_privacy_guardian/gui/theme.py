"""Pure GUI theme update helpers."""

from __future__ import annotations

from collections.abc import Mapping


THEME_TRANSLATABLE_OPTIONS = (
    "fg_color",
    "bg_color",
    "text_color",
    "hover_color",
    "border_color",
    "button_color",
    "button_hover_color",
    "scrollbar_fg_color",
    "scrollbar_button_color",
    "scrollbar_button_hover_color",
    "segmented_button_fg_color",
    "segmented_button_selected_color",
    "segmented_button_selected_hover_color",
    "segmented_button_unselected_color",
    "segmented_button_unselected_hover_color",
    "dropdown_fg_color",
    "dropdown_hover_color",
    "dropdown_text_color",
    "placeholder_text_color",
    "background",
    "foreground",
    "selectbackground",
    "selectforeground",
    "highlightbackground",
    "insertbackground",
)


THEME_TOKEN_PREFERENCES: Mapping[str, tuple[str, ...]] = {
    "fg_color": (
        "_page_bg",
        "_surface_fg",
        "_surface_alt",
        "_white_panel_fg",
        "_secondary_button_fg",
        "_primary_button_fg",
        "_success_panel_fg",
        "_success_badge_fg",
        "_pass_badge_fg",
        "_info_panel_fg",
        "_warning_panel_fg",
        "_warning_badge_fg",
        "_failure_badge_fg",
        "_output_fg",
    ),
    "bg_color": ("_page_bg", "_surface_fg", "_surface_alt", "_white_panel_fg"),
    "text_color": (
        "_text_heading",
        "_text_body",
        "_text_muted",
        "_secondary_button_text",
        "_success_text",
        "_pass_badge_text",
        "_info_text",
        "_warning_text",
        "_warning_strong_text",
        "_warning_badge_text",
        "_danger_text",
        "_failure_badge_text",
        "_output_text",
        "_output_empty_text",
        "_list_select_text",
    ),
    "hover_color": (
        "_primary_button_hover",
        "_secondary_button_hover",
        "_support_button_hover",
        "_tab_selected_hover",
        "_tab_unselected_hover",
        "_scrollbar_hover",
    ),
    "border_color": (
        "_card_border",
        "_white_panel_border",
        "_success_panel_border",
        "_info_panel_border",
        "_warning_panel_border",
        "_secondary_button_border",
    ),
    "button_color": ("_support_button_fg", "_scrollbar_thumb"),
    "button_hover_color": ("_support_button_hover", "_scrollbar_hover"),
    "scrollbar_fg_color": ("_scrollbar_track",),
    "scrollbar_button_color": ("_scrollbar_thumb",),
    "scrollbar_button_hover_color": ("_scrollbar_hover",),
    "segmented_button_fg_color": ("_tab_segment_fg",),
    "segmented_button_selected_color": ("_tab_selected_fg",),
    "segmented_button_selected_hover_color": ("_tab_selected_hover",),
    "segmented_button_unselected_color": ("_tab_unselected_fg",),
    "segmented_button_unselected_hover_color": ("_tab_unselected_hover",),
    "background": ("_white_panel_fg", "_surface_fg", "_surface_alt", "_header_fg", "_page_bg", "_output_fg"),
    "foreground": ("_list_text", "_output_text", "_text_body"),
    "selectbackground": ("_primary_button_fg",),
    "selectforeground": ("_list_select_text",),
    "insertbackground": ("_text_body", "_output_text"),
}


def parse_hex_rgb(color: str) -> tuple[int, int, int] | None:
    value = color.strip()
    if len(value) != 7 or not value.startswith("#"):
        return None
    try:
        return (int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16))
    except ValueError:
        return None


def theme_palette_snapshot_from_attrs(attrs: Mapping[str, object]) -> dict[str, str]:
    return {
        name: value
        for name, value in attrs.items()
        if name.startswith("_") and isinstance(value, str) and parse_hex_rgb(value) is not None
    }


def preferred_theme_token_for_option(
    option: str,
    token_names: list[str],
    *,
    sibling_values: Mapping[str, object],
    old_palette: Mapping[str, str],
) -> str | None:
    if option == "border_color" and "_white_panel_border" in token_names:
        sibling_fg = sibling_values.get("fg_color")
        if sibling_fg == old_palette.get("_white_panel_fg"):
            return "_white_panel_border"

    for preferred in THEME_TOKEN_PREFERENCES.get(option, ()):
        if preferred in token_names:
            return preferred
    return token_names[0] if token_names else None


def translate_theme_color(
    value: object,
    option: str,
    *,
    old_palette: Mapping[str, str],
    new_palette: Mapping[str, str],
    sibling_values: Mapping[str, object],
) -> object | None:
    if isinstance(value, (tuple, list)):
        translated_items = [
            translate_theme_color(
                item,
                option,
                old_palette=old_palette,
                new_palette=new_palette,
                sibling_values=sibling_values,
            )
            for item in value
        ]
        if all(item is None for item in translated_items):
            return None
        merged = [
            original if translated is None else translated
            for original, translated in zip(value, translated_items, strict=False)
        ]
        return tuple(merged) if isinstance(value, tuple) else merged

    if not isinstance(value, str) or parse_hex_rgb(value) is None:
        return None
    token_names = [name for name, old_value in old_palette.items() if old_value == value]
    if not token_names:
        return None
    if len(token_names) == 1:
        token_name = token_names[0]
    else:
        token_name = preferred_theme_token_for_option(
            option,
            token_names,
            sibling_values=sibling_values,
            old_palette=old_palette,
        )
    if token_name is None:
        return None
    new_value = new_palette.get(token_name)
    if not new_value or new_value == value:
        return None
    return new_value


def theme_option_updates(
    sibling_values: Mapping[str, object],
    *,
    old_palette: Mapping[str, str],
    new_palette: Mapping[str, str],
) -> dict[str, object]:
    updates: dict[str, object] = {}
    for option, value in sibling_values.items():
        translated = translate_theme_color(
            value,
            option,
            old_palette=old_palette,
            new_palette=new_palette,
            sibling_values=sibling_values,
        )
        if translated is not None:
            updates[option] = translated
    return updates


def special_widget_theme_updates(palette: Mapping[str, str]) -> dict[str, dict[str, str]]:
    return {
        "root": {"fg_color": palette["_page_bg"]},
        "app_frame": {
            "fg_color": palette["_page_bg"],
            "scrollbar_fg_color": palette["_scrollbar_track"],
            "scrollbar_button_color": palette["_scrollbar_thumb"],
            "scrollbar_button_hover_color": palette["_scrollbar_hover"],
        },
        "flow_tabs": {
            "fg_color": palette["_tabview_fg"],
            "segmented_button_fg_color": palette["_tab_segment_fg"],
            "segmented_button_selected_color": palette["_tab_selected_fg"],
            "segmented_button_selected_hover_color": palette["_tab_selected_hover"],
            "segmented_button_unselected_color": palette["_tab_unselected_fg"],
            "segmented_button_unselected_hover_color": palette["_tab_unselected_hover"],
            "text_color": palette["_text_heading"],
        },
        "flow_segmented_button": {
            "fg_color": palette["_tab_segment_fg"],
            "selected_color": palette["_tab_selected_fg"],
            "selected_hover_color": palette["_tab_selected_hover"],
            "unselected_color": palette["_tab_unselected_fg"],
            "unselected_hover_color": palette["_tab_unselected_hover"],
            "text_color": palette["_text_heading"],
        },
        "repo_scrollbar": {
            "fg_color": palette["_scrollbar_track"],
            "button_color": palette["_scrollbar_thumb"],
            "button_hover_color": palette["_scrollbar_hover"],
        },
        "repo_list": {
            "background": palette["_list_fg"],
            "foreground": palette["_list_text"],
            "selectbackground": palette["_primary_button_fg"],
            "selectforeground": palette["_list_select_text"],
        },
        "output": {
            "fg_color": palette["_output_fg"],
            "text_color": palette["_output_text"],
        },
        "output_empty_state_label": {
            "fg_color": palette["_output_fg"],
            "text_color": palette["_output_empty_text"],
        },
    }
