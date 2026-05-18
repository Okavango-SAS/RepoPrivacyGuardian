"""GUI window and runtime lifecycle helpers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


GUI_ROOT_INIT_ERROR_MESSAGE = (
    "GUI mode could not initialize Tk. "
    "On Linux desktop, install python3-tk and start from a graphical session. "
    "Otherwise, use the CLI."
)
DEFAULT_WINDOW_TITLE = "Repo Privacy Guardian"


@dataclass(frozen=True)
class GuiWindowGeometry:
    width: int
    height: int
    x: int
    y: int
    min_width: int
    min_height: int
    max_width: int
    max_height: int

    @property
    def geometry_value(self) -> str:
        return f"{self.width}x{self.height}+{self.x}+{self.y}"


def window_geometry_for_screen(screen_width: int, screen_height: int) -> GuiWindowGeometry:
    window_width = min(max(int(screen_width * 0.92), 1180), 1620)
    window_height = min(max(int(screen_height * 0.9), 760), 980)
    return GuiWindowGeometry(
        width=window_width,
        height=window_height,
        x=max((screen_width - window_width) // 2, 0),
        y=max((screen_height - window_height) // 2, 0),
        min_width=min(1180, screen_width),
        min_height=min(700, screen_height),
        max_width=screen_width,
        max_height=screen_height,
    )


def configure_ctk_theme(ctk: Any, appearance: str, *, color_theme: str = "blue") -> None:
    ctk.set_appearance_mode(appearance)
    ctk.set_default_color_theme(color_theme)


def create_root(ctk: Any, tcl_error: type[BaseException]) -> Any:
    try:
        return ctk.CTk()
    except tcl_error as exc:
        raise RuntimeError(GUI_ROOT_INIT_ERROR_MESSAGE) from exc


def configure_root_window(root: Any, *, title: str = DEFAULT_WINDOW_TITLE) -> GuiWindowGeometry:
    root.title(title)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    geometry = window_geometry_for_screen(screen_width, screen_height)
    root.geometry(geometry.geometry_value)
    root.minsize(geometry.min_width, geometry.min_height)
    root.maxsize(geometry.max_width, geometry.max_height)
    return geometry


def sync_ctk_system_appearance_probe(
    ctk: Any,
    *,
    current_appearance: str,
    system_appearance: str,
    record_warning: Callable[[str, Exception | None], None],
) -> None:
    if current_appearance != system_appearance:
        return
    tracker = getattr(ctk, "AppearanceModeTracker", None)
    init_appearance = getattr(tracker, "init_appearance_mode", None)
    if init_appearance is None:
        return
    try:
        init_appearance()
    except Exception as exc:
        record_warning("appearance mode tracker initialization failed", exc)


def register_appearance_mode_callback(
    ctk: Any,
    *,
    callback: Callable[[str], None],
    root: Any,
    already_registered: bool,
    record_warning: Callable[[str, Exception | None], None],
) -> bool:
    if already_registered:
        return True
    tracker = getattr(ctk, "AppearanceModeTracker", None)
    add_callback = getattr(tracker, "add", None)
    if add_callback is None:
        return False
    try:
        add_callback(callback, root)
    except Exception as exc:
        record_warning("appearance mode callback registration failed", exc)
        return False
    return True


def unregister_appearance_mode_callback(
    ctk: Any,
    *,
    callback: Callable[[str], None],
    was_registered: bool,
    record_warning: Callable[[str, Exception | None], None],
) -> bool:
    if not was_registered:
        return False
    tracker = getattr(ctk, "AppearanceModeTracker", None)
    remove_callback = getattr(tracker, "remove", None)
    if remove_callback is not None:
        try:
            remove_callback(callback)
        except Exception as exc:
            record_warning("appearance mode callback unregister failed", exc)
    return False


def should_apply_appearance_mode_change(*, gui_destroying: bool) -> bool:
    return not gui_destroying


def run_mainloop(root: Any) -> None:
    root.mainloop()
