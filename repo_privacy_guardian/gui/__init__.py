"""Desktop GUI package for Repo Privacy Guardian."""

from __future__ import annotations

__all__ = ["GuiApp"]


def __getattr__(name: str) -> object:
    if name == "GuiApp":
        from repo_privacy_guardian.gui.app import GuiApp

        return GuiApp
    raise AttributeError(name)
