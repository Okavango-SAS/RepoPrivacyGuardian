"""Pure tooling records and defaults shared by preflight and the facade."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

GUI_DRAG_DROP_INSTALL_PACKAGES = ["tkinterdnd2>=0.4.3,<0.5"]

GUI_INSTALL_PACKAGES = ["customtkinter>=5.2.2,<6", *GUI_DRAG_DROP_INSTALL_PACKAGES]

REMEDIATION_INSTALL_PACKAGES = ["git-filter-repo>=2.45,<3"]

WINGET_BOOTSTRAP_URL = "https://aka.ms/getwinget"

WINGET_PACKAGE_FAMILY_NAME = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"

DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 300


def subprocess_stdin(input_text: str | None = None) -> int:
    return subprocess.PIPE if input_text is not None else subprocess.DEVNULL


@dataclass
class ToolingCheck:
    name: str
    state: str
    blocking: bool
    detail: str
    install_hint: str | None = None
    auto_install_command: list[str] | None = None
