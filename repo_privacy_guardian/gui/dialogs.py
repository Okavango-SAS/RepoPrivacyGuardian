"""GUI file and directory dialog helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def dialog_initial_dir(current_value: str, *, default_dir: Path | str) -> str:
    fallback = Path(default_dir).expanduser()
    raw_value = current_value.strip()
    if not raw_value:
        return str(fallback)

    candidate = Path(raw_value).expanduser()
    if candidate.exists():
        return str(candidate if candidate.is_dir() else candidate.parent)

    if candidate.suffix:
        return str(candidate.parent if candidate.parent.exists() else fallback)

    return str(candidate if candidate.parent.exists() else fallback)


def browse_directory(
    filedialog: Any,
    target_var: Any,
    *,
    title: str,
    initial_dir: str,
    mustexist: bool = False,
) -> bool:
    selected = filedialog.askdirectory(title=title, initialdir=initial_dir, mustexist=mustexist)
    if not selected:
        return False
    target_var.set(selected)
    return True


def browse_existing_file(
    filedialog: Any,
    target_var: Any,
    *,
    title: str,
    initial_dir: str,
    filetypes: list[tuple[str, str]] | tuple[tuple[str, str], ...],
) -> bool:
    selected = filedialog.askopenfilename(title=title, initialdir=initial_dir, filetypes=filetypes)
    if not selected:
        return False
    target_var.set(selected)
    return True


def browse_save_file(
    filedialog: Any,
    target_var: Any,
    *,
    title: str,
    initial_dir: str,
    default_extension: str,
    filetypes: list[tuple[str, str]] | tuple[tuple[str, str], ...],
) -> bool:
    selected = filedialog.asksaveasfilename(
        title=title,
        initialdir=initial_dir,
        defaultextension=default_extension,
        filetypes=filetypes,
    )
    if not selected:
        return False
    target_var.set(selected)
    return True
