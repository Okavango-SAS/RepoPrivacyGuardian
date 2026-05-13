"""Pure parsing helpers for Git history patch scans."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from re import Pattern


GIT_DIFF_TARGET_RE = re.compile(r"diff --git a/(.+?) b/(.+)$")


def parse_git_diff_target(line: str) -> str | None:
    """Return the target path from a ``diff --git`` line, if it has one."""
    match = GIT_DIFF_TARGET_RE.match(line.strip())
    if not match:
        return None
    return match.group(2)


def extract_patch_change_context(line: str) -> str | None:
    """Return added/removed patch content without the diff prefix."""
    if line.startswith(("+++", "---")):
        return None
    if line.startswith(("+", "-")):
        return line[1:]
    return None


def format_history_patch_match(
    line_number: int,
    line: str,
    *,
    preview_limit: int = 240,
) -> str:
    return f"L{line_number}:{line.strip()[:preview_limit]}"


def format_history_email_match(
    *,
    line_number: int,
    current_file: str | None,
    leaked_emails: Iterable[str],
    line: str,
    preview_limit: int = 200,
) -> str | None:
    unique_emails = sorted(set(leaked_emails))
    if not unique_emails:
        return None
    rel_path = current_file or "-"
    return f"L{line_number}:{rel_path}:{', '.join(unique_emails)}:{line.strip()[:preview_limit]}"


def active_secret_file_from_patch_change(
    *,
    current_file: str | None,
    line_context: str,
    secret_pattern: Pattern[str],
    classify_secret_match_context: Callable[[str, str], str],
) -> str | None:
    if current_file is None:
        return None
    if secret_pattern.search(line_context) is None:
        return None
    if classify_secret_match_context(current_file, line_context) != "active":
        return None
    return current_file
