"""Internal package for Repo Privacy Guardian.

Public compatibility remains anchored at ``Repo_Privacy_Guardian`` for the
current 1.x line. This package also exposes the primary facade symbols lazily
so modular imports can use ``import repo_privacy_guardian as rpg`` without
forcing GUI/runtime imports during package initialization.
"""

from __future__ import annotations

from typing import Any


_PUBLIC_COMPAT_NAMES = frozenset(
    {
        "main",
        "make_parser",
        "GuardRunConfig",
        "RepoReport",
        "GuiApp",
        "persist_run_outputs",
        "build_agent_summary",
        "format_agent_summary_handoff",
        "load_configured_suppressions",
        "REPORT_DIFF_SCHEMA_VERSION",
        "compare_report_files",
        "compare_report_payloads",
        "find_previous_report_json",
        "format_report_diff_summary",
    }
)


def __getattr__(name: str) -> Any:
    if name not in _PUBLIC_COMPAT_NAMES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from repo_privacy_guardian import core

    return getattr(core, name)


def __dir__() -> list[str]:
    return sorted([*globals(), *_PUBLIC_COMPAT_NAMES])
