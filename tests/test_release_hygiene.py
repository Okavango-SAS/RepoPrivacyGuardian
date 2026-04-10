from __future__ import annotations

import re
import subprocess
from pathlib import Path


CAPTURE_LIKE_MEDIA_RE = re.compile(
    r"(?:^|/)(?:gui[_-]?capture|capture|report-\d{8}-\d{6}[^/]*)\.(?:png|jpe?g|webp)$",
    re.IGNORECASE,
)

GUI_CONTRACT_DOCS = [
    "AGENTS.MD",
    "README.MD",
    "docs/ARCHITECTURE.md",
    "docs/ENGINEERING_DECISIONS.md",
    "docs/KNOWN_ISSUES.md",
    "docs/LEARNED_LESSONS.md",
    "docs/RELEASE_CHECKLIST.md",
    "docs/ROADMAP.md",
    "prompts/02_PARIDAD_GUI_CLI.prompt.md",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tracked_paths() -> list[Path]:
    out = subprocess.check_output(
        ["git", "ls-files"],
        cwd=_repo_root(),
        text=True,
        encoding="utf-8",
    )
    return [_repo_root() / line for line in out.splitlines() if line.strip()]


def test_pyproject_declares_macos_support_classifier() -> None:
    pyproject = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")
    assert '"Operating System :: MacOS :: MacOS X"' in pyproject


def test_no_capture_like_release_media_is_tracked() -> None:
    offenders = []
    for path in _tracked_paths():
        rel = path.relative_to(_repo_root()).as_posix()
        if CAPTURE_LIKE_MEDIA_RE.search(rel):
            offenders.append(rel)

    assert not offenders, "Capture-like release media should not be tracked:\n" + "\n".join(offenders)


def test_gui_contract_docs_use_audit_repair_labels() -> None:
    offenders = []
    for rel in GUI_CONTRACT_DOCS:
        text = (_repo_root() / rel).read_text(encoding="utf-8")
        if "Auditar" in text or "Reparar" in text:
            offenders.append(rel)

    assert not offenders, "Legacy GUI labels still present in docs/prompts:\n" + "\n".join(offenders)
