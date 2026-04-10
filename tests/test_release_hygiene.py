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
    "docs/prompts/02_PARIDAD_GUI_CLI.prompt.md",
]

ROOT_LAYOUT_OFFENDERS = [
    "requirements.txt",
    "requirements-gui.txt",
    "requirements-remediation.txt",
    "requirements-dev.txt",
    "prompts",
]

ROOT_LAYOUT_REQUIRED = [
    "Repo_Privacy_Guardian.py",
    "README.MD",
    "config/requirements/requirements.txt",
    "config/requirements/requirements-gui.txt",
    "config/requirements/requirements-remediation.txt",
    "config/requirements/requirements-dev.txt",
    "repo_privacy_guardian_resources/__init__.py",
    "repo_privacy_guardian_resources/POLICY.md",
    "docs/prompts/01_AUDITORIA_Y_SEGUIMIENTO.prompt.md",
    "docs/prompts/02_PARIDAD_GUI_CLI.prompt.md",
    "docs/prompts/03_MEJORA_GUI_GITHUB_EMAIL.prompt.md",
    "docs/prompts/04_EJECUCION_AGENTICA_CLI.prompt.md",
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


def test_support_files_are_moved_out_of_root() -> None:
    root = _repo_root()

    offenders = [rel for rel in ROOT_LAYOUT_OFFENDERS if (root / rel).exists()]
    missing = [rel for rel in ROOT_LAYOUT_REQUIRED if not (root / rel).exists()]

    assert not offenders, "Support files should not live in the repository root:\n" + "\n".join(offenders)
    assert not missing, "Expected organized support files are missing:\n" + "\n".join(missing)


def test_packaged_policy_resource_matches_repo_policy() -> None:
    root = _repo_root()
    docs_policy = (root / "docs" / "POLICY.md").read_text(encoding="utf-8")
    packaged_policy = (root / "repo_privacy_guardian_resources" / "POLICY.md").read_text(encoding="utf-8")

    assert packaged_policy == docs_policy


def test_gui_contract_docs_use_audit_repair_labels() -> None:
    offenders = []
    for rel in GUI_CONTRACT_DOCS:
        text = (_repo_root() / rel).read_text(encoding="utf-8")
        if "Auditar" in text or "Reparar" in text:
            offenders.append(rel)

    assert not offenders, "Legacy GUI labels still present in docs/prompts:\n" + "\n".join(offenders)
