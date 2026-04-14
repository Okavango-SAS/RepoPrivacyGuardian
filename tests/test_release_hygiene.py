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

CI_WORKFLOW = ".github/workflows/ci.yml"

ROOT_LAYOUT_OFFENDERS = [
    "requirements.txt",
    "requirements-gui.txt",
    "requirements-remediation.txt",
    "requirements-dev.txt",
    "prompts",
]

ROOT_LAYOUT_REQUIRED = [
    "CHANGELOG.md",
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

RELEASE_DOCS_REQUIRED = [
    "docs/VERSIONING.md",
    "docs/RELEASE_NOTES_TEMPLATE.md",
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


def test_pyproject_uses_production_stable_classifier() -> None:
    pyproject = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")

    assert '"Development Status :: 5 - Production/Stable"' in pyproject
    assert '"Development Status :: 4 - Beta"' not in pyproject
    assert '"Development Status :: 3 - Alpha"' not in pyproject


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


def test_release_docs_exist_and_cover_versioning_exit_criteria() -> None:
    root = _repo_root()

    missing = [rel for rel in RELEASE_DOCS_REQUIRED if not (root / rel).exists()]
    assert not missing, "Release docs are missing:\n" + "\n".join(missing)

    versioning = (root / "docs" / "VERSIONING.md").read_text(encoding="utf-8")
    release_notes = (root / "docs" / "RELEASE_NOTES_TEMPLATE.md").read_text(encoding="utf-8")

    assert "`1.1.x`" in versioning
    assert "`1.0.0`" in versioning
    assert "semantic versioning" in versioning.lower()
    assert "Validation evidence" in release_notes


def test_docs_cover_optional_github_hardening_audit() -> None:
    readme = (_repo_root() / "README.MD").read_text(encoding="utf-8")
    agents = (_repo_root() / "AGENTS.MD").read_text(encoding="utf-8")
    policy = (_repo_root() / "docs" / "POLICY.md").read_text(encoding="utf-8")

    assert "--audit-github-hardening" in readme
    assert "--check-tooling" in readme
    assert "--install-missing-tools" in readme
    assert "winget" in readme
    assert "GitHub MCP is not a prerequisite" in readme
    assert "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN" in readme
    assert "--audit-github-hardening" in agents
    assert "--check-tooling" in agents
    assert "winget" in agents
    assert "branch protection" in policy.lower()


def test_changelog_records_stable_release() -> None:
    changelog = (_repo_root() / "CHANGELOG.md").read_text(encoding="utf-8")

    assert "## [1.1.0] - 2026-04-14" in changelog
    assert "Release-hardening and operator-playbook update." in changelog
    assert "## [1.0.0] - 2026-04-14" in changelog
    assert "Initial stable public release." in changelog


def test_release_checklist_mentions_clearing_stale_build_outputs() -> None:
    checklist = (_repo_root() / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")

    assert "Clear stale local build outputs" in checklist
    assert "`dist/`, `build/`, and `*.egg-info/`" in checklist


def test_repo_declares_single_owner_codeowners_file() -> None:
    codeowners = (_repo_root() / ".github" / "CODEOWNERS").read_text(encoding="utf-8")

    assert "* @axeljackal" in codeowners


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


def test_repo_gitignore_covers_local_packaging_and_backup_artifacts() -> None:
    gitignore = (_repo_root() / ".gitignore").read_text(encoding="utf-8")

    assert ".pkg-venv/" in gitignore
    assert "*-pre-publication-fix-*.bundle" in gitignore


def test_ci_workflow_uses_sha_pinned_actions_and_least_privilege() -> None:
    workflow = (_repo_root() / CI_WORKFLOW).read_text(encoding="utf-8")
    pinned_actions = re.findall(r"uses:\s+actions/(?:checkout|setup-python)@[0-9a-f]{40}", workflow)

    assert re.search(r"permissions:\s+contents:\s+read", workflow)
    assert workflow.count("timeout-minutes:") == 3
    assert workflow.count("persist-credentials: false") == 3
    assert len(pinned_actions) == 6
    assert not re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d", workflow)


def test_ci_workflow_covers_supported_python_versions_and_package_artifacts() -> None:
    workflow = (_repo_root() / CI_WORKFLOW).read_text(encoding="utf-8")

    for version in ('"3.10"', '"3.11"', '"3.12"', '"3.13"'):
        assert version in workflow

    assert "dist/*.whl" in workflow
    assert "dist/*.tar.gz" in workflow
    assert workflow.count("python tests/release_smoke_cli.py") >= 3
