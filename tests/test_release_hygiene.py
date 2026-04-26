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
    "docs/DOGFOODING.md",
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
    ".env.example",
    "Repo_Privacy_Guardian.py",
    "README.MD",
    "repo_privacy_guardian_artifacts.py",
    "config/requirements/requirements.txt",
    "config/requirements/requirements-gui.txt",
    "config/requirements/requirements-remediation.txt",
    "config/requirements/requirements-dev.txt",
    "repo_privacy_guardian_resources/__init__.py",
    "repo_privacy_guardian_resources/POLICY.md",
    "scripts/check_release_contract.py",
    "scripts/release_readiness.py",
    "docs/DOGFOODING.md",
    "docs/prompts/01_AUDITORIA_Y_SEGUIMIENTO.prompt.md",
    "docs/prompts/02_PARIDAD_GUI_CLI.prompt.md",
    "docs/prompts/03_MEJORA_GUI_GITHUB_EMAIL.prompt.md",
    "docs/prompts/04_EJECUCION_AGENTICA_CLI.prompt.md",
    "docs/prompts/05_DOGFOODING_AUDIT_ONLY.prompt.md",
]

RELEASE_DOCS_REQUIRED = [
    "docs/LOCAL_DEVELOPMENT.md",
    "docs/OPERATIONS.md",
    "docs/TROUBLESHOOTING.md",
    "docs/VERSIONING.md",
    "docs/RELEASE_NOTES_TEMPLATE.md",
]

UX_SCREENSHOT_PRIVATE_TOKENS = [
    b"C:\\Users",
    b"Documents\\Repositorios",
    b"RepoPrivacyGuardian\\docs\\POLICY.md",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tracked_paths() -> list[Path]:
    out = subprocess.check_output(
        ["git", "ls-files"],
        cwd=_repo_root(),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=30,
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


def test_ux_audit_screenshots_are_sanitized_for_public_docs() -> None:
    root = _repo_root()
    audit_doc = (root / "docs" / "UX_UI_AUDIT.md").read_text(encoding="utf-8")
    assert "Neutralized visible screenshot paths to non-user placeholder paths" in audit_doc
    assert "C:\\Users" not in audit_doc
    assert "Documents\\Repositorios" not in audit_doc

    screenshots = sorted((root / "docs" / "ux-audit").glob("*/*.png"))
    assert screenshots, "Expected maintained GUI UX screenshots under docs/ux-audit"
    for screenshot in screenshots:
        payload = screenshot.read_bytes()
        offenders = [token.decode("ascii") for token in UX_SCREENSHOT_PRIVATE_TOKENS if token in payload]
        assert not offenders, f"{screenshot.relative_to(root)} contains private path token(s): {offenders}"


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

    assert "`1.3.x`" in versioning
    assert "`1.0.0`" in versioning
    assert "`1.2.0`" in versioning
    assert "`1.2.1`" in versioning
    assert "`1.2.2`" in versioning
    assert "`1.2.3`" in versioning
    assert "`1.3.0`" in versioning
    assert "`1.3.1`" in versioning
    assert "`1.3.2`" in versioning
    assert "semantic versioning" in versioning.lower()
    assert "Validation evidence" in release_notes


def test_operational_docs_cover_release_harness_env_and_recovery() -> None:
    root = _repo_root()
    local_development = (root / "docs" / "LOCAL_DEVELOPMENT.md").read_text(encoding="utf-8")
    known_issues = (root / "docs" / "KNOWN_ISSUES.md").read_text(encoding="utf-8")
    operations = (root / "docs" / "OPERATIONS.md").read_text(encoding="utf-8")
    troubleshooting = (root / "docs" / "TROUBLESHOOTING.md").read_text(encoding="utf-8")

    assert ".env.example" in local_development
    assert "python scripts/check_release_contract.py" in local_development
    assert "python -m pytest -q" in local_development
    assert "python -m ruff check ." in local_development
    assert "pyright -p pyrightconfig.json" in local_development
    assert "python -m pip_audit -r config/requirements/requirements-dev.txt" in local_development
    assert "The repo-owned typecheck command is `pyright -p pyrightconfig.json`." in local_development
    assert "python scripts/release_readiness.py" in operations
    assert "python scripts/check_release_contract.py" in operations
    assert "runs `pip-audit` against dev, GUI, and remediation requirement files" in operations
    assert "Repo Privacy Guardian does not auto-load a `.env` file." in operations
    assert "The tracked `.env.example` file is only a reference template" in operations
    assert "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN" in operations
    assert "git clone path/to/<repo>-pre-publication-fix-<timestamp>.bundle recovered-repo" in operations
    assert "GUI does not include pause/resume controls." in known_issues
    assert "GUI supports cooperative cancellation" in known_issues
    assert "non-blocking fixture or safe-documentation buckets" in known_issues
    assert "Release harness skips the self-audit" in troubleshooting
    assert "Build artifacts look stale" in troubleshooting
    assert "GUI stop feels delayed" in troubleshooting
    assert "Stop After Current Step" in troubleshooting
    assert "Recovering after a bad rewrite" in troubleshooting


def test_ux_audit_doc_avoids_absolute_local_asset_paths() -> None:
    ux_audit = (_repo_root() / "docs" / "UX_UI_AUDIT.md").read_text(encoding="utf-8")

    assert "/C:/Users/" not in ux_audit
    assert "ux-audit/before/" in ux_audit
    assert "ux-audit/after/" in ux_audit


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
    assert "Token-gated coverage" in readme
    assert "secret scanning configuration" in readme
    assert "immutable releases" in readme
    assert ".env.example" in readme
    assert "--audit-github-hardening" in agents
    assert "--check-tooling" in agents
    assert "winget" in agents
    assert "branch protection" in policy.lower()
    assert "Checks that can run without authentication" in policy
    assert "Token-gated checks" in policy
    assert "secret scanning push protection" in policy
    assert "Alert findings stay redacted" in policy


def test_docs_cover_secret_taxonomy_confidence_buckets() -> None:
    root = _repo_root()
    readme = (root / "README.MD").read_text(encoding="utf-8")
    agents = (root / "AGENTS.MD").read_text(encoding="utf-8")
    dogfooding = (root / "docs" / "DOGFOODING.md").read_text(encoding="utf-8")
    policy = (root / "docs" / "POLICY.md").read_text(encoding="utf-8")

    for text in (readme, agents, dogfooding, policy):
        assert "tracked_secret_low_confidence" in text
        assert "git_metadata_secret" in text

    assert "Fixture and safe-documentation matches are separated" in policy
    assert "Safe documentation" in dogfooding
    assert "high-confidence blocking buckets" in agents


def test_changelog_records_stable_release() -> None:
    changelog = (_repo_root() / "CHANGELOG.md").read_text(encoding="utf-8")

    assert "## [1.3.0] - 2026-04-25" in changelog
    assert "GitHub owner audit mode and GUI/CLI parity update." in changelog
    assert "## [1.3.1] - 2026-04-25" in changelog
    assert "Release-readiness reliability hardening update." in changelog
    assert "## [1.3.2] - 2026-04-26" in changelog
    assert "Secret taxonomy and evidence-classification hardening update." in changelog
    assert "## [1.2.3] - 2026-04-24" in changelog
    assert "Public-release stabilization and GUI UX update." in changelog
    assert "## [1.2.2] - 2026-04-15" in changelog
    assert "Operations/readiness runbook update." in changelog
    assert "## [1.2.1] - 2026-04-14" in changelog
    assert "Release-hardening dependency update." in changelog
    assert "## [1.2.0] - 2026-04-14" in changelog
    assert "Tooling readiness and bootstrap update." in changelog
    assert "## [1.1.0] - 2026-04-14" in changelog
    assert "Release-hardening and operator-playbook update." in changelog
    assert "## [1.0.0] - 2026-04-14" in changelog
    assert "Initial stable public release." in changelog


def test_pyproject_version_matches_current_release_line() -> None:
    pyproject = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")
    readme = (_repo_root() / "README.MD").read_text(encoding="utf-8")

    assert 'version = "1.3.2"' in pyproject
    assert "Current release line: `v1.3.x`." in readme
    assert "`v1.3.2` is the current patch release with secret taxonomy and evidence-classification hardening." in readme
    assert "`v1.2.1` is the current patch-level" not in readme
    assert "`v1.2.2` is the current patch-level" not in readme
    assert "`v1.2.3` is the current patch-level" not in readme


def test_dev_pytest_floor_is_patched_against_known_alert() -> None:
    pyproject = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")
    dev_requirements = (_repo_root() / "config" / "requirements" / "requirements-dev.txt").read_text(encoding="utf-8")

    assert "pytest>=9.0.3,<10" in pyproject
    assert "pytest>=9.0.3,<10" in dev_requirements
    assert "pytest>=8.0,<9" not in pyproject
    assert "pytest>=8.0,<9" not in dev_requirements


def test_dev_requirements_include_dependency_audit_tool() -> None:
    pyproject = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")
    dev_requirements = (_repo_root() / "config" / "requirements" / "requirements-dev.txt").read_text(encoding="utf-8")

    assert "pip-audit>=2.10,<3" in pyproject
    assert "pip-audit>=2.10,<3" in dev_requirements


def test_coverage_targets_package_code_not_local_ops_scripts() -> None:
    pyproject = (_repo_root() / "pyproject.toml").read_text(encoding="utf-8")

    assert 'omit = ["tests/*", "scripts/*"]' in pyproject


def test_release_checklist_mentions_clearing_stale_build_outputs() -> None:
    checklist = (_repo_root() / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")

    assert "Clear stale local build outputs" in checklist
    assert "`dist/`, `build/`, and `*.egg-info/`" in checklist
    assert "python scripts/release_readiness.py" in checklist
    assert "Automatic CI smoke is green." in checklist


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
    assert "!.env.example" in gitignore
    assert "*-pre-publication-fix-*.bundle" in gitignore


def test_ci_workflow_uses_sha_pinned_actions_and_least_privilege() -> None:
    workflow = (_repo_root() / CI_WORKFLOW).read_text(encoding="utf-8")
    pinned_actions = re.findall(r"uses:\s+actions/(?:checkout|setup-python)@[0-9a-f]{40}", workflow)

    assert re.search(r"permissions:\s+contents:\s+read", workflow)
    assert workflow.count("timeout-minutes:") == 5
    assert workflow.count("persist-credentials: false") == 5
    assert len(pinned_actions) == 10
    assert not re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d", workflow)


def test_ci_workflow_matches_cost_first_validation_contract() -> None:
    workflow = (_repo_root() / CI_WORKFLOW).read_text(encoding="utf-8")

    assert "Cost-first policy" in workflow
    assert "manual extended validation suite" in workflow
    assert 'python-version: "3.13"' in workflow
    assert 'python-version: "3.11"' in workflow
    assert "python scripts/check_release_contract.py" in workflow
    for path in (
        '"CHANGELOG.md"',
        '"README.MD"',
        '"docs/KNOWN_ISSUES.md"',
        '"docs/POLICY.md"',
        '"docs/RELEASE_CHECKLIST.md"',
        '"docs/TROUBLESHOOTING.md"',
        '"docs/VERSIONING.md"',
        '"config/requirements/**"',
        '"scripts/check_release_contract.py"',
        '"scripts/release_readiness.py"',
        '"tests/**"',
    ):
        assert path in workflow
    assert "dist/*.whl" in workflow
    assert "dist/*.tar.gz" in workflow
    assert workflow.count("python tests/release_smoke_cli.py") >= 3


def test_release_docs_describe_cost_first_validation_tiers() -> None:
    readme = (_repo_root() / "README.MD").read_text(encoding="utf-8")
    known_issues = (_repo_root() / "docs" / "KNOWN_ISSUES.md").read_text(encoding="utf-8")
    checklist = (_repo_root() / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    troubleshooting = (_repo_root() / "docs" / "TROUBLESHOOTING.md").read_text(encoding="utf-8")
    versioning = (_repo_root() / "docs" / "VERSIONING.md").read_text(encoding="utf-8")

    assert "automatic CI smoke" in readme
    assert "manual extended CI" in readme
    assert "python scripts/check_release_contract.py" in readme
    assert "GUI supports cooperative cancellation" in known_issues
    assert "manual extended CI suite has been run" in checklist
    assert "validation tiers documented in README" in checklist
    assert "branch protection required status checks match the current automatic CI smoke job names" in checklist
    assert "Stopping after current step..." in troubleshooting
    assert "validation tiers" in versioning
    assert "automatic CI smoke" in versioning


def test_identity_contract_docs_cover_malformed_commit_tokens() -> None:
    readme = (_repo_root() / "README.MD").read_text(encoding="utf-8")
    known_issues = (_repo_root() / "docs" / "KNOWN_ISSUES.md").read_text(encoding="utf-8")
    policy = (_repo_root() / "docs" / "POLICY.md").read_text(encoding="utf-8")
    release_contract = (_repo_root() / "scripts" / "check_release_contract.py").read_text(
        encoding="utf-8"
    )

    assert "malformed non-email identity tokens" in readme
    assert "rewrite commit metadata email values, including malformed non-email tokens" in readme
    assert (
        "Malformed/non-email author/committer email-field values are treated as suspicious commit identity tokens."
        in known_issues
    )
    assert "malformed non-email identity tokens" in policy
    assert '%h %an <%ae> | %cn <%ce>' in policy
    assert "POLICY_REQUIREMENTS" in release_contract
