#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = "1.3.8"
CURRENT_VERSION_DESCRIPTION = "agentic IDE onboarding prompts and documentation"

README_REQUIREMENTS = [
    "automatic CI smoke",
    "manual extended CI",
    f"`v{CURRENT_VERSION}` is the current patch release with {CURRENT_VERSION_DESCRIPTION}",
    "## ⚡ 60-Second First Run",
    "How to read the first result:",
    "malformed non-email identity tokens",
    "--github-owner",
    "DOGFOODING",
    "Codex, Claude Code, Antigravity, GitHub Copilot, Cursor",
    "06_PREPARACION_ENTORNO_AGENTICA.prompt.md",
    "07_AUDITORIA_REPARACION_AGENTICA.prompt.md",
    "confirmed leaks, intentional fixtures/examples",
    "Token-gated coverage",
    "secret scanning configuration",
    "immutable releases",
    "tracked_secret_low_confidence",
    "git_metadata_secret_low_confidence",
]

CHECKLIST_REQUIREMENTS = [
    "Automatic CI smoke is green.",
    "manual extended CI suite has been run",
    "python -m pip_audit -r config/requirements/requirements-dev.txt",
    "validation tiers documented in README",
    "branch protection required status checks match the current automatic CI smoke job names",
    "Classify each finding as confirmed leak",
]

KNOWN_ISSUES_REQUIREMENTS = [
    "GUI does not include pause/resume controls.",
    "GUI supports cooperative cancellation",
    "Malformed/non-email author/committer email-field values are treated as suspicious commit identity tokens.",
]

POLICY_REQUIREMENTS = [
    "Public commits must use a GitHub noreply email.",
    "malformed non-email identity tokens",
    'git log --all --pretty=format:"%h %an <%ae> | %cn <%ce>"',
    "--github-owner",
    "Checks that can run without authentication",
    "Token-gated checks",
    "secret scanning push protection",
    "Alert findings stay redacted",
    "tracked_secret_low_confidence",
    "git_metadata_secret_matches",
]

TROUBLESHOOTING_REQUIREMENTS = [
    "## GUI stop feels delayed",
    "Stop After Current Step",
    "Stopping after current step...",
    "token-gated GitHub settings are not fully inspected",
    "security-alert access",
]

VERSIONING_REQUIREMENTS = [
    "validation tiers",
    "automatic CI smoke",
    "manual extended CI",
]

WORKFLOW_REQUIREMENTS = [
    'description: Run the manual extended validation suite',
    'run: python scripts/check_release_contract.py',
    'run: python tests/release_smoke_cli.py',
    'run: python tests/release_smoke_gui.py',
    '- "AGENTS.MD"',
    '- "CHANGELOG.md"',
    '- "README.MD"',
    '- "docs/DOGFOODING.md"',
    '- "docs/KNOWN_ISSUES.md"',
    '- "docs/POLICY.md"',
    '- "docs/RELEASE_CHECKLIST.md"',
    '- "docs/TROUBLESHOOTING.md"',
    '- "docs/VERSIONING.md"',
    '- "docs/prompts/**"',
    '- "config/requirements/**"',
    '- "scripts/check_release_contract.py"',
    '- "scripts/release_readiness.py"',
    '- "tests/**"',
]

DOGFOODING_REQUIREMENTS = [
    "The default posture is audit-only.",
    "repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes",
    "confirmed leak",
    "Intentional fixture/example",
    "Indeterminate/manual review",
    "Safe documentation",
    "Audit_Results/<run_id>/report.json",
    "do not paste raw secret values",
    "No destructive changes were applied.",
    "--audit-github-hardening",
    "Codex, Claude Code, Antigravity, GitHub Copilot, Cursor",
    "06_PREPARACION_ENTORNO_AGENTICA.prompt.md",
    "07_AUDITORIA_REPARACION_AGENTICA.prompt.md",
]

DOGFOODING_PROMPT_REQUIREMENTS = [
    "No destructive changes applied.",
    "confirmed leak",
    "fixture/documentacion intencional",
    "advisory hardening",
    "tooling/runtime issue",
    "No pegar secretos crudos",
    "--audit-github-hardening",
]


def _read(rel_path: str) -> str:
    return (REPO_ROOT / rel_path).read_text(encoding="utf-8")


def _require_contains(text: str, required: list[str], label: str) -> list[str]:
    return [f"{label}: missing `{item}`" for item in required if item not in text]


def validate_release_contract() -> list[str]:
    errors: list[str] = []
    readme = _read("README.MD")
    checklist = _read("docs/RELEASE_CHECKLIST.md")
    known_issues = _read("docs/KNOWN_ISSUES.md")
    policy = _read("docs/POLICY.md")
    troubleshooting = _read("docs/TROUBLESHOOTING.md")
    versioning = _read("docs/VERSIONING.md")
    dogfooding = _read("docs/DOGFOODING.md")
    dogfooding_prompt = _read("docs/prompts/05_DOGFOODING_AUDIT_ONLY.prompt.md")
    workflow = _read(".github/workflows/ci.yml")
    pyproject = _read("pyproject.toml")
    changelog = _read("CHANGELOG.md")

    errors.extend(_require_contains(readme, README_REQUIREMENTS, "README.MD"))
    errors.extend(_require_contains(checklist, CHECKLIST_REQUIREMENTS, "docs/RELEASE_CHECKLIST.md"))
    errors.extend(_require_contains(known_issues, KNOWN_ISSUES_REQUIREMENTS, "docs/KNOWN_ISSUES.md"))
    errors.extend(_require_contains(policy, POLICY_REQUIREMENTS, "docs/POLICY.md"))
    errors.extend(_require_contains(troubleshooting, TROUBLESHOOTING_REQUIREMENTS, "docs/TROUBLESHOOTING.md"))
    errors.extend(_require_contains(versioning, VERSIONING_REQUIREMENTS, "docs/VERSIONING.md"))
    errors.extend(_require_contains(dogfooding, DOGFOODING_REQUIREMENTS, "docs/DOGFOODING.md"))
    errors.extend(
        _require_contains(
            dogfooding_prompt,
            DOGFOODING_PROMPT_REQUIREMENTS,
            "docs/prompts/05_DOGFOODING_AUDIT_ONLY.prompt.md",
        )
    )
    errors.extend(_require_contains(workflow, WORKFLOW_REQUIREMENTS, ".github/workflows/ci.yml"))

    if f'version = "{CURRENT_VERSION}"' not in pyproject:
        errors.append(f'pyproject.toml: expected `version = "{CURRENT_VERSION}"`')
    if f"## [{CURRENT_VERSION}]" not in changelog:
        errors.append(f"CHANGELOG.md: missing current version section `{CURRENT_VERSION}`")
    if (
        "`v1.2.1` is the current patch-level" in readme
        or "`v1.2.2` is the current patch-level" in readme
        or "`v1.2.3` is the current patch-level" in readme
        or "`v1.3.0` is the current minor release" in readme
    ):
        errors.append("README.MD: stale current release reference")
    if "GUI does not include pause/resume or cancellation controls." in known_issues:
        errors.append("docs/KNOWN_ISSUES.md: stale claim that GUI has no cancellation support")

    return errors


def main() -> int:
    errors = validate_release_contract()
    if errors:
        raise SystemExit("Release contract drift detected:\n- " + "\n- ".join(errors))
    print("[RELEASE-CONTRACT] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
