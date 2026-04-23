#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

README_REQUIREMENTS = [
    "automatic CI smoke",
    "manual extended CI",
    "`v1.2.2` is the current patch-level operations/readiness update",
]

CHECKLIST_REQUIREMENTS = [
    "Automatic CI smoke is green.",
    "manual extended CI suite has been run",
    "validation tiers documented in README",
]

KNOWN_ISSUES_REQUIREMENTS = [
    "GUI does not include pause/resume controls.",
    "GUI supports cooperative cancellation",
]

TROUBLESHOOTING_REQUIREMENTS = [
    "## GUI stop feels delayed",
    "Stop After Current Step",
    "Stopping after current step...",
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
    '- "README.MD"',
    '- "docs/KNOWN_ISSUES.md"',
    '- "docs/RELEASE_CHECKLIST.md"',
    '- "docs/TROUBLESHOOTING.md"',
    '- "docs/VERSIONING.md"',
    '- "scripts/check_release_contract.py"',
    '- "tests/test_release_hygiene.py"',
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
    troubleshooting = _read("docs/TROUBLESHOOTING.md")
    versioning = _read("docs/VERSIONING.md")
    workflow = _read(".github/workflows/ci.yml")
    pyproject = _read("pyproject.toml")

    errors.extend(_require_contains(readme, README_REQUIREMENTS, "README.MD"))
    errors.extend(_require_contains(checklist, CHECKLIST_REQUIREMENTS, "docs/RELEASE_CHECKLIST.md"))
    errors.extend(_require_contains(known_issues, KNOWN_ISSUES_REQUIREMENTS, "docs/KNOWN_ISSUES.md"))
    errors.extend(_require_contains(troubleshooting, TROUBLESHOOTING_REQUIREMENTS, "docs/TROUBLESHOOTING.md"))
    errors.extend(_require_contains(versioning, VERSIONING_REQUIREMENTS, "docs/VERSIONING.md"))
    errors.extend(_require_contains(workflow, WORKFLOW_REQUIREMENTS, ".github/workflows/ci.yml"))

    if 'version = "1.2.2"' not in pyproject:
        errors.append('pyproject.toml: expected `version = "1.2.2"`')
    if "`v1.2.1` is the current patch-level" in readme:
        errors.append("README.MD: stale current patch-level reference to v1.2.1")
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
