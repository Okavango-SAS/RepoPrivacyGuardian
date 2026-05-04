from __future__ import annotations

from typing import Iterable


def build_github_hardening_fix_guide(
    findings: Iterable[str],
    warnings: Iterable[str],
) -> list[str]:
    text = "\n".join([*findings, *warnings]).lower()
    if not text.strip():
        return []

    guide: list[str] = []
    if "private vulnerability reporting" in text:
        guide.append(
            "Enable private vulnerability reporting in GitHub repository Settings > Security."
        )
    if "secret scanning push protection" in text or "push protection" in text:
        guide.append(
            "Enable secret scanning push protection in GitHub Advanced Security settings."
        )
    if "secret scanning" in text:
        guide.append("Enable secret scanning for the repository or organization.")
    if "branch protection" in text or "ruleset" in text or "default branch protection" in text:
        guide.append(
            "Create a branch protection rule or ruleset for main with pull requests, required status checks, and admin enforcement as appropriate."
        )
    if "workflow permission" in text or "actions permissions" in text:
        guide.append(
            "Set GitHub Actions workflow permissions to least privilege and restrict allowed actions where practical."
        )
    if "could not" in text or "skipped" in text or "partial" in text or "http_" in text:
        guide.append(
            "Re-run with REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, or an authenticated gh session to verify token-gated settings."
        )

    if not guide:
        guide.append(
            "Review repository Settings > Security and Settings > Branches/Rulesets, then re-run --audit-github-hardening."
        )
    return list(dict.fromkeys(guide))
