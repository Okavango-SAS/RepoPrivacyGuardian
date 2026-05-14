"""Policy classification and remediation decision helpers."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from repo_privacy_guardian.core import RepoReport


LITELLM_COMPROMISED_1828_RE = re.compile(r"(?i)\b1\.82\.8\b")
LITELLM_COMPROMISED_1827_RE = re.compile(r"(?i)\b1\.82\.7\b")


def repo_has_dirty_worktree(clean_status: str | None) -> bool:
    return len((clean_status or "").splitlines()) > 1


def validate_fix_preconditions(report: RepoReport) -> list[str]:
    issues: list[str] = []
    if repo_has_dirty_worktree(report.clean_status):
        issues.append(
            "automatic fix blocked: working tree is not clean; commit, stash, or discard local edits before remediation"
        )
    if not report.fsck_ok:
        issues.append("automatic fix blocked: git fsck failed; resolve repository integrity issues first")
    if report.execution_errors:
        issues.append(
            "automatic fix blocked: audit completed with execution errors; re-run after resolving lock, timeout, or git/runtime failures"
        )
    return issues


def email_decision_context(report: RepoReport) -> tuple[int, int, int, int, int, int]:
    owned_unexpected = len(
        report.unexpected_emails_owned_repo
        if report.email_ownership_evaluated
        else report.unexpected_emails
    )
    third_party_unexpected = len(report.unexpected_emails_third_party_repo)
    owned_unexpected_identity_tokens = len(
        report.unexpected_identity_tokens_owned_repo
        if report.email_ownership_evaluated
        else report.unexpected_identity_tokens
    )
    third_party_unexpected_identity_tokens = len(report.unexpected_identity_tokens_third_party_repo)
    high_conf = len(
        report.tracked_email_high_confidence + report.history_email_high_confidence
        if report.email_confidence_evaluated
        else report.tracked_email_matches + report.history_email_matches
    )
    low_conf = len(report.tracked_email_low_confidence + report.history_email_low_confidence)
    return (
        owned_unexpected,
        third_party_unexpected,
        owned_unexpected_identity_tokens,
        third_party_unexpected_identity_tokens,
        high_conf,
        low_conf,
    )


def email_remediation_decision(report: RepoReport) -> tuple[str, str]:
    (
        owned_unexpected,
        third_party_unexpected,
        owned_unexpected_identity_tokens,
        third_party_unexpected_identity_tokens,
        high_conf,
        low_conf,
    ) = email_decision_context(report)
    low_blocking = report.low_confidence_email_mode == "blocking"

    if (
        owned_unexpected
        or owned_unexpected_identity_tokens
        or high_conf
        or (low_blocking and low_conf)
    ):
        if low_blocking and low_conf and not (
            owned_unexpected or owned_unexpected_identity_tokens or high_conf
        ):
            return (
                "RECOMMENDED",
                "Blocking mode active: low-confidence email findings require explicit review/remediation.",
            )
        return (
            "RECOMMENDED",
            "Authorize commit identity remediation for owned-repo or malformed metadata findings first.",
        )

    if low_conf or third_party_unexpected or third_party_unexpected_identity_tokens:
        return (
            "REVIEW",
            "Informational commit-identity findings only; review samples before authorizing broad remediation.",
        )

    return ("SKIP", "No commit identity remediation action needed for this repository.")


def classify_litellm_incident_severity(report: RepoReport) -> str:
    if report.litellm_incident_severity and report.litellm_incident_severity != "NONE":
        return report.litellm_incident_severity

    compromised_lines = report.litellm_compromised_reference_hits
    if report.litellm_ioc_hits or any(LITELLM_COMPROMISED_1828_RE.search(line) for line in compromised_lines):
        return "CRITICAL"
    if any(LITELLM_COMPROMISED_1827_RE.search(line) for line in compromised_lines):
        return "HIGH"
    if report.litellm_reference_hits or report.litellm_install_command_hits:
        return "MEDIUM"
    return "NONE"


def repo_user_guidance(report: RepoReport) -> tuple[str, str, str, str]:
    email_status, email_message = email_remediation_decision(report)
    (
        owned_unexpected,
        _third_party_unexpected,
        owned_unexpected_identity_tokens,
        _third_party_unexpected_identity_tokens,
        high_conf,
        low_conf,
    ) = email_decision_context(report)
    low_blocking = report.low_confidence_email_mode == "blocking"
    litellm_severity = classify_litellm_incident_severity(report)
    worktree_dirty = repo_has_dirty_worktree(report.clean_status)

    if report.execution_errors:
        return (
            "IMMEDIATE",
            "Repository execution failed before the audit/fix flow completed.",
            "Possible consequence: results may be incomplete, stale, or skipped for this repository.",
            "Suggestion: review execution_errors for lock, timeout, or git/runtime failures, then re-run once the repository is stable.",
        )

    if report.fix_errors:
        return (
            "IMMEDIATE",
            "Requested remediation did not complete successfully.",
            "Possible consequence: repository state may be only partially remediated, or push/rewrite steps may have failed.",
            "Suggestion: review fix_errors, verify repository state manually, and re-run audit/fix after resolving the underlying issue.",
        )

    if litellm_severity in {"CRITICAL", "HIGH"}:
        return (
            "IMMEDIATE",
            "Critical supply-chain risk: LiteLLM compromise indicators were detected.",
            "Possible consequence: malicious package initialization or compromised dependencies in runtime/CI workflows.",
            "Suggestion: isolate affected environments, remove compromised versions, rotate secrets, and verify package provenance before redeploy.",
        )

    if litellm_severity == "MEDIUM":
        return (
            "PRIORITY",
            "Medium supply-chain risk: LiteLLM references were detected without direct compromise evidence.",
            "Possible consequence: potential exposure if vulnerable versions were installed temporarily in local or CI environments.",
            "Suggestion: verify resolved versions in lockfiles/environments and run targeted incident checks for IoCs.",
        )

    if worktree_dirty:
        return (
            "PRIORITY",
            "Medium risk: working tree is not clean.",
            "Possible consequence: publication decisions may be made against uncommitted or unpublished content.",
            "Suggestion: commit, stash, or discard local changes before relying on audit/fix results.",
        )

    has_secret_risk = bool(
        report.tracked_secret_matches
        or report.history_secret_matches
        or report.git_metadata_secret_matches
        or report.secret_file_candidates
        or report.history_sensitive_added
        or report.history_sensitive_deleted
    )
    has_path_risk = bool(report.tracked_path_matches or report.history_path_matches)
    has_identity_risk = bool(
        owned_unexpected
        or owned_unexpected_identity_tokens
        or high_conf
        or (low_blocking and low_conf)
    )

    if has_secret_risk:
        return (
            "IMMEDIATE",
            "High risk: secret indicators were detected.",
            "Possible consequence: credential leakage and unauthorized access if history is published.",
            "Suggestion: run fix in dry-run, review preview, then authorize secret purge/history rewrite.",
        )

    if has_identity_risk:
        return (
            "PRIORITY",
            "Medium-high risk: non-owner or malformed commit identity values are likely exposed in owned repository history/content.",
            "Possible consequence: personal identity exposure and compliance/privacy issues.",
            f"Suggestion: {email_message}",
        )

    if has_path_risk:
        return (
            "PRIORITY",
            "Medium risk: local/personal paths were detected.",
            "Possible consequence: host/user structure disclosure and unnecessary attack-surface context.",
            "Suggestion: review samples and authorize path-focused cleanup if repository will be public.",
        )

    if (
        report.tracked_secret_low_confidence
        or report.history_secret_low_confidence
        or report.git_metadata_secret_low_confidence
    ):
        return (
            "REVIEW",
            "Advisory review: generic secret-like assignments were detected.",
            "Possible consequence: a real credential may be hidden among noisy examples if not classified.",
            "Suggestion: classify each low-confidence secret finding as confirmed leak, fixture, safe documentation, or false positive before remediation.",
        )

    if report.exfil_code_indicators:
        return (
            "REVIEW",
            "Advisory review: outbound/exfil indicators were detected.",
            "Possible consequence: unexpected outbound behavior could disclose repository data or operator context if published unchecked.",
            "Suggestion: review each cited network-capable code path manually. This signal does not change PASS/FAIL by default.",
        )

    if report.github_hardening_findings_blocking and report.github_hardening_findings:
        return (
            "PRIORITY",
            "Release profile: GitHub repository hardening findings are blocking.",
            "Possible consequence: branch protection, secret scanning, or publication controls may be missing for release.",
            "Suggestion: apply the GitHub hardening fix guide manually and re-run with --audit-github-hardening.",
        )

    if report.github_hardening_findings:
        return (
            "REVIEW",
            "Advisory review: GitHub repository settings need hardening before public release.",
            "Possible consequence: direct pushes, weak workflow permissions, or missing review/security controls may remain active after publication.",
            "Suggestion: review github_hardening_findings, apply the remote settings manually, and re-run with --audit-github-hardening.",
        )

    if report.github_hardening_warnings:
        return (
            "REVIEW",
            "Advisory review: GitHub hardening audit was partial or could not authenticate.",
            "Possible consequence: repository settings may still have unaudited gaps even if local content checks passed.",
            "Suggestion: set REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN, or authenticate GitHub CLI with `gh auth login`, then re-run --audit-github-hardening.",
        )

    if email_status == "REVIEW":
        return (
            "REVIEW",
            "Low risk: commit identity findings look informational/noisy.",
            "Possible consequence: alert fatigue if remediated blindly.",
            f"Suggestion: {email_message}",
        )

    return (
        "SKIP",
        "No relevant privacy risk requiring remediation was detected.",
        "Possible consequence: none expected for this category.",
        "Suggestion: no remediation action required.",
    )


def classify_repo_severity(report: RepoReport) -> tuple[str, int, list[str]]:
    score = 0
    highlights: list[str] = []
    (
        owned_unexpected_count,
        third_party_unexpected_count,
        owned_unexpected_identity_token_count,
        third_party_unexpected_identity_token_count,
        high_conf_email_count,
        low_conf_email_count,
    ) = email_decision_context(report)
    low_confidence_blocking = report.low_confidence_email_mode == "blocking"
    litellm_severity = classify_litellm_incident_severity(report)
    worktree_dirty = repo_has_dirty_worktree(report.clean_status)

    if report.execution_errors:
        score = max(score, 85)
        highlights.append("Repository execution failed or was blocked")
    if report.fix_errors:
        score = max(score, 80)
        highlights.append("Remediation execution failed")
    if worktree_dirty:
        score = max(score, 55)
        highlights.append("Working tree contains uncommitted changes")
    if litellm_severity == "CRITICAL":
        score = max(score, 100)
        highlights.append("LiteLLM incident critical indicators detected (IoC or 1.82.8 evidence)")
    elif litellm_severity == "HIGH":
        score = max(score, 85)
        highlights.append("LiteLLM incident high-risk evidence detected (1.82.7)")
    elif litellm_severity == "MEDIUM":
        score = max(score, 50)
        highlights.append("LiteLLM references found; verify installed versions and provenance")

    if report.tracked_secret_matches or report.history_secret_matches or report.git_metadata_secret_matches:
        score = max(score, 100)
        highlights.append("Secret-like patterns found in tracked content, history, or Git metadata")
    if report.tracked_secret_low_confidence or report.history_secret_low_confidence:
        highlights.append("Low-confidence secret assignments require manual review (informational)")
    if report.git_metadata_secret_low_confidence:
        highlights.append("Low-confidence Git metadata secret indicators require manual review")
    if report.secret_file_candidates:
        score = max(score, 95)
        highlights.append("Secret file candidates detected")
    if report.history_sensitive_added or report.history_sensitive_deleted:
        score = max(score, 90)
        highlights.append("Sensitive filenames found in git history")
    if owned_unexpected_count:
        score = max(score, 75)
        highlights.append("Unexpected commit metadata emails in owned repository")
    if owned_unexpected_identity_token_count:
        score = max(score, 75)
        highlights.append("Malformed commit metadata identity tokens found in owned repository")
    if high_conf_email_count:
        score = max(score, 62)
        highlights.append("High-confidence non-owner email addresses found")
    if low_confidence_blocking and low_conf_email_count:
        score = max(score, 60)
        highlights.append("Low-confidence email findings are configured as blocking")
    if (not low_confidence_blocking) and low_conf_email_count:
        highlights.append("Low-confidence email findings are informational")
    if third_party_unexpected_count:
        highlights.append("Unexpected commit metadata emails in third-party repositories (informational)")
    if third_party_unexpected_identity_token_count:
        highlights.append("Malformed commit metadata identity tokens in third-party repositories (informational)")
    if report.tracked_path_matches or report.history_path_matches:
        score = max(score, 70)
        highlights.append("Personal/local path leakage detected")
    if report.tracked_but_ignored:
        score = max(score, 60)
        highlights.append("Ignored files are still tracked")
    if report.gitignore_missing_patterns:
        score = max(score, 40)
        highlights.append("Required .gitignore baseline is incomplete")
    if report.exfil_code_indicators:
        score = max(score, 20)
        highlights.append("Outbound/exfil heuristics require manual review (advisory)")
    if report.github_hardening_findings_blocking and report.github_hardening_findings:
        score = max(score, 65)
        highlights.append("GitHub release hardening findings are blocking under the selected strict profile")
    if report.github_hardening_findings:
        score = max(score, 25)
        highlights.append("GitHub release hardening settings need manual follow-up (advisory)")
    if report.github_hardening_warnings:
        score = max(score, 10)
        highlights.append("GitHub release hardening audit was partial/incomplete")

    if score >= 90:
        return "HIGH", score, highlights
    if score >= 60:
        return "MEDIUM", score, highlights
    if report.status == "FAIL":
        if not highlights:
            highlights.append("Non-critical policy failures found")
        return "LOW", score, highlights
    return "OK", score, highlights
