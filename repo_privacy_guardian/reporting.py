"""Report classification, redacted export, HTML, and artifact persistence."""

from __future__ import annotations

# ruff: noqa: F403,F405
from repo_privacy_guardian.core import *
from repo_privacy_guardian import core as _core

_redact_email_list = _core._redact_email_list
_redact_identity_list = _core._redact_identity_list
_redact_text_list = _core._redact_text_list


def sanitize_report_for_export(report: RepoReport) -> dict[str, object]:
    payload = dict(report.__dict__)
    payload["path"] = redact_sensitive_text(report.path)
    payload["origin_url"] = redact_sensitive_text(report.origin_url) if report.origin_url else None
    payload["upstream_url"] = redact_sensitive_text(report.upstream_url) if report.upstream_url else None
    payload["clean_status"] = redact_sensitive_text(report.clean_status or "")
    payload["author_emails"] = _redact_email_list(report.author_emails)
    payload["committer_emails"] = _redact_email_list(report.committer_emails)
    payload["author_identity_tokens"] = _redact_identity_list(report.author_identity_tokens)
    payload["committer_identity_tokens"] = _redact_identity_list(report.committer_identity_tokens)
    payload["unexpected_emails"] = _redact_email_list(report.unexpected_emails)
    payload["unexpected_emails_owned_repo"] = _redact_email_list(report.unexpected_emails_owned_repo)
    payload["unexpected_emails_third_party_repo"] = _redact_email_list(
        report.unexpected_emails_third_party_repo
    )
    payload["unexpected_identity_tokens"] = _redact_identity_list(report.unexpected_identity_tokens)
    payload["unexpected_identity_tokens_owned_repo"] = _redact_identity_list(
        report.unexpected_identity_tokens_owned_repo
    )
    payload["unexpected_identity_tokens_third_party_repo"] = _redact_identity_list(
        report.unexpected_identity_tokens_third_party_repo
    )
    payload["tracked_secret_matches"] = _redact_text_list(report.tracked_secret_matches)
    payload["tracked_secret_high_confidence"] = _redact_text_list(
        report.tracked_secret_high_confidence
    )
    payload["tracked_secret_low_confidence"] = _redact_text_list(report.tracked_secret_low_confidence)
    payload["tracked_secret_fixture_matches"] = _redact_text_list(
        report.tracked_secret_fixture_matches
    )
    payload["tracked_secret_documentation_matches"] = _redact_text_list(
        report.tracked_secret_documentation_matches
    )
    payload["tracked_path_matches"] = _redact_text_list(report.tracked_path_matches)
    payload["tracked_email_matches"] = _redact_text_list(report.tracked_email_matches)
    payload["tracked_email_high_confidence"] = _redact_text_list(report.tracked_email_high_confidence)
    payload["tracked_email_low_confidence"] = _redact_text_list(report.tracked_email_low_confidence)
    payload["tracked_email_fixture_matches"] = _redact_text_list(
        report.tracked_email_fixture_matches
    )
    payload["tracked_secret_files"] = _redact_text_list(report.tracked_secret_files)
    payload["history_secret_matches"] = _redact_text_list(report.history_secret_matches)
    payload["history_secret_high_confidence"] = _redact_text_list(
        report.history_secret_high_confidence
    )
    payload["history_secret_low_confidence"] = _redact_text_list(report.history_secret_low_confidence)
    payload["history_secret_fixture_matches"] = _redact_text_list(
        report.history_secret_fixture_matches
    )
    payload["history_secret_documentation_matches"] = _redact_text_list(
        report.history_secret_documentation_matches
    )
    payload["history_path_matches"] = _redact_text_list(report.history_path_matches)
    payload["history_email_matches"] = _redact_text_list(report.history_email_matches)
    payload["history_email_high_confidence"] = _redact_text_list(report.history_email_high_confidence)
    payload["history_email_low_confidence"] = _redact_text_list(report.history_email_low_confidence)
    payload["history_email_fixture_matches"] = _redact_text_list(
        report.history_email_fixture_matches
    )
    payload["history_secret_files"] = _redact_text_list(report.history_secret_files)
    payload["git_metadata_secret_matches"] = _redact_text_list(report.git_metadata_secret_matches)
    payload["git_metadata_secret_low_confidence"] = _redact_text_list(
        report.git_metadata_secret_low_confidence
    )
    payload["history_sensitive_added"] = _redact_text_list(report.history_sensitive_added)
    payload["history_sensitive_deleted"] = _redact_text_list(report.history_sensitive_deleted)
    payload["secret_file_candidates"] = _redact_text_list(report.secret_file_candidates)
    payload["secret_file_autopurge_candidates"] = _redact_text_list(report.secret_file_autopurge_candidates)
    payload["secret_file_manual_review_candidates"] = _redact_text_list(report.secret_file_manual_review_candidates)
    payload["secret_history_purge_paths"] = _redact_text_list(report.secret_history_purge_paths)
    payload["tracked_but_ignored"] = _redact_text_list(report.tracked_but_ignored)
    payload["gitignore_missing_patterns"] = _redact_text_list(report.gitignore_missing_patterns)
    payload["exfil_code_indicators"] = _redact_text_list(report.exfil_code_indicators)
    payload["github_hardening_findings"] = _redact_text_list(report.github_hardening_findings)
    payload["github_hardening_warnings"] = _redact_text_list(report.github_hardening_warnings)
    payload["github_hardening_fix_guide"] = _redact_text_list(report.github_hardening_fix_guide)
    payload["suppressed_findings"] = [
        {
            str(key): redact_sensitive_text(str(value))
            for key, value in item.items()
        }
        for item in report.suppressed_findings
    ]
    payload["backups_created"] = _redact_text_list(report.backups_created)
    payload["fix_actions"] = _redact_text_list(report.fix_actions)
    payload["fix_errors"] = _redact_text_list(report.fix_errors)
    payload["execution_errors"] = _redact_text_list(report.execution_errors)
    payload["fsck_output"] = _redact_text_list(report.fsck_output)
    return payload


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


def build_fix_preflight_summary(config: GuardRunConfig, repos: list[Path]) -> list[str]:
    if not config.fix:
        return []

    lines = [
        "[PREVIEW] Fix mode preflight summary",
        f"[PREVIEW] repositories targeted: {len(repos)}",
        f"[PREVIEW] dry_run={config.dry_run} push={config.push}",
        f"[PREVIEW] audit_litellm_incident={config.audit_litellm_incident}",
        f"[PREVIEW] audit_github_hardening={config.audit_github_hardening}",
        f"[PREVIEW] rewrite_personal_paths={config.rewrite_personal_paths}",
        f"[PREVIEW] explicit replace-text file={bool(config.replace_text_file)}",
        f"[PREVIEW] low-confidence email mode: {config.low_confidence_email_mode}",
        f"[PREVIEW] confirm_each_repo_fix={config.confirm_each_repo_fix}",
        "[PREVIEW] potential destructive actions: history rewrite, file untracking, force push",
    ]

    if config.allowed_remote_owners:
        owners = ", ".join(sorted(set(config.allowed_remote_owners)))
        lines.append(f"[PREVIEW] allowed remote owners: {owners}")
    elif not config.allow_non_owner_push and config.push:
        lines.append("[PREVIEW] push owner check active with no explicit allowlist")

    return lines


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


def build_detected_findings_preview(report: RepoReport) -> list[str]:
    findings: list[str] = []

    def add(label: str, items: list[str], limit: int = 4) -> None:
        if not items:
            return
        for item in items[:limit]:
            findings.append(f"{label}: {item}")
        if len(items) > limit:
            findings.append(f"{label}: ... and {len(items) - limit} more")

    add("tracked secret", report.tracked_secret_matches)
    add("history secret", report.history_secret_matches)
    add("git metadata secret", report.git_metadata_secret_matches)
    add("tracked secret low confidence", report.tracked_secret_low_confidence)
    add("history secret low confidence", report.history_secret_low_confidence)
    add("tracked secret fixture", report.tracked_secret_fixture_matches)
    add("history secret fixture", report.history_secret_fixture_matches)
    add("tracked secret safe documentation", report.tracked_secret_documentation_matches)
    add("history secret safe documentation", report.history_secret_documentation_matches)
    add("tracked email fixture", report.tracked_email_fixture_matches)
    add("history email fixture", report.history_email_fixture_matches)
    add("secret file candidate", report.secret_file_candidates)
    add("tracked path", report.tracked_path_matches)
    add("history path", report.history_path_matches)
    add("tracked email", report.tracked_email_high_confidence)
    add("history email", report.history_email_high_confidence)
    add("commit identity token", report.unexpected_identity_tokens)
    add("tracked but ignored", report.tracked_but_ignored)
    add("history sensitive add", report.history_sensitive_added)
    add("history sensitive delete", report.history_sensitive_deleted)
    add("exfil advisory", report.exfil_code_indicators)
    add("github advisory", report.github_hardening_findings)
    add("github audit warning", report.github_hardening_warnings)
    add("github fix guide", report.github_hardening_fix_guide)
    add(
        "suppressed finding",
        [
            f"{item.get('category', 'unknown')}: {item.get('finding', '')}"
            for item in report.suppressed_findings
        ],
    )
    add("litellm reference", report.litellm_reference_hits)
    add("litellm compromised", report.litellm_compromised_reference_hits)
    add("litellm ioc", report.litellm_ioc_hits)
    add("execution error", report.execution_errors)
    return findings


def build_planned_removals_preview(report: RepoReport) -> list[str]:
    planned: list[str] = []

    if report.secret_history_purge_paths:
        for path in report.secret_history_purge_paths[:8]:
            planned.append(f"history delete path: {path}")
        if len(report.secret_history_purge_paths) > 8:
            planned.append(
                f"history delete path: ... and {len(report.secret_history_purge_paths) - 8} more"
            )

    if report.tracked_but_ignored:
        for path in report.tracked_but_ignored[:8]:
            planned.append(f"stop tracking path: {path}")
        if len(report.tracked_but_ignored) > 8:
            planned.append(f"stop tracking path: ... and {len(report.tracked_but_ignored) - 8} more")

    if report.history_sensitive_added or report.history_sensitive_deleted:
        planned.append(
            "history delete by sensitive filename regex is eligible (.env, keys, id_rsa, pycache/pyc)"
        )

    return planned


def report_contains_sensitive_findings(report: RepoReport) -> bool:
    return bool(
        report.tracked_secret_matches
        or report.history_secret_matches
        or report.git_metadata_secret_matches
        or report.tracked_secret_low_confidence
        or report.history_secret_low_confidence
        or report.git_metadata_secret_low_confidence
        or report.tracked_secret_fixture_matches
        or report.history_secret_fixture_matches
        or report.tracked_secret_documentation_matches
        or report.history_secret_documentation_matches
        or report.secret_file_candidates
        or report.unexpected_emails
        or report.unexpected_identity_tokens
        or report.tracked_email_matches
        or report.history_email_matches
        or report.tracked_path_matches
        or report.history_path_matches
    )


def render_html_report(
    reports: list[RepoReport],
    artifacts: RunArtifacts,
    root_path: Path,
    policy_path: Path,
    run_settings: dict[str, str],
    finished_at: datetime,
    optional_supply_chain_payload: dict[str, object] | None = None,
) -> str:
    esc = html.escape
    total = len(reports)
    passed = sum(1 for item in reports if item.status == "PASS")
    failed = total - passed

    reason_counts: dict[str, int] = {}
    for rep in reports:
        for reason in rep.failures:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    ordered_reasons = sorted(reason_counts.items(), key=lambda entry: (-entry[1], entry[0]))

    repo_severity_data: list[tuple[RepoReport, str, int, list[str]]] = []
    for rep in reports:
        sev_label, sev_score, highlights = classify_repo_severity(rep)
        repo_severity_data.append((rep, sev_label, sev_score, highlights))
    repo_severity_data.sort(key=lambda item: (-item[2], item[0].name.lower()))

    high_risk_repos = [item for item in repo_severity_data if item[1] == "HIGH"]

    def render_lines(items: list[str], limit: int = 8) -> str:
        if not items:
            return '<div class="empty">No findings in this category.</div>'
        trimmed = items[:limit]
        content = "".join(f"<li><code>{esc(redact_sensitive_text(line))}</code></li>" for line in trimmed)
        suffix = ""
        if len(items) > limit:
            suffix = f'<div class="more">Showing {limit} of {len(items)} entries.</div>'
        return f"<ul class=\"finding-list\">{content}</ul>{suffix}"

    def count_report_keys(rep: RepoReport, keys: tuple[str, ...]) -> int:
        count = 0
        for key in keys:
            value = getattr(rep, key, [])
            if isinstance(value, list):
                count += len(value)
        return count

    blocking_findings = sum(
        count_report_keys(rep, agent_summary_helpers.BLOCKING_CATEGORY_KEYS)
        for rep in reports
    )
    manual_review_findings = sum(
        count_report_keys(rep, agent_summary_helpers.MANUAL_REVIEW_CATEGORY_KEYS)
        for rep in reports
    )
    fixture_documentation_findings = sum(
        count_report_keys(rep, agent_summary_helpers.FIXTURE_DOCUMENTATION_CATEGORY_KEYS)
        for rep in reports
    )
    suppressed_findings = sum(len(rep.suppressed_findings) for rep in reports)
    decision = "FAIL" if failed else ("REVIEW" if manual_review_findings else "PASS")
    decision_class = {
        "FAIL": "decision-fail",
        "REVIEW": "decision-review",
        "PASS": "decision-pass",
    }[decision]
    if decision == "FAIL":
        decision_next_action = (
            "Do not publish yet. Review blocking categories first, authorize only reviewed fixes, then re-run."
        )
    elif decision == "REVIEW":
        decision_next_action = (
            "Classify advisory/manual-review findings before publication. Blocking policy status is PASS."
        )
    else:
        decision_next_action = "No blocking or advisory action is required by the current policy."

    decision_rows = "".join(
        (
            f"<tr><td>Blocking findings</td><td class=\"num\">{blocking_findings}</td></tr>"
            f"<tr><td>Advisory/manual-review findings</td><td class=\"num\">{manual_review_findings}</td></tr>"
            f"<tr><td>Fixture/documentation findings</td><td class=\"num\">{fixture_documentation_findings}</td></tr>"
            f"<tr><td>Suppressed findings</td><td class=\"num\">{suppressed_findings}</td></tr>"
        )
    )

    reason_rows = "".join(
        f"<tr><td>{esc(reason)}</td><td class=\"num\">{count}</td></tr>"
        for reason, count in ordered_reasons
    )
    if not reason_rows:
        reason_rows = '<tr><td class="empty" colspan="2">No failure reasons recorded.</td></tr>'

    settings_rows = "".join(
        f"<tr><td>{esc(key)}</td><td><code>{esc(redact_sensitive_text(value))}</code></td></tr>"
        for key, value in sorted(run_settings.items(), key=lambda item: item[0])
    )

    high_cards = ""
    for rep, _label, _score, highlights in high_risk_repos:
        detail = "".join(f"<li>{esc(item)}</li>" for item in highlights)
        high_cards += (
            "<article class=\"high-card\">"
            f"<h4>{esc(rep.name)}</h4>"
            f"<p>Status: <strong>{esc(rep.status)}</strong> | Failures: <strong>{len(rep.failures)}</strong></p>"
            f"<ul>{detail}</ul>"
            "</article>"
        )
    if not high_cards:
        high_cards = '<div class="empty">No HIGH severity repositories in this run.</div>'

    supply_chain_panel = ""
    if optional_supply_chain_payload:
        global_severity = str(optional_supply_chain_payload.get("severity", "NONE")).upper()
        global_severity_css = {
            "CRITICAL": "sev-high",
            "HIGH": "sev-high",
            "MEDIUM": "sev-medium",
            "LOW": "sev-low",
            "NONE": "sev-ok",
        }.get(global_severity, "sev-low")
        critical_evidence_raw = optional_supply_chain_payload.get("critical_evidence", [])
        high_evidence_raw = optional_supply_chain_payload.get("high_evidence", [])
        medium_evidence_raw = optional_supply_chain_payload.get("medium_evidence", [])
        critical_evidence = (
            [str(item) for item in critical_evidence_raw if str(item)]
            if isinstance(critical_evidence_raw, list)
            else []
        )
        high_evidence = (
            [str(item) for item in high_evidence_raw if str(item)]
            if isinstance(high_evidence_raw, list)
            else []
        )
        medium_evidence = (
            [str(item) for item in medium_evidence_raw if str(item)]
            if isinstance(medium_evidence_raw, list)
            else []
        )
        python_probes = optional_supply_chain_payload.get("python_probes", [])
        probe_rows = ""
        if isinstance(python_probes, list):
            for probe in python_probes:
                if not isinstance(probe, dict):
                    continue
                probe_rows += (
                    "<tr>"
                    f"<td><code>{esc(redact_sensitive_text(str(probe.get('python', '-'))))}</code></td>"
                    f"<td>{esc(str(probe.get('installed', False)))}</td>"
                    f"<td>{esc(str(probe.get('version', '-')))}</td>"
                    f"<td><code>{esc(redact_sensitive_text(str(probe.get('location', '-'))))}</code></td>"
                    "</tr>"
                )
        if not probe_rows:
            probe_rows = '<tr><td class="empty" colspan="4">No python environment probes recorded.</td></tr>'

        supply_chain_panel = (
            '<section class="panel">'
            '<h2>Supply-chain incident audit (LiteLLM)</h2>'
            f'<p><strong>Global severity:</strong> <span class="sev-pill {global_severity_css}">{esc(global_severity)}</span></p>'
            '<div class="detail-grid">'
            '<section><h5>Critical evidence</h5>'
            f'{render_lines(critical_evidence, limit=12)}'
            '</section>'
            '<section><h5>High evidence</h5>'
            f'{render_lines(high_evidence, limit=12)}'
            '</section>'
            '</div>'
            '<div class="detail-grid">'
            '<section><h5>Medium evidence</h5>'
            f'{render_lines(medium_evidence, limit=12)}'
            '</section>'
            '<section><h5>Python environment probes</h5>'
            '<div class="table-wrap"><table>'
            '<tr><th>Python</th><th>LiteLLM installed</th><th>Version</th><th>Location</th></tr>'
            f'{probe_rows}'
            '</table></div>'
            '</section>'
            '</div>'
            '</section>'
        )

    repo_rows = ""
    repo_details = ""
    for rep, sev_label, _sev_score, highlights in repo_severity_data:
        decision_status, decision_message = email_remediation_decision(rep)
        guidance_level, guidance_risk, guidance_consequence, guidance_suggestion = repo_user_guidance(rep)
        owned_unexpected = (
            rep.unexpected_emails_owned_repo
            if rep.email_ownership_evaluated
            else rep.unexpected_emails
        )
        third_party_unexpected = (
            rep.unexpected_emails_third_party_repo if rep.email_ownership_evaluated else []
        )
        owned_unexpected_identity_tokens = (
            rep.unexpected_identity_tokens_owned_repo
            if rep.email_ownership_evaluated
            else rep.unexpected_identity_tokens
        )
        third_party_unexpected_identity_tokens = (
            rep.unexpected_identity_tokens_third_party_repo if rep.email_ownership_evaluated else []
        )
        tracked_email_high_confidence = (
            rep.tracked_email_high_confidence
            if rep.email_confidence_evaluated
            else rep.tracked_email_matches
        )
        tracked_email_low_confidence = (
            rep.tracked_email_low_confidence if rep.email_confidence_evaluated else []
        )
        tracked_email_fixture_matches = (
            rep.tracked_email_fixture_matches if rep.email_confidence_evaluated else []
        )
        history_email_high_confidence = (
            rep.history_email_high_confidence
            if rep.email_confidence_evaluated
            else rep.history_email_matches
        )
        history_email_low_confidence = (
            rep.history_email_low_confidence if rep.email_confidence_evaluated else []
        )
        history_email_fixture_matches = (
            rep.history_email_fixture_matches if rep.email_confidence_evaluated else []
        )

        sev_class = f"sev-{sev_label.lower()}"
        repo_rows += (
            "<tr>"
            f"<td>{esc(rep.name)}</td>"
            f"<td><span class=\"sev-pill {sev_class}\">{esc(sev_label)}</span></td>"
            f"<td>{esc(rep.status)}</td>"
            f"<td>{esc(classify_litellm_incident_severity(rep))}</td>"
            f"<td class=\"num\">{len(rep.failures)}</td>"
            f"<td class=\"num\">{len(rep.tracked_secret_matches) + len(rep.history_secret_matches) + len(rep.git_metadata_secret_matches)}</td>"
            f"<td class=\"num\">{len(rep.secret_file_candidates)}</td>"
            f"<td class=\"num\">{len(owned_unexpected)}</td>"
            f"<td class=\"num\">{len(owned_unexpected_identity_tokens)}</td>"
            f"<td class=\"num\">{len(rep.exfil_code_indicators)}</td>"
            f"<td class=\"num\">{len(rep.github_hardening_findings)}</td>"
            f"<td class=\"num\">{len(rep.litellm_ioc_hits)}</td>"
            f"<td class=\"num\">{len(rep.gitignore_missing_patterns)}</td>"
            "</tr>"
        )

        highlights_html = "".join(f"<li>{esc(item)}</li>" for item in highlights)
        if not highlights_html:
            highlights_html = "<li>No highlight details.</li>"

        failures_html = "".join(f"<li>{esc(item)}</li>" for item in rep.failures)
        if not failures_html:
            failures_html = "<li>No failures.</li>"

        detected_preview = build_detected_findings_preview(rep)
        planned_removals_preview = build_planned_removals_preview(rep)
        if not planned_removals_preview:
            planned_removals_preview = [
                "No deletion/untracking action is planned for current run settings."
            ]

        details_metrics = (
            "<table class=\"metrics\">"
            "<tr><th>Metric</th><th class=\"num\">Value</th></tr>"
            f"<tr><td>low_confidence_email_mode</td><td>{esc(rep.low_confidence_email_mode)}</td></tr>"
            f"<tr><td>unexpected_emails_total</td><td class=\"num\">{len(rep.unexpected_emails)}</td></tr>"
            f"<tr><td>unexpected_emails_owned_repo</td><td class=\"num\">{len(owned_unexpected)}</td></tr>"
            f"<tr><td>unexpected_emails_third_party_repo</td><td class=\"num\">{len(third_party_unexpected)}</td></tr>"
            f"<tr><td>unexpected_identity_tokens_total</td><td class=\"num\">{len(rep.unexpected_identity_tokens)}</td></tr>"
            f"<tr><td>unexpected_identity_tokens_owned_repo</td><td class=\"num\">{len(owned_unexpected_identity_tokens)}</td></tr>"
            f"<tr><td>unexpected_identity_tokens_third_party_repo</td><td class=\"num\">{len(third_party_unexpected_identity_tokens)}</td></tr>"
            f"<tr><td>tracked_secret_matches</td><td class=\"num\">{len(rep.tracked_secret_matches)}</td></tr>"
            f"<tr><td>tracked_secret_high_confidence</td><td class=\"num\">{len(rep.tracked_secret_high_confidence)}</td></tr>"
            f"<tr><td>tracked_secret_low_confidence</td><td class=\"num\">{len(rep.tracked_secret_low_confidence)}</td></tr>"
            f"<tr><td>tracked_secret_fixture_matches</td><td class=\"num\">{len(rep.tracked_secret_fixture_matches)}</td></tr>"
            f"<tr><td>tracked_secret_documentation_matches</td><td class=\"num\">{len(rep.tracked_secret_documentation_matches)}</td></tr>"
            f"<tr><td>history_secret_matches</td><td class=\"num\">{len(rep.history_secret_matches)}</td></tr>"
            f"<tr><td>history_secret_high_confidence</td><td class=\"num\">{len(rep.history_secret_high_confidence)}</td></tr>"
            f"<tr><td>history_secret_low_confidence</td><td class=\"num\">{len(rep.history_secret_low_confidence)}</td></tr>"
            f"<tr><td>history_secret_fixture_matches</td><td class=\"num\">{len(rep.history_secret_fixture_matches)}</td></tr>"
            f"<tr><td>history_secret_documentation_matches</td><td class=\"num\">{len(rep.history_secret_documentation_matches)}</td></tr>"
            f"<tr><td>git_metadata_secret_matches</td><td class=\"num\">{len(rep.git_metadata_secret_matches)}</td></tr>"
            f"<tr><td>git_metadata_secret_low_confidence</td><td class=\"num\">{len(rep.git_metadata_secret_low_confidence)}</td></tr>"
            f"<tr><td>secret_file_candidates</td><td class=\"num\">{len(rep.secret_file_candidates)}</td></tr>"
            f"<tr><td>tracked_path_matches</td><td class=\"num\">{len(rep.tracked_path_matches)}</td></tr>"
            f"<tr><td>history_path_matches</td><td class=\"num\">{len(rep.history_path_matches)}</td></tr>"
            f"<tr><td>tracked_email_matches</td><td class=\"num\">{len(rep.tracked_email_matches)}</td></tr>"
            f"<tr><td>tracked_email_high_confidence</td><td class=\"num\">{len(tracked_email_high_confidence)}</td></tr>"
            f"<tr><td>tracked_email_low_confidence</td><td class=\"num\">{len(tracked_email_low_confidence)}</td></tr>"
            f"<tr><td>tracked_email_fixture_matches</td><td class=\"num\">{len(tracked_email_fixture_matches)}</td></tr>"
            f"<tr><td>history_email_matches</td><td class=\"num\">{len(rep.history_email_matches)}</td></tr>"
            f"<tr><td>history_email_high_confidence</td><td class=\"num\">{len(history_email_high_confidence)}</td></tr>"
            f"<tr><td>history_email_low_confidence</td><td class=\"num\">{len(history_email_low_confidence)}</td></tr>"
            f"<tr><td>history_email_fixture_matches</td><td class=\"num\">{len(history_email_fixture_matches)}</td></tr>"
            f"<tr><td>history_sensitive_added</td><td class=\"num\">{len(rep.history_sensitive_added)}</td></tr>"
            f"<tr><td>history_sensitive_deleted</td><td class=\"num\">{len(rep.history_sensitive_deleted)}</td></tr>"
            f"<tr><td>tracked_but_ignored</td><td class=\"num\">{len(rep.tracked_but_ignored)}</td></tr>"
            f"<tr><td>gitignore_missing_patterns</td><td class=\"num\">{len(rep.gitignore_missing_patterns)}</td></tr>"
            f"<tr><td>exfil_code_indicators</td><td class=\"num\">{len(rep.exfil_code_indicators)}</td></tr>"
            f"<tr><td>github_hardening_checked</td><td>{esc(str(rep.github_hardening_checked))}</td></tr>"
            f"<tr><td>github_hardening_findings</td><td class=\"num\">{len(rep.github_hardening_findings)}</td></tr>"
            f"<tr><td>github_hardening_warnings</td><td class=\"num\">{len(rep.github_hardening_warnings)}</td></tr>"
            f"<tr><td>github_hardening_fix_guide</td><td class=\"num\">{len(rep.github_hardening_fix_guide)}</td></tr>"
            f"<tr><td>suppressed_findings</td><td class=\"num\">{len(rep.suppressed_findings)}</td></tr>"
            f"<tr><td>litellm_incident_severity</td><td>{esc(classify_litellm_incident_severity(rep))}</td></tr>"
            f"<tr><td>litellm_reference_hits</td><td class=\"num\">{len(rep.litellm_reference_hits)}</td></tr>"
            f"<tr><td>litellm_compromised_reference_hits</td><td class=\"num\">{len(rep.litellm_compromised_reference_hits)}</td></tr>"
            f"<tr><td>litellm_install_command_hits</td><td class=\"num\">{len(rep.litellm_install_command_hits)}</td></tr>"
            f"<tr><td>litellm_ioc_hits</td><td class=\"num\">{len(rep.litellm_ioc_hits)}</td></tr>"
            f"<tr><td>execution_errors</td><td class=\"num\">{len(rep.execution_errors)}</td></tr>"
            "</table>"
        )
        suppressed_preview = [
            f"{item.get('category', 'unknown')}: {item.get('finding', '')}"
            for item in rep.suppressed_findings
        ]

        detail_sections = (
            "<div class=\"detail-grid\">"
            "<section><h5>User guidance</h5>"
            f"<p><strong>{esc(guidance_level)}</strong> - {esc(guidance_risk)}</p>"
            f"<p><strong>Possible consequence:</strong> {esc(guidance_consequence)}</p>"
            f"<p><strong>Suggestion:</strong> {esc(guidance_suggestion)}</p>"
            "</section>"
            "<section><h5>Email remediation decision</h5>"
            f"<p><strong>{esc(decision_status)}</strong> - {esc(decision_message)}</p>"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Detected findings (explicit preview)</h5>"
            f"{render_lines(detected_preview, limit=12)}"
            "</section>"
            "<section><h5>Planned deletions/untracking (explicit preview)</h5>"
            f"{render_lines(planned_removals_preview, limit=12)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>LiteLLM references (sample)</h5>"
            f"{render_lines(rep.litellm_reference_hits)}"
            "</section>"
            "<section><h5>LiteLLM IoCs (sample)</h5>"
            f"{render_lines(rep.litellm_ioc_hits)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Failure reasons</h5>"
            f"<ul>{failures_html}</ul></section>"
            "<section><h5>Severity highlights</h5>"
            f"<ul>{highlights_html}</ul></section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Tracked secret matches (sample)</h5>"
            f"{render_lines(rep.tracked_secret_matches)}"
            "</section>"
            "<section><h5>History secret matches (sample)</h5>"
            f"{render_lines(rep.history_secret_matches)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Low-confidence secret assignments (tracked)</h5>"
            f"{render_lines(rep.tracked_secret_low_confidence)}"
            "</section>"
            "<section><h5>Low-confidence secret assignments (history)</h5>"
            f"{render_lines(rep.history_secret_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Secret fixtures/examples (safe)</h5>"
            f"{render_lines(rep.tracked_secret_fixture_matches + rep.history_secret_fixture_matches)}"
            "</section>"
            "<section><h5>Secret documentation examples (safe)</h5>"
            f"{render_lines(rep.tracked_secret_documentation_matches + rep.history_secret_documentation_matches)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Email fixtures/examples (safe)</h5>"
            f"{render_lines(tracked_email_fixture_matches + history_email_fixture_matches)}"
            "</section>"
            "<section><h5>Email examples requiring review</h5>"
            f"{render_lines(tracked_email_low_confidence + history_email_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Git metadata secret matches</h5>"
            f"{render_lines(rep.git_metadata_secret_matches)}"
            "</section>"
            "<section><h5>Git metadata low-confidence secret indicators</h5>"
            f"{render_lines(rep.git_metadata_secret_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Secret file candidates</h5>"
            f"{render_lines(rep.secret_file_candidates)}"
            "</section>"
            "<section><h5>Unexpected commit emails (owned repositories)</h5>"
            f"{render_lines(owned_unexpected)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Malformed commit identity tokens (owned repositories)</h5>"
            f"{render_lines(owned_unexpected_identity_tokens)}"
            "</section>"
            "<section><h5>Unexpected commit emails (third-party repositories)</h5>"
            f"{render_lines(third_party_unexpected)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Malformed commit identity tokens (third-party repositories)</h5>"
            f"{render_lines(third_party_unexpected_identity_tokens)}"
            "</section>"
            "<section><h5>Exfil indicators (advisory sample)</h5>"
            f"{render_lines(rep.exfil_code_indicators)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>GitHub hardening findings (advisory sample)</h5>"
            f"{render_lines(rep.github_hardening_findings)}"
            "</section>"
            "<section><h5>GitHub hardening audit warnings</h5>"
            f"{render_lines(rep.github_hardening_warnings)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>GitHub hardening fix guide</h5>"
            f"{render_lines(rep.github_hardening_fix_guide)}"
            "</section>"
            "<section><h5>Suppressed findings</h5>"
            f"{render_lines(suppressed_preview)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Path leaks in history (sample)</h5>"
            f"{render_lines(rep.history_path_matches)}"
            "</section>"
            "<section><h5>Path leaks in tracked files (sample)</h5>"
            f"{render_lines(rep.tracked_path_matches)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Email matches in tracked files (high confidence)</h5>"
            f"{render_lines(tracked_email_high_confidence)}"
            "</section>"
            "<section><h5>Email matches in tracked files (low confidence)</h5>"
            f"{render_lines(tracked_email_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Email leaks in history (high confidence)</h5>"
            f"{render_lines(history_email_high_confidence)}"
            "</section>"
            "<section><h5>Email leaks in history (low confidence)</h5>"
            f"{render_lines(history_email_low_confidence)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Ignore and history filename issues</h5>"
            f"{render_lines(rep.gitignore_missing_patterns + rep.history_sensitive_added + rep.history_sensitive_deleted)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Execution errors</h5>"
            f"{render_lines(rep.execution_errors)}"
            "</section>"
            "<section><h5>Fix errors</h5>"
            f"{render_lines(rep.fix_errors)}"
            "</section>"
            "</div>"
            "<section><h5>Metrics snapshot</h5>"
            f"{details_metrics}</section>"
        )

        repo_details += (
            "<details class=\"repo-detail\">"
            f"<summary>{esc(rep.name)} | severity {esc(sev_label)} | status {esc(rep.status)}</summary>"
            f"<p class=\"meta\">path: <code>{esc(redact_sensitive_text(rep.path))}</code></p>"
            f"<p class=\"meta\">origin: <code>{esc(redact_sensitive_text(rep.origin_url or '-'))}</code></p>"
            f"<p class=\"meta\">upstream: <code>{esc(redact_sensitive_text(rep.upstream_url or '-'))}</code></p>"
            f"{detail_sections}"
            "</details>"
        )

    duration = finished_at - artifacts.started_at
    duration_seconds = max(duration.total_seconds(), 0.0)

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Repo Privacy Guardian Audit Report - {esc(artifacts.run_id)}</title>
  <style>
    :root {{
      --bg: #f6f8fc;
      --surface: #ffffff;
      --text: #17233a;
      --muted: #4d5a73;
      --line: #d6deeb;
      --ok: #1e8e5a;
      --low: #a66a00;
      --med: #d95f02;
      --high: #b00020;
      --accent: #005bbb;
      --shadow: 0 10px 28px rgba(23, 35, 58, 0.08);
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0f172a;
        --surface: #1e293b;
        --text: #e2ecf6;
        --muted: #94a3b8;
        --line: #334155;
        --ok: #34d399;
        --low: #fbbf24;
        --med: #fb923c;
        --high: #f87171;
        --accent: #38bdf8;
        --shadow: 0 10px 28px rgba(0, 0, 0, 0.4);
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      background: radial-gradient(circle at top right, #dde8ff 0%, var(--bg) 42%);
      color: var(--text);
      line-height: 1.45;
    }}
    @media (prefers-color-scheme: dark) {{
      body {{
        background: radial-gradient(circle at top right, #1e293b 0%, var(--bg) 42%);
      }}
    }}
    .container {{ max-width: 1280px; margin: 0 auto; padding: 22px; }}
    .hero {{
      background: linear-gradient(125deg, #0f3c78 0%, #005bbb 55%, #2a7de1 100%);
      color: #fff;
      border-radius: 16px;
      padding: 24px;
      box-shadow: var(--shadow);
    }}
    .hero h1 {{ margin: 0 0 10px; font-size: 1.65rem; }}
    .hero p {{ margin: 6px 0; opacity: 0.95; }}
    .grid {{ display: grid; gap: 14px; margin-top: 18px; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); }}
    .card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 14px; box-shadow: var(--shadow); }}
    .card h3 {{ margin: 0 0 6px; font-size: 0.95rem; color: var(--muted); font-weight: 600; }}
    .metric {{ font-size: 1.8rem; font-weight: 700; margin: 0; }}
    .metric.fail {{ color: var(--high); }}
    .metric.pass {{ color: var(--ok); }}
    .decision-first {{ border-left: 6px solid var(--accent); }}
    .decision-badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-weight: 800; letter-spacing: 0; }}
    .decision-pass {{ background: #dff6e9; color: var(--ok); }}
    .decision-review {{ background: #fff8df; color: var(--low); }}
    .decision-fail {{ background: #ffe4e8; color: var(--high); }}
    section {{ margin-top: 18px; }}
    h2 {{ margin: 0 0 10px; font-size: 1.18rem; }}
    h4 {{ margin: 0 0 8px; }}
    .panel {{ background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 14px; box-shadow: var(--shadow); }}
    .table-wrap {{ width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }}
    .table-wrap table {{ width: 100%; border-collapse: collapse; min-width: 520px; }}
    .table-wrap.matrix table {{ min-width: 980px; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ background: #eef3fb; font-weight: 700; }}
    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .sev-pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.82rem; font-weight: 700; }}
    .sev-high {{ background: #ffe4e8; color: var(--high); }}
    .sev-medium {{ background: #fff1de; color: var(--med); }}
    .sev-low {{ background: #fff8df; color: var(--low); }}
    .sev-ok {{ background: #dff6e9; color: var(--ok); }}
    .high-card {{ border: 1px solid #f3b7bf; background: #fff0f3; border-radius: 10px; padding: 12px; margin-bottom: 10px; }}
    .repo-detail {{ border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; margin-bottom: 10px; background: var(--surface); box-shadow: var(--shadow); }}
    .repo-detail summary {{ cursor: pointer; font-weight: 700; }}
    .meta {{ margin: 8px 0 0; color: var(--muted); }}
    .detail-grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); margin-top: 10px; }}
    .finding-list {{ margin: 0; padding-left: 18px; }}
    .finding-list code {{ white-space: pre-wrap; word-break: break-word; }}
    code {{ background: #f1f5ff; color: #1b2f55; border-radius: 4px; padding: 1px 4px; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; }}
    .more, .empty {{ margin-top: 8px; color: var(--muted); font-style: italic; }}
    @media (prefers-color-scheme: dark) {{
      th {{ background: #0f172a; border-bottom-color: #334155; }}
      code {{ background: #0f172a; color: #bae6fd; }}
      .sev-high {{ background: #450a0a; color: var(--high); }}
      .sev-medium {{ background: #431407; color: var(--med); }}
      .sev-low {{ background: #422006; color: var(--low); }}
      .sev-ok {{ background: #064e3b; color: var(--ok); }}
      .decision-pass {{ background: #064e3b; color: var(--ok); }}
      .decision-review {{ background: #422006; color: var(--low); }}
      .decision-fail {{ background: #450a0a; color: var(--high); }}
      .high-card {{ border-color: #7f1d1d; background: #450a0a; }}
    }}
    @media (max-width: 760px) {{
      .container {{ padding: 12px; }}
      .hero {{ padding: 16px; }}
      th, td {{ padding: 8px; }}
            .table-wrap.matrix table {{ min-width: 820px; }}
    }}
  </style>
</head>
<body>
  <div class=\"container\">
    <header class=\"hero\">
      <h1>Repository Privacy Audit Report</h1>
      <p><strong>Run ID:</strong> {esc(artifacts.run_id)}</p>
      <p><strong>Started:</strong> {esc(artifacts.started_at.strftime('%Y-%m-%d %H:%M:%S'))} | <strong>Finished:</strong> {esc(finished_at.strftime('%Y-%m-%d %H:%M:%S'))} | <strong>Duration:</strong> {duration_seconds:.2f}s</p>
            <p><strong>Root:</strong> <code>{esc(redact_sensitive_text(str(root_path)))}</code></p>
            <p><strong>Policy:</strong> <code>{esc(redact_sensitive_text(str(policy_path)))}</code></p>
            <p><strong>Artifacts:</strong> <code>{esc(redact_sensitive_text(str(artifacts.run_dir)))}</code></p>
    </header>

    <section class=\"grid\">
      <article class=\"card\"><h3>Total repositories</h3><p class=\"metric\">{total}</p></article>
      <article class=\"card\"><h3>PASS</h3><p class=\"metric pass\">{passed}</p></article>
      <article class=\"card\"><h3>FAIL</h3><p class=\"metric fail\">{failed}</p></article>
            <article class=\"card\"><h3>HIGH severity repos</h3><p class=\"metric fail\">{len(high_risk_repos)}</p></article>
    </section>

    <section class=\"panel decision-first\">
      <h2>Decision first</h2>
      <p><span class=\"decision-badge {decision_class}\">{decision}</span></p>
      <p><strong>Next action:</strong> {esc(decision_next_action)}</p>
      <div class=\"table-wrap\">
        <table>
          <tr><th>Signal</th><th class=\"num\">Count</th></tr>
          {decision_rows}
        </table>
      </div>
    </section>

    <section class=\"panel\">
      <h2>Execution settings</h2>
      <div class=\"table-wrap\">
        <table>
          <tr><th>Setting</th><th>Value</th></tr>
          {settings_rows}
        </table>
      </div>
    </section>

    <section class=\"panel\">
            <h2>High severity focus</h2>
      {high_cards}
    </section>

        {supply_chain_panel}

    <section class=\"panel\">
      <h2>Failure reason frequency</h2>
      <div class=\"table-wrap\">
        <table>
          <tr><th>Reason</th><th class=\"num\">Repos</th></tr>
          {reason_rows}
        </table>
      </div>
    </section>

    <section class=\"panel\">
      <h2>Repository matrix</h2>
      <div class=\"table-wrap matrix\">
        <table>
          <tr>
            <th>Repository</th>
            <th>Severity</th>
            <th>Status</th>
                        <th>LiteLLM Incident</th>
            <th class=\"num\">Failures</th>
            <th class=\"num\">Secret matches</th>
            <th class=\"num\">Secret file candidates</th>
            <th class=\"num\">Unexpected emails (owned repo)</th>
            <th class=\"num\">Identity tokens (owned repo)</th>
            <th class=\"num\">Exfil indicators</th>
            <th class=\"num\">GitHub findings</th>
            <th class=\"num\">LiteLLM IoCs</th>
            <th class=\"num\">Missing .gitignore rules</th>
          </tr>
          {repo_rows}
        </table>
      </div>
    </section>

    <section>
      <h2>Repository details</h2>
      {repo_details}
    </section>
  </div>
</body>
</html>
"""


def persist_run_outputs(
    reports: list[RepoReport],
    artifacts: RunArtifacts,
    root_path: Path,
    policy_path: Path,
    run_settings: dict[str, str],
    logger: Callable[[str], None],
    optional_json_export: str | None = None,
    optional_supply_chain_payload: dict[str, object] | None = None,
    exit_code: int | None = None,
) -> None:
    artifact_helpers.persist_run_outputs(
        reports=reports,
        artifacts=artifacts,
        root_path=root_path,
        policy_path=policy_path,
        run_settings=run_settings,
        logger=logger,
        sanitize_report_for_export=sanitize_report_for_export,
        render_html_report=render_html_report,
        write_private_text_file=write_private_text_file,
        report_contains_sensitive_findings=report_contains_sensitive_findings,
        resolve_optional_json_export_path=resolve_optional_json_export_path,
        optional_json_export=optional_json_export,
        optional_supply_chain_payload=optional_supply_chain_payload,
        now_factory=datetime.now,
    )
    reports_payload = [sanitize_report_for_export(rep) for rep in reports]
    summary = agent_summary_helpers.build_agent_summary(
        reports_payload=reports_payload,
        artifacts=artifacts,
        root_path=Path(redact_sensitive_text(str(root_path))),
        policy_path=Path(redact_sensitive_text(str(policy_path))),
        run_settings=run_settings,
        exit_code=exit_code,
        generated_at=datetime.now(),
    )
    agent_summary_path = artifacts.agent_summary_path or artifacts.run_dir / "agent_summary.json"
    write_private_text_file(agent_summary_path, json.dumps(summary, indent=2))
    logger(f"[INFO] Agent summary written to {agent_summary_path}")
    if run_settings.get("agent_summary") == "True":
        logger(agent_summary_helpers.format_agent_summary_handoff(summary))


def open_html_report_in_browser(
    html_path: Path,
    logger: Callable[[str], None],
) -> None:
    if not html_path.exists():
        return

    try:
        opened = bool(webbrowser.open(html_path.resolve().as_uri()))
    except Exception as exc:
        logger(f"[WARN] Could not open HTML report automatically: {exc}")
        return

    if opened:
        logger(f"[INFO] Opened HTML report in browser: {html_path}")
    else:
        logger(f"[WARN] Browser did not open automatically. Open report manually: {html_path}")
