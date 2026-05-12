"""CLI and run-configuration normalization helpers."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable, TypeVar

from repo_privacy_guardian.github import infer_github_username_from_noreply
from repo_privacy_guardian import strict_profiles


MAX_GITHUB_CLONE_JOBS = 16

T = TypeVar("T")


def parse_positive_int(raw_value: str) -> int:
    try:
        parsed = int(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def normalize_github_jobs(value: int) -> int:
    return min(MAX_GITHUB_CLONE_JOBS, max(1, value))


def normalize_repo_filters(repo_names: list[str]) -> list[str] | None:
    return repo_names if repo_names else None


def normalize_csv_values(raw_value: str) -> list[str]:
    if not raw_value:
        return []
    return list(dict.fromkeys(item.strip() for item in raw_value.split(",") if item.strip()))


def normalize_text_values(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value.strip() for value in values if value and value.strip()))


def build_guard_run_config(
    *,
    config_factory: Callable[..., T],
    mode: str,
    root: Path,
    policy: Path,
    repos: list[str] | None,
    public_only: bool,
    fix: bool,
    push: bool,
    dry_run: bool,
    redact_third_party_emails: bool,
    purge_detected_secret_files: bool,
    purge_all_detected_secret_files: bool,
    rewrite_personal_paths: bool,
    low_confidence_email_mode: str,
    owner_name: str,
    owner_emails: list[str],
    noreply_email: str,
    placeholder_email: str,
    max_matches: int,
    open_report: bool,
    confirm_each_repo_fix: bool,
    allow_non_owner_push: bool,
    allowed_remote_owners: list[str],
    replace_text_file: str | None,
    report_json: str | None,
    github_owner: str | None = None,
    github_include_forks: bool = False,
    github_fast: bool = False,
    github_jobs: int = 4,
    audit_litellm_incident: bool = False,
    audit_github_hardening: bool = False,
    agent_summary: bool = False,
    strict_profile: str | None = None,
    suppressions: str | None = None,
) -> T:
    normalized_owner_emails = normalize_text_values(owner_emails)
    normalized_allowed_remote_owners = normalize_text_values(allowed_remote_owners)
    inferred_owner = infer_github_username_from_noreply(noreply_email)
    if inferred_owner and inferred_owner not in normalized_allowed_remote_owners:
        normalized_allowed_remote_owners.append(inferred_owner)
    strict_profile_config = strict_profiles.build_strict_profile_config(
        profile=strict_profile,
        low_confidence_email_mode=low_confidence_email_mode,
        audit_github_hardening=audit_github_hardening,
    )

    return config_factory(
        mode=mode,
        root=root,
        policy=policy,
        repos=repos,
        public_only=public_only,
        fix=fix,
        push=push,
        dry_run=dry_run,
        redact_third_party_emails=redact_third_party_emails,
        purge_detected_secret_files=purge_detected_secret_files,
        purge_all_detected_secret_files=purge_all_detected_secret_files,
        rewrite_personal_paths=rewrite_personal_paths,
        low_confidence_email_mode=strict_profile_config.low_confidence_email_mode,
        owner_name=owner_name,
        owner_emails=normalized_owner_emails,
        noreply_email=noreply_email,
        placeholder_email=placeholder_email,
        max_matches=max_matches,
        audit_litellm_incident=audit_litellm_incident,
        audit_github_hardening=audit_github_hardening,
        open_report=open_report,
        confirm_each_repo_fix=confirm_each_repo_fix,
        allow_non_owner_push=allow_non_owner_push,
        allowed_remote_owners=normalized_allowed_remote_owners,
        replace_text_file=replace_text_file,
        report_json=report_json,
        github_owner=(github_owner.strip() if github_owner and github_owner.strip() else None),
        github_include_forks=github_include_forks,
        github_fast=github_fast,
        github_jobs=normalize_github_jobs(github_jobs),
        agent_summary=agent_summary,
        strict_profile=strict_profile_config.name,
        github_hardening_findings_blocking=strict_profile_config.github_hardening_findings_blocking,
        suppressions=(suppressions.strip() if suppressions and suppressions.strip() else None),
    )


def build_cli_guard_run_config(
    args: argparse.Namespace,
    *,
    config_factory: Callable[..., T],
) -> T:
    return build_guard_run_config(
        config_factory=config_factory,
        mode="cli",
        root=Path(args.root),
        policy=Path(args.policy),
        repos=args.repos,
        public_only=args.public_only,
        fix=args.fix,
        push=args.push,
        dry_run=args.dry_run,
        redact_third_party_emails=args.redact_third_party_emails,
        purge_detected_secret_files=args.purge_detected_secret_files,
        purge_all_detected_secret_files=args.purge_all_detected_secret_files,
        rewrite_personal_paths=args.rewrite_personal_paths,
        low_confidence_email_mode=args.low_confidence_email_mode,
        owner_name=args.owner_name,
        owner_emails=args.owner_email,
        noreply_email=args.noreply_email,
        placeholder_email=args.placeholder_email,
        max_matches=args.max_matches,
        open_report=bool(args.open_report),
        confirm_each_repo_fix=not args.no_confirm_each_repo,
        allow_non_owner_push=args.allow_non_owner_push,
        allowed_remote_owners=args.allow_remote_owner,
        replace_text_file=args.replace_text_file,
        report_json=args.report_json,
        github_owner=args.github_owner,
        github_include_forks=args.github_include_forks,
        github_fast=args.github_fast,
        github_jobs=args.github_jobs,
        audit_litellm_incident=args.audit_litellm_incident,
        audit_github_hardening=args.audit_github_hardening,
        agent_summary=args.agent_summary,
        strict_profile=args.strict_profile,
        suppressions=args.suppressions,
    )
