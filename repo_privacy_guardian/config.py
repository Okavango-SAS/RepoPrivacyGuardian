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


def make_parser(
    *,
    default_root: Path,
    default_policy: Path,
    default_results_dir: Path,
    default_noreply: str,
    default_placeholder: str,
    public_only_default: bool = False,
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit/fix repository public-release safety based on docs/POLICY.md. "
            "Start safely with --check-tooling, then a --dry-run audit; fixes are opt-in. "
            "Outbound/exfil indicators remain advisory/manual-review by default."
        ),
        epilog=(
            "First-time safe path (no writes):\n"
            "  repo-privacy-guardian --check-tooling\n"
            "  repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes\n"
            "\n"
            "Read the result:\n"
            "  PASS   no blocking publication issues were found\n"
            "  REVIEW inspect advisory findings before publishing\n"
            "  FAIL   do not publish until blocking findings are fixed\n"
            "\n"
            "Common CLI flow:\n"
            "  repo-privacy-guardian --check-tooling\n"
            "  repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes\n"
            "  repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --dry-run --yes\n"
            "  repo-privacy-guardian --gui\n"
            "\n"
            "Agentic handoff:\n"
            "  Paste the README 60-Second First Run prompt into your coding agent; keep fixes and pushes approval-gated."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--root", default=str(default_root), help="Root folder containing repositories")
    parser.add_argument("--policy", default=str(default_policy), help="Policy markdown path")
    parser.add_argument("--repos", nargs="*", help="Repo folder names or absolute paths")
    parser.add_argument(
        "--public-only",
        action="store_true",
        default=public_only_default,
        help="Only include repositories with publicly accessible GitHub origin",
    )

    parser.add_argument("--fix", action="store_true", help="Apply automated fixes")
    parser.add_argument("--push", action="store_true", help="Force-push rewritten history to origin")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed")
    parser.add_argument(
        "--redact-third-party-emails",
        action="store_true",
        help="Redact non-owner emails to placeholder",
    )
    parser.add_argument(
        "--purge-detected-secret-files",
        action="store_true",
        help="When fixing, add secret files to .gitignore, untrack them, and purge them from history (safe candidates only)",
    )
    parser.add_argument(
        "--purge-all-detected-secret-files",
        action="store_true",
        help="When fixing, purge all detected secret files including risky/manual-review candidates",
    )
    parser.add_argument(
        "--rewrite-personal-paths",
        action="store_true",
        help="When fixing, rewrite detected personal absolute paths in tracked content/history",
    )
    parser.add_argument(
        "--low-confidence-email-mode",
        choices=["informational", "blocking"],
        default="informational",
        help="Treat low-confidence email findings as informational (default) or blocking",
    )
    parser.add_argument(
        "--strict-profile",
        choices=list(strict_profiles.STRICT_PROFILE_CHOICES),
        help=(
            "Apply a documented policy preset: audit-only rejects writes, internal is explicit current behavior, "
            "release promotes low-confidence emails and opt-in GitHub hardening findings to blocking."
        ),
    )
    parser.add_argument(
        "--suppressions",
        help=(
            "Versioned JSON suppression file for advisory/manual-review findings. "
            "High-confidence secrets, path leaks, git metadata blocking findings, fsck, dirty tree, and runtime errors cannot be suppressed."
        ),
    )
    parser.add_argument(
        "--agent-summary",
        action="store_true",
        help="Print a safe agent handoff summary and always write agent_summary.json in the run artifacts.",
    )
    parser.add_argument(
        "--audit-litellm-incident",
        action="store_true",
        help="Enable supply-chain incident audit checks for LiteLLM March-2026 indicators",
    )
    parser.add_argument(
        "--audit-github-hardening",
        action="store_true",
        help=(
            "Enable optional GitHub repository settings audit for GitHub remotes. "
            "Uses read-only GitHub API calls; token-gated checks require "
            "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, or authenticated gh."
        ),
    )
    parser.add_argument(
        "--accept-github-admin-bypass",
        action="store_true",
        help=(
            "When GitHub hardening audit is enabled, treat administrator branch-protection bypass "
            "as an explicit accepted risk for solo-maintainer repositories instead of a hardening finding."
        ),
    )
    parser.add_argument(
        "--github-owner",
        help=(
            "Opt-in remote audit: discover repositories for this GitHub user/org, "
            "clone them into a temporary private directory, audit, then remove the clones"
        ),
    )
    parser.add_argument(
        "--github-include-forks",
        action="store_true",
        help="With --github-owner, include forked repositories (forks are skipped by default)",
    )
    parser.add_argument(
        "--github-fast",
        action="store_true",
        help="With --github-owner, use shallow clones before auditing current files and available history",
    )
    parser.add_argument(
        "--github-jobs",
        type=parse_positive_int,
        default=4,
        help=f"With --github-owner, number of concurrent clone workers (default: 4, max: {MAX_GITHUB_CLONE_JOBS})",
    )

    parser.add_argument("--owner-name", default="Owner", help="Owner display name for rewritten commits")
    parser.add_argument(
        "--owner-email",
        action="append",
        default=[],
        help="Owner private email(s) to replace with noreply (can repeat)",
    )
    parser.add_argument("--noreply-email", default=default_noreply, help="Target noreply email")
    parser.add_argument(
        "--placeholder-email",
        default=default_placeholder,
        help="Placeholder email for redacted contributors",
    )
    parser.add_argument("--max-matches", type=parse_positive_int, default=50, help="Max findings per check")
    parser.add_argument(
        "--report-json",
        help=(
            "Optional extra JSON export path. Main JSON/LOG/HTML artifacts are always written to a timestamped "
            "run folder; with --compare-reports, this writes the comparison JSON."
        ),
    )
    parser.add_argument(
        "--compare-reports",
        nargs=2,
        metavar=("BEFORE_REPORT_JSON", "AFTER_REPORT_JSON"),
        help=(
            "Compare two redacted report.json artifacts and print count-only deltas without running a new audit."
        ),
    )
    parser.add_argument(
        "--report-dir",
        default=str(default_results_dir),
        help="Requested base directory for timestamped run folders; values outside Audit_Results are ignored by policy",
    )
    parser.add_argument(
        "--replace-text-file",
        help=(
            "Advanced remediation input: merge an explicit git-filter-repo replace-text file "
            "into the generated rewrite plan"
        ),
    )

    parser.add_argument("--yes", action="store_true", help="Skip destructive action confirmation prompt")
    parser.add_argument(
        "--check-tooling",
        action="store_true",
        help="Check required/optional local tooling for the selected mode and exit",
    )
    parser.add_argument(
        "--install-missing-tools",
        action="store_true",
        help="Attempt to install supported missing tools before continuing",
    )
    report_open_group = parser.add_mutually_exclusive_group()
    report_open_group.add_argument(
        "--open-report",
        action="store_true",
        help="Open the generated HTML report in a browser after a CLI run completes",
    )
    report_open_group.add_argument(
        "--no-open-report",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-confirm-each-repo",
        action="store_true",
        help="Disable per-repository fix confirmation prompts in CLI mode",
    )
    parser.add_argument(
        "--allow-non-owner-push",
        action="store_true",
        help="Bypass remote owner verification before force push (unsafe)",
    )
    parser.add_argument(
        "--allow-remote-owner",
        action="append",
        default=[],
        help="Allow force-push only when origin owner matches this value (can repeat)",
    )
    parser.add_argument("--gui", action="store_true", help="Launch the optional desktop GUI")
    return parser


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
    accept_github_admin_bypass: bool = False,
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
        accept_github_admin_bypass=accept_github_admin_bypass,
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
        accept_github_admin_bypass=args.accept_github_admin_bypass,
        agent_summary=args.agent_summary,
        strict_profile=args.strict_profile,
        suppressions=args.suppressions,
    )
