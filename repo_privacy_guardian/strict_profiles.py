from __future__ import annotations

from dataclasses import dataclass


STRICT_PROFILE_AUDIT_ONLY = "audit-only"
STRICT_PROFILE_INTERNAL = "internal"
STRICT_PROFILE_RELEASE = "release"
STRICT_PROFILE_CHOICES = (
    STRICT_PROFILE_AUDIT_ONLY,
    STRICT_PROFILE_INTERNAL,
    STRICT_PROFILE_RELEASE,
)


@dataclass(frozen=True)
class StrictProfileConfig:
    name: str | None
    low_confidence_email_mode: str
    github_hardening_findings_blocking: bool
    writes_allowed: bool


def normalize_strict_profile(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def build_strict_profile_config(
    *,
    profile: str | None,
    low_confidence_email_mode: str,
    audit_github_hardening: bool,
) -> StrictProfileConfig:
    normalized = normalize_strict_profile(profile)
    if normalized not in {*STRICT_PROFILE_CHOICES, None}:
        raise ValueError(f"Unsupported strict profile: {profile}")

    effective_low_confidence = low_confidence_email_mode
    github_hardening_findings_blocking = False
    writes_allowed = True

    if normalized == STRICT_PROFILE_AUDIT_ONLY:
        writes_allowed = False
    elif normalized == STRICT_PROFILE_RELEASE:
        effective_low_confidence = "blocking"
        github_hardening_findings_blocking = bool(audit_github_hardening)

    return StrictProfileConfig(
        name=normalized,
        low_confidence_email_mode=effective_low_confidence,
        github_hardening_findings_blocking=github_hardening_findings_blocking,
        writes_allowed=writes_allowed,
    )


def validate_strict_profile_runtime(
    *,
    profile: str | None,
    fix: bool,
    push: bool,
) -> list[str]:
    normalized = normalize_strict_profile(profile)
    if normalized == STRICT_PROFILE_AUDIT_ONLY and (fix or push):
        return ["--strict-profile audit-only cannot be combined with --fix or --push."]
    return []


def describe_strict_profile(profile: str | None) -> str:
    normalized = normalize_strict_profile(profile)
    if normalized == STRICT_PROFILE_AUDIT_ONLY:
        return "audit-only: blocks repair/push writes and keeps the run read-only."
    if normalized == STRICT_PROFILE_RELEASE:
        return (
            "release: treats low-confidence emails as blocking and, when GitHub hardening "
            "audit is explicitly enabled, treats hardening findings as blocking."
        )
    if normalized == STRICT_PROFILE_INTERNAL:
        return "internal: explicit current-default policy posture."
    return "default: current policy posture."
