from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import fnmatch
import json
from pathlib import Path
from typing import Any, Callable


SUPPRESSION_SCHEMA_VERSION = 1

SUPPRESSIBLE_CATEGORIES: frozenset[str] = frozenset(
    {
        "exfil_code_indicators",
        "tracked_secret_low_confidence",
        "history_secret_low_confidence",
        "git_metadata_secret_low_confidence",
        "tracked_email_low_confidence",
        "history_email_low_confidence",
        "tracked_secret_fixture_matches",
        "history_secret_fixture_matches",
        "tracked_secret_documentation_matches",
        "history_secret_documentation_matches",
        "github_hardening_findings",
        "github_hardening_warnings",
        "secret_file_manual_review_candidates",
    }
)


@dataclass(frozen=True)
class SuppressionRule:
    id: str
    category: str
    pattern: str
    reason: str
    owner: str
    expires: str


def _require_text(item: dict[str, Any], field: str, *, index: int) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"suppression[{index}].{field} must be a non-empty string")
    return value.strip()


def _validate_expiration(raw_value: str, *, index: int, today: date | None = None) -> None:
    current = today or date.today()
    try:
        expires = date.fromisoformat(raw_value)
    except ValueError as exc:
        raise ValueError(
            f"suppression[{index}].expires must be an ISO date in YYYY-MM-DD format"
        ) from exc
    if expires < current:
        raise ValueError(f"suppression[{index}] expired on {raw_value}")


def parse_suppression_payload(payload: object, *, today: date | None = None) -> list[SuppressionRule]:
    if not isinstance(payload, dict):
        raise ValueError("suppression file must contain a JSON object")
    if payload.get("schema_version") != SUPPRESSION_SCHEMA_VERSION:
        raise ValueError(f"suppression file schema_version must be {SUPPRESSION_SCHEMA_VERSION}")

    raw_items = payload.get("suppressions")
    if not isinstance(raw_items, list):
        raise ValueError("suppression file must contain a suppressions array")

    rules: list[SuppressionRule] = []
    seen_ids: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, dict):
            raise ValueError(f"suppression[{index}] must be a JSON object")
        rule_id = _require_text(raw_item, "id", index=index)
        if rule_id in seen_ids:
            raise ValueError(f"suppression id is duplicated: {rule_id}")
        seen_ids.add(rule_id)

        category = _require_text(raw_item, "category", index=index)
        if category not in SUPPRESSIBLE_CATEGORIES:
            raise ValueError(f"suppression[{index}].category is not suppressible: {category}")
        pattern = _require_text(raw_item, "pattern", index=index)
        reason = _require_text(raw_item, "reason", index=index)
        owner = _require_text(raw_item, "owner", index=index)
        expires = _require_text(raw_item, "expires", index=index)
        _validate_expiration(expires, index=index, today=today)
        rules.append(
            SuppressionRule(
                id=rule_id,
                category=category,
                pattern=pattern,
                reason=reason,
                owner=owner,
                expires=expires,
            )
        )
    return rules


def load_suppression_rules(path: Path, *, today: date | None = None) -> list[SuppressionRule]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"suppression file does not exist: {path}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"suppression file is not valid JSON: {exc}") from exc
    return parse_suppression_payload(payload, today=today)


def suppression_rule_to_public_dict(
    rule: SuppressionRule,
    *,
    redact_sensitive_text: Callable[[str], str],
) -> dict[str, str]:
    return {
        "id": redact_sensitive_text(rule.id),
        "category": rule.category,
        "pattern": redact_sensitive_text(rule.pattern),
        "reason": redact_sensitive_text(rule.reason),
        "owner": redact_sensitive_text(rule.owner),
        "expires": rule.expires,
    }


def apply_suppression_rules(
    report: object,
    rules: list[SuppressionRule],
    *,
    redact_sensitive_text: Callable[[str], str],
) -> list[dict[str, str]]:
    suppressed: list[dict[str, str]] = []
    if not rules:
        return suppressed

    by_category: dict[str, list[SuppressionRule]] = {}
    for rule in rules:
        by_category.setdefault(rule.category, []).append(rule)

    for category, category_rules in by_category.items():
        raw_values = getattr(report, category, None)
        if not isinstance(raw_values, list):
            continue

        kept: list[str] = []
        for raw_value in raw_values:
            text = str(raw_value)
            matched_rule: SuppressionRule | None = None
            for rule in category_rules:
                if fnmatch.fnmatchcase(text, rule.pattern) or fnmatch.fnmatchcase(
                    redact_sensitive_text(text),
                    rule.pattern,
                ):
                    matched_rule = rule
                    break
            if matched_rule is None:
                kept.append(text)
                continue

            suppressed.append(
                {
                    "id": redact_sensitive_text(matched_rule.id),
                    "category": category,
                    "pattern": redact_sensitive_text(matched_rule.pattern),
                    "reason": redact_sensitive_text(matched_rule.reason),
                    "owner": redact_sensitive_text(matched_rule.owner),
                    "expires": matched_rule.expires,
                    "finding": redact_sensitive_text(text),
                }
            )

        setattr(report, category, kept)

    return suppressed
