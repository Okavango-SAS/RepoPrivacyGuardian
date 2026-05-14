"""Pure secret taxonomy aggregation helpers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from re import Pattern
from typing import Literal


SecretTaxonomyBucketName = Literal[
    "high_confidence",
    "low_confidence",
    "fixtures",
    "documentation",
]


@dataclass
class SecretTaxonomyBuckets:
    high_confidence: list[str] = field(default_factory=list)
    low_confidence: list[str] = field(default_factory=list)
    fixtures: list[str] = field(default_factory=list)
    documentation: list[str] = field(default_factory=list)

    def as_tuple(self) -> tuple[list[str], list[str], list[str], list[str]]:
        return (
            self.high_confidence,
            self.low_confidence,
            self.fixtures,
            self.documentation,
        )

    def list_for(self, bucket: SecretTaxonomyBucketName) -> list[str]:
        if bucket == "high_confidence":
            return self.high_confidence
        if bucket == "low_confidence":
            return self.low_confidence
        if bucket == "fixtures":
            return self.fixtures
        return self.documentation


@dataclass(frozen=True)
class SecretTaxonomyMatch:
    bucket: SecretTaxonomyBucketName
    entry: str


def classify_secret_taxonomy_line(
    *,
    rel_path: str | None,
    line_number: int,
    line: str,
    secret_pattern: Pattern[str],
    low_confidence_pattern: Pattern[str],
    classify_secret_match_context: Callable[[str | None, str], str],
    history: bool = False,
    preview_limit: int = 240,
) -> SecretTaxonomyMatch | None:
    has_high_confidence_secret = secret_pattern.search(line) is not None
    has_low_confidence_secret = (
        not has_high_confidence_secret
        and low_confidence_pattern.search(line) is not None
    )
    if not has_high_confidence_secret and not has_low_confidence_secret:
        return None

    rel = rel_path or "-"
    snippet = line.strip()[:preview_limit]
    entry = f"L{line_number}:{rel}:{snippet}" if history else f"{rel}:{line_number}:{snippet}"
    context = classify_secret_match_context(rel_path, snippet)

    if context == "fixture":
        return SecretTaxonomyMatch("fixtures", entry)
    if context == "documentation":
        return SecretTaxonomyMatch("documentation", entry)
    if has_high_confidence_secret:
        return SecretTaxonomyMatch("high_confidence", entry)
    return SecretTaxonomyMatch("low_confidence", entry)


def append_secret_taxonomy_match(
    *,
    buckets: SecretTaxonomyBuckets,
    rel_path: str | None,
    line_number: int,
    line: str,
    secret_pattern: Pattern[str],
    low_confidence_pattern: Pattern[str],
    classify_secret_match_context: Callable[[str | None, str], str],
    max_matches: int,
    history: bool = False,
    preview_limit: int = 240,
) -> SecretTaxonomyMatch | None:
    match = classify_secret_taxonomy_line(
        rel_path=rel_path,
        line_number=line_number,
        line=line,
        secret_pattern=secret_pattern,
        low_confidence_pattern=low_confidence_pattern,
        classify_secret_match_context=classify_secret_match_context,
        history=history,
        preview_limit=preview_limit,
    )
    if match is None:
        return None

    target = buckets.list_for(match.bucket)
    if len(target) < max_matches:
        target.append(match.entry)
    return match
