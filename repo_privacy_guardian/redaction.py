"""Redaction and finding-context classification helpers."""

from __future__ import annotations

import re
from pathlib import Path

from repo_privacy_guardian.core import (
    DEFAULT_PLACEHOLDER,
    EMAIL_FIXTURE_PATH_RE,
    EMAIL_FIXTURE_SNIPPET_RE,
    EMAIL_LOW_CONFIDENCE_FILE_RE,
    EMAIL_LOW_CONFIDENCE_PATH_RE,
    EMAIL_LOW_CONFIDENCE_SNIPPET_RE,
    EMAIL_NOISE_DOMAINS,
    EMAIL_RE,
    LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE,
    PERSONAL_PATH_LITERAL_PATTERNS,
    REDACTED_EMAIL,
    REDACTED_IDENTITY_TOKEN,
    REDACTED_SECRET,
    SECRET_CONTENT_RE,
    SECRET_DOCUMENTATION_FILE_RE,
    SECRET_DOCUMENTATION_PATH_RE,
    SECRET_FIXTURE_PATH_RE,
    SECRET_SAFE_PLACEHOLDER_RE,
    SSH_REMOTE_PSEUDO_EMAILS,
)
from repo_privacy_guardian.github import parse_github_remote_owner


def is_relevant_email_candidate(email: str) -> bool:
    lowered = email.strip().lower()
    if not lowered or "@" not in lowered:
        return False

    if lowered == DEFAULT_PLACEHOLDER.lower():
        return True

    local, domain = lowered.rsplit("@", 1)
    if not local or not domain:
        return False

    if (local, domain) in SSH_REMOTE_PSEUDO_EMAILS:
        return False
    if domain in EMAIL_NOISE_DOMAINS:
        return False
    if domain.endswith(".local") or domain.endswith(".invalid") or domain.endswith(".example"):
        return False
    if domain.replace(".", "").isdigit():
        return False

    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False

    return True


def extract_email_match_context(match_line: str) -> tuple[str | None, str]:
    if not match_line:
        return None, ""

    if match_line.startswith("L"):
        parts = match_line.split(":", 3)
        if len(parts) == 4:
            return parts[1] if parts[1] != "-" else None, parts[3]
        parts = match_line.split(":", 2)
        snippet = parts[2] if len(parts) == 3 else match_line
        return None, snippet

    parts = match_line.split(":", 3)
    if len(parts) >= 4:
        return parts[0], parts[3]
    if len(parts) >= 2:
        return parts[0], parts[-1]
    return None, match_line


def classify_email_match_context(rel_path: str | None, snippet: str) -> str:
    normalized_path = (rel_path or "").replace("\\", "/").strip().lower()
    normalized_snippet = (snippet or "").strip().lower()

    if normalized_path:
        if EMAIL_FIXTURE_PATH_RE.search(normalized_path):
            return "fixture"
        file_name = Path(normalized_path).name
        if EMAIL_LOW_CONFIDENCE_FILE_RE.search(file_name):
            return "low_confidence"
        if EMAIL_LOW_CONFIDENCE_PATH_RE.search(normalized_path):
            return "low_confidence"

    if EMAIL_FIXTURE_SNIPPET_RE.search(normalized_snippet):
        return "fixture"
    if EMAIL_LOW_CONFIDENCE_SNIPPET_RE.search(normalized_snippet):
        return "low_confidence"

    return "active"


def is_low_confidence_email_context(rel_path: str | None, snippet: str) -> bool:
    return classify_email_match_context(rel_path, snippet) != "active"


def split_email_matches_by_taxonomy(
    matches: list[str],
) -> tuple[list[str], list[str], list[str]]:
    high_confidence: list[str] = []
    low_confidence: list[str] = []
    fixtures: list[str] = []

    for item in matches:
        rel_path, snippet = extract_email_match_context(item)
        context = classify_email_match_context(rel_path, snippet)
        if context == "fixture":
            fixtures.append(item)
        elif context == "low_confidence":
            low_confidence.append(item)
        else:
            high_confidence.append(item)

    return high_confidence, low_confidence, fixtures


def split_email_matches_by_confidence(matches: list[str]) -> tuple[list[str], list[str]]:
    high_confidence, low_confidence, fixtures = split_email_matches_by_taxonomy(matches)
    return high_confidence, low_confidence + fixtures


def extract_secret_match_context(match_line: str) -> tuple[str | None, str]:
    if not match_line:
        return None, ""

    if match_line.startswith("L"):
        parts = match_line.split(":", 3)
        if len(parts) == 4:
            return parts[1] if parts[1] != "-" else None, parts[3]
        parts = match_line.split(":", 2)
        snippet = parts[2] if len(parts) == 3 else match_line
        return None, snippet

    parts = match_line.split(":", 2)
    if len(parts) == 3:
        return parts[0], parts[2]
    if len(parts) >= 2:
        return parts[0], parts[-1]
    return None, match_line


def classify_secret_match_context(rel_path: str | None, snippet: str) -> str:
    normalized_path = (rel_path or "").replace("\\", "/").strip().lower()
    normalized_snippet = (snippet or "").strip()
    if not normalized_path or not normalized_snippet:
        return "active"

    if not SECRET_SAFE_PLACEHOLDER_RE.search(normalized_snippet):
        return "active"

    if SECRET_FIXTURE_PATH_RE.search(normalized_path):
        return "fixture"

    file_name = Path(normalized_path).name
    if SECRET_DOCUMENTATION_PATH_RE.search(normalized_path) or SECRET_DOCUMENTATION_FILE_RE.search(file_name):
        return "documentation"

    return "active"


def extract_personal_path_literals(text: str) -> list[str]:
    if not text:
        return []

    findings: list[str] = []
    seen: set[str] = set()
    for pattern in PERSONAL_PATH_LITERAL_PATTERNS:
        for match in pattern.finditer(text):
            candidate = match.group(0).strip().strip("`\"'()[]{}")
            candidate = candidate.rstrip(".,;:")
            if not candidate or candidate in seen:
                continue
            if any(existing.endswith(candidate) for existing in seen):
                continue
            nested = [existing for existing in seen if candidate.endswith(existing)]
            for existing in nested:
                seen.remove(existing)
                findings.remove(existing)
            seen.add(candidate)
            findings.append(candidate)
    return findings


def split_unexpected_emails_by_origin_ownership(
    unexpected_emails: list[str],
    origin_url: str | None,
    allowed_remote_owners: set[str] | list[str],
) -> tuple[list[str], list[str]]:
    if not unexpected_emails:
        return [], []

    normalized_owners = {
        owner.strip().lower()
        for owner in allowed_remote_owners
        if owner and owner.strip()
    }
    origin_owner = parse_github_remote_owner(origin_url or "")

    if not origin_url or not origin_owner or not normalized_owners:
        return list(unexpected_emails), []
    if origin_owner and origin_owner.lower() in normalized_owners:
        return list(unexpected_emails), []
    return [], list(unexpected_emails)


def _redact_low_confidence_secret_assignment(match: re.Match[str]) -> str:
    quote = match.group("quote") or ""
    closing_quote = quote if quote else ""
    return f"{match.group('key')}{match.group('sep')}{quote}{REDACTED_SECRET}{closing_quote}"


def redact_sensitive_text(value: str) -> str:
    text = str(value)
    text = SECRET_CONTENT_RE.sub(REDACTED_SECRET, text)
    text = LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE.sub(_redact_low_confidence_secret_assignment, text)
    # Handle escaped Windows paths often seen inside JSON string literals.
    text = re.sub(r"C:\\\\Users\\\\[^\\\s]+", r"C:\\\\Users\\\\<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(
        r"C:\\\\Documents and Settings\\\\[^\\\s]+",
        r"C:\\\\Documents and Settings\\\\<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"AppData\\\\[^\\\s]+", r"AppData\\\\<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(r"C:\\Users\\[^\\\s]+", r"C:\\Users\\<redacted>", text, flags=re.IGNORECASE)
    text = re.sub(
        r"C:\\Documents and Settings\\[^\\\s]+",
        r"C:\\Documents and Settings\\<redacted>",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"/Users/[^/\s]+", "/Users/<redacted>", text)
    text = re.sub(r"/home/[^/\s]+", "/home/<redacted>", text)
    text = re.sub(r"AppData\\[^\\\s]+", r"AppData\\<redacted>", text, flags=re.IGNORECASE)
    text = EMAIL_RE.sub(REDACTED_EMAIL, text)
    return text


def _redact_email_list(emails: list[str]) -> list[str]:
    if not emails:
        return []
    return [REDACTED_EMAIL for _ in emails]


def _redact_identity_list(items: list[str]) -> list[str]:
    if not items:
        return []
    return [REDACTED_IDENTITY_TOKEN for _ in items]


def _redact_text_list(items: list[str]) -> list[str]:
    return [redact_sensitive_text(item) for item in items]
