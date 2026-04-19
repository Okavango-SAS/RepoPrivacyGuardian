from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Mapping


GITHUB_REPO_API_URL = "https://api.github.com/repos/{owner}/{repo}"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_HARDENING_TOKEN_ENV_KEYS = (
    "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)
GITHUB_REMOTE_RE = re.compile(r"github\.com[:/]([^/]+)/([^/.]+)(?:\.git)?$", re.IGNORECASE)
ALLOWED_GITHUB_API_HOSTS = {"api.github.com"}


def read_github_cli_token(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[str | None, str]:
    try:
        proc = runner(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return None, "missing"
    except Exception as exc:
        return None, f"gh_error:{exc}"

    token = proc.stdout.strip()
    if proc.returncode == 0 and token:
        return token, "ready"

    detail = proc.stderr.strip() or proc.stdout.strip()
    if detail:
        return None, detail
    return None, "not_authenticated"


def infer_github_username_from_noreply(email: str) -> str | None:
    normalized = email.strip().lower()
    match = re.match(r"^[0-9]+\+([^@]+)@users\.noreply\.github\.com$", normalized)
    if not match:
        return None
    return match.group(1)


def parse_github_remote_owner(remote_url: str) -> str | None:
    if not remote_url:
        return None
    normalized = remote_url.strip()

    match = GITHUB_REMOTE_RE.search(normalized)
    if not match:
        redacted_scp = re.match(
            r"^[^@\s]+@([^:\s]+):([^/]+)/([^/.]+)(?:\.git)?$",
            normalized,
            flags=re.IGNORECASE,
        )
        if redacted_scp and redacted_scp.group(1).lower().endswith(".invalid"):
            return redacted_scp.group(2)
        return None
    return match.group(1)


def parse_github_remote_slug(remote_url: str) -> tuple[str, str] | None:
    if not remote_url:
        return None
    match = GITHUB_REMOTE_RE.search(remote_url.strip())
    if not match:
        return None
    return match.group(1), match.group(2)


def validate_outbound_https_url(url: str, allowed_hosts: set[str]) -> str:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        raise ValueError(f"Outbound request blocked: only HTTPS URLs are allowed ({url}).")
    if host not in {item.lower() for item in allowed_hosts}:
        raise ValueError(
            f"Outbound request blocked: host '{host}' is not in the allowlist."
        )
    return url


def is_public_github_remote(remote_url: str) -> tuple[bool | None, str]:
    slug = parse_github_remote_slug(remote_url)
    if not slug:
        return None, "not_github"

    owner, repo = slug
    url = validate_outbound_https_url(
        GITHUB_REPO_API_URL.format(owner=owner, repo=repo),
        ALLOWED_GITHUB_API_HOSTS,
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Repo-Privacy-Guardian",
        },
    )

    try:
        # URL validated against the HTTPS GitHub API allowlist.
        # nosec B310
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except ValueError:
        return None, "invalid_request_url"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, "private_or_not_found"
        if exc.code == 403:
            return None, "forbidden_or_rate_limited"
        return None, f"http_error_{exc.code}"
    except (TimeoutError, OSError, json.JSONDecodeError):
        return None, "request_failed"

    private = payload.get("private")
    if isinstance(private, bool):
        return (not private), "public" if not private else "private"

    return None, "unknown_visibility"


def resolve_github_hardening_token(
    env: Mapping[str, str] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    read_cli_token: Callable[
        [Callable[..., subprocess.CompletedProcess[str]]],
        tuple[str | None, str],
    ] = read_github_cli_token,
) -> str | None:
    current_env = os.environ if env is None else env
    for key in GITHUB_HARDENING_TOKEN_ENV_KEYS:
        value = current_env.get(key, "").strip()
        if value:
            return value
    token, _status = read_cli_token(runner)
    return token


def build_github_api_headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Repo-Privacy-Guardian",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_api_get_json(url: str, token: str | None = None) -> tuple[object | None, str]:
    url = validate_outbound_https_url(url, ALLOWED_GITHUB_API_HOSTS)
    request = urllib.request.Request(url, headers=build_github_api_headers(token))

    try:
        # URL validated against the HTTPS GitHub API allowlist.
        # nosec B310
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = response.read().decode("utf-8", errors="replace").strip()
            if not payload:
                return {}, f"http_{getattr(response, 'status', 200)}"
            return json.loads(payload), f"http_{getattr(response, 'status', 200)}"
    except ValueError:
        return None, "invalid_request_url"
    except urllib.error.HTTPError as exc:
        return None, f"http_{exc.code}"
    except (TimeoutError, OSError, json.JSONDecodeError):
        return None, "request_failed"


def github_api_probe_enabled(url: str, token: str | None = None) -> tuple[bool | None, str]:
    url = validate_outbound_https_url(url, ALLOWED_GITHUB_API_HOSTS)
    request = urllib.request.Request(url, headers=build_github_api_headers(token))

    try:
        # URL validated against the HTTPS GitHub API allowlist.
        # nosec B310
        with urllib.request.urlopen(request, timeout=8) as response:
            return True, f"http_{getattr(response, 'status', 200)}"
    except ValueError:
        return None, "invalid_request_url"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, "http_404"
        return None, f"http_{exc.code}"
    except (TimeoutError, OSError):
        return None, "request_failed"


def audit_github_release_hardening(
    repo: Path,
    remote_url: str,
    token: str | None = None,
    *,
    token_resolver: Callable[[], str | None] | None = None,
    json_getter: Callable[[str, str | None], tuple[object | None, str]] = github_api_get_json,
    probe_enabled: Callable[[str, str | None], tuple[bool | None, str]] = github_api_probe_enabled,
    text_normalizer: Callable[[list[str]], list[str]] | None = None,
) -> tuple[list[str], list[str]]:
    findings: list[str] = []
    warnings: list[str] = []
    slug = parse_github_remote_slug(remote_url)
    if not slug:
        warnings.append("GitHub hardening audit skipped: origin is not a GitHub remote.")
        return findings, warnings

    if not (repo / ".github" / "CODEOWNERS").exists():
        findings.append("GitHub repository hardening: .github/CODEOWNERS is missing.")

    owner, repo_name = slug
    repo_api_url = GITHUB_REPO_API_URL.format(owner=owner, repo=repo_name)
    resolved_token = token if token is not None else (token_resolver() if token_resolver else None)
    repo_payload, repo_reason = json_getter(repo_api_url, resolved_token)
    if not isinstance(repo_payload, dict):
        warnings.append(
            f"GitHub hardening audit could not read repository metadata ({repo_reason})."
        )
        return findings, warnings

    default_branch = str(repo_payload.get("default_branch") or "main")
    if repo_payload.get("has_wiki") is True:
        findings.append("GitHub repository settings: wiki is enabled.")
    if repo_payload.get("has_projects") is True:
        findings.append("GitHub repository settings: projects are enabled.")
    if repo_payload.get("allow_auto_merge") is True:
        findings.append("GitHub repository settings: auto-merge is enabled.")

    if not resolved_token:
        warnings.append(
            "Admin-only GitHub hardening checks were skipped. "
            "Set REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN "
            "or authenticate GitHub CLI with `gh auth login` to audit branch protection, "
            "Actions permissions, and security alerts."
        )
        if text_normalizer is None:
            return findings, warnings
        return text_normalizer(findings), text_normalizer(warnings)

    protection_url = (
        f"{repo_api_url}/branches/"
        f"{urllib.parse.quote(default_branch, safe='')}/protection"
    )
    protection_payload, protection_reason = json_getter(
        protection_url,
        resolved_token,
    )
    if isinstance(protection_payload, dict):
        pull_request_reviews = protection_payload.get("required_pull_request_reviews") or {}
        if not isinstance(pull_request_reviews, dict):
            pull_request_reviews = {}
        if not pull_request_reviews:
            findings.append(
                "GitHub default branch protection: pull request reviews are not required."
            )
        else:
            if int(pull_request_reviews.get("required_approving_review_count") or 0) < 1:
                findings.append(
                    "GitHub default branch protection: at least one approving review is not required."
                )
            if pull_request_reviews.get("require_code_owner_reviews") is not True:
                findings.append(
                    "GitHub default branch protection: code owner reviews are not required."
                )
            if pull_request_reviews.get("dismiss_stale_reviews") is not True:
                findings.append(
                    "GitHub default branch protection: stale reviews are not dismissed."
                )

        conversation_resolution = protection_payload.get("required_conversation_resolution") or {}
        if not isinstance(conversation_resolution, dict) or conversation_resolution.get("enabled") is not True:
            findings.append(
                "GitHub default branch protection: conversation resolution is not required."
            )

        status_checks = protection_payload.get("required_status_checks") or {}
        if not isinstance(status_checks, dict) or not (
            status_checks.get("contexts") or status_checks.get("checks")
        ):
            findings.append(
                "GitHub default branch protection: required status checks are not configured."
            )
        elif status_checks.get("strict") is not True:
            findings.append(
                "GitHub default branch protection: required status checks are not strict."
            )

        allow_force_pushes = protection_payload.get("allow_force_pushes") or {}
        if isinstance(allow_force_pushes, dict) and allow_force_pushes.get("enabled") is True:
            findings.append("GitHub default branch protection: force pushes are allowed.")

        allow_deletions = protection_payload.get("allow_deletions") or {}
        if isinstance(allow_deletions, dict) and allow_deletions.get("enabled") is True:
            findings.append("GitHub default branch protection: branch deletion is allowed.")
    elif protection_reason == "http_404":
        findings.append("GitHub default branch protection is not enabled.")
    else:
        warnings.append(
            f"GitHub default branch protection could not be audited ({protection_reason})."
        )

    actions_payload, actions_reason = json_getter(
        f"{repo_api_url}/actions/permissions",
        resolved_token,
    )
    if isinstance(actions_payload, dict):
        if str(actions_payload.get("allowed_actions") or "").lower() == "all":
            findings.append("GitHub Actions permissions: all external actions are allowed.")
        if actions_payload.get("sha_pinning_required") is not True:
            findings.append("GitHub Actions permissions: SHA pinning is not required.")
    else:
        warnings.append(
            f"GitHub Actions permissions could not be audited ({actions_reason})."
        )

    workflow_payload, workflow_reason = json_getter(
        f"{repo_api_url}/actions/permissions/workflow",
        resolved_token,
    )
    if isinstance(workflow_payload, dict):
        if str(workflow_payload.get("default_workflow_permissions") or "").lower() != "read":
            findings.append(
                "GitHub Actions workflow permissions are broader than read-only."
            )
        if workflow_payload.get("can_approve_pull_request_reviews") is True:
            findings.append("GitHub Actions workflow permissions allow PR approval.")
    else:
        warnings.append(
            f"GitHub Actions workflow permissions could not be audited ({workflow_reason})."
        )

    vulnerability_enabled, vulnerability_reason = probe_enabled(
        f"{repo_api_url}/vulnerability-alerts",
        resolved_token,
    )
    if vulnerability_enabled is False:
        findings.append("GitHub security alerts: Dependabot vulnerability alerts are disabled.")
    elif vulnerability_enabled is None:
        warnings.append(
            f"GitHub vulnerability alerts could not be audited ({vulnerability_reason})."
        )

    security_fixes_payload, security_fixes_reason = json_getter(
        f"{repo_api_url}/automated-security-fixes",
        resolved_token,
    )
    if isinstance(security_fixes_payload, dict):
        if security_fixes_payload.get("enabled") is not True or security_fixes_payload.get("paused") is True:
            findings.append(
                "GitHub security fixes: automated security fixes are disabled or paused."
            )
    elif security_fixes_reason == "http_404":
        findings.append("GitHub security fixes: automated security fixes are disabled.")
    else:
        warnings.append(
            f"GitHub automated security fixes could not be audited ({security_fixes_reason})."
        )

    if text_normalizer is None:
        return findings, warnings
    return text_normalizer(findings), text_normalizer(warnings)
