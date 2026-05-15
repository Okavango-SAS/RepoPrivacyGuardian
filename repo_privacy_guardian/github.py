from __future__ import annotations

from dataclasses import dataclass
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
GITHUB_USER_REPOS_API_URL = "https://api.github.com/users/{owner}/repos"
GITHUB_ORG_REPOS_API_URL = "https://api.github.com/orgs/{owner}/repos"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_REPOS_PER_PAGE = 100
GITHUB_REPOS_MAX_PAGES = 100
GITHUB_CLI_AUTH_TIMEOUT_SECONDS = 10
GITHUB_HARDENING_TOKEN_ENV_KEYS = (
    "REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)
GITHUB_SCP_REMOTE_RE = re.compile(
    r"^(?:[^@\s]+@)?github\.com:([^/\s]+)/([^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
GITHUB_BARE_REMOTE_RE = re.compile(
    r"^github\.com/([^/\s]+)/([^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
REDACTED_SCP_REMOTE_RE = re.compile(
    r"^[^@\s]+@([^:\s]+):([^/\s]+)/([^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
ALLOWED_GITHUB_API_HOSTS = {"api.github.com"}
GITHUB_ACTIONS_APP_ID = 15368
AUTOMATIC_WORKFLOW_TRIGGERS = {
    "push",
    "pull_request",
    "pull_request_target",
    "schedule",
    "workflow_run",
}
GITHUB_HARDENING_PUBLIC_METADATA_CHECKS = (
    "local CODEOWNERS",
    "repository visibility/archive/settings metadata",
    "private vulnerability reporting for public repositories when GitHub allows unauthenticated metadata reads",
)
GITHUB_HARDENING_TOKEN_CHECKS = (
    "default branch protection",
    "GitHub Actions repository and workflow permissions",
    "Dependabot vulnerability alerts and security updates",
    "secret scanning configuration and open alert presence",
    "immutable releases",
)


@dataclass(frozen=True)
class GitHubRemoteRepository:
    name: str
    full_name: str
    clone_url: str
    html_url: str
    private: bool
    fork: bool


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
            timeout=GITHUB_CLI_AUTH_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return None, "missing"
    except subprocess.TimeoutExpired:
        return None, "timeout"
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
    slug = parse_github_remote_slug(remote_url)
    if slug:
        return slug[0]

    normalized = (remote_url or "").strip()
    redacted_scp = REDACTED_SCP_REMOTE_RE.match(normalized)
    if redacted_scp and redacted_scp.group(1).lower().endswith(".invalid"):
        return redacted_scp.group(2)
    return None


def _strip_git_suffix(repo: str) -> str:
    if repo.lower().endswith(".git"):
        return repo[:-4]
    return repo


def _valid_github_slug_component(value: str) -> bool:
    return bool(value) and "/" not in value and "\\" not in value and not any(char.isspace() for char in value)


def _slug_from_github_path(path: str) -> tuple[str, str] | None:
    parts = [urllib.parse.unquote(item) for item in path.strip("/").split("/") if item]
    if len(parts) != 2:
        return None
    owner, repo = parts
    repo = _strip_git_suffix(repo)
    if not _valid_github_slug_component(owner) or not _valid_github_slug_component(repo):
        return None
    return owner, repo


def parse_github_remote_slug(remote_url: str) -> tuple[str, str] | None:
    if not remote_url:
        return None
    normalized = remote_url.strip()

    scp_match = GITHUB_SCP_REMOTE_RE.match(normalized)
    if scp_match:
        owner, repo = scp_match.group(1), _strip_git_suffix(scp_match.group(2))
        if not _valid_github_slug_component(owner) or not _valid_github_slug_component(repo):
            return None
        return owner, repo

    bare_match = GITHUB_BARE_REMOTE_RE.match(normalized)
    if bare_match:
        owner, repo = bare_match.group(1), _strip_git_suffix(bare_match.group(2))
        if not _valid_github_slug_component(owner) or not _valid_github_slug_component(repo):
            return None
        return owner, repo

    parsed = urllib.parse.urlparse(normalized)
    host = (parsed.hostname or "").lower()
    if host != "github.com":
        return None
    return _slug_from_github_path(parsed.path)


def github_repo_api_url(owner: str, repo: str) -> str:
    owner_path = urllib.parse.quote(owner.strip(), safe="")
    repo_path = urllib.parse.quote(repo.strip(), safe="")
    return validate_outbound_https_url(
        GITHUB_REPO_API_URL.format(owner=owner_path, repo=repo_path),
        ALLOWED_GITHUB_API_HOSTS,
    )


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
    url = github_repo_api_url(owner, repo)
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


def _github_owner_repos_url(owner: str, endpoint: str, page: int) -> str:
    owner_path = urllib.parse.quote(owner.strip(), safe="")
    query = urllib.parse.urlencode(
        {
            "per_page": str(GITHUB_REPOS_PER_PAGE),
            "page": str(page),
            "type": "all",
        }
    )
    return validate_outbound_https_url(
        endpoint.format(owner=owner_path) + f"?{query}",
        ALLOWED_GITHUB_API_HOSTS,
    )


def _fetch_github_owner_repo_pages(
    *,
    owner: str,
    endpoint: str,
    token: str | None,
    json_getter: Callable[[str, str | None], tuple[object | None, str]],
) -> tuple[list[dict[str, object]] | None, str]:
    repos: list[dict[str, object]] = []
    page = 1
    while page <= GITHUB_REPOS_MAX_PAGES:
        url = _github_owner_repos_url(owner, endpoint, page)
        payload, status = json_getter(url, token)
        if payload is None:
            return None, status
        if not isinstance(payload, list):
            return None, f"unexpected_payload:{status}"
        if not payload:
            return repos, status

        for item in payload:
            if isinstance(item, dict):
                repos.append(item)
        page += 1

    return None, "page_limit_reached"


def fetch_github_owner_repositories(
    owner: str,
    *,
    token: str | None = None,
    include_forks: bool = False,
    public_only: bool = False,
    repo_names: list[str] | None = None,
    json_getter: Callable[[str, str | None], tuple[object | None, str]] = github_api_get_json,
) -> tuple[list[GitHubRemoteRepository], list[str]]:
    normalized_owner = owner.strip()
    warnings: list[str] = []
    if not normalized_owner:
        return [], ["GitHub owner is empty."]

    requested_names = {
        item.strip().lower()
        for item in (repo_names or [])
        if item and item.strip()
    }

    raw_repos, status = _fetch_github_owner_repo_pages(
        owner=normalized_owner,
        endpoint=GITHUB_USER_REPOS_API_URL,
        token=token,
        json_getter=json_getter,
    )
    if raw_repos is None and status == "http_404":
        raw_repos, status = _fetch_github_owner_repo_pages(
            owner=normalized_owner,
            endpoint=GITHUB_ORG_REPOS_API_URL,
            token=token,
            json_getter=json_getter,
        )

    if raw_repos is None:
        if status == "http_404":
            warnings.append(f"GitHub owner not found or not accessible: {normalized_owner}.")
        elif status == "http_403":
            warnings.append(
                "GitHub repository discovery was forbidden or rate-limited; configure a token or authenticate gh."
            )
        elif status == "page_limit_reached":
            warnings.append(
                "GitHub repository discovery reached the page limit; narrow --repos or split the owner audit."
            )
        else:
            warnings.append(f"GitHub repository discovery failed: {status}.")
        return [], warnings

    repos: list[GitHubRemoteRepository] = []
    seen_full_names: set[str] = set()
    for item in raw_repos:
        name = str(item.get("name") or "").strip()
        full_name = str(item.get("full_name") or "").strip()
        if not name or not full_name:
            warnings.append("Skipped a GitHub repository record with missing name/full_name.")
            continue

        if requested_names and name.lower() not in requested_names and full_name.lower() not in requested_names:
            continue

        is_fork = bool(item.get("fork"))
        if is_fork and not include_forks:
            continue

        is_private = bool(item.get("private"))
        if public_only and is_private:
            continue

        clone_url = str(item.get("clone_url") or "").strip()
        html_url = str(item.get("html_url") or "").strip()
        if not clone_url and not html_url:
            warnings.append(f"Skipped {full_name}: no clone URL was provided by GitHub.")
            continue

        if full_name.lower() in seen_full_names:
            continue
        seen_full_names.add(full_name.lower())
        repos.append(
            GitHubRemoteRepository(
                name=name,
                full_name=full_name,
                clone_url=clone_url,
                html_url=html_url,
                private=is_private,
                fork=is_fork,
            )
        )

    return repos, warnings


def _strip_yaml_scalar(value: str) -> str:
    normalized = value.strip()
    if (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0] in {"'", '"'}
    ):
        return normalized[1:-1]
    return normalized.split(" #", 1)[0].strip()


def _workflow_has_automatic_trigger(workflow_text: str) -> bool:
    inline_match = re.search(r"(?m)^on:\s*\[([^\]]+)\]\s*$", workflow_text)
    if inline_match:
        triggers = {
            item.strip().strip("'\"")
            for item in inline_match.group(1).split(",")
            if item.strip()
        }
        return bool(triggers & AUTOMATIC_WORKFLOW_TRIGGERS)

    scalar_match = re.search(r"(?m)^on:\s*([A-Za-z_]+)\s*$", workflow_text)
    if scalar_match:
        return scalar_match.group(1) in AUTOMATIC_WORKFLOW_TRIGGERS

    return bool(
        re.search(
            r"(?m)^  (?:"
            + "|".join(re.escape(item) for item in sorted(AUTOMATIC_WORKFLOW_TRIGGERS))
            + r"):\s*$",
            workflow_text,
        )
    )


def _extract_automatic_workflow_check_names(workflow_text: str) -> set[str]:
    if not _workflow_has_automatic_trigger(workflow_text):
        return set()

    names: set[str] = set()
    lines = workflow_text.splitlines()
    in_jobs = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if not in_jobs:
            if re.match(r"^jobs:\s*(?:#.*)?$", line):
                in_jobs = True
            index += 1
            continue

        if line and not line.startswith(" ") and not line.lstrip().startswith("#"):
            break

        job_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
        if not job_match:
            index += 1
            continue

        job_id = job_match.group(1)
        job_name = job_id
        manual_only = False
        index += 1
        while index < len(lines):
            child = lines[index]
            if re.match(r"^  [A-Za-z0-9_-]+:\s*(?:#.*)?$", child):
                break
            if child and not child.startswith(" ") and not child.lstrip().startswith("#"):
                break
            name_match = re.match(r"^    name:\s*(.+?)\s*$", child)
            if name_match:
                job_name = _strip_yaml_scalar(name_match.group(1))
            if_match = re.match(r"^    if:\s*(.+?)\s*$", child)
            if if_match:
                condition = if_match.group(1)
                if "workflow_dispatch" in condition or "inputs.extended_checks" in condition:
                    manual_only = True
            index += 1

        if not manual_only:
            names.add(job_name)

    return names


def collect_local_automatic_workflow_check_names(repo: Path) -> set[str]:
    workflows_dir = repo / ".github" / "workflows"
    if not workflows_dir.exists() or not workflows_dir.is_dir():
        return set()

    names: set[str] = set()
    for workflow in sorted(
        list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    ):
        try:
            text = workflow.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names.update(_extract_automatic_workflow_check_names(text))
    return names


def _github_actions_required_status_contexts(status_checks: dict[str, object]) -> list[str]:
    contexts: set[str] = set()

    raw_contexts = status_checks.get("contexts")
    if isinstance(raw_contexts, list):
        contexts.update(str(item) for item in raw_contexts if str(item).strip())

    raw_checks = status_checks.get("checks")
    if isinstance(raw_checks, list):
        for item in raw_checks:
            if not isinstance(item, dict):
                continue
            app_id = item.get("app_id")
            if app_id not in {None, GITHUB_ACTIONS_APP_ID}:
                continue
            context = str(item.get("context") or "").strip()
            if context:
                contexts.add(context)

    return sorted(contexts)


def _github_url_with_query(url: str, **params: str) -> str:
    query = urllib.parse.urlencode(params)
    separator = "&" if urllib.parse.urlparse(url).query else "?"
    return validate_outbound_https_url(url + separator + query, ALLOWED_GITHUB_API_HOSTS)


def _github_feature_status(payload: dict[str, object], feature: str) -> str | None:
    security_and_analysis = payload.get("security_and_analysis")
    if not isinstance(security_and_analysis, dict):
        return None
    feature_payload = security_and_analysis.get(feature)
    if not isinstance(feature_payload, dict):
        return None
    status = feature_payload.get("status")
    if status is None:
        return None
    return str(status).strip().lower()


def _github_security_and_analysis_present(payload: dict[str, object]) -> bool:
    return isinstance(payload.get("security_and_analysis"), dict)


def _append_feature_disabled_finding(
    findings: list[str],
    payload: dict[str, object],
    feature: str,
    label: str,
) -> bool:
    status = _github_feature_status(payload, feature)
    if status is None:
        return False
    if status != "enabled":
        findings.append(f"GitHub security and analysis: {label} status is {status}.")
    return True


def _audit_private_vulnerability_reporting(
    *,
    repo_api_url: str,
    token: str | None,
    findings: list[str],
    warnings: list[str],
    json_getter: Callable[[str, str | None], tuple[object | None, str]],
) -> None:
    payload, reason = json_getter(
        f"{repo_api_url}/private-vulnerability-reporting",
        token,
    )
    if isinstance(payload, dict):
        if payload.get("enabled") is not True:
            findings.append(
                "GitHub private vulnerability reporting is not enabled."
            )
    elif reason != "http_422":
        warnings.append(
            f"GitHub private vulnerability reporting could not be audited ({reason})."
        )


def _audit_alert_presence(
    *,
    repo_api_url: str,
    token: str,
    path: str,
    label: str,
    findings: list[str],
    warnings: list[str],
    json_getter: Callable[[str, str | None], tuple[object | None, str]],
) -> None:
    url = _github_url_with_query(
        f"{repo_api_url}/{path}",
        state="open",
        per_page="1",
    )
    payload, reason = json_getter(url, token)
    if isinstance(payload, list):
        if payload:
            findings.append(f"GitHub {label}: at least one open alert exists.")
    else:
        warnings.append(f"GitHub {label} could not be audited ({reason}).")


def audit_github_release_hardening(
    repo: Path,
    remote_url: str,
    token: str | None = None,
    *,
    token_resolver: Callable[[], str | None] | None = None,
    json_getter: Callable[[str, str | None], tuple[object | None, str]] = github_api_get_json,
    probe_enabled: Callable[[str, str | None], tuple[bool | None, str]] = github_api_probe_enabled,
    text_normalizer: Callable[[list[str]], list[str]] | None = None,
    accept_admin_bypass: bool = False,
    accepted_risks: list[str] | None = None,
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
    if token is not None:
        resolved_token = token
    elif token_resolver is not None:
        resolved_token = token_resolver()
    else:
        resolved_token = resolve_github_hardening_token()
    repo_payload, repo_reason = json_getter(repo_api_url, resolved_token)
    if not isinstance(repo_payload, dict):
        warnings.append(
            f"GitHub hardening audit could not read repository metadata ({repo_reason})."
        )
        return findings, warnings

    default_branch = str(repo_payload.get("default_branch") or "main")
    visibility = str(repo_payload.get("visibility") or "").strip().lower()
    if not visibility:
        visibility = "private" if repo_payload.get("private") is True else "public"
    if visibility != "public":
        findings.append(
            f"GitHub repository visibility: repository is {visibility}; confirm this matches release intent."
        )
    if repo_payload.get("archived") is True:
        findings.append("GitHub repository settings: repository is archived.")
    if repo_payload.get("disabled") is True:
        findings.append("GitHub repository settings: repository is disabled.")
    if repo_payload.get("has_issues") is False:
        findings.append(
            "GitHub repository settings: issues are disabled; confirm an alternate vulnerability intake path exists."
        )
    if repo_payload.get("has_wiki") is True:
        findings.append("GitHub repository settings: wiki is enabled.")
    if repo_payload.get("has_projects") is True:
        findings.append("GitHub repository settings: projects are enabled.")
    if repo_payload.get("allow_auto_merge") is True:
        findings.append("GitHub repository settings: auto-merge is enabled.")

    _audit_private_vulnerability_reporting(
        repo_api_url=repo_api_url,
        token=resolved_token,
        findings=findings,
        warnings=warnings,
        json_getter=json_getter,
    )
    security_and_analysis_seen = _github_security_and_analysis_present(repo_payload)
    if security_and_analysis_seen:
        _append_feature_disabled_finding(
            findings,
            repo_payload,
            "secret_scanning",
            "secret scanning",
        )
        _append_feature_disabled_finding(
            findings,
            repo_payload,
            "secret_scanning_push_protection",
            "secret scanning push protection",
        )
        _append_feature_disabled_finding(
            findings,
            repo_payload,
            "dependabot_security_updates",
            "Dependabot security updates",
        )
        _append_feature_disabled_finding(
            findings,
            repo_payload,
            "dependency_graph",
            "dependency graph",
        )
    elif resolved_token:
        warnings.append(
            "GitHub security and analysis metadata was not returned; token may lack admin, owner, or security-manager access."
        )

    if not resolved_token:
        warnings.append(
            "Token-gated GitHub hardening checks were skipped. "
            "Unauthenticated coverage is limited to "
            + ", ".join(GITHUB_HARDENING_PUBLIC_METADATA_CHECKS)
            + ". "
            "Set REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN "
            "or authenticate GitHub CLI with `gh auth login` to audit "
            + ", ".join(GITHUB_HARDENING_TOKEN_CHECKS)
            + "."
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
            bypass_allowances = pull_request_reviews.get("bypass_pull_request_allowances")
            if isinstance(bypass_allowances, dict) and any(
                bool(bypass_allowances.get(key)) for key in ("users", "teams", "apps")
            ):
                findings.append(
                    "GitHub default branch protection: pull request review bypass allowances are configured."
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
        else:
            required_contexts = _github_actions_required_status_contexts(status_checks)
            workflows_dir = repo / ".github" / "workflows"
            if required_contexts and workflows_dir.exists():
                automatic_check_names = collect_local_automatic_workflow_check_names(repo)
                if automatic_check_names:
                    stale_contexts = [
                        context
                        for context in required_contexts
                        if context not in automatic_check_names
                    ]
                    if stale_contexts:
                        findings.append(
                            "GitHub default branch protection: required status checks "
                            "include contexts not produced by local automatic workflows: "
                            + ", ".join(stale_contexts)
                        )
                else:
                    warnings.append(
                        "GitHub default branch protection: required status check drift "
                        "could not be audited because no local automatic workflow jobs were found."
                    )

        allow_force_pushes = protection_payload.get("allow_force_pushes") or {}
        if isinstance(allow_force_pushes, dict) and allow_force_pushes.get("enabled") is True:
            findings.append("GitHub default branch protection: force pushes are allowed.")

        allow_deletions = protection_payload.get("allow_deletions") or {}
        if isinstance(allow_deletions, dict) and allow_deletions.get("enabled") is True:
            findings.append("GitHub default branch protection: branch deletion is allowed.")

        enforce_admins = protection_payload.get("enforce_admins") or {}
        if isinstance(enforce_admins, dict) and enforce_admins.get("enabled") is not True:
            finding = "GitHub default branch protection: administrators can bypass branch protection."
            if accept_admin_bypass:
                if accepted_risks is not None:
                    accepted_risks.append(
                        finding
                        + " Accepted by --accept-github-admin-bypass for solo-maintainer operations."
                    )
            else:
                findings.append(finding)
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
        if actions_payload.get("enabled") is False:
            findings.append("GitHub Actions permissions: Actions are disabled.")
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

    _audit_alert_presence(
        repo_api_url=repo_api_url,
        token=resolved_token,
        path="dependabot/alerts",
        label="Dependabot alerts",
        findings=findings,
        warnings=warnings,
        json_getter=json_getter,
    )
    _audit_alert_presence(
        repo_api_url=repo_api_url,
        token=resolved_token,
        path="secret-scanning/alerts",
        label="secret scanning alerts",
        findings=findings,
        warnings=warnings,
        json_getter=json_getter,
    )

    immutable_payload, immutable_reason = json_getter(
        f"{repo_api_url}/immutable-releases",
        resolved_token,
    )
    if isinstance(immutable_payload, dict):
        if immutable_payload.get("enabled") is not True:
            findings.append("GitHub releases: immutable releases are not enabled.")
    elif immutable_reason == "http_404":
        findings.append("GitHub releases: immutable releases are not enabled.")
    else:
        warnings.append(
            f"GitHub immutable releases could not be audited ({immutable_reason})."
        )

    if text_normalizer is None:
        return findings, warnings
    if accepted_risks is not None:
        accepted_risks[:] = text_normalizer(accepted_risks)
    return text_normalizer(findings), text_normalizer(warnings)
