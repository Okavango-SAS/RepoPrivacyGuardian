"""Repository scanning and mechanical remediation engine."""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from repo_privacy_guardian import execution as execution_helpers
from repo_privacy_guardian import evidence_taxonomy as evidence_taxonomy_helpers
from repo_privacy_guardian import history_parsing as history_parsing_helpers
from repo_privacy_guardian import remediation as remediation_helpers

if TYPE_CHECKING:
    from repo_privacy_guardian.core import (
        CODE_EXTENSIONS,
        DEFAULT_GIT_STREAM_TIMEOUT_SECONDS,
        DEFAULT_IGNORE_BASELINE,
        DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        EMAIL_RE,
        LITELLM_COMPROMISED_VERSION_RE,
        LITELLM_INSTALL_COMMAND_RE,
        LITELLM_IOC_RE,
        LITELLM_REFERENCE_RE,
        LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE,
        PERSONAL_PATH_RE,
        POLICY_MINIMUM_BASELINE_END_RE,
        POLICY_MINIMUM_BASELINE_RE,
        REDACTED_PATH,
        REMEDIATION_INSTALL_PACKAGES,
        REPO_LOCK_FILENAME,
        REPO_LOCK_RETRY_SECONDS,
        REPO_LOCK_WAIT_SECONDS,
        SECRET_CONTENT_RE,
        SECRET_REMEDIATE_FILENAME_RE,
        SENSITIVE_FILENAME_RE,
        SIMPLE_EMAIL_RE,
        SUPPLY_CHAIN_CANDIDATE_FILENAMES,
        CommandResult,
        RepoExecutionLock,
        RepoReport,
        _apply_private_permissions,
        _close_fd_safely,
        _missing_executable_message,
        _read_json_from_locked_fd,
        _write_json_to_locked_fd,
        acquire_advisory_file_lock,
        audit_github_release_hardening,
        classify_litellm_incident_severity,
        classify_secret_match_context,
        cleanup_private_temp_text_file,
        create_private_temp_text_file,
        discover_repository_targets,
        ensure_private_directory,
        extract_personal_path_literals,
        github_fix_guide,
        infer_github_username_from_noreply,
        is_public_github_remote,
        is_relevant_email_candidate,
        is_repo_privacy_guardian_reviewed_network_indicator,
        is_repo_privacy_guardian_source_tree,
        line_has_exfil_indicator,
        normalize_text_values,
        parse_github_remote_owner,
        read_text_file_for_scan,
        release_advisory_file_lock,
        repo_display_name,
        split_email_matches_by_taxonomy,
        split_unexpected_emails_by_origin_ownership,
        streaming_popen_kwargs,
        subprocess_stdin,
        validate_fix_preconditions,
        write_private_text_file,
    )


class RepoPublicationGuard:  # pragma: no cover
    def __init__(
        self,
        root: Path,
        policy_path: Path,
        noreply_email: str,
        placeholder_email: str,
        owner_name: str,
        owner_emails: list[str],
        redact_third_party: bool,
        purge_detected_secret_files: bool,
        purge_all_detected_secret_files: bool,
        low_confidence_email_mode: str,
        push: bool,
        dry_run: bool,
        max_matches: int,
        audit_litellm_incident: bool,
        audit_github_hardening: bool,
        allow_non_owner_push: bool,
        allowed_remote_owners: list[str],
        replace_text_file: str | None,
        logger: Callable[[str], None],
    ) -> None:
        _sync_scanner_public_overrides()
        self.root = root
        self.policy_path = policy_path
        self.noreply_email = noreply_email
        self.placeholder_email = placeholder_email
        self.owner_name = owner_name
        self.owner_emails = set(owner_emails)
        self.redact_third_party = redact_third_party
        self.purge_detected_secret_files = purge_detected_secret_files
        self.purge_all_detected_secret_files = purge_all_detected_secret_files
        self.low_confidence_email_mode = (
            low_confidence_email_mode
            if low_confidence_email_mode in {"informational", "blocking"}
            else "informational"
        )
        self.push = push
        self.dry_run = dry_run
        self.max_matches = max_matches
        self.audit_litellm_incident = audit_litellm_incident
        self.audit_github_hardening = audit_github_hardening
        self.allow_non_owner_push = allow_non_owner_push
        self.allowed_remote_owners = {
            owner.strip().lower()
            for owner in allowed_remote_owners
            if owner.strip()
        }
        self.replace_text_file = replace_text_file
        self.rewrite_personal_paths = False
        self.log = logger
        self._repo_runtime_issues: list[str] = []

        inferred_owner = infer_github_username_from_noreply(self.noreply_email)
        if inferred_owner:
            self.allowed_remote_owners.add(inferred_owner.lower())

        self.required_ignore_patterns = self._load_required_ignore_patterns()

    def _record_repo_runtime_issue(self, issue: str) -> None:
        normalized = issue.strip()
        if not normalized:
            return
        self._repo_runtime_issues.append(normalized)

    def _flush_repo_runtime_issues(self) -> list[str]:
        issues = normalize_text_values(self._repo_runtime_issues)
        self._repo_runtime_issues = []
        return issues

    def _command_adapter(self) -> execution_helpers.GitSubprocessAdapter[CommandResult]:
        return execution_helpers.GitSubprocessAdapter(
            timeout_seconds=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
            result_factory=CommandResult,
            missing_executable_message=_missing_executable_message,
            stdin_selector=subprocess_stdin,
            remediation_install_packages=tuple(REMEDIATION_INSTALL_PACKAGES),
            python_executable=sys.executable,
            runner=subprocess.run,
        )

    def _stream_adapter(self) -> execution_helpers.GitStreamingAdapter:
        return execution_helpers.GitStreamingAdapter(
            timeout_seconds=DEFAULT_GIT_STREAM_TIMEOUT_SECONDS,
            popen_kwargs_factory=streaming_popen_kwargs,
            popen_factory=subprocess.Popen,
        )

    def _run(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        return self._command_adapter().run(cmd, cwd=cwd, input_text=input_text)

    def _run_checked(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        return self._command_adapter().run_checked(cmd, cwd=cwd, input_text=input_text)

    def _git(self, repo: Path, *args: str) -> CommandResult:
        return self._command_adapter().git(repo, *args)

    def _git_checked(self, repo: Path, *args: str) -> CommandResult:
        return self._command_adapter().git_checked(repo, *args)

    def _read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def _load_required_ignore_patterns(self) -> list[str]:
        patterns = list(DEFAULT_IGNORE_BASELINE)
        if not self.policy_path.exists():
            return list(dict.fromkeys(patterns))

        raw = self._read_text(self.policy_path)
        in_block = False
        extracted: list[str] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if POLICY_MINIMUM_BASELINE_RE.match(stripped):
                in_block = True
                continue
            if in_block and POLICY_MINIMUM_BASELINE_END_RE.match(stripped):
                break
            if in_block and stripped.startswith("- "):
                candidate = stripped[2:].strip()
                if re.match(r"^[!A-Za-z0-9_.*\-/]+$", candidate):
                    extracted.append(candidate)

        patterns.extend(extracted)
        return list(dict.fromkeys(patterns))

    def _resolve_git_dir(self, repo: Path) -> Path:
        result = self._git(repo, "rev-parse", "--absolute-git-dir")
        if result.returncode == 0 and result.stdout.strip():
            git_dir = Path(result.stdout.strip())
            return git_dir if git_dir.is_absolute() else (repo / git_dir)
        return repo / ".git"

    def _read_lock_metadata(self, lock_path: Path) -> dict[str, object] | None:
        try:
            return json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _open_repo_lock_fd(self, lock_path: Path) -> int:
        if lock_path.is_symlink():
            raise RuntimeError(f"Refusing to use symlinked lock file path: {lock_path}")

        flags = os.O_RDWR | os.O_CREAT
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        try:
            fd = os.open(str(lock_path), flags, 0o600)
        except OSError as exc:
            if getattr(exc, "errno", None) == errno.ELOOP:
                raise RuntimeError(f"Refusing to use symlinked lock file path: {lock_path}") from exc
            raise
        _apply_private_permissions(lock_path, 0o600)
        return fd

    def _format_repo_lock_holder(self, metadata: dict[str, object] | None) -> str:
        if not metadata:
            return "unknown holder"

        details: list[str] = []
        owner_token = str(metadata.get("owner_token") or "").strip()
        if owner_token:
            details.append(owner_token)

        host = str(metadata.get("host") or "").strip()
        if host:
            details.append(f"host={host}")

        pid_raw = metadata.get("pid")
        if isinstance(pid_raw, int):
            details.append(f"pid={pid_raw}")

        acquired_at = str(metadata.get("acquired_at") or "").strip()
        if acquired_at:
            details.append(f"acquired_at={acquired_at}")

        return ", ".join(details) if details else "unknown holder"

    def acquire_repo_lock(self, repo: Path) -> RepoExecutionLock:
        git_dir = self._resolve_git_dir(repo)
        lock_parent = git_dir if git_dir.is_dir() else repo
        ensure_private_directory(lock_parent)
        lock_path = lock_parent / REPO_LOCK_FILENAME
        owner_token = f"{os.getpid()}-{threading.get_ident()}-{time.time_ns()}"
        deadline = time.monotonic() + REPO_LOCK_WAIT_SECONDS
        waiting_logged = False

        while True:
            fd: int | None = None
            acquired = False
            try:
                fd = self._open_repo_lock_fd(lock_path)
                acquired = acquire_advisory_file_lock(fd)
            except RuntimeError:
                raise
            except OSError as exc:
                raise RuntimeError(
                    f"Unable to open repository execution lock at {lock_path}: {exc}"
                ) from exc

            if not acquired:
                _close_fd_safely(fd)
                metadata = self._read_lock_metadata(lock_path)
                if time.monotonic() >= deadline:
                    holder = self._format_repo_lock_holder(metadata)
                    raise RuntimeError(
                        f"repository execution lock is busy ({holder}); retry after the active run finishes"
                    )
                if not waiting_logged:
                    self.log(f"[INFO] {repo_display_name(repo)}: waiting for repository execution lock")
                    waiting_logged = True
                time.sleep(REPO_LOCK_RETRY_SECONDS)
                continue

            acquired_at = datetime.now()
            payload = {
                "repo": str(repo),
                "owner_token": owner_token,
                "pid": os.getpid(),
                "thread_id": threading.get_ident(),
                "host": socket.gethostname(),
                "python_executable": sys.executable,
                "lock_kind": "os-advisory-file-lock",
                "acquired_at": acquired_at.isoformat(timespec="seconds"),
            }
            try:
                _write_json_to_locked_fd(fd, payload)
            except OSError:
                try:
                    release_advisory_file_lock(fd)
                except OSError:
                    pass
                _close_fd_safely(fd)
                raise
            self.log(f"[INFO] {repo_display_name(repo)}: acquired repository execution lock")
            return RepoExecutionLock(
                repo=repo,
                lock_path=lock_path,
                owner_token=owner_token,
                acquired_at=acquired_at,
                lock_fd=fd,
            )

    def release_repo_lock(self, repo_lock: RepoExecutionLock | None) -> None:
        if repo_lock is None:
            return

        metadata = _read_json_from_locked_fd(repo_lock.lock_fd) or self._read_lock_metadata(repo_lock.lock_path)
        owner_changed = (
            metadata is not None
            and str(metadata.get("owner_token") or "").strip()
            not in {"", repo_lock.owner_token}
        )
        if owner_changed:
            self.log(
                f"[WARN] {repo_display_name(repo_lock.repo)}: repository execution lock owner changed before release; releasing OS lock only"
            )
        try:
            release_payload = {
                "status": "released",
                "released_at": datetime.now().isoformat(timespec="seconds"),
                "previous_owner_token": repo_lock.owner_token,
                "pid": os.getpid(),
                "host": socket.gethostname(),
            }
            _write_json_to_locked_fd(repo_lock.lock_fd, release_payload)
        except OSError as exc:
            self.log(
                f"[WARN] {repo_display_name(repo_lock.repo)}: could not update repository execution lock metadata: {exc}"
            )

        try:
            release_advisory_file_lock(repo_lock.lock_fd)
            self.log(f"[INFO] {repo_display_name(repo_lock.repo)}: released repository execution lock")
        except OSError as exc:
            self.log(f"[WARN] {repo_display_name(repo_lock.repo)}: could not release repository execution lock: {exc}")
        finally:
            _close_fd_safely(repo_lock.lock_fd)

    def _read_local_git_config(self, repo: Path, key: str) -> str | None:
        result = self._git(repo, "config", "--local", "--get", key)
        if result.returncode != 0:
            return None
        value = result.stdout.strip()
        return value if value else None

    def _capture_local_identity(self, repo: Path) -> dict[str, str | None]:
        return {
            "user.name": self._read_local_git_config(repo, "user.name"),
            "user.email": self._read_local_git_config(repo, "user.email"),
        }

    def _restore_local_identity(self, repo: Path, original_identity: dict[str, str | None]) -> None:
        if self.dry_run:
            return

        for key, original_value in original_identity.items():
            if original_value is None:
                self._git(repo, "config", "--local", "--unset-all", key)
                continue
            self._git_checked(repo, "config", "--local", key, original_value)

    def discover_repositories(
        self,
        repo_filters: list[str] | None,
        public_only: bool,
    ) -> list[Path]:
        repos, skipped, root_error = discover_repository_targets(self.root, repo_filters)
        if root_error:
            raise RuntimeError(root_error)

        for skipped_path in skipped:
            self.log(f"[WARN] Not a git repo or missing path: {skipped_path}")

        if public_only:
            filtered: list[Path] = []
            visibility_cache: dict[str, tuple[bool | None, str]] = {}
            for repo in repos:
                origin = self._git(repo, "remote", "get-url", "origin")
                if origin.returncode != 0:
                    self.log(f"[WARN] {repo_display_name(repo)}: origin remote unavailable; excluded by public-only filter")
                    continue

                remote_url = origin.stdout.strip()
                if not remote_url:
                    self.log(f"[WARN] {repo_display_name(repo)}: empty origin remote; excluded by public-only filter")
                    continue

                if remote_url not in visibility_cache:
                    visibility_cache[remote_url] = is_public_github_remote(remote_url)

                is_public, reason = visibility_cache[remote_url]
                if is_public:
                    filtered.append(repo)
                    continue

                if reason == "not_github":
                    self.log(
                        f"[INFO] {repo_display_name(repo)}: origin is not a GitHub remote; excluded by public-only filter"
                    )
                elif reason in {"private", "private_or_not_found"}:
                    self.log(
                        f"[INFO] {repo_display_name(repo)}: origin appears private (or not publicly accessible); excluded"
                    )
                else:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: unable to verify public visibility ({reason}); excluded"
                    )

            repos = filtered

        return repos

    def _iter_tracked_files(self, repo: Path) -> list[Path]:
        result = self._git(repo, "ls-files", "-z")
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown git ls-files failure"
            self._record_repo_runtime_issue(
                f"tracked-file enumeration failed: {detail}"
            )
            return []
        files: list[Path] = []
        for chunk in result.stdout.split("\x00"):
            if not chunk:
                continue
            files.append(repo / chunk)
        return files

    def _scan_tracked_content(
        self,
        repo: Path,
        regex: re.Pattern[str],
        only_code_files: bool = False,
        path_filter: Callable[[str], bool] | None = None,
    ) -> list[str]:
        matches: list[str] = []
        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            if path_filter and not path_filter(rel):
                continue
            if only_code_files and file_path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append(f"{rel}:{idx}:{line.strip()[:240]}")
                    if len(matches) >= self.max_matches:
                        return matches
        return matches

    def _append_secret_taxonomy_match(
        self,
        *,
        rel_path: str | None,
        line_number: int,
        line: str,
        high_confidence: list[str],
        low_confidence: list[str],
        fixtures: list[str],
        documentation: list[str],
        history: bool = False,
    ) -> None:
        buckets = evidence_taxonomy_helpers.SecretTaxonomyBuckets(
            high_confidence=high_confidence,
            low_confidence=low_confidence,
            fixtures=fixtures,
            documentation=documentation,
        )
        evidence_taxonomy_helpers.append_secret_taxonomy_match(
            buckets=buckets,
            rel_path=rel_path,
            line_number=line_number,
            line=line,
            secret_pattern=SECRET_CONTENT_RE,
            low_confidence_pattern=LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE,
            classify_secret_match_context=classify_secret_match_context,
            max_matches=self.max_matches,
            history=history,
        )

    def _scan_tracked_secret_taxonomy(
        self,
        repo: Path,
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        buckets = evidence_taxonomy_helpers.SecretTaxonomyBuckets()

        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                evidence_taxonomy_helpers.append_secret_taxonomy_match(
                    buckets=buckets,
                    rel_path=rel,
                    line_number=idx,
                    line=line,
                    secret_pattern=SECRET_CONTENT_RE,
                    low_confidence_pattern=LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE,
                    classify_secret_match_context=classify_secret_match_context,
                    max_matches=self.max_matches,
                )
        return buckets.as_tuple()

    def _scan_network_code_indicators(self, repo: Path) -> tuple[list[str], list[str]]:
        matches: list[str] = []
        reviewed: list[str] = []
        is_rpg_source_tree = is_repo_privacy_guardian_source_tree(repo)
        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            if file_path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                if line_has_exfil_indicator(line, rel_path=rel):
                    entry = f"{rel}:{idx}:{line.strip()[:240]}"
                    if is_rpg_source_tree and is_repo_privacy_guardian_reviewed_network_indicator(line, rel_path=rel):
                        if len(reviewed) < self.max_matches:
                            reviewed.append(entry)
                        continue
                    matches.append(entry)
                    if len(matches) >= self.max_matches:
                        return matches, reviewed
        return matches, reviewed

    def _is_supply_chain_candidate_path(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/").strip().lower()
        file_name = Path(normalized).name

        if file_name in SUPPLY_CHAIN_CANDIDATE_FILENAMES:
            return True
        if normalized.startswith(".github/workflows/"):
            return True
        if normalized.startswith(".gitlab/") and file_name.endswith((".yml", ".yaml")):
            return True
        if normalized.startswith("ci/") or normalized.startswith("scripts/"):
            return file_name.endswith((".py", ".sh", ".ps1", ".yml", ".yaml", ".toml", ".txt"))

        return False

    def _scan_litellm_incident(self, repo: Path, report: RepoReport) -> None:
        report.litellm_reference_hits = self._scan_tracked_content(
            repo,
            LITELLM_REFERENCE_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_compromised_reference_hits = self._scan_tracked_content(
            repo,
            LITELLM_COMPROMISED_VERSION_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_install_command_hits = self._scan_tracked_content(
            repo,
            LITELLM_INSTALL_COMMAND_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_ioc_hits = self._scan_tracked_content(
            repo,
            LITELLM_IOC_RE,
            path_filter=self._is_supply_chain_candidate_path,
        )
        report.litellm_incident_severity = classify_litellm_incident_severity(report)

    def _scan_git_metadata_secrets(self, repo: Path, report: RepoReport) -> None:
        high_confidence: list[str] = []
        low_confidence: list[str] = []

        def inspect_value(label: str, value: str | None) -> None:
            if not value:
                return
            snippet = value.strip()[:240]
            normalized_assignment = re.sub(r"^([^\s=]+)\s+", r"\1=", snippet, count=1)
            candidates = [snippet]
            if normalized_assignment != snippet:
                candidates.append(normalized_assignment)
            if any(SECRET_CONTENT_RE.search(candidate) for candidate in candidates):
                if len(high_confidence) < self.max_matches:
                    high_confidence.append(f"{label}:{snippet}")
                return
            low_confidence_candidate = next(
                (
                    candidate
                    for candidate in candidates
                    if LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE.search(candidate)
                ),
                None,
            )
            if low_confidence_candidate:
                if len(low_confidence) < self.max_matches:
                    low_confidence.append(f"{label}:{low_confidence_candidate}")

        inspect_value("origin_url", report.origin_url)
        inspect_value("upstream_url", report.upstream_url)

        config = self._git(
            repo,
            "config",
            "--local",
            "--get-regexp",
            r"^(http\..*\.extraheader|url\..*\.insteadOf|credential\..*)",
        )
        if config.returncode not in {0, 1}:
            detail = (config.stderr or config.stdout or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"git metadata secret scan failed with exit code {config.returncode}{suffix}"
            )
            report.git_metadata_secret_matches = high_confidence
            report.git_metadata_secret_low_confidence = low_confidence
            return

        for line in config.stdout.splitlines():
            inspect_value("git_config", line)

        report.git_metadata_secret_matches = high_confidence
        report.git_metadata_secret_low_confidence = low_confidence

    def _scan_github_hardening(self, repo: Path, report: RepoReport) -> None:
        findings, warnings = audit_github_release_hardening(
            repo=repo,
            remote_url=report.origin_url or report.upstream_url or "",
        )
        report.github_hardening_checked = True
        report.github_hardening_findings = findings[: self.max_matches]
        report.github_hardening_warnings = warnings[: self.max_matches]
        report.github_hardening_fix_guide = github_fix_guide.build_github_hardening_fix_guide(
            report.github_hardening_findings,
            report.github_hardening_warnings,
        )

    def _finalize_git_stream_process(
        self,
        proc: execution_helpers.StreamingProcessLike,
        timeout: int | None = None,
    ) -> tuple[int | None, str]:
        return self._stream_adapter().finalize(proc, timeout=timeout)

    def _terminate_process_if_running(self, proc: execution_helpers.StreamingProcessLike) -> None:
        self._stream_adapter().terminate_if_running(proc)

    def _scan_history_patch(self, repo: Path, regex: re.Pattern[str]) -> list[str]:
        try:
            proc = self._stream_adapter().start_git_history_patch(repo)
        except FileNotFoundError:
            self._record_repo_runtime_issue("history patch scan failed to start: Git executable not found")
            return []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history patch scan failed to start: {exc}")
            return []
        matches: list[str] = []
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        terminated_early = False
        try:
            stream = proc.stdout
            if stream is None:
                return matches
            for idx, line in enumerate(stream, start=1):
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history patch scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if regex.search(line):
                    matches.append(history_parsing_helpers.format_history_patch_match(idx, line))
                    if len(matches) >= self.max_matches:
                        self._terminate_process_if_running(proc)
                        terminated_early = True
                        break
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history patch scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif not terminated_early and returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history patch scan failed with exit code {returncode}{suffix}"
            )
        return matches

    def _scan_history_secret_taxonomy(
        self,
        repo: Path,
    ) -> tuple[list[str], list[str], list[str], list[str]]:
        try:
            proc = self._stream_adapter().start_git_history_patch(repo)
        except FileNotFoundError:
            self._record_repo_runtime_issue("history secret taxonomy scan failed to start: Git executable not found")
            return [], [], [], []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history secret taxonomy scan failed to start: {exc}")
            return [], [], [], []

        buckets = evidence_taxonomy_helpers.SecretTaxonomyBuckets()
        current_file: str | None = None
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        try:
            stream = proc.stdout
            if stream is None:
                return buckets.as_tuple()
            for idx, raw_line in enumerate(stream, start=1):
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history secret taxonomy scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if raw_line.startswith("diff --git "):
                    current_file = history_parsing_helpers.parse_git_diff_target(raw_line)
                    continue

                line_context = history_parsing_helpers.extract_patch_change_context(raw_line)
                if line_context is None:
                    continue
                evidence_taxonomy_helpers.append_secret_taxonomy_match(
                    buckets=buckets,
                    rel_path=current_file,
                    line_number=idx,
                    line=line_context,
                    secret_pattern=SECRET_CONTENT_RE,
                    low_confidence_pattern=LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE,
                    classify_secret_match_context=classify_secret_match_context,
                    max_matches=self.max_matches,
                    history=True,
                )
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history secret taxonomy scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history secret taxonomy scan failed with exit code {returncode}{suffix}"
            )
        return buckets.as_tuple()

    def _scan_history_non_allowed_emails(self, repo: Path) -> list[str]:
        try:
            proc = self._stream_adapter().start_git_history_patch(repo)
        except FileNotFoundError:
            self._record_repo_runtime_issue("history email scan failed to start: Git executable not found")
            return []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history email scan failed to start: {exc}")
            return []
        matches: list[str] = []
        current_file: str | None = None
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        terminated_early = False
        try:
            stream = proc.stdout
            if stream is None:
                return matches
            for idx, line in enumerate(stream, start=1):
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history email scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if line.startswith("diff --git "):
                    current_file = history_parsing_helpers.parse_git_diff_target(line)
                    continue
                emails = [
                    email
                    for email in EMAIL_RE.findall(line)
                    if is_relevant_email_candidate(email)
                ]
                leaked = [email for email in emails if not self._is_allowed_email(email)]
                finding = history_parsing_helpers.format_history_email_match(
                    line_number=idx,
                    current_file=current_file,
                    leaked_emails=leaked,
                    line=line,
                )
                if finding is None:
                    continue
                matches.append(finding)
                if len(matches) >= self.max_matches:
                    self._terminate_process_if_running(proc)
                    terminated_early = True
                    break
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history email scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif not terminated_early and returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history email scan failed with exit code {returncode}{suffix}"
            )
        return matches

    def _scan_tracked_non_allowed_emails(self, repo: Path) -> list[str]:
        matches: list[str] = []
        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            text = read_text_file_for_scan(file_path)
            if text is None:
                continue
            for idx, line in enumerate(text.splitlines(), start=1):
                emails = [
                    email
                    for email in EMAIL_RE.findall(line)
                    if is_relevant_email_candidate(email)
                ]
                leaked = [email for email in emails if not self._is_allowed_email(email)]
                if not leaked:
                    continue
                uniq = ", ".join(sorted(set(leaked)))
                matches.append(f"{rel}:{idx}:{uniq}:{line.strip()[:200]}")
                if len(matches) >= self.max_matches:
                    return matches
        return matches

    def _scan_history_secret_files(self, repo: Path) -> list[str]:
        try:
            proc = self._stream_adapter().start_git_history_patch(repo)
        except FileNotFoundError:
            self._record_repo_runtime_issue("history secret-file scan failed to start: Git executable not found")
            return []
        except Exception as exc:
            self._record_repo_runtime_issue(f"history secret-file scan failed to start: {exc}")
            return []

        files: list[str] = []
        seen: set[str] = set()
        current_file: str | None = None
        deadline = time.monotonic() + DEFAULT_GIT_STREAM_TIMEOUT_SECONDS
        timed_out = False
        terminated_early = False

        try:
            stream = proc.stdout
            if stream is None:
                return files
            for line in stream:
                if time.monotonic() >= deadline:
                    self.log(
                        f"[WARN] {repo_display_name(repo)}: history secret-file scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
                    )
                    self._terminate_process_if_running(proc)
                    timed_out = True
                    break
                if line.startswith("diff --git "):
                    current_file = history_parsing_helpers.parse_git_diff_target(line)
                    continue

                line_context = history_parsing_helpers.extract_patch_change_context(line)
                if line_context is None:
                    continue

                secret_file = history_parsing_helpers.active_secret_file_from_patch_change(
                    current_file=current_file,
                    line_context=line_context,
                    secret_pattern=SECRET_CONTENT_RE,
                    classify_secret_match_context=classify_secret_match_context,
                )
                if secret_file and secret_file not in seen:
                    seen.add(secret_file)
                    files.append(secret_file)
                    if len(files) >= self.max_matches:
                        self._terminate_process_if_running(proc)
                        terminated_early = True
                        break
        finally:
            returncode, stderr_text = self._finalize_git_stream_process(proc)
        if timed_out:
            self._record_repo_runtime_issue(
                f"history secret-file scan timed out after {DEFAULT_GIT_STREAM_TIMEOUT_SECONDS}s"
            )
        elif not terminated_early and returncode not in {0, None}:
            detail = (stderr_text or "").strip()[:240]
            suffix = f": {detail}" if detail else ""
            self._record_repo_runtime_issue(
                f"history secret-file scan failed with exit code {returncode}{suffix}"
            )

        return files

    def _extract_file_paths_from_match_lines(self, matches: list[str]) -> list[str]:
        seen: set[str] = set()
        files: list[str] = []
        for item in matches:
            if ":" not in item:
                continue
            candidate = item.split(":", 1)[0].strip()
            if not candidate or candidate.startswith("L"):
                continue
            if candidate not in seen:
                seen.add(candidate)
                files.append(candidate)
        return files

    def _build_secret_remediation_plan(self, report: RepoReport) -> None:
        combined = sorted(set(report.tracked_secret_files + report.history_secret_files))
        report.secret_file_candidates = combined

        autopurge: list[str] = []
        manual_review: list[str] = []
        for path in combined:
            if SECRET_REMEDIATE_FILENAME_RE.search(path):
                autopurge.append(path)
            else:
                manual_review.append(path)

        report.secret_file_autopurge_candidates = autopurge
        report.secret_file_manual_review_candidates = manual_review

    def _normalize_gitignore_entry(self, rel_path: str) -> str:
        path = rel_path.replace("\\", "/").strip("/")
        if not path:
            return rel_path
        return f"{path}"

    def _build_secret_gitignore_entries(self, secret_paths: list[str]) -> list[str]:
        entries = [self._normalize_gitignore_entry(path) for path in secret_paths]
        return sorted(set(entries))

    def _append_gitignore_lines(self, repo: Path, lines: list[str], header: str) -> bool:
        if not lines:
            return False

        gitignore = repo / ".gitignore"
        if gitignore.is_symlink():
            raise RuntimeError(f"Refusing to update symlinked .gitignore: {gitignore}")
        existing_text = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.exists() else ""
        existing_lines = {
            line.strip()
            for line in existing_text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        missing = [line for line in lines if line not in existing_lines]
        if not missing:
            return False

        block = ["", f"# {header}"] + missing
        new_text = existing_text.rstrip() + "\n" + "\n".join(block) + "\n"
        write_private_text_file(gitignore, new_text)
        return True

    def _history_file_matches(self, repo: Path, diff_filter: str) -> list[str]:
        out = self._git(repo, "log", "--all", f"--diff-filter={diff_filter}", "--name-only", "--pretty=format:")
        if out.returncode != 0:
            return []
        hits: list[str] = []
        for idx, line in enumerate(out.stdout.splitlines(), start=1):
            item = line.strip()
            if not item:
                continue
            if SENSITIVE_FILENAME_RE.search(item):
                hits.append(f"{idx}:{item}")
                if len(hits) >= self.max_matches:
                    break
        return hits

    def _unique_commit_metadata_values(self, repo: Path, field: str) -> list[str]:
        out = self._git(repo, "log", "--all", f"--pretty=format:{field}")
        if out.returncode != 0:
            return []
        return sorted({line.strip() for line in out.stdout.splitlines() if line.strip()})

    def _unique_commit_emails(self, repo: Path, field: str) -> list[str]:
        return [
            value
            for value in self._unique_commit_metadata_values(repo, field)
            if SIMPLE_EMAIL_RE.match(value)
        ]

    def _unique_commit_identity_tokens(self, repo: Path, field: str) -> list[str]:
        return [
            value
            for value in self._unique_commit_metadata_values(repo, field)
            if not SIMPLE_EMAIL_RE.match(value)
        ]

    def _resolve_upstream_head(self, repo: Path) -> str | None:
        upstream = self._git(
            repo,
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        )
        if upstream.returncode != 0 or not upstream.stdout.strip():
            return None
        return self._git(repo, "rev-parse", "--short", "@{upstream}").stdout.strip() or None

    def _is_allowed_email(self, email: str) -> bool:
        if not email:
            return True
        if email == self.noreply_email:
            return True
        if email == self.placeholder_email:
            return True
        if email == "noreply@github.com":
            return True
        if email.endswith("@users.noreply.github.com"):
            return True
        return False

    def audit_repo(self, repo: Path) -> RepoReport:
        report = RepoReport(name=repo_display_name(repo), path=str(repo))
        report.low_confidence_email_mode = self.low_confidence_email_mode
        self._repo_runtime_issues = []

        report.origin_url = self._git(repo, "remote", "get-url", "origin").stdout.strip() or None
        report.upstream_url = self._git(repo, "remote", "get-url", "upstream").stdout.strip() or None
        report.branch = self._git(repo, "branch", "--show-current").stdout.strip() or None
        report.head = self._git(repo, "rev-parse", "--short", "HEAD").stdout.strip() or None
        report.origin_head = self._resolve_upstream_head(repo)
        report.clean_status = self._git(repo, "status", "--short", "--branch").stdout.strip()

        fsck = self._git(repo, "fsck", "--full")
        report.fsck_ok = fsck.returncode == 0
        if fsck.stdout.strip() or fsck.stderr.strip():
            payload = (fsck.stdout + "\n" + fsck.stderr).strip()
            report.fsck_output = payload.splitlines()[: self.max_matches]

        report.author_emails = self._unique_commit_emails(repo, "%ae")
        report.committer_emails = self._unique_commit_emails(repo, "%ce")
        report.author_identity_tokens = self._unique_commit_identity_tokens(repo, "%ae")
        report.committer_identity_tokens = self._unique_commit_identity_tokens(repo, "%ce")

        all_emails = sorted(set(report.author_emails + report.committer_emails))
        all_identity_tokens = sorted(
            set(report.author_identity_tokens + report.committer_identity_tokens)
        )
        report.unexpected_emails = [email for email in all_emails if not self._is_allowed_email(email)]
        (
            report.unexpected_emails_owned_repo,
            report.unexpected_emails_third_party_repo,
        ) = split_unexpected_emails_by_origin_ownership(
            report.unexpected_emails,
            report.origin_url,
            self.allowed_remote_owners,
        )
        report.unexpected_identity_tokens = all_identity_tokens
        (
            report.unexpected_identity_tokens_owned_repo,
            report.unexpected_identity_tokens_third_party_repo,
        ) = split_unexpected_emails_by_origin_ownership(
            report.unexpected_identity_tokens,
            report.origin_url,
            self.allowed_remote_owners,
        )
        report.email_ownership_evaluated = True

        (
            report.tracked_secret_high_confidence,
            report.tracked_secret_low_confidence,
            report.tracked_secret_fixture_matches,
            report.tracked_secret_documentation_matches,
        ) = self._scan_tracked_secret_taxonomy(repo)
        report.tracked_secret_matches = list(report.tracked_secret_high_confidence)
        report.tracked_secret_files = self._extract_file_paths_from_match_lines(report.tracked_secret_matches)
        self._scan_git_metadata_secrets(repo, report)
        report.tracked_path_matches = self._scan_tracked_content(repo, PERSONAL_PATH_RE)
        report.tracked_email_matches = self._scan_tracked_non_allowed_emails(repo)
        (
            report.tracked_email_high_confidence,
            report.tracked_email_low_confidence,
            report.tracked_email_fixture_matches,
        ) = split_email_matches_by_taxonomy(report.tracked_email_matches)

        (
            report.history_secret_high_confidence,
            report.history_secret_low_confidence,
            report.history_secret_fixture_matches,
            report.history_secret_documentation_matches,
        ) = self._scan_history_secret_taxonomy(repo)
        report.history_secret_matches = list(report.history_secret_high_confidence)
        report.history_secret_files = self._scan_history_secret_files(repo)
        report.history_path_matches = self._scan_history_patch(repo, PERSONAL_PATH_RE)
        report.history_email_matches = self._scan_history_non_allowed_emails(repo)
        (
            report.history_email_high_confidence,
            report.history_email_low_confidence,
            report.history_email_fixture_matches,
        ) = split_email_matches_by_taxonomy(report.history_email_matches)
        report.email_confidence_evaluated = True
        report.secret_confidence_evaluated = True

        self._build_secret_remediation_plan(report)

        report.history_sensitive_added = self._history_file_matches(repo, "A")
        report.history_sensitive_deleted = self._history_file_matches(repo, "D")

        ignored = self._git(repo, "ls-files", "-ci", "--exclude-standard")
        if ignored.returncode == 0:
            report.tracked_but_ignored = [
                line.strip() for line in ignored.stdout.splitlines() if line.strip()
            ][: self.max_matches]

        report.exfil_code_indicators, report.reviewed_network_indicators = self._scan_network_code_indicators(repo)

        if self.audit_github_hardening:
            self._scan_github_hardening(repo, report)

        if self.audit_litellm_incident:
            self._scan_litellm_incident(repo, report)

        gitignore = repo / ".gitignore"
        if gitignore.exists():
            raw_lines = {
                line.strip()
                for line in self._read_text(gitignore).splitlines()
                if line.strip() and not line.strip().startswith("#")
            }
            report.gitignore_missing_patterns = [
                pattern for pattern in self.required_ignore_patterns if pattern not in raw_lines
            ]
        else:
            report.gitignore_missing_patterns = list(self.required_ignore_patterns)

        report.execution_errors.extend(self._flush_repo_runtime_issues())
        report.finalize()
        return report

    def _ensure_git_filter_repo(self) -> None:
        self._command_adapter().ensure_git_filter_repo()

    def _write_mailmap(self, report: RepoReport) -> Path | None:
        lines: list[str] = []
        mapped_old_values: set[str] = set()

        def add_mapping(name: str, new_email: str, old_value: str) -> None:
            normalized = old_value.strip()
            if not normalized or normalized in mapped_old_values:
                return
            mapped_old_values.add(normalized)
            lines.append(f"{name} <{new_email}> <{normalized}>")

        unique_emails = sorted(set(report.author_emails + report.committer_emails))
        for email in unique_emails:
            if not email:
                continue
            if email == self.noreply_email:
                continue
            if email == "noreply@github.com":
                continue
            if email == self.placeholder_email:
                continue

            if email in self.owner_emails:
                add_mapping(self.owner_name, self.noreply_email, email)
                continue

            if email.endswith("@users.noreply.github.com"):
                if self.redact_third_party:
                    add_mapping("Redacted Contributor", self.placeholder_email, email)
                continue

            if self.redact_third_party:
                add_mapping("Redacted Contributor", self.placeholder_email, email)

        owned_identity_tokens = (
            report.unexpected_identity_tokens_owned_repo
            if report.email_ownership_evaluated
            else report.unexpected_identity_tokens
        )
        for token in owned_identity_tokens:
            add_mapping(self.owner_name, self.noreply_email, token)

        if self.redact_third_party:
            for token in report.unexpected_identity_tokens_third_party_repo:
                add_mapping("Redacted Contributor", self.placeholder_email, token)

        if not lines:
            return None

        return create_private_temp_text_file(
            "repo-publication-guard-",
            "mailmap.txt",
            "\n".join(lines) + "\n",
        )

    def _write_replace_text_file(self, report: RepoReport) -> Path | None:
        explicit_replace_lines: tuple[str, ...] = ()
        explicit_replace_source: Path | None = None
        replace_text_file = getattr(self, "replace_text_file", None)
        if replace_text_file:
            explicit_rules = remediation_helpers.load_explicit_replace_text_rules(replace_text_file)
            explicit_replace_lines = explicit_rules.lines
            explicit_replace_source = explicit_rules.path

        plan = remediation_helpers.build_replace_text_plan(
            report,
            email_pattern=EMAIL_RE,
            is_relevant_email_candidate=is_relevant_email_candidate,
            is_allowed_email=self._is_allowed_email,
            owner_emails=self.owner_emails,
            noreply_email=self.noreply_email,
            placeholder_email=self.placeholder_email,
            redact_third_party=self.redact_third_party,
            rewrite_personal_paths=getattr(self, "rewrite_personal_paths", False),
            extract_personal_path_literals=extract_personal_path_literals,
            redacted_path=REDACTED_PATH,
            explicit_replace_lines=explicit_replace_lines,
            explicit_replace_source=explicit_replace_source,
        )
        report.fix_actions.extend(plan.fix_actions)

        if not plan.lines:
            return None

        return create_private_temp_text_file(
            "repo-publication-guard-",
            "replace-text.txt",
            "\n".join(plan.lines) + "\n",
        )

    def _append_missing_gitignore_patterns(self, repo: Path, missing: list[str]) -> bool:
        return self._append_gitignore_lines(
            repo,
            missing,
            "Added by Repo_Privacy_Guardian.py (policy baseline)",
        )

    def _remove_tracked_ignored(self, repo: Path) -> list[str]:
        out = self._git(repo, "ls-files", "-ci", "--exclude-standard")
        if out.returncode != 0:
            return []
        files = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        if not files:
            return []

        if self.dry_run:
            return files

        for file_path in files:
            self._git_checked(repo, "rm", "--cached", "--", file_path)
        return files

    def _save_remotes(self, repo: Path) -> dict[str, str]:
        names = self._git(repo, "remote").stdout.splitlines()
        remotes: dict[str, str] = {}
        for name in names:
            name = name.strip()
            if not name:
                continue
            url = self._git(repo, "remote", "get-url", name).stdout.strip()
            if url:
                remotes[name] = url
        return remotes

    def _restore_remotes(self, repo: Path, remotes: dict[str, str]) -> None:
        existing = {
            line.strip()
            for line in self._git(repo, "remote").stdout.splitlines()
            if line.strip()
        }
        for name, url in remotes.items():
            if name in existing:
                continue
            self._git_checked(repo, "remote", "add", name, url)

    def _is_file_tracked(self, repo: Path, rel_path: str) -> bool:
        probe = self._git(repo, "ls-files", "--error-unmatch", "--", rel_path)
        return probe.returncode == 0

    def _apply_secret_file_remediation(self, repo: Path, report: RepoReport) -> None:
        if not report.secret_file_candidates:
            return

        report.fix_actions.append(
            f"detected secret-file candidates: {len(report.secret_file_candidates)}"
        )
        preview = ", ".join(report.secret_file_candidates[:5])
        report.fix_actions.append(f"secret-file candidates preview: {preview}")
        if len(report.secret_file_candidates) > 5:
            report.fix_actions.append("secret-file candidates preview truncated")

        if not self.purge_detected_secret_files:
            report.fix_actions.append(
                "secret remediation available: re-run with --purge-detected-secret-files"
            )
            report.fix_actions.append(
                "for aggressive mode use --purge-all-detected-secret-files (risky)"
            )
            return

        targets = (
            list(report.secret_file_candidates)
            if self.purge_all_detected_secret_files
            else list(report.secret_file_autopurge_candidates)
        )

        if not targets:
            report.fix_actions.append(
                "secret remediation skipped: no safe auto-purge candidates"
            )
            if report.secret_file_manual_review_candidates:
                report.fix_actions.append(
                    f"manual review required for {len(report.secret_file_manual_review_candidates)} files"
                )
                report.fix_actions.append(
                    "to purge manual-review files, add --purge-all-detected-secret-files"
                )
            return

        report.secret_history_purge_paths = sorted(set(targets))

        ignore_entries = self._build_secret_gitignore_entries(targets)
        if self.dry_run:
            report.fix_actions.append(
                f"[dry-run] would append secret file ignore entries: {len(ignore_entries)}"
            )
            preview_entries = ", ".join(ignore_entries[:5])
            if preview_entries:
                report.fix_actions.append(f"[dry-run] ignore entries preview: {preview_entries}")
            if len(ignore_entries) > 5:
                report.fix_actions.append("[dry-run] ignore entries preview truncated")
        else:
            changed = self._append_gitignore_lines(
                repo,
                ignore_entries,
                "Added by Repo_Privacy_Guardian.py (secret remediation)",
            )
            if changed:
                report.fix_actions.append("appended secret file entries to .gitignore")

        tracked_targets = [path for path in targets if self._is_file_tracked(repo, path)]
        if tracked_targets:
            if self.dry_run:
                report.fix_actions.append(
                    f"[dry-run] would untrack secret files: {len(tracked_targets)}"
                )
                preview_targets = ", ".join(tracked_targets[:5])
                if preview_targets:
                    report.fix_actions.append(f"[dry-run] secret file untrack preview: {preview_targets}")
                if len(tracked_targets) > 5:
                    report.fix_actions.append("[dry-run] secret file untrack preview truncated")
            else:
                for path in tracked_targets:
                    self._git_checked(repo, "rm", "--cached", "--", path)
                report.fix_actions.append(f"untracked secret files: {len(tracked_targets)}")

        report.fix_actions.append(
            f"prepared secret-history purge paths: {len(report.secret_history_purge_paths)}"
        )
        if report.secret_file_manual_review_candidates and not self.purge_all_detected_secret_files:
            report.fix_actions.append(
                f"manual review candidates kept (no auto-purge): {len(report.secret_file_manual_review_candidates)}"
            )

    def _rewrite_history(self, repo: Path, report: RepoReport) -> None:
        mailmap = self._write_mailmap(report)
        replace_text = self._write_replace_text_file(report)
        rewrite_plan = remediation_helpers.build_history_rewrite_plan(
            report,
            mailmap_enabled=bool(mailmap),
            replace_text_enabled=bool(replace_text),
        )
        if not rewrite_plan.do_rewrite:
            report.fix_actions.append("history rewrite skipped (no mappings required)")
            return

        remotes = self._save_remotes(repo)

        if self.dry_run:
            report.fix_actions.extend(rewrite_plan.dry_run_actions())
            return

        try:
            self._ensure_git_filter_repo()
            cmd = remediation_helpers.build_git_filter_repo_command(
                python_executable=sys.executable,
                mailmap=mailmap,
                replace_text=replace_text,
                rewrite_plan=rewrite_plan,
            )
            self._run_checked(cmd, cwd=repo, input_text="y\n")
            self._restore_remotes(repo, remotes)
            report.fix_actions.append("history rewritten with git-filter-repo")
        finally:
            cleanup_private_temp_text_file(mailmap)
            cleanup_private_temp_text_file(replace_text)

    def _make_backup_bundle(self, repo: Path) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        bundle = self.root / f"{repo_display_name(repo)}-pre-publication-fix-{stamp}.bundle"
        if self.dry_run:
            return bundle
        self._git_checked(repo, "bundle", "create", str(bundle), "--all")
        _apply_private_permissions(bundle, 0o600)
        return bundle

    def _commit_if_needed(self, repo: Path, message: str) -> str:
        porcelain = self._git(repo, "status", "--porcelain").stdout.strip()
        if not porcelain:
            return "none"
        if self.dry_run:
            return "preview"
        self._git_checked(repo, "add", "-A")
        self._git_checked(repo, "commit", "-m", message)
        return "committed"

    def _set_local_identity(self, repo: Path) -> None:
        if self.dry_run:
            return
        self._git_checked(repo, "config", "--local", "user.name", self.owner_name)
        self._git_checked(repo, "config", "--local", "user.email", self.noreply_email)

    def _validate_push_owner(self, report: RepoReport) -> None:
        if self.allow_non_owner_push:
            return

        if not self.allowed_remote_owners:
            raise RuntimeError(
                "push blocked: no allowed remote owners configured. "
                "Use --allow-remote-owner or --allow-non-owner-push."
            )

        owner = parse_github_remote_owner(report.origin_url or "")
        if not owner:
            raise RuntimeError(
                "push blocked: unable to infer origin owner from remote URL. "
                "Use --allow-non-owner-push to bypass this guardrail."
            )

        if owner.lower() not in self.allowed_remote_owners:
            allowed = ", ".join(sorted(self.allowed_remote_owners))
            raise RuntimeError(
                f"push blocked: origin owner '{owner}' is not in allowed owner set ({allowed})."
            )

    def _push_if_requested(self, repo: Path, report: RepoReport) -> None:
        if not self.push:
            return

        branch = report.branch or "main"
        if self.dry_run:
            report.fix_actions.append("[dry-run] force push skipped")
            return

        self._validate_push_owner(report)
        report.fix_actions.append("validated remote owner before force push")

        self._git_checked(repo, "fetch", "origin", branch)
        self._git_checked(repo, "push", "--force-with-lease", "origin", branch)
        # Restore tracking relationship
        self._git(repo, "branch", "--set-upstream-to", f"origin/{branch}", branch)

    def apply_fixes(self, repo: Path, report: RepoReport) -> RepoReport:
        report.fix_errors.extend(validate_fix_preconditions(report))
        if report.fix_errors:
            return report

        original_identity = self._capture_local_identity(repo)
        try:
            self.log(f"[FIX] {repo_display_name(repo)}: creating backup bundle")
            bundle = self._make_backup_bundle(repo)
            report.backups_created.append(str(bundle))

            self._set_local_identity(repo)

            if report.gitignore_missing_patterns:
                if self.dry_run:
                    report.fix_actions.append(
                        "[dry-run] would append missing .gitignore patterns"
                    )
                else:
                    changed = self._append_missing_gitignore_patterns(
                        repo,
                        report.gitignore_missing_patterns,
                    )
                    if changed:
                        report.fix_actions.append("appended missing .gitignore patterns")

            self._apply_secret_file_remediation(repo, report)

            removed = self._remove_tracked_ignored(repo)
            if removed:
                report.fix_actions.append(f"untracked ignored files: {len(removed)}")

            commit_state = self._commit_if_needed(
                repo,
                "chore(security): align ignore rules and untrack sensitive/local artifacts",
            )
            if commit_state == "preview":
                report.fix_actions.append("[dry-run] would commit ignore-hygiene changes")
            elif commit_state == "committed":
                report.fix_actions.append("committed ignore-hygiene changes")

            self.log(f"[FIX] {repo_display_name(repo)}: rewriting history (emails + sensitive artifacts)")
            self._rewrite_history(repo, report)

            if not self.dry_run:
                self._git(repo, "reflog", "expire", "--expire=now", "--all")
                self._git(repo, "gc", "--prune=now")
                report.fix_actions.append("reflog/gc cleanup completed")

            self._push_if_requested(repo, report)
            if self.push:
                report.fix_actions.append("force push completed")

        except Exception as exc:
            report.fix_errors.append(str(exc))
        finally:
            try:
                self._restore_local_identity(repo, original_identity)
                if not self.dry_run:
                    report.fix_actions.append("restored local git identity")
            except Exception as exc:
                report.fix_errors.append(f"failed to restore local git identity: {exc}")

        return report


from repo_privacy_guardian import core as _core  # noqa: E402

_SCANNER_OVERRIDE_NAMES = (
    "CODE_EXTENSIONS",
    "CommandResult",
    "DEFAULT_GIT_STREAM_TIMEOUT_SECONDS",
    "DEFAULT_IGNORE_BASELINE",
    "DEFAULT_SUBPROCESS_TIMEOUT_SECONDS",
    "EMAIL_RE",
    "LITELLM_COMPROMISED_VERSION_RE",
    "LITELLM_INSTALL_COMMAND_RE",
    "LITELLM_IOC_RE",
    "LITELLM_REFERENCE_RE",
    "LOW_CONFIDENCE_SECRET_ASSIGNMENT_RE",
    "PERSONAL_PATH_RE",
    "POLICY_MINIMUM_BASELINE_END_RE",
    "POLICY_MINIMUM_BASELINE_RE",
    "Path",
    "REDACTED_PATH",
    "REMEDIATION_INSTALL_PACKAGES",
    "REPO_LOCK_FILENAME",
    "REPO_LOCK_RETRY_SECONDS",
    "REPO_LOCK_WAIT_SECONDS",
    "RepoExecutionLock",
    "RepoReport",
    "SECRET_CONTENT_RE",
    "SECRET_REMEDIATE_FILENAME_RE",
    "SENSITIVE_FILENAME_RE",
    "SIMPLE_EMAIL_RE",
    "SUPPLY_CHAIN_CANDIDATE_FILENAMES",
    "_apply_private_permissions",
    "_close_fd_safely",
    "_missing_executable_message",
    "_read_json_from_locked_fd",
    "_write_json_to_locked_fd",
    "acquire_advisory_file_lock",
    "audit_github_release_hardening",
    "classify_litellm_incident_severity",
    "classify_secret_match_context",
    "cleanup_private_temp_text_file",
    "create_private_temp_text_file",
    "datetime",
    "discover_repository_targets",
    "ensure_private_directory",
    "errno",
    "extract_personal_path_literals",
    "github_fix_guide",
    "infer_github_username_from_noreply",
    "is_public_github_remote",
    "is_relevant_email_candidate",
    "is_repo_privacy_guardian_reviewed_network_indicator",
    "is_repo_privacy_guardian_source_tree",
    "json",
    "line_has_exfil_indicator",
    "normalize_text_values",
    "os",
    "parse_github_remote_owner",
    "re",
    "read_text_file_for_scan",
    "release_advisory_file_lock",
    "repo_display_name",
    "socket",
    "split_email_matches_by_taxonomy",
    "split_unexpected_emails_by_origin_ownership",
    "streaming_popen_kwargs",
    "subprocess",
    "subprocess_stdin",
    "sys",
    "threading",
    "time",
    "validate_fix_preconditions",
    "write_private_text_file",
)


def _sync_scanner_public_overrides() -> None:
    for name in _SCANNER_OVERRIDE_NAMES:
        globals()[name] = getattr(_core, name)


_sync_scanner_public_overrides()


def _wrap_guard_method(method: Callable[..., Any]) -> Callable[..., Any]:
    def synced(self: object, *args: Any, **kwargs: Any) -> Any:
        _sync_scanner_public_overrides()
        return method(self, *args, **kwargs)

    synced.__name__ = getattr(method, "__name__", "synced")
    synced.__doc__ = getattr(method, "__doc__", None)
    return synced


for _method_name, _method in list(RepoPublicationGuard.__dict__.items()):
    if callable(_method) and not _method_name.startswith("__"):
        setattr(RepoPublicationGuard, _method_name, _wrap_guard_method(_method))
