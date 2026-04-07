#!/usr/bin/env python3
"""
Repository Publication Guard

Audits repositories for public-release safety and can optionally apply automated fixes.
The checks are aligned with docs/POLICY.md.

Features:
- CLI mode (audit and optional fix)
- Simple Tkinter GUI mode
- History and working-tree scans for secrets/PII/path leaks
- Git identity and commit metadata checks
- .gitignore completeness checks based on policy + baseline patterns
- Optional automated fixes (history rewrite, ignore hygiene, force push)
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable


DEFAULT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = Path(__file__).resolve().parent / "docs" / "POLICY.md"
DEFAULT_NOREPLY = "noreply@github.com"
DEFAULT_PLACEHOLDER = "redacted-contributor@example.invalid"
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "Audit_Results"

DEFAULT_IGNORE_BASELINE = [
    ".venv/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".env",
    ".env.*",
    "wsa-config.local.yaml",
    "sessions/*",
    "artifacts/",
    "exports/",
    "*.log",
    "*.tmp",
    "*.bak",
    ".vscode/",
    ".idea/",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
]

SENSITIVE_FILENAME_RE = re.compile(
    r"^\.env$|^\.env\.|\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|id_rsa|"
    r"secrets?\.|credentials?\.|token|__pycache__/|\.pyc$",
    re.IGNORECASE,
)

SECRET_CONTENT_RE = re.compile(
    r"ghp_[A-Za-z0-9]{36}|"
    r"github_pat_[A-Za-z0-9_]{40,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z\-_]{35}|"
    r"xox[baprs]-[A-Za-z0-9-]+|"
    r"Authorization:\s*(Bearer|token)\s+[A-Za-z0-9._-]+|"
    r"BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"
)

SECRET_REMEDIATE_FILENAME_RE = re.compile(
    r"(^|/)\.env(\..*)?$|"
    r"\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|"
    r"(^|/)id_rsa$|"
    r"secret|credential|token|password|passwd|api[_-]?key",
    re.IGNORECASE,
)

PERSONAL_PATH_RE = re.compile(r"C:\\Users\\|/Users/|/home/|AppData\\|Documents\\")
EMAIL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

EXFIL_CODE_RE = re.compile(
    r"Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|HttpClient|WebClient|"
    r"requests\.|httpx|aiohttp|urllib|urlopen|websockets|socket\.|"
    r"upload|webhook|telemetry|analytics"
)

CODE_EXTENSIONS = {
    ".py",
    ".ps1",
    ".psm1",
    ".sh",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rs",
}


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class RunArtifacts:
    run_id: str
    run_dir: Path
    json_path: Path
    log_path: Path
    html_path: Path
    started_at: datetime


class RunLogger:
    def __init__(self, log_path: Path, sink: Callable[[str], None] | None = None) -> None:
        self.log_path = log_path
        self.sink = sink
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")

    def __call__(self, msg: str) -> None:
        text = str(msg)
        if self.sink:
            self.sink(text)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{stamp}] {text}\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)


@dataclass
class RepoReport:
    name: str
    path: str
    origin_url: str | None = None
    upstream_url: str | None = None
    branch: str | None = None
    head: str | None = None
    origin_head: str | None = None
    clean_status: str | None = None
    fsck_ok: bool = True
    fsck_output: list[str] = field(default_factory=list)

    author_emails: list[str] = field(default_factory=list)
    committer_emails: list[str] = field(default_factory=list)
    unexpected_emails: list[str] = field(default_factory=list)

    tracked_secret_matches: list[str] = field(default_factory=list)
    tracked_path_matches: list[str] = field(default_factory=list)
    tracked_email_matches: list[str] = field(default_factory=list)
    tracked_secret_files: list[str] = field(default_factory=list)

    history_secret_matches: list[str] = field(default_factory=list)
    history_path_matches: list[str] = field(default_factory=list)
    history_email_matches: list[str] = field(default_factory=list)
    history_secret_files: list[str] = field(default_factory=list)

    history_sensitive_added: list[str] = field(default_factory=list)
    history_sensitive_deleted: list[str] = field(default_factory=list)

    secret_file_candidates: list[str] = field(default_factory=list)
    secret_file_autopurge_candidates: list[str] = field(default_factory=list)
    secret_file_manual_review_candidates: list[str] = field(default_factory=list)
    secret_history_purge_paths: list[str] = field(default_factory=list)

    tracked_but_ignored: list[str] = field(default_factory=list)
    gitignore_missing_patterns: list[str] = field(default_factory=list)
    exfil_code_indicators: list[str] = field(default_factory=list)

    backups_created: list[str] = field(default_factory=list)
    fix_actions: list[str] = field(default_factory=list)
    fix_errors: list[str] = field(default_factory=list)

    status: str = "PASS"
    failures: list[str] = field(default_factory=list)

    def finalize(self) -> None:
        checks = [
            (not self.fsck_ok, "git fsck failed"),
            (bool(self.unexpected_emails), "unexpected commit metadata emails"),
            (bool(self.tracked_secret_matches), "secret-like patterns in tracked files"),
            (bool(self.tracked_path_matches), "personal path patterns in tracked files"),
            (bool(self.history_secret_matches), "secret-like patterns in history patches"),
            (bool(self.history_path_matches), "personal path patterns in history patches"),
            (bool(self.history_email_matches), "email addresses in history patches"),
            (bool(self.history_sensitive_added), "sensitive filenames added in history"),
            (bool(self.history_sensitive_deleted), "sensitive filenames deleted in history"),
            (bool(self.tracked_but_ignored), "tracked files that should be ignored"),
            (bool(self.gitignore_missing_patterns), "missing required .gitignore patterns"),
        ]
        self.failures = [reason for bad, reason in checks if bad]
        self.status = "FAIL" if self.failures else "PASS"


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
        push: bool,
        dry_run: bool,
        max_matches: int,
        logger: Callable[[str], None],
    ) -> None:
        self.root = root
        self.policy_path = policy_path
        self.noreply_email = noreply_email
        self.placeholder_email = placeholder_email
        self.owner_name = owner_name
        self.owner_emails = set(owner_emails)
        self.redact_third_party = redact_third_party
        self.purge_detected_secret_files = purge_detected_secret_files
        self.purge_all_detected_secret_files = purge_all_detected_secret_files
        self.push = push
        self.dry_run = dry_run
        self.max_matches = max_matches
        self.log = logger

        self.required_ignore_patterns = self._load_required_ignore_patterns()

    def _run(self, cmd: list[str], cwd: Path | None = None) -> CommandResult:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def _run_checked(self, cmd: list[str], cwd: Path | None = None) -> CommandResult:
        result = self._run(cmd, cwd=cwd)
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed ({result.returncode}): {shlex.join(cmd)}\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        return result

    def _git(self, repo: Path, *args: str) -> CommandResult:
        return self._run(["git", "-C", str(repo), *args])

    def _git_checked(self, repo: Path, *args: str) -> CommandResult:
        return self._run_checked(["git", "-C", str(repo), *args])

    def _read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def _load_required_ignore_patterns(self) -> list[str]:
        patterns = list(DEFAULT_IGNORE_BASELINE)
        if not self.policy_path.exists():
            return sorted(set(patterns))

        raw = self._read_text(self.policy_path)
        in_block = False
        extracted: list[str] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("minimo recomendado"):
                in_block = True
                continue
            if in_block and stripped.startswith("Comprobar ignored"):
                break
            if in_block and stripped.startswith("- "):
                candidate = stripped[2:].strip()
                if re.match(r"^[A-Za-z0-9_.*\-/]+$", candidate):
                    extracted.append(candidate)

        patterns.extend(extracted)
        unique = sorted(set(patterns))
        return unique

    def discover_repositories(
        self,
        repo_filters: list[str] | None,
        public_only: bool,
    ) -> list[Path]:
        repos: list[Path] = []

        if repo_filters:
            for item in repo_filters:
                p = Path(item)
                if not p.is_absolute():
                    p = self.root / p
                if (p / ".git").exists():
                    repos.append(p)
                else:
                    self.log(f"[WARN] Not a git repo or missing path: {p}")
        else:
            for child in sorted(self.root.iterdir()):
                if child.is_dir() and (child / ".git").exists():
                    repos.append(child)

        if public_only:
            filtered: list[Path] = []
            for repo in repos:
                origin = self._git(repo, "remote", "get-url", "origin")
                if origin.returncode == 0 and "github.com" in origin.stdout.strip().lower():
                    filtered.append(repo)
            repos = filtered

        return repos

    def _iter_tracked_files(self, repo: Path) -> list[Path]:
        result = self._git(repo, "ls-files", "-z")
        if result.returncode != 0:
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
    ) -> list[str]:
        matches: list[str] = []
        for file_path in self._iter_tracked_files(repo):
            rel = file_path.relative_to(repo).as_posix()
            if only_code_files and file_path.suffix.lower() not in CODE_EXTENSIONS:
                continue
            try:
                data = file_path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data:
                continue
            text = data.decode("utf-8", errors="replace")
            for idx, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    matches.append(f"{rel}:{idx}:{line.strip()[:240]}")
                    if len(matches) >= self.max_matches:
                        return matches
        return matches

    def _scan_history_patch(self, repo: Path, regex: re.Pattern[str]) -> list[str]:
        cmd = [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "-p",
            "--no-color",
            "--pretty=format:",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        matches: list[str] = []
        assert proc.stdout is not None
        for idx, line in enumerate(proc.stdout, start=1):
            if regex.search(line):
                matches.append(f"L{idx}:{line.strip()[:240]}")
                if len(matches) >= self.max_matches:
                    proc.kill()
                    break
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        return matches

    def _scan_history_non_allowed_emails(self, repo: Path) -> list[str]:
        cmd = [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "-p",
            "--no-color",
            "--pretty=format:",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        matches: list[str] = []
        assert proc.stdout is not None
        for idx, line in enumerate(proc.stdout, start=1):
            emails = EMAIL_RE.findall(line)
            leaked = [email for email in emails if not self._is_allowed_email(email)]
            if leaked:
                uniq = ", ".join(sorted(set(leaked)))
                matches.append(f"L{idx}:{uniq}:{line.strip()[:200]}")
                if len(matches) >= self.max_matches:
                    proc.kill()
                    break
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        return matches

    def _scan_history_secret_files(self, repo: Path) -> list[str]:
        cmd = [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "-p",
            "--no-color",
            "--pretty=format:",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        files: list[str] = []
        seen: set[str] = set()
        current_file: str | None = None

        assert proc.stdout is not None
        for line in proc.stdout:
            if line.startswith("diff --git "):
                match = re.match(r"diff --git a/(.+?) b/(.+)$", line.strip())
                if match:
                    current_file = match.group(2)
                else:
                    current_file = None
                continue

            if not current_file:
                continue

            if line.startswith("+++") or line.startswith("---"):
                continue

            if not (line.startswith("+") or line.startswith("-")):
                continue

            if SECRET_CONTENT_RE.search(line) and current_file not in seen:
                seen.add(current_file)
                files.append(current_file)
                if len(files) >= self.max_matches:
                    proc.kill()
                    break

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

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
        gitignore.write_text(new_text, encoding="utf-8")
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

    def _unique_commit_emails(self, repo: Path, field: str) -> list[str]:
        out = self._git(repo, "log", "--all", f"--pretty=format:{field}")
        if out.returncode != 0:
            return []
        emails = sorted({line.strip() for line in out.stdout.splitlines() if line.strip()})
        return emails

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
        report = RepoReport(name=repo.name, path=str(repo))

        report.origin_url = self._git(repo, "remote", "get-url", "origin").stdout.strip() or None
        report.upstream_url = self._git(repo, "remote", "get-url", "upstream").stdout.strip() or None
        report.branch = self._git(repo, "branch", "--show-current").stdout.strip() or None
        report.head = self._git(repo, "rev-parse", "--short", "HEAD").stdout.strip() or None
        report.origin_head = self._git(repo, "rev-parse", "--short", "origin/main").stdout.strip() or None
        report.clean_status = self._git(repo, "status", "--short", "--branch").stdout.strip()

        fsck = self._git(repo, "fsck", "--full")
        report.fsck_ok = fsck.returncode == 0
        if fsck.stdout.strip() or fsck.stderr.strip():
            payload = (fsck.stdout + "\n" + fsck.stderr).strip()
            report.fsck_output = payload.splitlines()[: self.max_matches]

        report.author_emails = self._unique_commit_emails(repo, "%ae")
        report.committer_emails = self._unique_commit_emails(repo, "%ce")

        all_emails = sorted(set(report.author_emails + report.committer_emails))
        report.unexpected_emails = [email for email in all_emails if not self._is_allowed_email(email)]

        report.tracked_secret_matches = self._scan_tracked_content(repo, SECRET_CONTENT_RE)
        report.tracked_secret_files = self._extract_file_paths_from_match_lines(report.tracked_secret_matches)
        report.tracked_path_matches = self._scan_tracked_content(repo, PERSONAL_PATH_RE)
        report.tracked_email_matches = self._scan_tracked_content(repo, EMAIL_RE)

        report.history_secret_matches = self._scan_history_patch(repo, SECRET_CONTENT_RE)
        report.history_secret_files = self._scan_history_secret_files(repo)
        report.history_path_matches = self._scan_history_patch(repo, PERSONAL_PATH_RE)
        report.history_email_matches = self._scan_history_non_allowed_emails(repo)

        self._build_secret_remediation_plan(report)

        report.history_sensitive_added = self._history_file_matches(repo, "A")
        report.history_sensitive_deleted = self._history_file_matches(repo, "D")

        ignored = self._git(repo, "ls-files", "-ci", "--exclude-standard")
        if ignored.returncode == 0:
            report.tracked_but_ignored = [
                line.strip() for line in ignored.stdout.splitlines() if line.strip()
            ][: self.max_matches]

        report.exfil_code_indicators = self._scan_tracked_content(
            repo,
            EXFIL_CODE_RE,
            only_code_files=True,
        )

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

        report.finalize()
        return report

    def _ensure_git_filter_repo(self) -> None:
        probe = self._run([sys.executable, "-m", "git_filter_repo", "--help"])
        if probe.returncode == 0:
            return

        self.log("[INFO] git-filter-repo not found in current interpreter. Installing...")
        install = self._run([sys.executable, "-m", "pip", "install", "git-filter-repo"])
        if install.returncode != 0:
            raise RuntimeError(
                "Unable to install git-filter-repo.\n"
                f"STDOUT:\n{install.stdout}\nSTDERR:\n{install.stderr}"
            )

        verify = self._run([sys.executable, "-m", "git_filter_repo", "--help"])
        if verify.returncode != 0:
            raise RuntimeError("git-filter-repo installation verification failed.")

    def _write_mailmap(self, repo: Path, unique_emails: list[str]) -> Path | None:
        lines: list[str] = []

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
                lines.append(f"{self.owner_name} <{self.noreply_email}> <{email}>")
                continue

            if email.endswith("@users.noreply.github.com"):
                if self.redact_third_party:
                    lines.append(
                        f"Redacted Contributor <{self.placeholder_email}> <{email}>"
                    )
                continue

            if self.redact_third_party:
                lines.append(f"Redacted Contributor <{self.placeholder_email}> <{email}>")

        if not lines:
            return None

        tmp = Path(tempfile.mkdtemp(prefix="repo-publication-guard-")) / "mailmap.txt"
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return tmp

    def _write_replace_text_file(self, report: RepoReport) -> Path | None:
        replacement_map: dict[str, str] = {}

        candidate_lines = (
            report.tracked_email_matches
            + report.history_email_matches
            + report.tracked_path_matches
            + report.history_path_matches
        )

        for line in candidate_lines:
            for email in EMAIL_RE.findall(line):
                if self._is_allowed_email(email):
                    continue

                if email in self.owner_emails:
                    replacement_map[email] = self.noreply_email
                elif self.redact_third_party:
                    replacement_map[email] = self.placeholder_email

        if not replacement_map:
            return None

        lines = [f"literal:{src}==>{dst}" for src, dst in sorted(replacement_map.items())]
        tmp = Path(tempfile.mkdtemp(prefix="repo-publication-guard-")) / "replace-text.txt"
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return tmp

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
        unique = sorted(set(report.author_emails + report.committer_emails))
        mailmap = self._write_mailmap(repo, unique)
        replace_text = self._write_replace_text_file(report)

        purge_by_filename_signals = bool(report.history_sensitive_added or report.history_sensitive_deleted)
        purge_paths = sorted(set(report.secret_history_purge_paths))
        needs_history_purge = bool(purge_by_filename_signals or purge_paths)
        do_rewrite = bool(mailmap) or bool(replace_text) or needs_history_purge
        if not do_rewrite:
            report.fix_actions.append("history rewrite skipped (no mappings required)")
            return

        remotes = self._save_remotes(repo)

        if self.dry_run:
            report.fix_actions.append("[dry-run] history rewrite would run")
            return

        self._ensure_git_filter_repo()

        cmd = [sys.executable, "-m", "git_filter_repo", "--force"]
        if mailmap:
            cmd.extend(["--mailmap", str(mailmap)])
        if replace_text:
            cmd.extend(["--replace-text", str(replace_text)])

        if needs_history_purge:
            for purge_path in purge_paths:
                cmd.extend(["--path", purge_path])

            if purge_by_filename_signals:
                # Purge common sensitive/local artifacts from whole history.
                cmd.extend(
                    [
                        "--path-regex",
                        r"(^|.*/)__pycache__/.*|.*\.pyc$|(^|.*/)\.env(\..*)?$|"
                        r".*\.(pem|key|p12|pfx|kdbx)$|(^|.*/)id_rsa$",
                    ]
                )

            cmd.append("--invert-paths")

        self._run_checked(cmd, cwd=repo)
        self._restore_remotes(repo, remotes)
        report.fix_actions.append("history rewritten with git-filter-repo")

    def _make_backup_bundle(self, repo: Path) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        bundle = self.root / f"{repo.name}-pre-publication-fix-{stamp}.bundle"
        if self.dry_run:
            return bundle
        self._git_checked(repo, "bundle", "create", str(bundle), "--all")
        return bundle

    def _commit_if_needed(self, repo: Path, message: str) -> bool:
        porcelain = self._git(repo, "status", "--porcelain").stdout.strip()
        if not porcelain:
            return False
        if self.dry_run:
            return True
        self._git_checked(repo, "add", "-A")
        self._git_checked(repo, "commit", "-m", message)
        return True

    def _set_local_identity(self, repo: Path) -> None:
        if self.dry_run:
            return
        self._git_checked(repo, "config", "--local", "user.name", self.owner_name)
        self._git_checked(repo, "config", "--local", "user.email", self.noreply_email)

    def _push_if_requested(self, repo: Path, report: RepoReport) -> None:
        if not self.push:
            return

        branch = report.branch or "main"
        if self.dry_run:
            report.fix_actions.append("[dry-run] force push skipped")
            return

        self._git_checked(repo, "fetch", "origin", branch)
        self._git_checked(repo, "push", "--force-with-lease", "origin", branch)
        # Restore tracking relationship
        self._git(repo, "branch", "--set-upstream-to", f"origin/{branch}", branch)

    def apply_fixes(self, repo: Path, report: RepoReport) -> RepoReport:
        try:
            self.log(f"[FIX] {repo.name}: creating backup bundle")
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

            committed = self._commit_if_needed(
                repo,
                "chore(security): align ignore rules and untrack sensitive/local artifacts",
            )
            if committed:
                report.fix_actions.append("committed ignore-hygiene changes")

            self.log(f"[FIX] {repo.name}: rewriting history (emails + sensitive artifacts)")
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

        return report


def print_report(report: RepoReport, logger: Callable[[str], None]) -> None:  # pragma: no cover
    logger(f"\n=== {report.name} ===")
    logger(f"path: {report.path}")
    logger(f"origin: {report.origin_url or '-'}")
    logger(f"upstream: {report.upstream_url or '-'}")
    logger(f"branch/head/origin_main: {report.branch or '-'} / {report.head or '-'} / {report.origin_head or '-'}")
    logger(f"status: {report.status}")
    if report.failures:
        logger("failures:")
        for item in report.failures:
            logger(f"  - {item}")

    logger(f"unexpected_emails: {len(report.unexpected_emails)}")
    logger(f"tracked_secret_matches: {len(report.tracked_secret_matches)}")
    logger(f"tracked_secret_files: {len(report.tracked_secret_files)}")
    logger(f"tracked_path_matches: {len(report.tracked_path_matches)}")
    logger(f"tracked_email_matches: {len(report.tracked_email_matches)}")
    logger(f"history_secret_matches: {len(report.history_secret_matches)}")
    logger(f"history_secret_files: {len(report.history_secret_files)}")
    logger(f"history_path_matches: {len(report.history_path_matches)}")
    logger(f"history_email_matches: {len(report.history_email_matches)}")
    logger(f"history_sensitive_added: {len(report.history_sensitive_added)}")
    logger(f"history_sensitive_deleted: {len(report.history_sensitive_deleted)}")
    logger(f"secret_file_candidates: {len(report.secret_file_candidates)}")
    logger(f"secret_autopurge_candidates: {len(report.secret_file_autopurge_candidates)}")
    logger(f"secret_manual_review_candidates: {len(report.secret_file_manual_review_candidates)}")
    logger(f"tracked_but_ignored: {len(report.tracked_but_ignored)}")
    logger(f"gitignore_missing_patterns: {len(report.gitignore_missing_patterns)}")
    logger(f"exfil_code_indicators: {len(report.exfil_code_indicators)}")

    if report.fix_actions:
        logger("fix_actions:")
        for action in report.fix_actions:
            logger(f"  - {action}")

    if report.fix_errors:
        logger("fix_errors:")
        for err in report.fix_errors:
            logger(f"  - {err}")


def create_run_artifacts(base_dir: Path) -> RunArtifacts:
    base_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = base_dir / stamp
    suffix = 1
    while run_dir.exists():
        run_dir = base_dir / f"{stamp}-{suffix:02d}"
        suffix += 1
    run_dir.mkdir(parents=True, exist_ok=False)
    started = datetime.now()
    return RunArtifacts(
        run_id=run_dir.name,
        run_dir=run_dir,
        json_path=run_dir / "report.json",
        log_path=run_dir / "run.log",
        html_path=run_dir / "report.html",
        started_at=started,
    )


def enforce_results_dir(requested_dir: Path | None) -> tuple[Path, bool]:
    base = DEFAULT_RESULTS_DIR.resolve()
    if requested_dir is None:
        return base, False

    requested = requested_dir.resolve()
    if requested == base:
        return requested, False

    try:
        requested.relative_to(base)
        return requested, False
    except ValueError:
        return base, True


def resolve_optional_json_export_path(raw_value: str | None, default_name: str) -> Path | None:
    if not raw_value:
        return None
    raw = Path(raw_value)
    raw_text = str(raw_value)
    if raw_text.endswith("/") or raw_text.endswith("\\") or (raw.exists() and raw.is_dir()):
        raw.mkdir(parents=True, exist_ok=True)
        return raw / default_name
    if raw.suffix.lower() != ".json":
        raw.mkdir(parents=True, exist_ok=True)
        return raw / default_name
    raw.parent.mkdir(parents=True, exist_ok=True)
    return raw


def classify_repo_severity(report: RepoReport) -> tuple[str, int, list[str]]:
    score = 0
    highlights: list[str] = []

    if report.tracked_secret_matches or report.history_secret_matches:
        score = max(score, 100)
        highlights.append("Secret-like patterns found in tracked content or history")
    if report.secret_file_candidates:
        score = max(score, 95)
        highlights.append("Secret file candidates detected")
    if report.history_sensitive_added or report.history_sensitive_deleted:
        score = max(score, 90)
        highlights.append("Sensitive filenames found in git history")
    if report.unexpected_emails:
        score = max(score, 75)
        highlights.append("Unexpected commit metadata emails")
    if report.tracked_path_matches or report.history_path_matches:
        score = max(score, 70)
        highlights.append("Personal/local path leakage detected")
    if report.tracked_but_ignored:
        score = max(score, 60)
        highlights.append("Ignored files are still tracked")
    if report.gitignore_missing_patterns:
        score = max(score, 40)
        highlights.append("Required .gitignore baseline is incomplete")

    if score >= 90:
        return "ALTA", score, highlights
    if score >= 60:
        return "MEDIA", score, highlights
    if report.status == "FAIL":
        if not highlights:
            highlights.append("Non-critical policy failures found")
        return "BAJA", score, highlights
    return "OK", score, highlights


def render_html_report(
    reports: list[RepoReport],
    artifacts: RunArtifacts,
    root_path: Path,
    policy_path: Path,
    run_settings: dict[str, str],
    finished_at: datetime,
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

    high_risk_repos = [item for item in repo_severity_data if item[1] == "ALTA"]

    def render_lines(items: list[str], limit: int = 8) -> str:
        if not items:
            return '<div class="empty">No findings in this category.</div>'
        trimmed = items[:limit]
        content = "".join(f"<li><code>{esc(line)}</code></li>" for line in trimmed)
        suffix = ""
        if len(items) > limit:
            suffix = f'<div class="more">Showing {limit} of {len(items)} entries.</div>'
        return f"<ul class=\"finding-list\">{content}</ul>{suffix}"

    reason_rows = "".join(
        f"<tr><td>{esc(reason)}</td><td class=\"num\">{count}</td></tr>"
        for reason, count in ordered_reasons
    )
    if not reason_rows:
        reason_rows = '<tr><td class="empty" colspan="2">No failure reasons recorded.</td></tr>'

    settings_rows = "".join(
        f"<tr><td>{esc(key)}</td><td><code>{esc(value)}</code></td></tr>"
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
        high_cards = '<div class="empty">No ALTA severity repositories in this run.</div>'

    repo_rows = ""
    repo_details = ""
    for rep, sev_label, _sev_score, highlights in repo_severity_data:
        sev_class = f"sev-{sev_label.lower()}"
        repo_rows += (
            "<tr>"
            f"<td>{esc(rep.name)}</td>"
            f"<td><span class=\"sev-pill {sev_class}\">{esc(sev_label)}</span></td>"
            f"<td>{esc(rep.status)}</td>"
            f"<td class=\"num\">{len(rep.failures)}</td>"
            f"<td class=\"num\">{len(rep.tracked_secret_matches) + len(rep.history_secret_matches)}</td>"
            f"<td class=\"num\">{len(rep.secret_file_candidates)}</td>"
            f"<td class=\"num\">{len(rep.unexpected_emails)}</td>"
            f"<td class=\"num\">{len(rep.gitignore_missing_patterns)}</td>"
            "</tr>"
        )

        highlights_html = "".join(f"<li>{esc(item)}</li>" for item in highlights)
        if not highlights_html:
            highlights_html = "<li>No highlight details.</li>"

        failures_html = "".join(f"<li>{esc(item)}</li>" for item in rep.failures)
        if not failures_html:
            failures_html = "<li>No failures.</li>"

        details_metrics = (
            "<table class=\"metrics\">"
            "<tr><th>Metric</th><th>Value</th></tr>"
            f"<tr><td>unexpected_emails</td><td class=\"num\">{len(rep.unexpected_emails)}</td></tr>"
            f"<tr><td>tracked_secret_matches</td><td class=\"num\">{len(rep.tracked_secret_matches)}</td></tr>"
            f"<tr><td>history_secret_matches</td><td class=\"num\">{len(rep.history_secret_matches)}</td></tr>"
            f"<tr><td>secret_file_candidates</td><td class=\"num\">{len(rep.secret_file_candidates)}</td></tr>"
            f"<tr><td>tracked_path_matches</td><td class=\"num\">{len(rep.tracked_path_matches)}</td></tr>"
            f"<tr><td>history_path_matches</td><td class=\"num\">{len(rep.history_path_matches)}</td></tr>"
            f"<tr><td>history_email_matches</td><td class=\"num\">{len(rep.history_email_matches)}</td></tr>"
            f"<tr><td>history_sensitive_added</td><td class=\"num\">{len(rep.history_sensitive_added)}</td></tr>"
            f"<tr><td>history_sensitive_deleted</td><td class=\"num\">{len(rep.history_sensitive_deleted)}</td></tr>"
            f"<tr><td>tracked_but_ignored</td><td class=\"num\">{len(rep.tracked_but_ignored)}</td></tr>"
            f"<tr><td>gitignore_missing_patterns</td><td class=\"num\">{len(rep.gitignore_missing_patterns)}</td></tr>"
            "</table>"
        )

        detail_sections = (
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
            "<section><h5>Secret file candidates</h5>"
            f"{render_lines(rep.secret_file_candidates)}"
            "</section>"
            "<section><h5>Unexpected commit emails</h5>"
            f"{render_lines(rep.unexpected_emails)}"
            "</section>"
            "</div>"
            "<div class=\"detail-grid\">"
            "<section><h5>Path/email leaks in history (sample)</h5>"
            f"{render_lines(rep.history_path_matches + rep.history_email_matches)}"
            "</section>"
            "<section><h5>Ignore and history filename issues</h5>"
            f"{render_lines(rep.gitignore_missing_patterns + rep.history_sensitive_added + rep.history_sensitive_deleted)}"
            "</section>"
            "</div>"
            "<section><h5>Metrics snapshot</h5>"
            f"{details_metrics}</section>"
        )

        repo_details += (
            "<details class=\"repo-detail\">"
            f"<summary>{esc(rep.name)} | severity {esc(sev_label)} | status {esc(rep.status)}</summary>"
            f"<p class=\"meta\">path: <code>{esc(rep.path)}</code></p>"
            f"<p class=\"meta\">origin: <code>{esc(rep.origin_url or '-')}</code></p>"
            f"<p class=\"meta\">upstream: <code>{esc(rep.upstream_url or '-')}</code></p>"
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
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      background: radial-gradient(circle at top right, #dde8ff 0%, var(--bg) 42%);
      color: var(--text);
      line-height: 1.45;
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
    section {{ margin-top: 18px; }}
    h2 {{ margin: 0 0 10px; font-size: 1.18rem; }}
    h4 {{ margin: 0 0 8px; }}
    .panel {{ background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 14px; box-shadow: var(--shadow); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ background: #eef3fb; font-weight: 700; }}
    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .sev-pill {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.82rem; font-weight: 700; }}
    .sev-alta {{ background: #ffe4e8; color: var(--high); }}
    .sev-media {{ background: #fff1de; color: var(--med); }}
    .sev-baja {{ background: #fff8df; color: var(--low); }}
    .sev-ok {{ background: #dff6e9; color: var(--ok); }}
    .high-card {{ border: 1px solid #f3b7bf; background: #fff0f3; border-radius: 10px; padding: 12px; margin-bottom: 10px; }}
    .repo-detail {{ border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; margin-bottom: 10px; background: var(--surface); box-shadow: var(--shadow); }}
    .repo-detail summary {{ cursor: pointer; font-weight: 700; }}
    .meta {{ margin: 8px 0 0; color: var(--muted); }}
    .detail-grid {{ display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); margin-top: 10px; }}
    .finding-list {{ margin: 0; padding-left: 18px; }}
    .finding-list code {{ white-space: pre-wrap; word-break: break-word; }}
    code {{ background: #f1f5ff; color: #1b2f55; border-radius: 4px; padding: 1px 4px; }}
    .more, .empty {{ margin-top: 8px; color: var(--muted); font-style: italic; }}
    @media (max-width: 760px) {{
      .container {{ padding: 12px; }}
      .hero {{ padding: 16px; }}
      th, td {{ padding: 8px; }}
    }}
  </style>
</head>
<body>
  <div class=\"container\">
    <header class=\"hero\">
      <h1>Repository Privacy Audit Report</h1>
      <p><strong>Run ID:</strong> {esc(artifacts.run_id)}</p>
      <p><strong>Started:</strong> {esc(artifacts.started_at.strftime('%Y-%m-%d %H:%M:%S'))} | <strong>Finished:</strong> {esc(finished_at.strftime('%Y-%m-%d %H:%M:%S'))} | <strong>Duration:</strong> {duration_seconds:.2f}s</p>
      <p><strong>Root:</strong> <code>{esc(str(root_path))}</code></p>
      <p><strong>Policy:</strong> <code>{esc(str(policy_path))}</code></p>
      <p><strong>Artifacts:</strong> <code>{esc(str(artifacts.run_dir))}</code></p>
    </header>

    <section class=\"grid\">
      <article class=\"card\"><h3>Total repositories</h3><p class=\"metric\">{total}</p></article>
      <article class=\"card\"><h3>PASS</h3><p class=\"metric pass\">{passed}</p></article>
      <article class=\"card\"><h3>FAIL</h3><p class=\"metric fail\">{failed}</p></article>
      <article class=\"card\"><h3>ALTA severity repos</h3><p class=\"metric fail\">{len(high_risk_repos)}</p></article>
    </section>

    <section class=\"panel\">
      <h2>Execution settings</h2>
      <table>
        <tr><th>Setting</th><th>Value</th></tr>
        {settings_rows}
      </table>
    </section>

    <section class=\"panel\">
      <h2>High severity focus (ALTA)</h2>
      {high_cards}
    </section>

    <section class=\"panel\">
      <h2>Failure reason frequency</h2>
      <table>
        <tr><th>Reason</th><th class=\"num\">Repos</th></tr>
        {reason_rows}
      </table>
    </section>

    <section class=\"panel\">
      <h2>Repository matrix</h2>
      <table>
        <tr>
          <th>Repository</th>
          <th>Severity</th>
          <th>Status</th>
          <th class=\"num\">Failures</th>
          <th class=\"num\">Secret matches</th>
          <th class=\"num\">Secret file candidates</th>
          <th class=\"num\">Unexpected emails</th>
          <th class=\"num\">Missing .gitignore rules</th>
        </tr>
        {repo_rows}
      </table>
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
) -> None:
    finished_at = datetime.now()
    payload = [rep.__dict__ for rep in reports]
    artifacts.json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger(f"[INFO] JSON report written to {artifacts.json_path}")

    html_report = render_html_report(
        reports=reports,
        artifacts=artifacts,
        root_path=root_path,
        policy_path=policy_path,
        run_settings=run_settings,
        finished_at=finished_at,
    )
    artifacts.html_path.write_text(html_report, encoding="utf-8")
    logger(f"[INFO] HTML report written to {artifacts.html_path}")
    logger(f"[INFO] LOG report written to {artifacts.log_path}")

    export_path = resolve_optional_json_export_path(optional_json_export, artifacts.json_path.name)
    if export_path:
        export_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger(f"[INFO] Extra JSON export written to {export_path}")


class GuiApp:  # pragma: no cover
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import messagebox, scrolledtext, ttk

        self.tk = tk
        self.messagebox = messagebox
        self.root = tk.Tk()
        self.root.title("Repos Publication Guard")
        self.root.geometry("980x720")

        self.root_var = tk.StringVar(value=str(DEFAULT_ROOT))
        self.policy_var = tk.StringVar(value=str(DEFAULT_POLICY))
        self.noreply_var = tk.StringVar(value=DEFAULT_NOREPLY)
        self.placeholder_var = tk.StringVar(value=DEFAULT_PLACEHOLDER)
        self.owner_name_var = tk.StringVar(value="Owner")
        self.owner_emails_var = tk.StringVar(value="")

        self.public_only_var = tk.BooleanVar(value=True)
        self.fix_var = tk.BooleanVar(value=False)
        self.push_var = tk.BooleanVar(value=False)
        self.redact_var = tk.BooleanVar(value=False)
        self.purge_detected_secret_files_var = tk.BooleanVar(value=False)
        self.purge_all_detected_secret_files_var = tk.BooleanVar(value=False)
        self.dry_run_var = tk.BooleanVar(value=False)

        frm = ttk.Frame(self.root)
        frm.pack(fill="both", expand=True, padx=10, pady=10)

        row = 0
        ttk.Label(frm, text="Root").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.root_var, width=95).grid(row=row, column=1, sticky="we", padx=4)
        ttk.Button(frm, text="Refresh", command=self.refresh_repos).grid(row=row, column=2, sticky="we")

        row += 1
        ttk.Label(frm, text="Policy").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.policy_var, width=95).grid(row=row, column=1, sticky="we", padx=4)

        row += 1
        ttk.Label(frm, text="Noreply email").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.noreply_var, width=40).grid(row=row, column=1, sticky="w", padx=4)

        row += 1
        ttk.Label(frm, text="Placeholder email").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.placeholder_var, width=40).grid(row=row, column=1, sticky="w", padx=4)

        row += 1
        ttk.Label(frm, text="Owner name").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.owner_name_var, width=30).grid(row=row, column=1, sticky="w", padx=4)

        row += 1
        ttk.Label(frm, text="Owner private emails (comma)").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.owner_emails_var, width=70).grid(row=row, column=1, sticky="w", padx=4)

        row += 1
        opts = ttk.Frame(frm)
        opts.grid(row=row, column=1, sticky="w", pady=6)
        ttk.Checkbutton(opts, text="Public remotes only", variable=self.public_only_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Apply fix", variable=self.fix_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Force push", variable=self.push_var).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Redact third-party emails", variable=self.redact_var).pack(side="left", padx=4)
        ttk.Checkbutton(
            opts,
            text="Purge detected secret files (safe)",
            variable=self.purge_detected_secret_files_var,
        ).pack(side="left", padx=4)
        ttk.Checkbutton(
            opts,
            text="Purge all detected secret files (risky)",
            variable=self.purge_all_detected_secret_files_var,
        ).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Dry run", variable=self.dry_run_var).pack(side="left", padx=4)

        row += 1
        ttk.Label(frm, text="Repositories").grid(row=row, column=0, sticky="nw")
        self.repo_list = tk.Listbox(frm, selectmode="extended", height=12)
        self.repo_list.grid(row=row, column=1, sticky="nsew", padx=4)

        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=1, sticky="w", pady=6)
        ttk.Button(btns, text="Run", command=self.run_clicked).pack(side="left", padx=4)
        ttk.Button(btns, text="Select all", command=self.select_all).pack(side="left", padx=4)
        ttk.Button(btns, text="Clear", command=self.clear_output).pack(side="left", padx=4)

        row += 1
        self.output = scrolledtext.ScrolledText(frm, height=20)
        self.output.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=8)

        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(row, weight=1)

        self.refresh_repos()

    def log(self, msg: str) -> None:
        self.output.insert("end", msg + "\n")
        self.output.see("end")

    def clear_output(self) -> None:
        self.output.delete("1.0", "end")

    def select_all(self) -> None:
        self.repo_list.select_set(0, "end")

    def refresh_repos(self) -> None:
        self.repo_list.delete(0, "end")
        root = Path(self.root_var.get())
        if not root.exists():
            return
        for child in sorted(root.iterdir()):
            if child.is_dir() and (child / ".git").exists():
                self.repo_list.insert("end", child.name)

    def run_clicked(self) -> None:
        selected = [self.repo_list.get(i) for i in self.repo_list.curselection()]
        if not selected:
            self.messagebox.showwarning("No repositories", "Select at least one repository.")
            return

        if self.fix_var.get() and self.push_var.get() and not self.messagebox.askyesno(
            "Confirm force push",
            "Apply fix + force push rewrites history. Continue?",
        ):
            return

        thread = threading.Thread(target=self._run_worker, args=(selected,), daemon=True)
        thread.start()

    def _run_worker(self, selected: list[str]) -> None:
        root = Path(self.root_var.get())
        policy = Path(self.policy_var.get())
        owner_emails = [item.strip() for item in self.owner_emails_var.get().split(",") if item.strip()]

        artifacts = create_run_artifacts(DEFAULT_RESULTS_DIR)
        gui_logger = RunLogger(
            artifacts.log_path,
            sink=lambda m: self.root.after(0, self.log, m),
        )
        gui_logger(f"[INFO] Run artifacts directory: {artifacts.run_dir}")

        run_settings = {
            "mode": "gui",
            "root": str(root),
            "policy": str(policy),
            "public_only": str(self.public_only_var.get()),
            "fix": str(self.fix_var.get()),
            "push": str(self.push_var.get()),
            "dry_run": str(self.dry_run_var.get()),
            "redact_third_party_emails": str(self.redact_var.get()),
            "purge_detected_secret_files": str(self.purge_detected_secret_files_var.get()),
            "purge_all_detected_secret_files": str(self.purge_all_detected_secret_files_var.get()),
        }

        reports: list[RepoReport] = []
        try:
            guard = RepoPublicationGuard(
                root=root,
                policy_path=policy,
                noreply_email=self.noreply_var.get().strip(),
                placeholder_email=self.placeholder_var.get().strip(),
                owner_name=self.owner_name_var.get().strip() or "Owner",
                owner_emails=owner_emails,
                redact_third_party=self.redact_var.get(),
                purge_detected_secret_files=self.purge_detected_secret_files_var.get(),
                purge_all_detected_secret_files=self.purge_all_detected_secret_files_var.get(),
                push=self.push_var.get(),
                dry_run=self.dry_run_var.get(),
                max_matches=50,
                logger=gui_logger,
            )

            if self.purge_all_detected_secret_files_var.get() and not self.purge_detected_secret_files_var.get():
                gui_logger("[WARN] Purge-all implies purge-detected-secret-files")
                guard.purge_detected_secret_files = True
                run_settings["purge_detected_secret_files"] = "True"

            repos = guard.discover_repositories(selected, public_only=self.public_only_var.get())
            if not repos:
                gui_logger("[INFO] No repositories matched.")
                gui_logger("\n[SUMMARY] PASS 0/0")
            else:
                for repo in repos:
                    gui_logger(f"[AUDIT] {repo.name}")
                    rep = guard.audit_repo(repo)
                    if self.fix_var.get():
                        gui_logger(f"[FIX] {repo.name}")
                        fixed = guard.apply_fixes(repo, rep)
                        rep = guard.audit_repo(repo)
                        rep.backups_created = fixed.backups_created
                        rep.fix_actions = fixed.fix_actions
                        rep.fix_errors = fixed.fix_errors
                    reports.append(rep)
                    print_report(rep, gui_logger)

            passed = sum(1 for r in reports if r.status == "PASS")
            gui_logger(f"\n[SUMMARY] PASS {passed}/{len(reports)}")
        except Exception as exc:
            gui_logger(f"[ERROR] Unhandled runtime error: {exc}")
            gui_logger(traceback.format_exc())
        finally:
            persist_run_outputs(
                reports=reports,
                artifacts=artifacts,
                root_path=root,
                policy_path=policy,
                run_settings=run_settings,
                logger=gui_logger,
                optional_json_export=None,
            )

    def run(self) -> None:
        self.root.mainloop()


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit/fix repository public-release safety based on docs/POLICY.md",
    )
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="Root folder containing repositories")
    parser.add_argument("--policy", default=str(DEFAULT_POLICY), help="Policy markdown path")
    parser.add_argument("--repos", nargs="*", help="Repo folder names or absolute paths")
    parser.add_argument("--public-only", action="store_true", help="Only include repos with GitHub origin")

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

    parser.add_argument("--owner-name", default="Owner", help="Owner display name for rewritten commits")
    parser.add_argument(
        "--owner-email",
        action="append",
        default=[],
        help="Owner private email(s) to replace with noreply (can repeat)",
    )
    parser.add_argument("--noreply-email", default=DEFAULT_NOREPLY, help="Target noreply email")
    parser.add_argument(
        "--placeholder-email",
        default=DEFAULT_PLACEHOLDER,
        help="Placeholder email for redacted contributors",
    )
    parser.add_argument("--max-matches", type=int, default=50, help="Max findings per check")
    parser.add_argument(
        "--report-json",
        help="Optional extra JSON export path. Main JSON/LOG/HTML artifacts are always written to a timestamped run folder",
    )
    parser.add_argument(
        "--report-dir",
        default=str(DEFAULT_RESULTS_DIR),
        help="Requested base directory for timestamped run folders; values outside Audit_Results are ignored by policy",
    )

    parser.add_argument("--yes", action="store_true", help="Skip destructive action confirmation prompt")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    return parser

def run_cli(args: argparse.Namespace) -> int:  # pragma: no cover
    root = Path(args.root)
    policy = Path(args.policy)

    owner_emails = list(dict.fromkeys(args.owner_email))

    enforced_results_dir, forced = enforce_results_dir(Path(args.report_dir))
    artifacts = create_run_artifacts(enforced_results_dir)
    cli_logger = RunLogger(artifacts.log_path, sink=print)
    if forced:
        cli_logger(
            f"[WARN] report-dir was forced to {DEFAULT_RESULTS_DIR} to comply with mandatory Audit_Results policy"
        )
    cli_logger(f"[INFO] Run artifacts directory: {artifacts.run_dir}")

    run_settings = {
        "mode": "cli",
        "root": str(root),
        "policy": str(policy),
        "public_only": str(args.public_only),
        "fix": str(args.fix),
        "push": str(args.push),
        "dry_run": str(args.dry_run),
        "purge_detected_secret_files": str(args.purge_detected_secret_files),
        "purge_all_detected_secret_files": str(args.purge_all_detected_secret_files),
        "redact_third_party_emails": str(args.redact_third_party_emails),
        "max_matches": str(args.max_matches),
        "results_dir": str(enforced_results_dir),
    }

    guard = RepoPublicationGuard(
        root=root,
        policy_path=policy,
        noreply_email=args.noreply_email,
        placeholder_email=args.placeholder_email,
        owner_name=args.owner_name,
        owner_emails=owner_emails,
        redact_third_party=args.redact_third_party_emails,
        purge_detected_secret_files=args.purge_detected_secret_files,
        purge_all_detected_secret_files=args.purge_all_detected_secret_files,
        push=args.push,
        dry_run=args.dry_run,
        max_matches=args.max_matches,
        logger=cli_logger,
    )

    if args.purge_all_detected_secret_files and not args.purge_detected_secret_files:
        cli_logger("[WARN] --purge-all-detected-secret-files implies --purge-detected-secret-files")
        guard.purge_detected_secret_files = True
        run_settings["purge_detected_secret_files"] = "True"

    repos = guard.discover_repositories(args.repos, public_only=args.public_only)
    reports: list[RepoReport] = []
    exit_code = 0

    try:
        if not repos:
            cli_logger("[INFO] No repositories matched. Nothing to do.")
            cli_logger("\n[SUMMARY] PASS 0/0")
        else:
            if args.fix and args.push and not args.yes:
                print("WARNING: --fix with --push rewrites history and force-pushes.")
                answer = input("Continue? [y/N]: ").strip().lower()
                if answer not in {"y", "yes"}:
                    cli_logger("[INFO] Run aborted by user confirmation gate.")
                    exit_code = 1
                    repos = []

            for repo in repos:
                cli_logger(f"[AUDIT] {repo.name}")
                report = guard.audit_repo(repo)

                if args.fix:
                    cli_logger(f"[FIX] {repo.name}")
                    fixed = guard.apply_fixes(repo, report)
                    cli_logger(f"[RE-AUDIT] {repo.name}")
                    report = guard.audit_repo(repo)
                    report.backups_created = fixed.backups_created
                    report.fix_actions = fixed.fix_actions
                    report.fix_errors = fixed.fix_errors

                reports.append(report)
                print_report(report, cli_logger)

            passed = sum(1 for rep in reports if rep.status == "PASS")
            cli_logger(f"\n[SUMMARY] PASS {passed}/{len(reports)}")
            if exit_code == 0 and reports:
                exit_code = 0 if passed == len(reports) else 2
    except Exception as exc:
        cli_logger(f"[ERROR] Unhandled runtime error: {exc}")
        cli_logger(traceback.format_exc())
        exit_code = 3
    finally:
        persist_run_outputs(
            reports=reports,
            artifacts=artifacts,
            root_path=root,
            policy_path=policy,
            run_settings=run_settings,
            logger=cli_logger,
            optional_json_export=args.report_json,
        )

    return exit_code


def main() -> int:  # pragma: no cover
    parser = make_parser()
    args = parser.parse_args()

    if args.gui:
        app = GuiApp()
        app.run()
        return 0

    return run_cli(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
