"""Mechanical remediation planning helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from re import Pattern
from typing import TYPE_CHECKING, Callable, Iterable

if TYPE_CHECKING:
    from repo_privacy_guardian.core import RepoReport


SENSITIVE_FILENAME_PURGE_REGEX = (
    r"(^|.*/)__pycache__/.*|.*\.pyc$|(^|.*/)\.env(\..*)?$|"
    r".*\.(pem|key|p12|pfx|kdbx)$|(^|.*/)id_rsa$"
)


@dataclass(frozen=True)
class ExplicitReplaceTextRules:
    path: Path
    lines: tuple[str, ...]


@dataclass(frozen=True)
class ReplaceTextPlan:
    lines: tuple[str, ...]
    fix_actions: tuple[str, ...]


@dataclass(frozen=True)
class HistoryRewritePlan:
    mailmap_enabled: bool
    replace_text_enabled: bool
    purge_paths: tuple[str, ...]
    purge_by_filename_signals: bool

    @property
    def needs_history_purge(self) -> bool:
        return self.purge_by_filename_signals or bool(self.purge_paths)

    @property
    def do_rewrite(self) -> bool:
        return self.mailmap_enabled or self.replace_text_enabled or self.needs_history_purge

    def dry_run_actions(self) -> list[str]:
        actions = [
            "[dry-run] history rewrite would run",
            f"[dry-run] mailmap enabled: {self.mailmap_enabled}",
            f"[dry-run] replace-text enabled: {self.replace_text_enabled}",
        ]
        if self.purge_paths:
            preview_paths = ", ".join(self.purge_paths[:5])
            actions.append(f"[dry-run] purge paths preview: {preview_paths}")
            if len(self.purge_paths) > 5:
                actions.append("[dry-run] purge paths preview truncated")
        if self.purge_by_filename_signals:
            actions.append("[dry-run] sensitive filename signal purge regex enabled")
        return actions

    def filter_repo_purge_args(self) -> list[str]:
        if not self.needs_history_purge:
            return []

        args: list[str] = []
        for purge_path in self.purge_paths:
            args.extend(["--path", purge_path])

        if self.purge_by_filename_signals:
            args.extend(["--path-regex", SENSITIVE_FILENAME_PURGE_REGEX])

        args.append("--invert-paths")
        return args


def build_git_filter_repo_command(
    *,
    python_executable: str | Path,
    mailmap: Path | None,
    replace_text: Path | None,
    rewrite_plan: HistoryRewritePlan,
) -> list[str]:
    cmd = [str(python_executable), "-m", "git_filter_repo", "--force"]
    if mailmap:
        cmd.extend(["--mailmap", str(mailmap)])
    if replace_text:
        cmd.extend(["--replace-text", str(replace_text)])
    cmd.extend(rewrite_plan.filter_repo_purge_args())
    return cmd


def load_explicit_replace_text_rules(replace_text_file: str | Path) -> ExplicitReplaceTextRules:
    replace_path = Path(replace_text_file).expanduser().resolve()
    try:
        raw_extra_lines = replace_path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"Unable to read --replace-text-file '{replace_path}': {exc}") from exc

    lines = tuple(
        line.strip()
        for line in raw_extra_lines.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    return ExplicitReplaceTextRules(path=replace_path, lines=lines)


def build_replace_text_plan(
    report: RepoReport,
    *,
    email_pattern: Pattern[str],
    is_relevant_email_candidate: Callable[[str], bool],
    is_allowed_email: Callable[[str], bool],
    owner_emails: Iterable[str],
    noreply_email: str,
    placeholder_email: str,
    redact_third_party: bool,
    rewrite_personal_paths: bool,
    extract_personal_path_literals: Callable[[str], Iterable[str]],
    redacted_path: str,
    explicit_replace_lines: Iterable[str] = (),
    explicit_replace_source: Path | None = None,
) -> ReplaceTextPlan:
    replacement_map: dict[str, str] = {}
    owner_email_set = set(owner_emails)
    fix_actions: list[str] = []

    candidate_lines = (
        report.tracked_email_matches
        + report.history_email_matches
        + report.tracked_path_matches
        + report.history_path_matches
    )

    for line in candidate_lines:
        for email in email_pattern.findall(line):
            if not is_relevant_email_candidate(email):
                continue
            if is_allowed_email(email):
                continue

            if email in owner_email_set:
                replacement_map[email] = noreply_email
            elif redact_third_party:
                replacement_map[email] = placeholder_email

    if rewrite_personal_paths:
        for line in report.tracked_path_matches + report.history_path_matches:
            for path_literal in extract_personal_path_literals(line):
                replacement_map[path_literal] = redacted_path
    elif report.tracked_path_matches or report.history_path_matches:
        fix_actions.append(
            "path remediation skipped: explicit opt-in required (--rewrite-personal-paths)"
        )

    normalized_explicit_lines = tuple(
        line.strip()
        for line in explicit_replace_lines
        if line.strip()
    )
    if normalized_explicit_lines and explicit_replace_source is not None:
        fix_actions.append(f"merged explicit replace-text mappings from {explicit_replace_source}")

    lines = [f"literal:{src}==>{dst}" for src, dst in sorted(replacement_map.items())]
    lines.extend(normalized_explicit_lines)
    return ReplaceTextPlan(lines=tuple(dict.fromkeys(lines)), fix_actions=tuple(fix_actions))


def build_history_rewrite_plan(
    report: RepoReport,
    *,
    mailmap_enabled: bool,
    replace_text_enabled: bool,
) -> HistoryRewritePlan:
    return HistoryRewritePlan(
        mailmap_enabled=mailmap_enabled,
        replace_text_enabled=replace_text_enabled,
        purge_paths=tuple(sorted(set(report.secret_history_purge_paths))),
        purge_by_filename_signals=bool(
            report.history_sensitive_added or report.history_sensitive_deleted
        ),
    )
