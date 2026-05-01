from __future__ import annotations

import os
from pathlib import Path
import threading


EXIT_OK = 0
EXIT_ABORTED = 1
EXIT_POLICY_FAILED = 2
EXIT_RUNTIME_ERROR = 3


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def request_cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


def resolve_run_status(exit_code: int) -> str:
    if exit_code == EXIT_OK:
        return "completed"
    if exit_code == EXIT_ABORTED:
        return "aborted"
    return "failed"


def is_git_repository(path: Path) -> bool:
    return (path / ".git").exists()


def _repository_identity_key(path: Path) -> str:
    try:
        normalized = path.resolve()
    except OSError:
        normalized = path.absolute()
    return os.path.normcase(str(normalized))


def validate_repository_root(root: Path) -> str | None:
    try:
        if not root.exists():
            return f"Root folder does not exist: {root}"
        if not root.is_dir():
            return f"Root path is not a directory: {root}"
    except OSError as exc:
        return f"Root folder is not accessible: {root} ({exc})"
    return None


def discover_repository_targets(
    root: Path,
    repo_filters: list[str] | None,
) -> tuple[list[Path], list[str], str | None]:
    root_error = validate_repository_root(root)
    if root_error:
        return [], [], root_error

    repos: list[Path] = []
    skipped: list[str] = []
    seen_repos: set[str] = set()

    def append_repo_once(candidate: Path) -> None:
        key = _repository_identity_key(candidate)
        if key in seen_repos:
            return
        seen_repos.add(key)
        repos.append(candidate)

    if repo_filters:
        for item in repo_filters:
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = root / candidate
            if is_git_repository(candidate):
                append_repo_once(candidate)
            else:
                skipped.append(str(candidate))
        return repos, skipped, None

    if is_git_repository(root):
        append_repo_once(root)

    try:
        for child in sorted(root.iterdir()):
            if child.is_dir() and is_git_repository(child):
                append_repo_once(child)
    except OSError as exc:
        return [], skipped, f"Root folder is not accessible: {root} ({exc})"

    return repos, skipped, None


def describe_no_target_resolution(
    *,
    root: Path,
    repo_filters: list[str] | None,
    public_only: bool,
) -> tuple[str, str]:
    if repo_filters:
        requested = ", ".join(repo_filters)
        if public_only:
            return (
                f"No target repositories matched the requested filters after applying --public-only: {requested}",
                "[ERROR] Check --root/--repos, verify each selected path is a git repository, and confirm the matching origin is publicly accessible on GitHub.",
            )
        return (
            f"No target repositories matched the requested filters: {requested}",
            "[ERROR] Check --root/--repos and verify each selected path is a git repository.",
        )

    if public_only:
        return (
            f"No public GitHub repositories matched under Root: {root}",
            "[ERROR] Check origin visibility, origin remote availability, or remove --public-only.",
        )

    return (
        f"No git repositories were found under Root: {root}",
        "[ERROR] Clone a repository under --root or point --root at an existing git checkout.",
    )
