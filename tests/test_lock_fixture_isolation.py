from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

import Repo_Privacy_Guardian as rpg


def _init_repo(repo: Path) -> None:
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True, capture_output=True)


def _guard(root: Path) -> rpg.RepoPublicationGuard:
    return rpg.RepoPublicationGuard(
        root=root,
        policy_path=root / "POLICY.md",
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        owner_name="Fixture",
        owner_emails=[],
        redact_third_party=False,
        purge_detected_secret_files=False,
        purge_all_detected_secret_files=False,
        low_confidence_email_mode="informational",
        push=False,
        dry_run=False,
        max_matches=50,
        audit_litellm_incident=False,
        audit_github_hardening=False,
        allow_non_owner_push=False,
        allowed_remote_owners=[],
        replace_text_file=None,
        logger=lambda _message: None,
    )


@pytest.mark.parametrize("enclosing_repository", [False, True])
def test_lock_lifecycle_uses_fixture_git_directory(
    tmp_path: Path, enclosing_repository: bool
) -> None:
    parent = tmp_path / "parent"
    if enclosing_repository:
        _init_repo(parent)
    repo = parent / "fixture"
    _init_repo(repo)
    guard = _guard(parent)

    # Invalid empty .git directories can let Git discover an enclosing checkout.
    # Verify isolation before a test acquires any lock.
    assert guard._resolve_git_dir(repo).resolve() == (repo / ".git").resolve()
    lock_path = repo / ".git" / rpg.REPO_LOCK_FILENAME
    rpg.write_private_json_file(lock_path, {"owner_token": "stale-fixture-holder"})
    file_identity = lock_path.stat().st_ino

    for _iteration in range(3):
        repo_lock = guard.acquire_repo_lock(repo)
        try:
            assert repo_lock.lock_path.resolve() == lock_path.resolve()
            payload = rpg._read_json_from_locked_fd(repo_lock.lock_fd)
            assert payload is not None
            assert payload["owner_token"] == repo_lock.owner_token
        finally:
            guard.release_repo_lock(repo_lock)
        released = json.loads(lock_path.read_text(encoding="utf-8"))
        assert released["status"] == "released"
        assert released["previous_owner_token"] == repo_lock.owner_token
        assert lock_path.stat().st_ino == file_identity


_CHILD_LOCK = """
import time
from pathlib import Path
import sys
import Repo_Privacy_Guardian as rpg

repo = Path(sys.argv[1])
guard = rpg.RepoPublicationGuard(
    root=repo.parent, policy_path=repo.parent / "POLICY.md",
    noreply_email=rpg.DEFAULT_NOREPLY, placeholder_email=rpg.DEFAULT_PLACEHOLDER,
    owner_name="Fixture", owner_emails=[], redact_third_party=False,
    purge_detected_secret_files=False, purge_all_detected_secret_files=False,
    low_confidence_email_mode="informational", push=False, dry_run=False,
    max_matches=50, audit_litellm_incident=False, audit_github_hardening=False,
    allow_non_owner_push=False, allowed_remote_owners=[], replace_text_file=None,
    logger=lambda _message: None,
)
assert guard._resolve_git_dir(repo).resolve() == (repo / ".git").resolve()
lock = guard.acquire_repo_lock(repo)
(repo / "child-ready").write_text(lock.owner_token, encoding="utf-8")
time.sleep(30)
"""


def test_process_death_releases_fixture_os_lock(tmp_path: Path, monkeypatch) -> None:
    parent = tmp_path / "enclosing"
    _init_repo(parent)
    repo = parent / "fixture"
    _init_repo(repo)
    guard = _guard(parent)
    assert guard._resolve_git_dir(repo).resolve() == (repo / ".git").resolve()
    monkeypatch.setattr(rpg, "REPO_LOCK_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(rpg, "REPO_LOCK_RETRY_SECONDS", 0.0)

    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD_LOCK, str(repo)],
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )
    try:
        ready_path = repo / "child-ready"
        deadline = time.monotonic() + 10
        while not ready_path.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready_path.exists(), "Fixture child did not acquire its isolated lock"
        child_owner = ready_path.read_text(encoding="utf-8")
        lock_path = repo / ".git" / rpg.REPO_LOCK_FILENAME
        file_identity = lock_path.stat().st_ino
        with pytest.raises(RuntimeError, match="repository execution lock is busy"):
            guard.acquire_repo_lock(repo)

        child.kill()
        child.communicate(timeout=10)
        repo_lock = guard.acquire_repo_lock(repo)
        try:
            assert repo_lock.owner_token != child_owner
            payload = rpg._read_json_from_locked_fd(repo_lock.lock_fd)
            assert payload is not None
            assert payload["owner_token"] == repo_lock.owner_token
        finally:
            guard.release_repo_lock(repo_lock)
        released = json.loads(lock_path.read_text(encoding="utf-8"))
        assert released["status"] == "released"
        assert released["previous_owner_token"] == repo_lock.owner_token
        assert lock_path.stat().st_ino == file_identity
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)
