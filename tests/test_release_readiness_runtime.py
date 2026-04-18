from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_release_readiness_module():
    script_path = REPO_ROOT / "scripts" / "release_readiness.py"
    spec = importlib.util.spec_from_file_location("release_readiness_script", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_readiness_runtime_paths_are_unique() -> None:
    module = _load_release_readiness_module()
    first = module.create_release_runtime_workspace()
    second = module.create_release_runtime_workspace()

    try:
        assert first != second

        first_pytest, first_coverage = module.build_release_pytest_artifact_paths(first)
        second_pytest, second_coverage = module.build_release_pytest_artifact_paths(second)

        assert first_pytest.parent == first
        assert first_coverage.parent == first
        assert second_pytest.parent == second
        assert second_coverage.parent == second
        assert first_pytest != second_pytest
        assert first_coverage != second_coverage
    finally:
        shutil.rmtree(first, ignore_errors=True)
        shutil.rmtree(second, ignore_errors=True)


def test_remove_tree_if_present_retries_transient_permission_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_release_readiness_module()
    target = tmp_path / "dist"
    target.mkdir()
    (target / "artifact.txt").write_text("payload", encoding="utf-8")

    real_rmtree = shutil.rmtree
    attempts = {"count": 0}

    def flaky_rmtree(path, ignore_errors=False):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise PermissionError("locked")
        return real_rmtree(path, ignore_errors=ignore_errors)

    monkeypatch.setattr(module.shutil, "rmtree", flaky_rmtree)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    module._remove_tree_if_present(tmp_path, target)

    assert attempts["count"] == 2
    assert not target.exists()


def test_remove_tree_if_present_raises_after_retry_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_release_readiness_module()
    target = tmp_path / "dist"
    target.mkdir()
    (target / "artifact.txt").write_text("payload", encoding="utf-8")

    monkeypatch.setattr(module.shutil, "rmtree", lambda _path, ignore_errors=False: (_ for _ in ()).throw(PermissionError("locked")))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="Unable to remove stale build output after retries"):
        module._remove_tree_if_present(tmp_path, target)
