from __future__ import annotations

import ast
import importlib.util
import re
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


def test_remove_tree_if_present_refuses_symlink_before_resolving_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_readiness_module()
    target = tmp_path / "dist"
    target.mkdir()
    (target / "artifact.txt").write_text("payload", encoding="utf-8")
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == target:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    with pytest.raises(RuntimeError, match="Refusing to recursively remove symlinked path"):
        module._remove_tree_if_present(tmp_path, target)

    assert target.exists()
    assert (target / "artifact.txt").exists()


def test_remove_tree_if_present_refuses_symlinked_parent_component(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_release_readiness_module()
    linked_parent = tmp_path / "linked-parent"
    target = linked_parent / "dist"
    target.mkdir(parents=True)
    (target / "artifact.txt").write_text("payload", encoding="utf-8")
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self == linked_parent:
            return True
        return original_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    with pytest.raises(RuntimeError, match="Refusing to recursively remove symlinked path"):
        module._remove_tree_if_present(tmp_path, target)

    assert target.exists()
    assert (target / "artifact.txt").exists()


def test_remove_tree_if_present_raises_after_retry_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_release_readiness_module()
    target = tmp_path / "dist"
    target.mkdir()
    (target / "artifact.txt").write_text("payload", encoding="utf-8")

    monkeypatch.setattr(module.shutil, "rmtree", lambda _path, ignore_errors=False: (_ for _ in ()).throw(PermissionError("locked")))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match="Unable to remove stale build output after retries"):
        module._remove_tree_if_present(tmp_path, target)


def test_cleanup_release_runtime_workspace_removes_readonly_files(tmp_path: Path) -> None:
    module = _load_release_readiness_module()
    runtime_dir = tmp_path / "rpg-release-runtime-test"
    nested = runtime_dir / "pytest" / "locked"
    nested.mkdir(parents=True)
    artifact = nested / "coverage.xml"
    artifact.write_text("<coverage />", encoding="utf-8")
    artifact.chmod(0o400)

    module.cleanup_release_runtime_workspace(runtime_dir)

    assert runtime_dir.exists() is False


def test_run_dependency_audits_covers_all_requirement_groups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_release_readiness_module()
    calls: list[tuple[str, list[str], Path, int]] = []

    def fake_run_named_command(name: str, cmd: list[str], *, cwd: Path, timeout: int, env=None) -> None:
        del env
        calls.append((name, cmd, cwd, timeout))

    monkeypatch.setattr(module, "run_named_command", fake_run_named_command)

    module.run_dependency_audits(tmp_path)

    audited_files = [call[1][-1] for call in calls]
    assert audited_files == list(module.DEPENDENCY_AUDIT_REQUIREMENT_FILES)
    assert all(call[1][:3] == [module.sys.executable, "-m", "pip_audit"] for call in calls)
    assert all(call[2] == tmp_path for call in calls)
    assert all(call[3] == module.DEFAULT_TIMEOUTS["quick"] for call in calls)


def test_release_byte_compile_paths_cover_packaged_modules_and_scripts() -> None:
    module = _load_release_readiness_module()
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"py-modules\s*=\s*(\[[^\n]+\])", pyproject)
    assert match is not None
    packaged_modules = ast.literal_eval(match.group(1))

    expected_paths = {f"{name}.py" for name in packaged_modules}
    expected_paths.update(
        {
            "scripts/check_release_contract.py",
            "scripts/release_readiness.py",
        }
    )

    configured_paths = set(module.RELEASE_BYTE_COMPILE_PATHS)
    assert expected_paths <= configured_paths
    for rel_path in configured_paths:
        assert (REPO_ROOT / rel_path).exists(), rel_path
