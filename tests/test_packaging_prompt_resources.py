from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

import build_helpers
from repo_privacy_guardian import prompts
from repo_privacy_guardian.gui.app import GuiApp
from scripts import check_artifact_install as artifact_check


REPO_ROOT = Path(__file__).resolve().parents[1]


def _canonical_sources(root: Path) -> None:
    for prompt in prompts.PROMPT_REGISTRY:
        target = prompt.path(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(prompt.path(REPO_ROOT).read_bytes())
    registry = root / "repo_privacy_guardian" / "prompts.py"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_bytes((REPO_ROOT / "repo_privacy_guardian" / "prompts.py").read_bytes())


def test_build_generates_exact_registered_prompt_bytes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _canonical_sources(source)
    generated = build_helpers.copy_prompt_resources(source, tmp_path / "build")
    assert len(generated) == 8
    assert {path.relative_to(tmp_path / "build").as_posix() for path in generated} == {
        "repo_privacy_guardian_resources/prompts/" + "/".join(prompts.prompt_resource_parts(prompt))
        for prompt in prompts.PROMPT_REGISTRY
    }
    for prompt, packaged in zip(prompts.PROMPT_REGISTRY, generated):
        assert packaged.read_bytes() == prompt.path(source).read_bytes()


def test_build_rejects_missing_canonical_prompt(tmp_path: Path) -> None:
    _canonical_sources(tmp_path)
    prompts.PROMPT_REGISTRY[0].path(tmp_path).unlink()
    with pytest.raises(FileNotFoundError, match="canonical registered prompt"):
        build_helpers.copy_prompt_resources(tmp_path, tmp_path / "build")


def test_checkout_content_remains_authoritative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prompt = prompts.PROMPT_REGISTRY[0]
    path = prompt.path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("edited source prompt", encoding="utf-8")
    monkeypatch.setattr(prompts.resources, "files", lambda _package: pytest.fail("Checkout prompt should be authoritative"))
    assert prompts.read_prompt_text(prompt, tmp_path) == "edited source prompt"
    assert prompts.PromptFileSession().materialize(prompt, tmp_path) == path


def _zip_resource(monkeypatch: pytest.MonkeyPatch, prompt: prompts.AgenticPrompt):
    memory = io.BytesIO()
    archive = zipfile.ZipFile(memory, "w")
    resource_path = "prompts/" + "/".join(prompts.prompt_resource_parts(prompt))
    archive.writestr(resource_path, "packaged prompt content")
    monkeypatch.setattr(prompts.resources, "files", lambda _package: zipfile.Path(archive))
    return archive


def test_packaged_prompt_open_lifetime_and_gui_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prompt = prompts.PROMPT_REGISTRY[0]
    archive = _zip_resource(monkeypatch, prompt)
    copied = []
    opened = []
    root = object()
    app = SimpleNamespace(
        root=root,
        _copy_text_to_clipboard=lambda text, _message: copied.append(text),
        _open_local_path=lambda path: opened.append(path),
        _t=lambda key, **_kwargs: key,
        _unregister_appearance_mode_callback=lambda: None,
        log=lambda message: pytest.fail(message),
    )
    monkeypatch.setattr(sys.modules["repo_privacy_guardian.core"], "source_tree_root", lambda: tmp_path)
    try:
        GuiApp._copy_prompt_to_clipboard(app, prompt)
        GuiApp._open_prompt_file(app, prompt, tmp_path)
        assert copied == ["packaged prompt content"]
        assert opened[0].read_text(encoding="utf-8") == copied[0]
        GuiApp._on_root_destroy(app, SimpleNamespace(widget=object()))
        assert opened[0].exists()
        GuiApp._on_root_destroy(app, SimpleNamespace(widget=root))
        assert not opened[0].exists()
        app._prompt_file_session.close()
    finally:
        app._prompt_file_session.close()
        archive.close()


def test_missing_packaged_prompt_has_recovery_guidance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(prompts.resources, "files", lambda _package: tmp_path)
    with pytest.raises(FileNotFoundError, match="Reinstall a complete"):
        prompts.read_prompt_text(prompts.PROMPT_REGISTRY[0], tmp_path)


def test_materialization_rejects_resource_traversal() -> None:
    unsafe = prompts.AgenticPrompt("unsafe", "en", "", "", "docs/prompts/../../elsewhere.md", "")
    with pytest.raises(ValueError, match="docs/prompts"):
        prompts.prompt_resource_parts(unsafe)


def test_artifact_validator_uses_external_directory_and_clean_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo_root = tmp_path / "repo"
    _canonical_sources(repo_root)
    (repo_root / "docs" / "POLICY.md").write_text("policy", encoding="utf-8")
    smoke = repo_root / "tests" / "release_smoke_cli.py"
    smoke.parent.mkdir()
    smoke.write_text("# copied smoke helper", encoding="utf-8")
    artifact = repo_root / "example.whl"
    artifact.touch()
    calls = []

    def fake_command(cmd, *, cwd, timeout, env):
        assert not cwd.is_relative_to(repo_root)
        assert "PYTHONPATH" not in env
        assert "PYTHONHOME" not in env
        assert env["PYTHONNOUSERSITE"] == "1"
        assert timeout <= artifact_check.INSTALL_TIMEOUT_SECONDS
        calls.append([str(part) for part in cmd])
        if "-c" in cmd:
            expected = json.loads((cwd / "expected-resources.json").read_text(encoding="utf-8"))
            assert len(expected["prompts"]) == 8

    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT))
    monkeypatch.setenv("PYTHONHOME", str(REPO_ROOT))
    monkeypatch.setattr(artifact_check, "run_command", fake_command)
    artifact_check.install_smoke_for_artifact(repo_root, artifact)
    assert any(command[-2:] == ["pip", "check"] for command in calls)
    assert any(command[-3:] == ["-m", "Repo_Privacy_Guardian", "--help"] for command in calls)
    assert any(command[-1].endswith("release_smoke_cli.py") for command in calls)


@pytest.mark.parametrize("omit_prompt", [False, True])
def test_isolated_resource_probe_rejects_incomplete_synthetic_install(tmp_path: Path, omit_prompt: bool) -> None:
    source = tmp_path / "source"
    _canonical_sources(source)
    (source / "docs" / "POLICY.md").write_text("policy", encoding="utf-8")
    installed = tmp_path / "installation"
    generated = build_helpers.copy_prompt_resources(source, installed)
    if omit_prompt:
        generated[0].unlink()
    package = installed / "repo_privacy_guardian"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "prompts.py").write_bytes((REPO_ROOT / "repo_privacy_guardian" / "prompts.py").read_bytes())
    resource_package = installed / "repo_privacy_guardian_resources"
    (resource_package / "__init__.py").write_text("", encoding="utf-8")
    (resource_package / "POLICY.md").write_text("policy", encoding="utf-8")
    (installed / "Repo_Privacy_Guardian.py").write_text(
        "from pathlib import Path\nDEFAULT_POLICY = Path(__file__).parent / 'repo_privacy_guardian_resources' / 'POLICY.md'\n",
        encoding="utf-8",
    )
    work = tmp_path / "work"
    work.mkdir()
    (work / "expected-resources.json").write_text(json.dumps(artifact_check.expected_resource_hashes(source)), encoding="utf-8")
    prefix = (
        "import sys, sysconfig\n"
        f"sys.path.insert(0, {str(installed)!r})\n"
        f"sysconfig.get_path = lambda _name: {str(installed)!r}\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", prefix + artifact_check.INSTALLED_RESOURCE_PROBE],
        cwd=work, env=artifact_check.isolated_child_environment(), capture_output=True,
        text=True, stdin=subprocess.DEVNULL, timeout=30,
    )
    assert (result.returncode != 0) is omit_prompt
    if omit_prompt:
        assert "Prompt content is unavailable" in result.stderr
    else:
        assert "all eight prompt resources verified" in result.stdout
