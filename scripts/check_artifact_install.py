#!/usr/bin/env python3
"""Install and validate a wheel or sdist without checkout import shadowing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from repo_privacy_guardian.prompts import PROMPT_REGISTRY  # noqa: E402


INSTALL_TIMEOUT_SECONDS = 900
PROBE_TIMEOUT_SECONDS = 120
INSTALLED_RESOURCE_PROBE = """
import hashlib
import json
from pathlib import Path
import sysconfig
import Repo_Privacy_Guardian as rpg
from repo_privacy_guardian import prompts

expected = json.loads(Path('expected-resources.json').read_text(encoding='utf-8'))
installation = Path(sysconfig.get_path('purelib')).resolve()
for module in (rpg, prompts):
    assert Path(module.__file__).resolve().is_relative_to(installation), 'Checkout import shadowed the installed artifact'
policy = Path(rpg.DEFAULT_POLICY).resolve()
assert policy.is_relative_to(installation), 'Policy did not resolve from the installed artifact'
assert hashlib.sha256(policy.read_text(encoding='utf-8').encode('utf-8')).hexdigest() == expected['policy'], 'Installed policy content differs'
registered = {prompt.relative_path for prompt in prompts.PROMPT_REGISTRY}
assert registered == set(expected['prompts']), 'Installed prompt registry differs'
for prompt in prompts.PROMPT_REGISTRY:
    resource = prompts.resolve_prompt_resource(prompt, Path.cwd())
    assert hashlib.sha256(resource.read_bytes()).hexdigest() == expected['prompts'][prompt.relative_path], 'Installed prompt content differs'
    assert prompts.read_prompt_text(prompt, Path.cwd()) == resource.read_text(encoding='utf-8'), 'Installed prompt read differs'
assert len(prompts.agentic_prompt_cards('en')) == 4
assert len(prompts.agentic_prompt_cards('es-419')) == 4
session = prompts.PromptFileSession()
opened = []
try:
    for prompt in prompts.PROMPT_REGISTRY:
        path = session.materialize(prompt, Path.cwd())
        opened.append(path)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected['prompts'][prompt.relative_path], 'Materialized prompt content differs'
finally:
    session.close()
assert all(not path.exists() for path in opened), 'Temporary prompt resources were not cleaned'
print('Installed module, policy, and all eight prompt resources verified.')
"""


def isolated_child_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def expected_resource_hashes(repo_root: Path) -> dict[str, object]:
    return {
        "policy": hashlib.sha256((repo_root / "docs" / "POLICY.md").read_text(encoding="utf-8").encode("utf-8")).hexdigest(),
        "prompts": {
            prompt.relative_path: hashlib.sha256(prompt.path(repo_root).read_bytes()).hexdigest()
            for prompt in PROMPT_REGISTRY
        },
    }


def run_command(cmd: list[str | Path], *, cwd: Path, timeout: int, env: dict[str, str]) -> None:
    subprocess.run(
        [str(part) for part in cmd], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        check=True, timeout=timeout,
    )


def install_smoke_for_artifact(repo_root: Path, artifact: Path) -> None:
    repo_root = repo_root.resolve()
    artifact = artifact.resolve(strict=True)
    env = isolated_child_environment()
    with tempfile.TemporaryDirectory(prefix="rpg-artifact-check-") as temp_dir:
        workspace = Path(temp_dir).resolve()
        if workspace.is_relative_to(repo_root):
            raise RuntimeError("Artifact validation requires a temporary directory outside the checkout.")
        cwd = workspace / "work"
        cwd.mkdir()
        venv_dir = workspace / "venv"
        run_command([sys.executable, "-m", "venv", venv_dir], cwd=cwd, env=env, timeout=INSTALL_TIMEOUT_SECONDS)
        scripts = venv_dir / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        console = scripts / ("repo-privacy-guardian.exe" if os.name == "nt" else "repo-privacy-guardian")
        run_command([python, "-m", "pip", "install", "--upgrade", "pip"], cwd=cwd, env=env, timeout=INSTALL_TIMEOUT_SECONDS)
        run_command([python, "-m", "pip", "install", artifact], cwd=cwd, env=env, timeout=INSTALL_TIMEOUT_SECONDS)
        run_command([python, "-m", "pip", "check"], cwd=cwd, env=env, timeout=PROBE_TIMEOUT_SECONDS)
        (cwd / "expected-resources.json").write_text(
            json.dumps(expected_resource_hashes(repo_root)), encoding="utf-8",
        )
        run_command([python, "-c", INSTALLED_RESOURCE_PROBE], cwd=cwd, env=env, timeout=PROBE_TIMEOUT_SECONDS)
        run_command([console, "--help"], cwd=cwd, env=env, timeout=PROBE_TIMEOUT_SECONDS)
        run_command([python, "-m", "Repo_Privacy_Guardian", "--help"], cwd=cwd, env=env, timeout=PROBE_TIMEOUT_SECONDS)
        # The copied smoke helper cannot inject the source checkout into sys.path.
        smoke_helper = cwd / "release_smoke_cli.py"
        shutil.copyfile(repo_root / "tests" / "release_smoke_cli.py", smoke_helper)
        run_command([python, smoke_helper], cwd=cwd, env=env, timeout=PROBE_TIMEOUT_SECONDS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", nargs="+", type=Path, help="Wheel or sdist artifacts to install and validate.")
    args = parser.parse_args(argv)
    for artifact in args.artifacts:
        install_smoke_for_artifact(REPO_ROOT, artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
