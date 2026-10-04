"""Generate package prompt data from the canonical maintained documents."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import sys

from setuptools.command.build_py import build_py


def canonical_prompt_paths(source_root: Path) -> tuple[Path, ...]:
    """Load the independent registry without importing the CLI or optional GUI."""
    spec = importlib.util.spec_from_file_location(
        "_rpg_build_prompt_registry", source_root / "repo_privacy_guardian" / "prompts.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the maintained prompt registry.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        paths = tuple(prompt.path(source_root) for prompt in module.PROMPT_REGISTRY)
    finally:
        sys.modules.pop(spec.name, None)
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError("A canonical registered prompt is missing from the source distribution.")
    return paths


def copy_prompt_resources(source_root: Path, build_root: Path) -> tuple[Path, ...]:
    destinations = []
    canonical_root = source_root / "docs" / "prompts"
    for source in canonical_prompt_paths(source_root):
        destination = build_root / "repo_privacy_guardian_resources" / "prompts" / source.relative_to(canonical_root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destinations.append(destination)
    return tuple(destinations)


class BuildPromptResources(build_py):
    def run(self) -> None:
        super().run()
        copy_prompt_resources(Path(__file__).resolve().parent, Path(self.build_lib))
