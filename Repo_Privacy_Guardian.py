#!/usr/bin/env python3
"""Compatibility facade for Repo Privacy Guardian.

The implementation now lives under :mod:`repo_privacy_guardian`. This module
keeps the stable 1.x public entry points intact:

- ``repo-privacy-guardian`` console script
- ``python -m Repo_Privacy_Guardian``
- ``python Repo_Privacy_Guardian.py``
- ``import Repo_Privacy_Guardian as rpg``
"""

from __future__ import annotations

import sys

from repo_privacy_guardian.core import *  # noqa: F403
from repo_privacy_guardian import core as _core

globals().update(
    {
        name: value
        for name, value in vars(_core).items()
        if not (name.startswith("__") and name.endswith("__"))
    }
)

__all__ = [
    name
    for name in globals()
    if not (name.startswith("__") and name.endswith("__"))
]

if __name__ != "__main__":
    sys.modules[__name__] = _core


if __name__ == "__main__":
    raise SystemExit(_core.main())
