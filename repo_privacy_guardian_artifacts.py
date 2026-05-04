"""Compatibility shim for :mod:`repo_privacy_guardian.artifacts`."""

from __future__ import annotations

import sys

from repo_privacy_guardian.artifacts import *  # noqa: F403
from repo_privacy_guardian import artifacts as _artifacts

sys.modules[__name__] = _artifacts
