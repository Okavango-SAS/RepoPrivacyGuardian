"""Compatibility shim for :mod:`repo_privacy_guardian.runtime`."""

from __future__ import annotations

import sys

from repo_privacy_guardian.runtime import *  # noqa: F403
from repo_privacy_guardian import runtime as _runtime

sys.modules[__name__] = _runtime
