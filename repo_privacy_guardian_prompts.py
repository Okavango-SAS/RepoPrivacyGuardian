"""Compatibility shim for :mod:`repo_privacy_guardian.prompts`."""

from __future__ import annotations

import sys

from repo_privacy_guardian.prompts import *  # noqa: F403
from repo_privacy_guardian import prompts as _prompts

sys.modules[__name__] = _prompts
