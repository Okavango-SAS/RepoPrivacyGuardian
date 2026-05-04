"""Compatibility shim for :mod:`repo_privacy_guardian.github`."""

from __future__ import annotations

import sys

from repo_privacy_guardian.github import *  # noqa: F403
from repo_privacy_guardian import github as _github

sys.modules[__name__] = _github
