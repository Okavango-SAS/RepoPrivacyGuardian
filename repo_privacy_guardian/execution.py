"""Side-effecting subprocess and Git execution adapters."""

from __future__ import annotations

import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, Protocol, TypeVar


class CommandResultLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


class CompletedProcessLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


CommandResultT = TypeVar("CommandResultT", bound=CommandResultLike)


@dataclass(frozen=True)
class GitSubprocessAdapter(Generic[CommandResultT]):
    timeout_seconds: int
    result_factory: Callable[[int, str, str], CommandResultT]
    missing_executable_message: Callable[[str], str]
    stdin_selector: Callable[[str | None], int]
    remediation_install_packages: Sequence[str]
    python_executable: str = sys.executable
    runner: Callable[..., CompletedProcessLike] = subprocess.run

    def run(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> CommandResultT:
        try:
            proc = self.runner(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                input=input_text,
                stdin=self.stdin_selector(input_text),
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError:
            return self.result_factory(127, "", self.missing_executable_message(cmd[0]))
        except subprocess.TimeoutExpired:
            return self.result_factory(
                124,
                "",
                f"Command timed out after {self.timeout_seconds}s: {shlex.join(cmd)}",
            )
        except Exception as exc:
            return self.result_factory(1, "", f"Unable to execute {shlex.join(cmd)}: {exc}")
        return self.result_factory(proc.returncode, proc.stdout, proc.stderr)

    def run_checked(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
    ) -> CommandResultT:
        result = self.run(cmd, cwd=cwd, input_text=input_text)
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed ({result.returncode}): {shlex.join(cmd)}\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )
        return result

    def git(self, repo: Path, *args: str) -> CommandResultT:
        return self.run(["git", "-C", str(repo), *args])

    def git_checked(self, repo: Path, *args: str) -> CommandResultT:
        return self.run_checked(["git", "-C", str(repo), *args])

    def ensure_git_filter_repo(self) -> None:
        probe = self.run([self.python_executable, "-m", "git_filter_repo", "--help"])
        if probe.returncode == 0:
            return

        detail = probe.stderr.strip() or probe.stdout.strip()
        raise RuntimeError(
            "git-filter-repo is required for remediation that rewrites history. "
            f"Install it with: {self.python_executable} -m pip install {' '.join(self.remediation_install_packages)} "
            "or re-run with --install-missing-tools."
            + (f"\nDetails: {detail}" if detail else "")
        )
