"""Side-effecting subprocess and Git execution adapters."""

from __future__ import annotations

import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, Protocol, TypeVar


class CommandResultLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


class CompletedProcessLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


class StreamingProcessLike(Protocol):
    stdout: Any | None
    stderr: Any | None
    returncode: int | None

    def wait(self, timeout: float | None = None) -> int | None: ...

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


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


@dataclass(frozen=True)
class GitStreamingAdapter:
    timeout_seconds: int
    popen_kwargs_factory: Callable[[], dict[str, Any]]
    popen_factory: Callable[..., StreamingProcessLike] = subprocess.Popen

    def start(self, cmd: list[str]) -> StreamingProcessLike:
        return self.popen_factory(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **self.popen_kwargs_factory(),
        )

    def start_git_history_patch(self, repo: Path) -> StreamingProcessLike:
        return self.start(
            [
                "git",
                "-C",
                str(repo),
                "log",
                "--all",
                "-p",
                "--no-color",
                "--pretty=format:",
            ]
        )

    def finalize(self, proc: StreamingProcessLike, timeout: int | None = None) -> tuple[int | None, str]:
        stderr_text = ""
        effective_timeout = self.timeout_seconds if timeout is None else timeout
        try:
            proc.wait(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            self.terminate_if_running(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        finally:
            if proc.stderr is not None:
                try:
                    stderr_text = proc.stderr.read()
                except Exception:
                    stderr_text = ""
            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            if proc.stderr is not None:
                try:
                    proc.stderr.close()
                except Exception:
                    pass
        return proc.returncode, stderr_text

    def terminate_if_running(self, proc: StreamingProcessLike) -> None:
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=2)
            return
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass
