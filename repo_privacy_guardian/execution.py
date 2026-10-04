"""Side-effecting subprocess and Git execution adapters."""

from __future__ import annotations

import shlex
import subprocess
import sys
import codecs
import io
import os
import queue
import re
import select
import signal
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar, Token
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


class AuditCommandCancelled(RuntimeError):
    """A read-only command stopped after an operator cancellation request."""


_write_signal_protection: ContextVar[bool] = ContextVar("rpg_write_signal_protection", default=False)


def subprocess_signal_isolation_kwargs(platform_name: str | None = None) -> dict[str, Any]:
    """Keep a child outside the console's Ctrl+C broadcast group."""
    platform_name = os.name if platform_name is None else platform_name
    if platform_name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)}
    return {"start_new_session": True}


def _protected_process_kwargs(existing: dict[str, Any] | None = None) -> dict[str, Any]:
    kwargs = dict(existing or {})
    if _write_signal_protection.get():
        isolation = subprocess_signal_isolation_kwargs()
        if "creationflags" in isolation:
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | isolation["creationflags"]
        else:
            kwargs.update(isolation)
    return kwargs


@contextmanager
def protect_write_commands() -> Iterator[None]:
    """Defer console interruption of child commands until their write boundary."""
    token = _write_signal_protection.set(True)
    try:
        yield
    finally:
        _write_signal_protection.reset(token)


class ConsoleCancellationScope:
    """Turn console SIGINT into a token during one reviewed repair batch.

    Main-thread CLI use temporarily replaces the handler; GUI worker use leaves
    signal handlers alone. Both isolate child processes. The caller reads
    requested() after the context and aborts at its next Git-safe boundary.
    """

    def __init__(self) -> None:
        self._requested = False
        self._protection_token: Token[bool] | None = None
        self._previous_handler: Any = None
        self._signal_installed = False

    def request(self) -> None:
        # A plain assignment is safe under repeated/reentrant Python SIGINT
        # delivery; acquiring an Event's lock in a signal handler is unnecessary.
        self._requested = True

    def requested(self) -> bool:
        return self._requested

    def _handle_sigint(self, signum: int, frame: Any) -> None:
        del signum, frame
        self.request()

    def __enter__(self) -> ConsoleCancellationScope:
        if self._protection_token is not None:
            raise RuntimeError("A console cancellation scope cannot be entered twice")
        self._protection_token = _write_signal_protection.set(True)
        try:
            if threading.current_thread() is threading.main_thread():
                self._previous_handler = signal.signal(signal.SIGINT, self._handle_sigint)
                self._signal_installed = True
        except BaseException:
            _write_signal_protection.reset(self._protection_token)
            self._protection_token = None
            raise
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        del exc_type, exc_value, traceback
        try:
            if self._signal_installed:
                signal.signal(signal.SIGINT, self._previous_handler)
                self._signal_installed = False
        finally:
            if self._protection_token is not None:
                _write_signal_protection.reset(self._protection_token)
                self._protection_token = None


@dataclass(frozen=True)
class GitSubprocessAdapter(Generic[CommandResultT]):
    timeout_seconds: int
    result_factory: Callable[[int, str, str], CommandResultT]
    missing_executable_message: Callable[[str], str]
    stdin_selector: Callable[[str | None], int]
    remediation_install_packages: Sequence[str]
    python_executable: str = sys.executable
    runner: Callable[..., CompletedProcessLike] = subprocess.run
    popen_factory: Callable[..., StreamingProcessLike] = subprocess.Popen

    def run(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        input_text: str | None = None,
        *,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> CommandResultT:
        if cancel_requested is not None and input_text is None:
            return self._run_cancellable(cmd, cwd, cancel_requested)
        try:
            proc = self.runner(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                input=input_text,
                timeout=self.timeout_seconds,
                # subprocess.run creates its own PIPE whenever input is set;
                # passing stdin as well rejects the command before it starts.
                **({"stdin": self.stdin_selector(None)} if input_text is None else {}),
                **_protected_process_kwargs(),
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

    def _run_cancellable(
        self,
        cmd: list[str],
        cwd: Path | None,
        cancel_requested: Callable[[], bool],
    ) -> CommandResultT:
        if cancel_requested():
            raise AuditCommandCancelled("Audit cancelled during a read-only command")
        adapter = GitStreamingAdapter(
            timeout_seconds=self.timeout_seconds,
            popen_kwargs_factory=lambda: {
                "cwd": str(cwd) if cwd else None,
                "stdin": self.stdin_selector(None),
                "start_new_session": True,
            },
            popen_factory=self.popen_factory,
        )
        try:
            proc = adapter.start(cmd)
            with adapter.stream(proc, cancel_requested=cancel_requested) as lifecycle:
                output = list(lifecycle)
            if lifecycle.cancelled:
                raise AuditCommandCancelled("Audit cancelled during a read-only command")
            if lifecycle.timed_out:
                return self.result_factory(124, "", f"Command timed out after {self.timeout_seconds}s")
            return self.result_factory(
                lifecycle.returncode if lifecycle.returncode is not None else 1,
                "".join(output),
                lifecycle.stderr_text,
            )
        except AuditCommandCancelled:
            raise
        except FileNotFoundError:
            return self.result_factory(127, "", self.missing_executable_message(cmd[0]))
        except Exception as exc:
            # Command arguments and exception strings can contain private values.
            return self.result_factory(1, "", f"Unable to execute audit command ({type(exc).__name__})")

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

    def git(
        self,
        repo: Path,
        *args: str,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> CommandResultT:
        return self.run(["git", "-C", str(repo), *args], cancel_requested=cancel_requested)

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
        kwargs = _protected_process_kwargs(self.popen_kwargs_factory())
        return self.popen_factory(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            **kwargs,
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

    def stream(
        self,
        proc: StreamingProcessLike,
        *,
        timeout: float | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> GitStreamLifecycle:
        """Own both pipes until EOF or cleanup; callers never read them directly."""
        return GitStreamLifecycle(
            self,
            proc,
            timeout=float(self.timeout_seconds) if timeout is None else timeout,
            cancel_requested=cancel_requested,
        )

    def finalize(self, proc: StreamingProcessLike, timeout: int | None = None) -> tuple[int | None, str]:
        # Compatibility for callers that already consumed stdout. Any unread output
        # is drained concurrently with stderr, including while waiting for exit.
        with self.stream(proc, timeout=timeout) as lifecycle:
            for _line in lifecycle:
                pass
        return lifecycle.returncode, lifecycle.stderr_text

    def terminate_if_running(self, proc: StreamingProcessLike) -> None:
        try:
            if proc.poll() is not None:
                return
        except Exception:
            pass
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
        try:
            proc.wait(timeout=2)
        except Exception:
            pass


STREAM_POLL_SECONDS = 0.05
STREAM_PIPE_POLL_SECONDS = 0.002
STREAM_READ_CHUNK_BYTES = 65_536
STREAM_STDERR_PREVIEW_CHARS = 16_384
STREAM_QUEUE_LINES = 64


class GitStreamLifecycle:
    """Concurrent, bounded Git pipe delivery with cooperative audit cancellation.

    The monotonic deadline covers reading and process completion. Cleanup spends
    at most four seconds terminating/reaping and two seconds joining readers.
    Real pipes are polled before os.read, so even a partial line or inherited open
    pipe cannot leave a reader blocked when the consumer exits early.
    """

    def __init__(
        self,
        adapter: GitStreamingAdapter,
        proc: StreamingProcessLike,
        *,
        timeout: float,
        cancel_requested: Callable[[], bool] | None,
    ) -> None:
        self.adapter = adapter
        self.proc = proc
        self.deadline = time.monotonic() + max(0.0, timeout)
        self.cancel_requested = cancel_requested
        self.timed_out = False
        self.cancelled = False
        self._stop = threading.Event()
        self._stdout_done = threading.Event()
        self._lines: queue.Queue[str] = queue.Queue(maxsize=STREAM_QUEUE_LINES)
        self._stderr_parts: list[str] = []
        self._stderr_length = 0
        self._reader_errors: list[Exception] = []
        self._readers: list[threading.Thread] = []
        self._entered = False
        self._closed = False
        self._exhausted = False
        self._peek_named_pipe: Any | None = None
        if os.name == "nt":
            import ctypes

            self._peek_named_pipe = ctypes.WinDLL("kernel32", use_last_error=True).PeekNamedPipe

    @property
    def returncode(self) -> int | None:
        return self.proc.returncode

    @property
    def stderr_text(self) -> str:
        return "".join(self._stderr_parts)

    @property
    def reader_threads(self) -> tuple[threading.Thread, ...]:
        return tuple(self._readers)

    def __enter__(self) -> GitStreamLifecycle:
        if self._entered:
            raise RuntimeError("A Git stream lifecycle cannot be entered twice")
        self._entered = True
        try:
            for name, reader in (("stdout", self._read_stdout), ("stderr", self._read_stderr)):
                thread = threading.Thread(target=reader, name=f"rpg-git-{name}")
                self._readers.append(thread)
                thread.start()
        except BaseException:
            self._cleanup(terminate=True)
            raise
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        del exc_value, traceback
        completed = False
        try:
            if exc_type is None and self._exhausted and not self._interrupted():
                self._wait_for_exit()
                completed = self.proc.poll() is not None and not (self.timed_out or self.cancelled)
        finally:
            self._cleanup(
                terminate=not completed or bool(self._reader_errors)
            )
        if exc_type is None and self._reader_errors:
            raise RuntimeError("Unable to read Git streaming output") from self._reader_errors[0]

    def __iter__(self) -> Iterator[str]:
        if not self._entered or self._closed:
            raise RuntimeError("Iterate a Git stream inside its context manager")
        while not self._interrupted():
            if self._reader_errors:
                raise RuntimeError("Unable to read Git streaming output") from self._reader_errors[0]
            try:
                line = self._lines.get(timeout=self._poll_timeout())
            except queue.Empty:
                if self._stdout_done.is_set():
                    self._exhausted = True
                    return
                continue
            yield line

    def _poll_timeout(self) -> float:
        return max(0.001, min(STREAM_POLL_SECONDS, self.deadline - time.monotonic()))

    def _interrupted(self) -> bool:
        if self.timed_out or self.cancelled:
            return True
        if self.cancel_requested is not None and self.cancel_requested():
            self.cancelled = True
            return True
        if time.monotonic() >= self.deadline:
            self.timed_out = True
            return True
        return False

    def _wait_for_exit(self) -> None:
        while self.proc.poll() is None and not self._interrupted():
            pause = self._poll_timeout()
            started = time.monotonic()
            try:
                self.proc.wait(timeout=pause)
            except subprocess.TimeoutExpired:
                # Controlled adapters may raise immediately; do not busy-spin.
                self._stop.wait(max(0.0, pause - (time.monotonic() - started)))

    def _cleanup(self, *, terminate: bool) -> None:
        if self._closed:
            return
        self._closed = True
        if terminate:
            self._stop.set()
            self.adapter.terminate_if_running(self.proc)
        # After normal exit let stderr drain to EOF before asking readers to stop.
        join_deadline = time.monotonic() + 1.0
        for thread in self._readers:
            if thread.ident is not None:
                thread.join(timeout=max(0.0, join_deadline - time.monotonic()))
        self._stop.set()
        join_deadline = time.monotonic() + 1.0
        for thread in self._readers:
            if thread.ident is not None:
                thread.join(timeout=max(0.0, join_deadline - time.monotonic()))
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass

    def _pipe_read_size(self, fd: int) -> int | None:
        if os.name == "nt":
            import ctypes
            import msvcrt

            available = ctypes.c_ulong()
            assert self._peek_named_pipe is not None
            result = self._peek_named_pipe(
                ctypes.c_void_p(msvcrt.get_osfhandle(fd)),
                None,
                0,
                None,
                ctypes.byref(available),
                None,
            )
            if not result:
                error = ctypes.get_last_error()
                if error in {109, 232}:  # Broken pipe / pipe closing: EOF.
                    return 0
                raise OSError(error, "Unable to inspect Git output pipe")
            if available.value:
                return min(STREAM_READ_CHUNK_BYTES, available.value)
            if self.proc.poll() is not None:
                return 0
            # Pipe refill cadence must not throttle a producer with a small OS
            # buffer. Deadline/cancellation delivery has its separate 50ms poll.
            self._stop.wait(STREAM_PIPE_POLL_SECONDS)
            return None
        ready, _, _ = select.select([fd], [], [], STREAM_POLL_SECONDS)
        return STREAM_READ_CHUNK_BYTES if ready else None

    def _text_chunks(self, stream: Any, *, stdout: bool) -> Iterator[str]:
        try:
            fd = stream.fileno()
        except (AttributeError, OSError, ValueError):
            # Lightweight, in-memory adapters retain the existing test protocol.
            if stdout and hasattr(stream, "__iter__"):
                yield from stream
            else:
                yield stream.read()
            return
        decoder = io.IncrementalNewlineDecoder(
            codecs.getincrementaldecoder("utf-8")(errors="replace"), translate=True
        )
        while not self._stop.is_set():
            size = self._pipe_read_size(fd)
            if size is None:
                continue
            chunk = os.read(fd, size) if size else b""
            if not chunk:
                tail = decoder.decode(b"", final=True)
                if tail:
                    yield tail
                return
            text = decoder.decode(chunk)
            if text:
                yield text

    def _put_line(self, line: str) -> bool:
        while not self._stop.is_set():
            try:
                self._lines.put(line, timeout=STREAM_POLL_SECONDS)
                return True
            except queue.Full:
                continue
        return False

    def _read_stdout(self) -> None:
        fragments: list[str] = []
        trailing_cr = False
        try:
            if self.proc.stdout is None:
                return
            for chunk in self._text_chunks(self.proc.stdout, stdout=True):
                if trailing_cr:
                    if not self._put_line("".join(fragments) + "\n"):
                        return
                    fragments.clear()
                    chunk = chunk[1:] if chunk.startswith("\n") else chunk
                    trailing_cr = False
                # Split each bounded chunk rather than repeatedly copying/searching
                # an arbitrarily long unterminated line.
                pieces = re.split(r"(\r\n|\r|\n)", chunk)
                for index, piece in enumerate(pieces):
                    if index % 2 == 0:
                        if piece:
                            fragments.append(piece)
                    elif piece == "\r" and index == len(pieces) - 2 and not pieces[-1]:
                        trailing_cr = True
                    else:
                        if not self._put_line("".join(fragments) + "\n"):
                            return
                        fragments.clear()
            if (fragments or trailing_cr) and not self._stop.is_set():
                self._put_line("".join(fragments) + ("\n" if trailing_cr else ""))
        except Exception as exc:
            self._reader_errors.append(exc)
        finally:
            self._stdout_done.set()

    def _read_stderr(self) -> None:
        try:
            if self.proc.stderr is None:
                return
            for chunk in self._text_chunks(self.proc.stderr, stdout=False):
                remaining = STREAM_STDERR_PREVIEW_CHARS - self._stderr_length
                if remaining > 0:
                    preview = chunk[:remaining]
                    self._stderr_parts.append(preview)
                    self._stderr_length += len(preview)
        except Exception as exc:
            self._reader_errors.append(exc)
