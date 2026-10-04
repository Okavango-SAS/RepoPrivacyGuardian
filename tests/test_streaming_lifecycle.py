"""Benign local subprocess checks for bounded Git stream ownership."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import json
import os
import signal
from pathlib import Path

import pytest

from repo_privacy_guardian import execution
from repo_privacy_guardian.execution import (
    GitStreamLifecycle,
    GitSubprocessAdapter,
    GitStreamingAdapter,
    AuditCommandCancelled,
    STREAM_STDERR_PREVIEW_CHARS,
    StreamingProcessLike,
)


def _adapter() -> GitStreamingAdapter:
    return GitStreamingAdapter(
        timeout_seconds=10,
        popen_kwargs_factory=lambda: {"stdin": subprocess.DEVNULL},
    )


def _start(adapter: GitStreamingAdapter, source: str) -> StreamingProcessLike:
    return adapter.start([sys.executable, "-u", "-c", source])


def _assert_released(lifecycle: GitStreamLifecycle) -> None:
    assert lifecycle.proc.poll() is not None
    assert lifecycle.reader_threads
    assert all(not reader.is_alive() for reader in lifecycle.reader_threads)
    assert lifecycle.proc.stdout is not None and lifecycle.proc.stdout.closed
    assert lifecycle.proc.stderr is not None and lifecycle.proc.stderr.closed


def test_stream_preserves_lines_utf8_and_universal_newlines() -> None:
    adapter = _adapter()
    proc = _start(
        adapter,
        "import os, time\n"
        "os.write(1, b'first\\r')\n"
        "time.sleep(.06)\n"
        "os.write(1, b'\\nsecond\\rthird\\n\\xe2')\n"
        "time.sleep(.06)\n"
        "os.write(1, b'\\x82\\xac-tail')\n"
        "os.write(2, b'diagnostic')\n",
    )
    with adapter.stream(proc) as lifecycle:
        lines = list(lifecycle)

    assert lines == ["first\n", "second\n", "third\n", "\u20ac-tail"]
    assert lifecycle.returncode == 0
    assert lifecycle.stderr_text == "diagnostic"
    assert not lifecycle.timed_out
    _assert_released(lifecycle)


@pytest.mark.parametrize("output", ["", "partial without newline"])
def test_stream_deadline_does_not_wait_for_line(output: str) -> None:
    adapter = _adapter()
    proc = _start(
        adapter,
        f"import sys, time; sys.stdout.write({output!r}); sys.stdout.flush(); "
        "sys.stderr.write('waiting'); sys.stderr.flush(); time.sleep(10)",
    )
    started = time.monotonic()
    with adapter.stream(proc, timeout=.3) as lifecycle:
        assert list(lifecycle) == []

    assert lifecycle.timed_out
    assert not lifecycle.cancelled
    assert lifecycle.stderr_text == "waiting"
    assert time.monotonic() - started < .3 + 7
    _assert_released(lifecycle)


def test_deadline_covers_process_exit_after_stdout_eof() -> None:
    adapter = _adapter()
    proc = _start(adapter, "import os, time; os.close(1); time.sleep(10)")
    started = time.monotonic()
    with adapter.stream(proc, timeout=.3) as lifecycle:
        assert list(lifecycle) == []

    assert lifecycle.timed_out
    assert time.monotonic() - started < .3 + 7
    _assert_released(lifecycle)


def test_stderr_is_drained_concurrently_and_preview_is_capped() -> None:
    adapter = _adapter()
    proc = _start(
        adapter,
        "import sys\n"
        "sys.stderr.write('d' * 1000000); sys.stderr.flush()\n"
        "for number in range(2500):\n"
        "    print('line-' + str(number))\n",
    )
    with adapter.stream(proc) as lifecycle:
        lines = list(lifecycle)

    assert lifecycle.returncode == 0
    assert lines == [f"line-{number}\n" for number in range(2500)]
    assert lifecycle.stderr_text == "d" * STREAM_STDERR_PREVIEW_CHARS
    assert not lifecycle.timed_out
    _assert_released(lifecycle)


def test_stderr_preserves_text_mode_newline_and_decode_behavior() -> None:
    adapter = _adapter()
    proc = _start(
        adapter,
        "import os, time\n"
        "os.write(2, b'first\\r')\n"
        "time.sleep(.06)\n"
        "os.write(2, b'\\nsecond\\rthird\\xff')\n",
    )
    with adapter.stream(proc) as lifecycle:
        assert list(lifecycle) == []

    assert lifecycle.stderr_text == "first\nsecond\nthird\ufffd"
    _assert_released(lifecycle)


def test_early_consumer_exit_reaps_process_and_closes_readers() -> None:
    adapter = _adapter()
    proc = _start(
        adapter,
        "import time\n"
        "for number in range(10000):\n"
        "    print('line-' + str(number))\n"
        "time.sleep(10)\n",
    )
    with adapter.stream(proc) as lifecycle:
        for line in lifecycle:
            assert line == "line-0\n"
            break

    assert not lifecycle.timed_out
    _assert_released(lifecycle)


def test_consumer_exception_preserves_error_and_cleans_process() -> None:
    adapter = _adapter()
    proc = _start(adapter, "import time; print('ready'); time.sleep(10)")
    with pytest.raises(ValueError, match="consumer stopped"):
        with adapter.stream(proc) as lifecycle:
            for _line in lifecycle:
                raise ValueError("consumer stopped")

    _assert_released(lifecycle)


def test_audit_cancellation_is_separate_from_timeout() -> None:
    adapter = _adapter()
    proc = _start(adapter, "import time; time.sleep(10)")
    cancelled = threading.Event()
    timer = threading.Timer(.1, cancelled.set)
    started = time.monotonic()
    timer.start()
    try:
        with adapter.stream(proc, cancel_requested=cancelled.is_set) as lifecycle:
            assert list(lifecycle) == []
    finally:
        timer.cancel()
        timer.join()

    assert lifecycle.cancelled
    assert not lifecycle.timed_out
    assert time.monotonic() - started < 2
    _assert_released(lifecycle)


def test_cancellation_callback_error_preserves_error_and_cleans_process() -> None:
    adapter = _adapter()
    proc = _start(adapter, "import time; time.sleep(10)")

    def callback() -> bool:
        raise ValueError("audit interrupted")

    with pytest.raises(ValueError, match="audit interrupted"):
        with adapter.stream(proc, cancel_requested=callback) as lifecycle:
            list(lifecycle)

    _assert_released(lifecycle)


def test_cancellation_callback_error_at_finalization_releases_process() -> None:
    adapter = _adapter()
    proc = _start(adapter, "import os, time; os.close(1); time.sleep(10)")
    calls = 0

    def callback() -> bool:
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise ValueError("audit interrupted at EOF")
        return False

    with pytest.raises(ValueError, match="audit interrupted at EOF"):
        with adapter.stream(proc, cancel_requested=callback) as lifecycle:
            list(lifecycle)

    _assert_released(lifecycle)


def test_reader_start_failure_cleans_started_reader_and_process(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = _adapter()
    proc = _start(adapter, "import time; time.sleep(10)")
    original_start = threading.Thread.start

    def fail_second_reader(thread: threading.Thread) -> None:
        if thread.name == "rpg-git-stderr":
            raise RuntimeError("controlled reader start failure")
        original_start(thread)

    lifecycle = adapter.stream(proc)
    monkeypatch.setattr(threading.Thread, "start", fail_second_reader)
    with pytest.raises(RuntimeError, match="controlled reader start failure"):
        with lifecycle:
            pass

    _assert_released(lifecycle)


def test_unconsumed_context_releases_process() -> None:
    adapter = _adapter()
    proc = _start(adapter, "import time; time.sleep(10)")
    with adapter.stream(proc) as lifecycle:
        pass

    _assert_released(lifecycle)


def test_finalize_compatibility_drains_unread_stdout_and_stderr() -> None:
    adapter = _adapter()
    proc = _start(
        adapter,
        "import sys; print('x' * 100000); "
        "sys.stderr.write('d' * 100000); sys.stderr.flush()",
    )
    returncode, stderr = adapter.finalize(proc)

    assert returncode == 0
    assert len(stderr) == STREAM_STDERR_PREVIEW_CHARS
    assert proc.stdout is not None and proc.stdout.closed
    assert proc.stderr is not None and proc.stderr.closed


def test_failed_start_propagates_without_readers() -> None:
    def missing(*_args: object, **_kwargs: object) -> StreamingProcessLike:
        raise FileNotFoundError("controlled missing executable")

    adapter = GitStreamingAdapter(1, lambda: {}, popen_factory=missing)
    before = set(threading.enumerate())
    with pytest.raises(FileNotFoundError, match="controlled missing executable"):
        adapter.start(["controlled-missing-executable"])
    assert set(threading.enumerate()) == before


def test_terminate_escalates_to_kill_and_waits_for_exit() -> None:
    class ControlledProcess:
        stdout = None
        stderr = None
        returncode: int | None = None

        def __init__(self) -> None:
            self.actions: list[str] = []

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            self.actions.append("wait")
            if self.returncode is None:
                raise subprocess.TimeoutExpired(["controlled"], timeout)
            return self.returncode

        def terminate(self) -> None:
            self.actions.append("terminate")

        def kill(self) -> None:
            self.actions.append("kill")
            self.returncode = -9

    proc = ControlledProcess()
    _adapter().terminate_if_running(proc)
    assert proc.actions == ["terminate", "wait", "kill", "wait"]
    assert proc.poll() == -9


def test_reader_failure_is_runtime_error_and_releases_process() -> None:
    class FailingStream:
        closed = False

        def read(self) -> str:
            raise OSError("controlled read failure")

        def close(self) -> None:
            self.closed = True

    class ControlledProcess:
        def __init__(self) -> None:
            self.stdout = FailingStream()
            self.stderr = FailingStream()
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int | None:
            del timeout
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -1

        def kill(self) -> None:
            self.returncode = -9

    proc = ControlledProcess()
    adapter = _adapter()
    with pytest.raises(RuntimeError, match="Unable to read Git streaming output"):
        with adapter.stream(proc) as lifecycle:
            list(lifecycle)

    _assert_released(lifecycle)


def _command_adapter(**kwargs: object) -> GitSubprocessAdapter:
    return GitSubprocessAdapter(
        timeout_seconds=10,
        result_factory=lambda code, out, err: subprocess.CompletedProcess(["controlled"], code, out, err),
        missing_executable_message=lambda _binary: "controlled missing executable",
        stdin_selector=lambda _input: subprocess.DEVNULL,
        remediation_install_packages=(),
        **kwargs,
    )


def test_cancellable_read_command_keeps_success_output_parity() -> None:
    command = [
        sys.executable, "-u", "-c",
        "import os; os.write(1, b'alpha\\x00beta\\r\\ntail'); os.write(2, b'diagnostic\\r\\n')",
    ]
    adapter = _command_adapter()
    regular = adapter.run(command)
    cancellable = adapter.run(command, cancel_requested=lambda: False)

    assert cancellable.returncode == regular.returncode == 0
    assert cancellable.stdout == regular.stdout == "alpha\x00beta\ntail"
    assert cancellable.stderr == regular.stderr == "diagnostic\n"


def test_cancellable_read_command_keeps_nonzero_exit_output() -> None:
    result = _command_adapter().run(
        [sys.executable, "-u", "-c", "import sys; print('progress'); sys.stderr.write('diagnostic'); sys.exit(2)"],
        cancel_requested=lambda: False,
    )
    assert result.returncode == 2
    assert result.stdout == "progress\n"
    assert result.stderr == "diagnostic"


def test_read_only_git_wait_cancels_and_reaps_process(tmp_path: Path) -> None:
    processes: list[StreamingProcessLike] = []
    commands: list[list[str]] = []

    def controlled_start(command: list[str], **kwargs: object) -> StreamingProcessLike:
        commands.append(command)
        proc = subprocess.Popen([sys.executable, "-u", "-c", "import time; time.sleep(10)"], **kwargs)
        processes.append(proc)
        return proc

    adapter = _command_adapter(popen_factory=controlled_start)
    cancelled = threading.Event()
    timer = threading.Timer(.1, cancelled.set)
    started = time.monotonic()
    timer.start()
    try:
        with pytest.raises(AuditCommandCancelled, match="read-only command"):
            adapter.git(tmp_path, "fsck", "--strict", cancel_requested=cancelled.is_set)
    finally:
        timer.cancel()
        timer.join()

    assert time.monotonic() - started < 2
    assert commands == [["git", "-C", str(tmp_path), "fsck", "--strict"]]
    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert processes[0].stdout is not None and processes[0].stdout.closed
    assert processes[0].stderr is not None and processes[0].stderr.closed


def test_pending_cancellation_does_not_start_read_command() -> None:
    def unexpected_start(*_args: object, **_kwargs: object) -> StreamingProcessLike:
        pytest.fail("A command started after cancellation")

    adapter = _command_adapter(popen_factory=unexpected_start)
    with pytest.raises(AuditCommandCancelled):
        adapter.run(["controlled"], cancel_requested=lambda: True)


def test_input_command_retains_runner_and_ignores_audit_cancellation() -> None:
    calls: list[dict[str, object]] = []

    def controlled_runner(_command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(kwargs)
        return subprocess.CompletedProcess(["controlled"], 0, "ok", "")

    def unexpected_start(*_args: object, **_kwargs: object) -> StreamingProcessLike:
        pytest.fail("An input command used the cancellable read backend")

    adapter = _command_adapter(runner=controlled_runner, popen_factory=unexpected_start)
    result = adapter.run(["controlled"], input_text="reviewed input", cancel_requested=lambda: True)
    assert result.stdout == "ok"
    assert calls[0]["input"] == "reviewed input"
    assert "stdin" not in calls[0]


@pytest.mark.parametrize("input_text", ["", "reviewed input\n"])
@pytest.mark.parametrize("protected", [False, True])
def test_native_input_echo_runs_with_and_without_repair_protection(input_text: str, protected: bool) -> None:
    adapter = _command_adapter()
    command = [sys.executable, "-u", "-c", "import sys; sys.stdout.write(sys.stdin.read())"]
    if protected:
        with execution.ConsoleCancellationScope():
            result = adapter.run(command, input_text=input_text, cancel_requested=lambda: True)
    else:
        result = adapter.run(command, input_text=input_text, cancel_requested=lambda: True)
    assert result.returncode == 0
    assert result.stdout == input_text
    assert result.stderr == ""


def test_cancellable_start_failure_returns_existing_missing_executable_result() -> None:
    def missing(*_args: object, **_kwargs: object) -> StreamingProcessLike:
        raise FileNotFoundError("controlled missing executable")

    result = _command_adapter(popen_factory=missing).run(["controlled"], cancel_requested=lambda: False)
    assert result.returncode == 127
    assert result.stderr == "controlled missing executable"


def test_cancellable_error_does_not_include_command_arguments_or_exception_details() -> None:
    def denied(*_args: object, **_kwargs: object) -> StreamingProcessLike:
        raise OSError("synthetic-error-detail")

    result = _command_adapter(popen_factory=denied).run(
        ["controlled", "synthetic-argument-marker"], cancel_requested=lambda: False,
    )
    assert result.returncode == 1
    assert result.stderr == "Unable to execute audit command (OSError)"


def test_cancellable_command_deadline_returns_sanitized_runtime_result() -> None:
    adapter = _command_adapter()
    # The fixture limit is separate from the preserved production defaults.
    from dataclasses import replace

    adapter = replace(adapter, timeout_seconds=1)
    started = time.monotonic()
    result = adapter.run(
        [sys.executable, "-u", "-c", "import time; time.sleep(10)", "synthetic-argument-marker"],
        cancel_requested=lambda: False,
    )
    assert result.returncode == 124
    assert result.stdout == ""
    assert result.stderr == "Command timed out after 1s"
    assert time.monotonic() - started < 1 + 7


def test_console_repair_scope_defers_repeated_sigint_and_restores_handler() -> None:
    previous_handler = signal.getsignal(signal.SIGINT)
    with execution.ConsoleCancellationScope() as scope:
        signal.raise_signal(signal.SIGINT)
        signal.raise_signal(signal.SIGINT)
        assert scope.requested()
    assert signal.getsignal(signal.SIGINT) is previous_handler
    assert scope.requested()


def test_console_repair_scope_restores_handler_after_error() -> None:
    calls: list[dict[str, object]] = []

    def runner(_command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(kwargs)
        return subprocess.CompletedProcess(["controlled"], 0, "done", "")

    adapter = _command_adapter(runner=runner)
    previous_handler = signal.getsignal(signal.SIGINT)
    with pytest.raises(ValueError, match="controlled repair error"):
        with execution.ConsoleCancellationScope():
            adapter.run(["controlled"])
            raise ValueError("controlled repair error")
    adapter.run(["controlled"])
    assert signal.getsignal(signal.SIGINT) is previous_handler
    for key, value in execution.subprocess_signal_isolation_kwargs().items():
        assert calls[0][key] == value
        assert key not in calls[1]


def test_worker_repair_scope_keeps_main_handler_and_isolates_commands() -> None:
    previous_handler = signal.getsignal(signal.SIGINT)
    observed: list[dict[str, object]] = []
    failures: list[BaseException] = []

    def runner(_command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        observed.append(kwargs)
        return subprocess.CompletedProcess(["controlled"], 0, "done", "")

    def worker() -> None:
        try:
            with execution.ConsoleCancellationScope() as scope:
                assert signal.getsignal(signal.SIGINT) is previous_handler
                assert not scope.requested()
                _command_adapter(runner=runner).run(["controlled"])
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert failures == []
    assert signal.getsignal(signal.SIGINT) is previous_handler
    for key, value in execution.subprocess_signal_isolation_kwargs().items():
        assert observed[0][key] == value


def test_nested_write_protection_keeps_legacy_kwargs_outside_scope() -> None:
    calls: list[dict[str, object]] = []

    def runner(_command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(kwargs)
        return subprocess.CompletedProcess(["controlled"], 0, "done", "")

    adapter = _command_adapter(runner=runner)
    adapter.run(["controlled"])
    with execution.protect_write_commands():
        adapter.run(["controlled"])
        with execution.protect_write_commands():
            adapter.run(["controlled"])
        adapter.run(["controlled"])
    adapter.run(["controlled"])
    for key, value in execution.subprocess_signal_isolation_kwargs().items():
        assert key not in calls[0]
        assert key not in calls[4]
        assert all(call[key] == value for call in calls[1:4])


def test_write_protection_is_context_local_across_threads() -> None:
    calls: list[dict[str, object]] = []

    def runner(_command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(kwargs)
        return subprocess.CompletedProcess(["controlled"], 0, "done", "")

    adapter = _command_adapter(runner=runner)
    with execution.protect_write_commands():
        worker = threading.Thread(target=lambda: adapter.run(["controlled"]))
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive()
        adapter.run(["controlled"])
    for key, value in execution.subprocess_signal_isolation_kwargs().items():
        assert key not in calls[0]
        assert calls[1][key] == value


def test_protected_stream_keeps_existing_windows_creation_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []

    class ControlledProcess:
        stdout = None
        stderr = None
        returncode = 0

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def terminate(self) -> None:
            pass

        def kill(self) -> None:
            pass

    def start(_command: list[str], **kwargs: object) -> StreamingProcessLike:
        captured.append(kwargs)
        return ControlledProcess()

    monkeypatch.setattr(execution, "subprocess_signal_isolation_kwargs", lambda: {"creationflags": 0x200})
    adapter = GitStreamingAdapter(1, lambda: {"creationflags": 0x08000000}, popen_factory=start)
    adapter.start(["controlled"])
    with execution.protect_write_commands():
        adapter.start(["controlled"])
    assert captured[0]["creationflags"] == 0x08000000
    assert captured[1]["creationflags"] == 0x08000200


def test_signal_isolation_platform_contract() -> None:
    assert execution.subprocess_signal_isolation_kwargs("nt") == {"creationflags": 0x200}
    assert execution.subprocess_signal_isolation_kwargs("posix") == {"start_new_session": True}


def test_console_scope_failed_handler_install_resets_protection(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(_signal: object, _handler: object) -> None:
        raise RuntimeError("controlled handler installation failure")

    monkeypatch.setattr(execution.signal, "signal", denied)
    with pytest.raises(RuntimeError, match="controlled handler installation failure"):
        with execution.ConsoleCancellationScope():
            pass
    assert execution._protected_process_kwargs() == {}


@pytest.mark.skipif(os.name == "nt", reason="Native POSIX foreground-group broadcast regression")
def test_native_sigint_batch_protects_benign_child_until_safe_boundary() -> None:
    # The probe starts in a new session and verifies its own group before sending
    # SIGINT. It cannot broadcast to the test runner or any unrelated process.
    source = """
import json, os, signal, subprocess, sys, threading, time
from repo_privacy_guardian.execution import ConsoleCancellationScope, GitSubprocessAdapter
assert os.getpgrp() == os.getpid()
adapter = GitSubprocessAdapter(
    5, lambda code, out, err: subprocess.CompletedProcess(['controlled'], code, out, err),
    lambda binary: 'missing', lambda text: subprocess.DEVNULL, (),
)
def interrupt():
    time.sleep(.15)
    os.killpg(os.getpgrp(), signal.SIGINT)
    time.sleep(.03)
    os.killpg(os.getpgrp(), signal.SIGINT)
with ConsoleCancellationScope() as scope:
    sender = threading.Thread(target=interrupt)
    sender.start()
    result = adapter.run([sys.executable, '-u', '-c', "import time; time.sleep(.6); print('safe-boundary')"])
    sender.join(timeout=2)
print(json.dumps({'code': result.returncode, 'out': result.stdout, 'cancel': scope.requested()}))
"""
    proc = subprocess.run(
        [sys.executable, "-u", "-c", source],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=10,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"code": 0, "out": "safe-boundary\n", "cancel": True}
