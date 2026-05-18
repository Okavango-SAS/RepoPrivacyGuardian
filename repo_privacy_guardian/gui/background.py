"""GUI background-worker and UI-thread scheduling helpers."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, TypeVar


T = TypeVar("T")
ThreadFactory = Callable[..., threading.Thread]


def start_daemon_worker(
    *,
    target: Callable[..., None],
    args: tuple[object, ...] = (),
    thread_factory: ThreadFactory = threading.Thread,
) -> threading.Thread:
    thread = thread_factory(target=target, args=args, daemon=True)
    thread.start()
    return thread


def schedule_on_ui(root: Any, callback: Callable[[], None], *, delay_ms: int = 0) -> object:
    return root.after(delay_ms, callback)


def call_on_ui_thread_blocking(root: Any, callback: Callable[[], T], *, default: T) -> T:
    result: dict[str, T] = {"value": default}
    done = threading.Event()

    def _run() -> None:
        try:
            result["value"] = callback()
        finally:
            done.set()

    schedule_on_ui(root, _run)
    done.wait()
    return result["value"]


def ask_bool_on_ui(root: Any, callback: Callable[[], object], *, default: bool = False) -> bool:
    return bool(call_on_ui_thread_blocking(root, callback, default=default))
