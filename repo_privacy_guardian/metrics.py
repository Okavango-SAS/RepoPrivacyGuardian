from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from collections.abc import Iterator
import time


@dataclass
class RunMetrics:
    started_perf: float = field(default_factory=time.perf_counter)
    phase_timings: dict[str, float] = field(default_factory=dict)
    repo_timings: dict[str, dict[str, float]] = field(default_factory=dict)
    repo_counters: dict[str, dict[str, int]] = field(default_factory=dict)

    def begin_phase(self) -> float:
        return time.perf_counter()

    def end_phase(self, name: str, started: float) -> None:
        elapsed = max(time.perf_counter() - started, 0.0)
        self.phase_timings[name] = self.phase_timings.get(name, 0.0) + elapsed

    def add_repo_timing(self, repo_name: str, phase: str, elapsed: float) -> None:
        bucket = self.repo_timings.setdefault(repo_name, {})
        bucket[phase] = bucket.get(phase, 0.0) + max(elapsed, 0.0)

    @contextmanager
    def measure_repo(self, repo_name: str, phase: str) -> Iterator[None]:
        started = self.begin_phase()
        try:
            yield
        finally:
            self.add_repo_timing(repo_name, phase, time.perf_counter() - started)

    def add_repo_count(self, repo_name: str, counter: str, amount: int = 1) -> None:
        """Add numeric workload data; callers use fixed names, never finding values."""
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValueError("counter increments must be non-negative integers")
        if not counter or len(counter) > 64 or not all(char.isalnum() or char == "_" for char in counter):
            raise ValueError("counter names must be short identifiers")
        bucket = self.repo_counters.setdefault(repo_name, {})
        if counter not in bucket and len(bucket) >= 64:
            raise ValueError("too many workload counter names")
        bucket[counter] = min(bucket.get(counter, 0) + amount, 1_000_000_000_000)

    def merge_scanner(self, scanner_metrics: RunMetrics) -> None:
        for repo_name, timings in scanner_metrics.repo_timings.items():
            for phase, seconds in timings.items():
                self.add_repo_timing(repo_name, phase, seconds)
        for repo_name, counters in scanner_metrics.repo_counters.items():
            for counter, count in counters.items():
                self.add_repo_count(repo_name, counter, count)

    def snapshot(self) -> dict[str, object]:
        return {
            "total_seconds": max(time.perf_counter() - self.started_perf, 0.0),
            "phases": {key: round(value, 4) for key, value in sorted(self.phase_timings.items())},
            "repositories": {
                repo: {phase: round(seconds, 4) for phase, seconds in sorted(values.items())}
                for repo, values in sorted(self.repo_timings.items())
            },
            "repository_counters": {
                repo: dict(sorted(values.items()))
                for repo, values in sorted(self.repo_counters.items())
            },
        }
