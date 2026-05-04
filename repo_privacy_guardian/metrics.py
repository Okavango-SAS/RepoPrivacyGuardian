from __future__ import annotations

from dataclasses import dataclass, field
import time


@dataclass
class RunMetrics:
    started_perf: float = field(default_factory=time.perf_counter)
    phase_timings: dict[str, float] = field(default_factory=dict)
    repo_timings: dict[str, dict[str, float]] = field(default_factory=dict)

    def begin_phase(self) -> float:
        return time.perf_counter()

    def end_phase(self, name: str, started: float) -> None:
        elapsed = max(time.perf_counter() - started, 0.0)
        self.phase_timings[name] = self.phase_timings.get(name, 0.0) + elapsed

    def add_repo_timing(self, repo_name: str, phase: str, elapsed: float) -> None:
        bucket = self.repo_timings.setdefault(repo_name, {})
        bucket[phase] = bucket.get(phase, 0.0) + max(elapsed, 0.0)

    def snapshot(self) -> dict[str, object]:
        return {
            "total_seconds": max(time.perf_counter() - self.started_perf, 0.0),
            "phases": {key: round(value, 4) for key, value in sorted(self.phase_timings.items())},
            "repositories": {
                repo: {phase: round(seconds, 4) for phase, seconds in sorted(values.items())}
                for repo, values in sorted(self.repo_timings.items())
            },
        }
