from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_benchmark_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_large_history.py"
    spec = importlib.util.spec_from_file_location("benchmark_large_history", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_large_history_benchmark_flattens_and_compares_run_state_timings(tmp_path: Path) -> None:
    benchmark = _load_benchmark_module()
    current_state = tmp_path / "current-run_state.json"
    baseline_state = tmp_path / "baseline-run_state.json"
    current_state.write_text(
        json.dumps(
            {
                "performance": {
                    "total_seconds": 3.0,
                    "phases": {"audit": 2.5, "discovery": 0.5},
                    "repositories": {"large-history-benchmark": {"audit": 2.4}},
                }
            }
        ),
        encoding="utf-8",
    )
    baseline_state.write_text(
        json.dumps(
            {
                "performance": {
                    "total_seconds": 2.0,
                    "phases": {"audit": 1.0},
                    "repositories": {"large-history-benchmark": {"audit": 1.0}},
                }
            }
        ),
        encoding="utf-8",
    )

    current = benchmark.load_run_state_timings(current_state)
    baseline = benchmark.load_run_state_timings(baseline_state)
    comparisons = benchmark.compare_timing_maps(
        current,
        baseline,
        max_regression_percent=100.0,
    )

    by_key = {item.key: item for item in comparisons}
    assert current["phase:audit"] == 2.5
    assert current["repo:large-history-benchmark:audit"] == 2.4
    assert by_key["phase:audit"].delta_seconds == 1.5
    assert by_key["phase:audit"].delta_percent == 150.0
    assert by_key["phase:audit"].exceeded_threshold is True
    assert by_key["phase:discovery"].baseline_seconds is None
    assert "REGRESSION" in benchmark.render_comparison(comparisons)


def test_large_history_benchmark_smoke_runs_real_pipeline(tmp_path: Path) -> None:
    benchmark = _load_benchmark_module()

    result = benchmark.run_large_history_benchmark(
        output_dir=tmp_path / "benchmark",
        commit_count=3,
        file_count=2,
        max_regression_percent=None,
        verbose=False,
    )

    assert result.exit_code == 0
    assert result.repository.exists()
    assert result.run_state_path.exists()
    assert "phase:audit" in result.timings
    assert "repo:large-history-benchmark:audit" in result.timings
    assert result.timings["repo:large-history-benchmark:audit"] >= 0
    assert result.comparisons
