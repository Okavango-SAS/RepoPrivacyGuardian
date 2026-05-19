#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import Repo_Privacy_Guardian as rpg  # noqa: E402


BENCHMARK_SCHEMA_VERSION = 1
BENCHMARK_REPO_NAME = "large-history-benchmark"
DEFAULT_COMMIT_COUNT = 120
DEFAULT_FILE_COUNT = 8


@dataclass(frozen=True)
class TimingComparison:
    key: str
    current_seconds: float
    baseline_seconds: float | None
    delta_seconds: float | None
    delta_percent: float | None
    exceeded_threshold: bool


@dataclass(frozen=True)
class BenchmarkResult:
    output_dir: Path
    repository: Path
    artifacts_dir: Path
    run_state_path: Path
    exit_code: int
    commit_count: int
    file_count: int
    timings: dict[str, float]
    comparisons: tuple[TimingComparison, ...]


def positive_int(raw_value: str) -> int:
    try:
        parsed = int(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def non_negative_float(raw_value: str) -> float:
    try:
        parsed = float(raw_value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be zero or a positive number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or a positive number")
    return parsed


def default_output_dir() -> Path:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    return REPO_ROOT / ".local-meta" / "benchmarks" / run_id


def run_command(cmd: list[str], *, cwd: Path) -> None:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}{suffix}")


def create_synthetic_history_repo(root: Path, *, commit_count: int, file_count: int) -> Path:
    if commit_count <= 0:
        raise ValueError("commit_count must be positive")
    if file_count <= 0:
        raise ValueError("file_count must be positive")

    repo = root / BENCHMARK_REPO_NAME
    if repo.exists():
        raise RuntimeError(f"benchmark repository already exists: {repo}")
    source_dir = repo / "src"
    source_dir.mkdir(parents=True)

    run_command(["git", "init", "--initial-branch", "main"], cwd=repo)
    run_command(["git", "config", "user.name", "Repo Privacy Benchmark"], cwd=repo)
    run_command(["git", "config", "user.email", rpg.DEFAULT_NOREPLY], cwd=repo)
    (repo / ".gitignore").write_text(rpg.render_ignore_baseline() + "\n", encoding="utf-8", newline="\n")

    for index in range(commit_count):
        target = source_dir / f"module_{index % file_count:03d}.txt"
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"commit={index:04d}; file={target.name}; value={index * 17}\n")
        add_targets = [".gitignore", "src"] if index == 0 else ["src"]
        run_command(["git", "add", *add_targets], cwd=repo)
        run_command(["git", "commit", "--quiet", "-m", f"benchmark commit {index:04d}"], cwd=repo)

    return repo


def as_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def flatten_performance(performance: Mapping[str, object]) -> dict[str, float]:
    timings: dict[str, float] = {}
    total_seconds = as_float(performance.get("total_seconds"))
    if total_seconds is not None:
        timings["total"] = total_seconds

    phases = performance.get("phases")
    if isinstance(phases, Mapping):
        for name, seconds in phases.items():
            parsed = as_float(seconds)
            if parsed is not None:
                timings[f"phase:{name}"] = parsed

    repositories = performance.get("repositories")
    if isinstance(repositories, Mapping):
        for repo_name, repo_timings in repositories.items():
            if not isinstance(repo_timings, Mapping):
                continue
            for phase, seconds in repo_timings.items():
                parsed = as_float(seconds)
                if parsed is not None:
                    timings[f"repo:{repo_name}:{phase}"] = parsed

    return dict(sorted(timings.items()))


def load_run_state_timings(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    performance = payload.get("performance") if isinstance(payload, dict) else None
    if not isinstance(performance, Mapping):
        raise ValueError(f"run_state.json has no performance object: {path}")
    return flatten_performance(performance)


def compare_timing_maps(
    current: Mapping[str, float],
    baseline: Mapping[str, float] | None,
    *,
    max_regression_percent: float | None,
) -> tuple[TimingComparison, ...]:
    if baseline is None:
        return tuple(
            TimingComparison(
                key=key,
                current_seconds=current[key],
                baseline_seconds=None,
                delta_seconds=None,
                delta_percent=None,
                exceeded_threshold=False,
            )
            for key in sorted(current)
        )

    comparisons: list[TimingComparison] = []
    for key in sorted(set(current) | set(baseline)):
        current_seconds = current.get(key, 0.0)
        baseline_seconds = baseline.get(key)
        delta_seconds: float | None = None
        delta_percent: float | None = None
        exceeded = False
        if baseline_seconds is not None:
            delta_seconds = current_seconds - baseline_seconds
            if baseline_seconds > 0:
                delta_percent = (delta_seconds / baseline_seconds) * 100
                if max_regression_percent is not None:
                    exceeded = delta_percent > max_regression_percent
        comparisons.append(
            TimingComparison(
                key=key,
                current_seconds=current_seconds,
                baseline_seconds=baseline_seconds,
                delta_seconds=delta_seconds,
                delta_percent=delta_percent,
                exceeded_threshold=exceeded,
            )
        )
    return tuple(comparisons)


def render_comparison(comparisons: tuple[TimingComparison, ...]) -> str:
    lines = ["Timing summary:"]
    for item in comparisons:
        if item.baseline_seconds is None:
            lines.append(f"- {item.key}: {item.current_seconds:.4f}s")
            continue
        delta = item.delta_seconds if item.delta_seconds is not None else 0.0
        if item.delta_percent is None:
            percent = "n/a"
        else:
            percent = f"{item.delta_percent:+.1f}%"
        marker = " REGRESSION" if item.exceeded_threshold else ""
        lines.append(
            f"- {item.key}: {item.current_seconds:.4f}s "
            f"(baseline {item.baseline_seconds:.4f}s, delta {delta:+.4f}s, {percent}){marker}"
        )
    return "\n".join(lines)


def benchmark_summary(result: BenchmarkResult) -> dict[str, object]:
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "commit_count": result.commit_count,
        "file_count": result.file_count,
        "exit_code": result.exit_code,
        "output_dir": str(result.output_dir),
        "repository": str(result.repository),
        "artifacts_dir": str(result.artifacts_dir),
        "run_state_path": str(result.run_state_path),
        "timings": result.timings,
        "comparisons": [asdict(item) for item in result.comparisons],
    }


def run_large_history_benchmark(
    *,
    output_dir: Path,
    commit_count: int,
    file_count: int,
    baseline_run_state: Path | None = None,
    max_regression_percent: float | None = None,
    verbose: bool = False,
) -> BenchmarkResult:
    if output_dir.exists():
        if not output_dir.is_dir():
            raise RuntimeError(f"benchmark output path must be a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise RuntimeError(f"benchmark output directory must be empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    workspace = output_dir / "workspace"
    artifacts_base = output_dir / "Audit_Results"
    workspace.mkdir()

    repo = create_synthetic_history_repo(workspace, commit_count=commit_count, file_count=file_count)
    artifacts = rpg.create_run_artifacts(artifacts_base)
    logger = rpg.RunLogger(artifacts.log_path, sink=print if verbose else None)
    logger(f"[BENCHMARK] synthetic commits: {commit_count}")
    logger(f"[BENCHMARK] synthetic files: {file_count}")

    config = rpg.GuardRunConfig(
        mode="benchmark",
        root=workspace,
        policy=REPO_ROOT / "docs" / "POLICY.md",
        repos=[BENCHMARK_REPO_NAME],
        public_only=False,
        fix=False,
        push=False,
        dry_run=True,
        redact_third_party_emails=False,
        purge_detected_secret_files=False,
        purge_all_detected_secret_files=False,
        rewrite_personal_paths=False,
        low_confidence_email_mode="informational",
        owner_name="Repo Privacy Benchmark",
        owner_emails=[],
        noreply_email=rpg.DEFAULT_NOREPLY,
        placeholder_email=rpg.DEFAULT_PLACEHOLDER,
        max_matches=25,
        open_report=False,
        confirm_each_repo_fix=True,
        allow_non_owner_push=False,
        allowed_remote_owners=[],
        replace_text_file=None,
        report_json=None,
    )
    exit_code = rpg.execute_guard_pipeline(
        config=config,
        artifacts=artifacts,
        logger=logger,
        results_dir=artifacts_base,
    )
    timings = load_run_state_timings(artifacts.state_path)
    baseline = load_run_state_timings(baseline_run_state) if baseline_run_state else None
    comparisons = compare_timing_maps(
        timings,
        baseline,
        max_regression_percent=max_regression_percent,
    )
    return BenchmarkResult(
        output_dir=output_dir,
        repository=repo,
        artifacts_dir=artifacts.run_dir,
        run_state_path=artifacts.state_path,
        exit_code=exit_code,
        commit_count=commit_count,
        file_count=file_count,
        timings=timings,
        comparisons=comparisons,
    )


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a synthetic Git repository with many commits, run the real "
            "audit pipeline, and summarize run_state.json timing metrics."
        )
    )
    parser.add_argument("--commits", type=positive_int, default=DEFAULT_COMMIT_COUNT)
    parser.add_argument("--files", type=positive_int, default=DEFAULT_FILE_COUNT)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--baseline-run-state", type=Path, default=None)
    parser.add_argument("--export-json", type=Path, default=None)
    parser.add_argument("--max-regression-percent", type=non_negative_float, default=None)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    output_dir = args.output_dir or default_output_dir()
    try:
        result = run_large_history_benchmark(
            output_dir=output_dir,
            commit_count=args.commits,
            file_count=args.files,
            baseline_run_state=args.baseline_run_state,
            max_regression_percent=args.max_regression_percent,
            verbose=args.verbose,
        )
    except Exception as exc:
        print(f"[BENCHMARK] ERROR: {exc}", file=sys.stderr)
        return 2

    print(f"[BENCHMARK] output: {result.output_dir}")
    print(f"[BENCHMARK] run_state: {result.run_state_path}")
    print(render_comparison(result.comparisons))
    if args.export_json:
        args.export_json.parent.mkdir(parents=True, exist_ok=True)
        args.export_json.write_text(
            json.dumps(benchmark_summary(result), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"[BENCHMARK] summary JSON: {args.export_json}")

    if result.exit_code != rpg.EXIT_OK:
        return result.exit_code
    if any(item.exceeded_threshold for item in result.comparisons):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
