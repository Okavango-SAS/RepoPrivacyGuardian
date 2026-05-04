from __future__ import annotations

import json
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, TypeVar


RUN_ARTIFACT_COLLISION_ATTEMPTS = 1000


@dataclass
class RunArtifacts:
    run_id: str
    run_dir: Path
    json_path: Path
    log_path: Path
    html_path: Path
    state_path: Path
    started_at: datetime
    agent_summary_path: Path | None = None

    def __post_init__(self) -> None:
        if self.agent_summary_path is None:
            self.agent_summary_path = self.run_dir / "agent_summary.json"


ReportT = TypeVar("ReportT")


class RunLogger:
    def __init__(
        self,
        log_path: Path,
        sink: Callable[[str], None] | None = None,
        *,
        ensure_private_directory: Callable[[Path], None],
        write_private_text_file: Callable[[Path, str], None],
        append_private_text_file: Callable[[Path, str], None],
        redact_sensitive_text: Callable[[str], str],
        stdout: object | None = None,
        now_factory: Callable[[], datetime] = datetime.now,
    ) -> None:
        self.log_path = log_path
        self.sink = sink
        self._lock = threading.Lock()
        self._append_private_text_file = append_private_text_file
        self._redact_sensitive_text = redact_sensitive_text
        self._stdout = stdout if stdout is not None else sys.stdout
        self._now_factory = now_factory
        ensure_private_directory(self.log_path.parent)
        write_private_text_file(self.log_path, "")

    def __call__(self, msg: str) -> None:
        text = self._redact_sensitive_text(str(msg))
        with self._lock:
            if self.sink:
                try:
                    self.sink(text)
                except UnicodeEncodeError:
                    encoding = getattr(self._stdout, "encoding", None) or "utf-8"
                    safe_text = text.encode(encoding, errors="replace").decode(
                        encoding,
                        errors="replace",
                    )
                    try:
                        self.sink(safe_text)
                    except Exception:
                        pass
                except Exception:
                    pass
            stamp = self._now_factory().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{stamp}] {text}\n"
            self._append_private_text_file(self.log_path, line)


class RunStateTracker:
    def __init__(
        self,
        path: Path,
        *,
        run_id: str,
        started_at: datetime,
        mode: str,
        root: Path,
        policy: Path,
        requested_repositories: list[str],
        pid: int,
        write_private_json_file: Callable[[Path, dict[str, object]], None],
        now_factory: Callable[[], datetime] = datetime.now,
    ) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._write_private_json_file = write_private_json_file
        self._now_factory = now_factory
        started_iso = started_at.isoformat(timespec="seconds")
        self._state: dict[str, object] = {
            "status": "running",
            "phase": "starting",
            "run_id": run_id,
            "started_at": started_iso,
            "last_update": started_iso,
            "mode": mode,
            "pid": pid,
            "root": str(root),
            "policy": str(policy),
            "requested_repositories": requested_repositories,
            "completed_repositories": 0,
            "total_repositories": 0,
            "current_repository": "",
            "exit_code": None,
        }
        self.update()

    def update(self, **fields: object) -> None:
        with self._lock:
            if fields:
                self._state.update(fields)
            self._state["last_update"] = self._now_factory().isoformat(timespec="seconds")
            self._write_private_json_file(self.path, self._state)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return dict(self._state)


def create_run_artifacts(
    base_dir: Path,
    *,
    ensure_private_directory: Callable[[Path], None],
    path_has_existing_symlink_ancestor: Callable[[Path], bool],
    apply_private_permissions: Callable[[Path, int], None],
    run_state_filename: str,
    now_factory: Callable[[], datetime] = datetime.now,
    max_collision_attempts: int = RUN_ARTIFACT_COLLISION_ATTEMPTS,
) -> RunArtifacts:
    if max_collision_attempts <= 0:
        raise ValueError("max_collision_attempts must be positive")

    ensure_private_directory(base_dir)
    stamp = now_factory().strftime("%Y%m%d-%H%M%S")
    run_dir: Path | None = None
    for suffix in range(max_collision_attempts):
        run_name = stamp if suffix == 0 else f"{stamp}-{suffix:02d}"
        candidate = base_dir / run_name
        if path_has_existing_symlink_ancestor(candidate):
            raise RuntimeError(f"Refusing to create run artifacts under symlinked path: {candidate}")
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            run_dir = candidate
            break
        except FileExistsError:
            continue
    if run_dir is None:
        raise RuntimeError(
            f"Unable to create unique run artifacts directory after {max_collision_attempts} attempts under {base_dir}"
        )

    apply_private_permissions(run_dir, 0o700)
    started = now_factory()
    return RunArtifacts(
        run_id=run_dir.name,
        run_dir=run_dir,
        json_path=run_dir / "report.json",
        log_path=run_dir / "run.log",
        html_path=run_dir / "report.html",
        state_path=run_dir / run_state_filename,
        started_at=started,
        agent_summary_path=run_dir / "agent_summary.json",
    )


def resolve_optional_json_export_path(
    raw_value: str | None,
    default_name: str,
    *,
    ensure_private_directory: Callable[[Path], None],
) -> Path | None:
    if not raw_value:
        return None
    raw = Path(raw_value)
    raw_text = str(raw_value)
    if raw_text.endswith("/") or raw_text.endswith("\\") or (raw.exists() and raw.is_dir()):
        ensure_private_directory(raw)
        return raw / default_name
    if raw.suffix.lower() != ".json":
        ensure_private_directory(raw)
        return raw / default_name
    ensure_private_directory(raw.parent)
    return raw


def persist_run_outputs(
    reports: list[ReportT],
    artifacts: RunArtifacts,
    root_path: Path,
    policy_path: Path,
    run_settings: dict[str, str],
    logger: Callable[[str], None],
    *,
    sanitize_report_for_export: Callable[[ReportT], dict[str, object]],
    render_html_report: Callable[..., str],
    write_private_text_file: Callable[[Path, str], None],
    report_contains_sensitive_findings: Callable[[ReportT], bool],
    resolve_optional_json_export_path: Callable[[str | None, str], Path | None],
    optional_json_export: str | None = None,
    optional_supply_chain_payload: dict[str, object] | None = None,
    now_factory: Callable[[], datetime] = datetime.now,
) -> None:
    finished_at = now_factory()
    payload = [sanitize_report_for_export(rep) for rep in reports]
    payload_json = json.dumps(payload, indent=2)
    write_private_text_file(artifacts.json_path, payload_json)
    logger(f"[INFO] JSON report written to {artifacts.json_path}")

    html_report = render_html_report(
        reports=reports,
        artifacts=artifacts,
        root_path=root_path,
        policy_path=policy_path,
        run_settings=run_settings,
        finished_at=finished_at,
        optional_supply_chain_payload=optional_supply_chain_payload,
    )
    write_private_text_file(artifacts.html_path, html_report)
    logger(f"[INFO] HTML report written to {artifacts.html_path}")
    logger(f"[INFO] LOG report written to {artifacts.log_path}")

    export_path = resolve_optional_json_export_path(optional_json_export, artifacts.json_path.name)
    if export_path:
        write_private_text_file(export_path, payload_json)
        logger(f"[INFO] Extra JSON export written to {export_path}")

    if any(report_contains_sensitive_findings(rep) for rep in reports):
        logger(
            "[WARN] Sensitive findings were detected in this run. "
            "After review, consider deleting the run folder in Audit_Results/ to avoid retaining recovered context."
        )
