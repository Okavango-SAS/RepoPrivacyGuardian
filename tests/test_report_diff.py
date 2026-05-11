from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any, NoReturn

import Repo_Privacy_Guardian as rpg


def _write_report(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _sample_before_report() -> list[dict[str, object]]:
    return [
        {
            "name": "RepoA",
            "status": "FAIL",
            "failures": ["tracked secret finding"],
            "tracked_secret_matches": [{"file": "app.py", "value": "<redacted-secret>"}],
            "exfil_code_indicators": ["network review"],
            "tracked_email_fixture_matches": ["fixture@example.test"],
        },
        {
            "name": "RemovedRepo",
            "status": "FAIL",
            "failures": ["old blocking finding"],
        },
    ]


def _sample_after_report() -> list[dict[str, object]]:
    return [
        {
            "name": "RepoA",
            "status": "PASS",
            "exfil_code_indicators": ["network review", "new outbound review"],
            "tracked_email_fixture_matches": ["fixture@example.test", "second-fixture@example.test"],
        },
        {
            "name": "NewRepo",
            "status": "FAIL",
            "tracked_secret_matches": ["new blocking finding"],
        },
    ]


def test_compare_report_payloads_counts_regressions_without_raw_evidence() -> None:
    diff = rpg.compare_report_payloads(
        _sample_before_report(),
        _sample_after_report(),
        before_label="old/report.json",
        after_label="new/report.json",
    )

    assert diff["schema_version"] == rpg.REPORT_DIFF_SCHEMA_VERSION
    assert diff["repositories"] == {
        "before": 2,
        "after": 2,
        "added": 1,
        "removed": 1,
        "unchanged": 1,
        "status_changed": 1,
    }
    totals = diff["totals"]
    assert isinstance(totals, dict)
    assert totals["blocking"] == {"before": 3, "after": 1, "resolved": 3, "added": 1, "unchanged": 0}
    assert totals["manual_review"] == {"before": 1, "after": 2, "resolved": 0, "added": 1, "unchanged": 1}
    assert totals["fixture_documentation"] == {"before": 1, "after": 2, "resolved": 0, "added": 1, "unchanged": 1}

    summary = rpg.format_report_diff_summary(diff)
    assert "Report diff: old/report.json -> new/report.json" in summary
    assert "blocking: 3 -> 1 (resolved 3, added 1, unchanged 0)" in summary
    assert "blocking.tracked_secret_matches" in summary
    assert "tracked secret finding" not in summary
    assert "<redacted-secret>" not in summary
    assert "new outbound review" not in summary


def test_cli_compare_reports_bypasses_audit_and_can_export_json(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    before_path = tmp_path / "Audit_Results" / "20260101-000000" / "report.json"
    after_path = tmp_path / "Audit_Results" / "20260102-000000" / "report.json"
    diff_path = tmp_path / "diff.json"
    _write_report(before_path, _sample_before_report())
    _write_report(after_path, _sample_after_report())

    def fail_if_audit_config_is_built(_args: Any) -> NoReturn:
        raise AssertionError("comparison mode must not build an audit config")

    monkeypatch.setattr(rpg, "build_cli_guard_run_config", fail_if_audit_config_is_built)

    exit_code = rpg.main(
        [
            "--compare-reports",
            str(before_path),
            str(after_path),
            "--report-json",
            str(diff_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == rpg.EXIT_OK
    assert "Report diff:" in captured.out
    assert "[INFO] Report comparison JSON written" in captured.out
    assert "Run artifacts directory" not in captured.out
    exported = json.loads(diff_path.read_text(encoding="utf-8"))
    assert exported["totals"]["blocking"]["added"] == 1


def test_find_previous_report_json_selects_latest_prior_run(tmp_path: Path) -> None:
    results_dir = tmp_path / "Audit_Results"
    oldest = results_dir / "20260101-000000" / "report.json"
    previous = results_dir / "20260102-000000" / "report.json"
    current = results_dir / "20260103-000000" / "report.json"
    for index, path in enumerate((oldest, previous, current), start=1):
        _write_report(path, [])
        os.utime(path, (index, index))

    assert rpg.find_previous_report_json(current) == previous.resolve()


def test_gui_compare_previous_report_copies_count_only_summary(tmp_path: Path) -> None:
    results_dir = tmp_path / "Audit_Results"
    previous_path = results_dir / "20260101-000000" / "report.json"
    current_path = results_dir / "20260102-000000" / "report.json"
    _write_report(previous_path, _sample_before_report())
    _write_report(current_path, _sample_after_report())
    artifacts = rpg.RunArtifacts(
        run_id="20260102-000000",
        run_dir=current_path.parent,
        json_path=current_path,
        log_path=current_path.parent / "run.log",
        html_path=current_path.parent / "report.html",
        state_path=current_path.parent / "run_state.json",
        started_at=datetime(2026, 1, 2),
    )
    app = object.__new__(rpg.GuiApp)
    app._last_run_artifacts = artifacts
    logs: list[str] = []
    copied: dict[str, str] = {}

    def translate(key: str, **kwargs: object) -> str:
        messages = {
            "latest_artifacts_none": "none",
            "report_diff_no_previous": "no previous",
            "report_diff_failed": "failed: {error}",
            "report_diff_copied": "copied",
        }
        return messages.get(key, key).format(**kwargs)

    app._t = translate
    app.log = logs.append
    app._artifact_handoff_path = lambda path: f"{Path(path).parent.name}/{Path(path).name}"
    app._copy_text_to_clipboard = lambda text, message: copied.update({"text": text, "message": message})

    rpg.GuiApp._compare_previous_report_to_latest(app)

    assert copied["message"] == "copied"
    assert copied["text"].startswith("Report diff: 20260101-000000/report.json -> 20260102-000000/report.json")
    assert any(line.startswith("blocking:") for line in logs)
    assert "tracked secret finding" not in copied["text"]
    assert "new outbound review" not in copied["text"]
