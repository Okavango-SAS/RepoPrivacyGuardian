from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


AGENT_SUMMARY_SCHEMA_VERSION = 1

BLOCKING_CATEGORY_KEYS = (
    "failures",
    "tracked_secret_matches",
    "tracked_secret_high_confidence",
    "history_secret_matches",
    "history_secret_high_confidence",
    "git_metadata_secret_matches",
    "tracked_path_matches",
    "history_path_matches",
    "tracked_email_high_confidence",
    "history_email_high_confidence",
    "history_sensitive_added",
    "history_sensitive_deleted",
    "tracked_but_ignored",
    "gitignore_missing_patterns",
    "fix_errors",
    "execution_errors",
)

MANUAL_REVIEW_CATEGORY_KEYS = (
    "tracked_secret_low_confidence",
    "history_secret_low_confidence",
    "git_metadata_secret_low_confidence",
    "tracked_email_low_confidence",
    "history_email_low_confidence",
    "exfil_code_indicators",
    "github_hardening_findings",
    "github_hardening_warnings",
    "secret_file_manual_review_candidates",
)

FIXTURE_DOCUMENTATION_CATEGORY_KEYS = (
    "tracked_secret_fixture_matches",
    "history_secret_fixture_matches",
    "tracked_secret_documentation_matches",
    "history_secret_documentation_matches",
    "tracked_email_fixture_matches",
    "history_email_fixture_matches",
    "reviewed_network_indicators",
)


def _safe_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _count_keys(payload: dict[str, object], keys: tuple[str, ...]) -> int:
    return sum(len(_safe_list(payload.get(key))) for key in keys)


def _category_counts(payload: dict[str, object], keys: tuple[str, ...]) -> dict[str, int]:
    return {
        key: len(_safe_list(payload.get(key)))
        for key in keys
        if len(_safe_list(payload.get(key))) > 0
    }


def _decision_from_counts(blocking_count: int, manual_review_count: int) -> str:
    if blocking_count:
        return "FAIL"
    if manual_review_count:
        return "REVIEW"
    return "PASS"


def _next_action(decision: str) -> str:
    if decision == "FAIL":
        return (
            "Review blocking categories in report.json/report.html, authorize only reviewed fixes, "
            "then re-run until PASS."
        )
    if decision == "REVIEW":
        return (
            "Classify advisory/manual-review findings as confirmed leak, fixture/documentation, "
            "false positive, or accepted risk before publication."
        )
    return "No blocking or advisory action is required by the current policy."


def build_agent_summary(
    *,
    reports_payload: list[dict[str, object]],
    artifacts: Any,
    root_path: Path,
    policy_path: Path,
    run_settings: dict[str, str],
    exit_code: int | None = None,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    generated = generated_at or datetime.now()
    repositories: list[dict[str, object]] = []
    total_blocking = 0
    total_manual_review = 0
    total_fixture_documentation = 0
    total_suppressed = 0

    for report in reports_payload:
        blocking_count = _count_keys(report, BLOCKING_CATEGORY_KEYS)
        manual_review_count = _count_keys(report, MANUAL_REVIEW_CATEGORY_KEYS)
        fixture_documentation_count = _count_keys(report, FIXTURE_DOCUMENTATION_CATEGORY_KEYS)
        suppressed_count = len(_safe_list(report.get("suppressed_findings")))
        total_blocking += blocking_count
        total_manual_review += manual_review_count
        total_fixture_documentation += fixture_documentation_count
        total_suppressed += suppressed_count
        decision = _decision_from_counts(blocking_count, manual_review_count)
        repositories.append(
            {
                "name": str(report.get("name", "")),
                "status": str(report.get("status", "PASS")),
                "decision": decision,
                "blocking_count": blocking_count,
                "manual_review_count": manual_review_count,
                "fixture_documentation_count": fixture_documentation_count,
                "suppressed_count": suppressed_count,
                "blocking_categories": _category_counts(report, BLOCKING_CATEGORY_KEYS),
                "manual_review_categories": _category_counts(report, MANUAL_REVIEW_CATEGORY_KEYS),
                "fixture_documentation_categories": _category_counts(
                    report,
                    FIXTURE_DOCUMENTATION_CATEGORY_KEYS,
                ),
                "failure_reasons": _safe_list(report.get("failures")),
                "next_action": _next_action(decision),
            }
        )

    failed = sum(1 for report in reports_payload if report.get("status") == "FAIL")
    passed = len(reports_payload) - failed
    overall_decision = _decision_from_counts(total_blocking, total_manual_review)

    return {
        "schema_version": AGENT_SUMMARY_SCHEMA_VERSION,
        "generated_at": generated.isoformat(timespec="seconds"),
        "run_id": getattr(artifacts, "run_id", ""),
        "status": overall_decision,
        "exit_code": exit_code,
        "counts": {
            "repositories": len(reports_payload),
            "pass": passed,
            "fail": failed,
            "blocking_findings": total_blocking,
            "manual_review_findings": total_manual_review,
            "fixture_documentation_findings": total_fixture_documentation,
            "suppressed_findings": total_suppressed,
        },
        "artifacts": {
            "run_dir": ".",
            "agent_summary": "agent_summary.json",
            "report_json": "report.json",
            "report_html": "report.html",
            "run_log": "run.log",
            "run_state": Path(getattr(artifacts, "state_path", "run_state.json")).name,
        },
        "run_context": {
            "root": str(root_path),
            "policy": str(policy_path),
            "mode": run_settings.get("mode", ""),
            "strict_profile": run_settings.get("strict_profile", ""),
            "dry_run": run_settings.get("dry_run", ""),
            "fix": run_settings.get("fix", ""),
            "push": run_settings.get("push", ""),
        },
        "repositories": repositories,
        "next_action": _next_action(overall_decision),
    }


def format_agent_summary_handoff(summary: dict[str, object]) -> str:
    raw_counts = summary.get("counts")
    counts: dict[str, object] = raw_counts if isinstance(raw_counts, dict) else {}
    raw_artifacts = summary.get("artifacts")
    artifacts: dict[str, object] = raw_artifacts if isinstance(raw_artifacts, dict) else {}
    return "\n".join(
        [
            "[AGENT-SUMMARY]",
            f"status: {summary.get('status', 'UNKNOWN')}",
            f"repositories: {counts.get('repositories', 0)}",
            f"blocking_findings: {counts.get('blocking_findings', 0)}",
            f"manual_review_findings: {counts.get('manual_review_findings', 0)}",
            f"suppressed_findings: {counts.get('suppressed_findings', 0)}",
            f"next_action: {summary.get('next_action', '')}",
            "artifacts: "
            f"{artifacts.get('agent_summary', 'agent_summary.json')}, "
            f"{artifacts.get('report_json', 'report.json')}, "
            f"{artifacts.get('report_html', 'report.html')}, "
            f"{artifacts.get('run_log', 'run.log')}",
        ]
    )
