"""Publication guidance shared by reports, agent handoffs, and GUI state.

Policy success alone cannot establish that the selected audit completed.  This
module deliberately accepts only numeric and categorical execution context, so
guidance never carries diagnostic output or detected values.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


def _count(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


@dataclass(frozen=True)
class RunDecision:
    status: str
    completion: str
    reason: str
    next_action: str
    phase: str
    total_repositories: int | None
    completed_repositories: int | None

    def completion_context(self) -> dict[str, object]:
        return {
            "completion": self.completion,
            "decision_reason": self.reason,
            "phase": self.phase,
            "total_repositories": self.total_repositories,
            "completed_repositories": self.completed_repositories,
        }


def evaluate_run_decision(
    *,
    exit_code: int | None = None,
    policy_failed: bool = False,
    execution_error_count: int = 0,
    blocking_count: int = 0,
    manual_review_count: int = 0,
    available_repositories: int | None = None,
    run_context: Mapping[str, object] | None = None,
) -> RunDecision:
    """Require explicit completion evidence before returning PASS.

Missing context is a supported legacy input, with unknown completion. Failure
signals remain authoritative even when evidence is empty or incomplete.
"""
    context = run_context or {}
    raw_phase = context.get("phase")
    # Do not reflect arbitrary strings from a legacy artifact into guidance.
    known_phases = {"starting", "discovering", "auditing", "repairing", "persisting", "finished"}
    phase = raw_phase if isinstance(raw_phase, str) and raw_phase in known_phases else "unknown"
    total = _count(context.get("total_repositories"))
    completed = _count(context.get("completed_repositories"))
    available = _count(available_repositories)
    if completed is not None and available is not None:
        completed = min(completed, available)
    if exit_code == 1:
        completion = "aborted"
    elif phase == "finished" and total is not None and total > 0 and completed is not None and completed >= total:
        completion = "complete"
    elif total == 0 or phase != "unknown" or (total is not None and completed is not None and completed < total):
        completion = "incomplete"
    else:
        completion = "unknown"

    runtime_errors = execution_error_count + (_count(context.get("execution_error_count")) or 0)
    if exit_code == 3 or runtime_errors:
        status, reason = "FAIL", "runtime_error"
        action = "Resolve the runtime/tooling or artifact error, then re-run the audit before publication."
    elif exit_code == 2 or policy_failed or context.get("policy_failed") is True or blocking_count:
        status, reason = "FAIL", "policy_failure"
        action = (
            "Review blocking categories in report.json/report.html, authorize only reviewed fixes, "
            "then re-run until PASS."
        )
    elif exit_code == 1:
        status, reason = "REVIEW", "aborted"
        action = "The run was aborted. Review partial artifacts and re-run all selected targets before publication."
    elif completion != "complete" or exit_code != 0:
        status, reason = "REVIEW", "incomplete"
        action = "Completion is incomplete or unknown. Review run_state.json and re-run all selected targets before publication."
    elif manual_review_count:
        status, reason = "REVIEW", "advisory"
        action = (
            "Classify advisory/manual-review findings as confirmed leak, fixture/documentation, "
            "false positive, or accepted risk before publication."
        )
    else:
        status, reason = "PASS", "complete"
        action = "No blocking or advisory action is required by the current policy."
    return RunDecision(status, completion, reason, action, phase, total, completed)
