from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from repo_privacy_guardian import agent_summary


REPORT_DIFF_SCHEMA_VERSION = 1

REPORT_DIFF_CATEGORY_GROUPS: dict[str, tuple[str, ...]] = {
    "blocking": agent_summary.BLOCKING_CATEGORY_KEYS,
    "manual_review": agent_summary.MANUAL_REVIEW_CATEGORY_KEYS,
    "fixture_documentation": agent_summary.FIXTURE_DOCUMENTATION_CATEGORY_KEYS,
    "accepted_risk": agent_summary.ACCEPTED_RISK_CATEGORY_KEYS,
}


def _safe_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _safe_text(value: object) -> str:
    return str(value).strip() if isinstance(value, str) and value.strip() else ""


def _json_fingerprint(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _category_fingerprints(report: dict[str, object], category: str) -> set[str]:
    return {_json_fingerprint(item) for item in _safe_list(report.get(category))}


def _status(report: dict[str, object] | None) -> str:
    if report is None:
        return ""
    return _safe_text(report.get("status")) or "PASS"


def _repo_key(report: dict[str, object], index: int) -> str:
    name = _safe_text(report.get("name"))
    if name:
        return f"name:{name.casefold()}"
    path = _safe_text(report.get("path"))
    if path:
        return f"path:{_json_fingerprint(path)}"
    return f"index:{index}"


def _repo_label(report: dict[str, object], index: int) -> str:
    return _safe_text(report.get("name")) or f"repository #{index + 1}"


def _report_map(reports: Iterable[dict[str, object]]) -> dict[str, dict[str, object]]:
    mapped: dict[str, dict[str, object]] = {}
    collisions: dict[str, int] = {}
    for index, report in enumerate(reports):
        base_key = _repo_key(report, index)
        collision = collisions.get(base_key, 0)
        collisions[base_key] = collision + 1
        key = base_key if collision == 0 else f"{base_key}#{collision + 1}"
        mapped[key] = {
            "label": _repo_label(report, index),
            "index": index,
            "report": report,
        }
    return mapped


def _empty_delta() -> dict[str, int]:
    return {
        "before": 0,
        "after": 0,
        "resolved": 0,
        "added": 0,
        "unchanged": 0,
    }


def _merge_counts(target: dict[str, int], delta: dict[str, int]) -> None:
    for key in ("before", "after", "resolved", "added", "unchanged"):
        target[key] = target.get(key, 0) + delta.get(key, 0)


def _category_delta(
    before_report: dict[str, object] | None,
    after_report: dict[str, object] | None,
    category: str,
) -> dict[str, int]:
    before_items = _category_fingerprints(before_report, category) if before_report is not None else set()
    after_items = _category_fingerprints(after_report, category) if after_report is not None else set()
    return {
        "before": len(before_items),
        "after": len(after_items),
        "resolved": len(before_items - after_items),
        "added": len(after_items - before_items),
        "unchanged": len(before_items & after_items),
    }


def _next_action(totals: dict[str, dict[str, int]]) -> str:
    blocking = totals.get("blocking", _empty_delta())
    manual = totals.get("manual_review", _empty_delta())
    if blocking.get("added", 0) > 0:
        return "Review newly added blocking findings before publication, then re-run until the diff shows no blocking additions."
    if blocking.get("after", 0) > 0:
        return "Blocking findings remain after the latest run; review report.html/report.json and authorize only reviewed fixes."
    if manual.get("added", 0) > 0:
        return "Classify newly added manual-review findings before publication."
    if manual.get("after", 0) > 0:
        return "Manual-review findings remain; classify them as fixture/documentation, false positive, accepted risk, or issue."
    if blocking.get("resolved", 0) > 0 or manual.get("resolved", 0) > 0:
        return "No blocking or manual-review regressions are present in this comparison."
    return "No blocking or manual-review change is present in this comparison."


def _normalize_report_payload(payload: object) -> list[dict[str, object]]:
    if isinstance(payload, list):
        reports = payload
    elif isinstance(payload, dict):
        nested = payload.get("reports")
        if isinstance(nested, list):
            reports = nested
        else:
            reports = [payload]
    else:
        raise ValueError("report JSON must contain a report object, a reports list, or a list of reports")
    normalized: list[dict[str, object]] = []
    for index, item in enumerate(reports):
        if not isinstance(item, dict):
            raise ValueError(f"report entry {index + 1} is not a JSON object")
        normalized.append(dict(item))
    return normalized


def load_report_json(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return _normalize_report_payload(payload)


def report_path_label(path: Path) -> str:
    if path.name == "report.json" and path.parent.name:
        return f"{path.parent.name}/report.json"
    return path.name


def compare_report_payloads(
    before_reports: list[dict[str, object]],
    after_reports: list[dict[str, object]],
    *,
    before_label: str = "before",
    after_label: str = "after",
) -> dict[str, object]:
    before_by_key = _report_map(before_reports)
    after_by_key = _report_map(after_reports)
    all_keys = sorted(before_by_key.keys() | after_by_key.keys())
    totals: dict[str, dict[str, int]] = {
        group: _empty_delta()
        for group in REPORT_DIFF_CATEGORY_GROUPS
    }
    category_totals: dict[str, dict[str, int]] = {}
    repositories: list[dict[str, object]] = []
    added_repositories = 0
    removed_repositories = 0
    status_changed = 0

    for key in all_keys:
        before_entry = before_by_key.get(key)
        after_entry = after_by_key.get(key)
        before_report = before_entry["report"] if before_entry is not None else None
        after_report = after_entry["report"] if after_entry is not None else None
        if not isinstance(before_report, dict):
            before_report = None
        if not isinstance(after_report, dict):
            after_report = None
        if before_entry is None:
            added_repositories += 1
        if after_entry is None:
            removed_repositories += 1
        before_status = _status(before_report)
        after_status = _status(after_report)
        changed_status = before_entry is not None and after_entry is not None and before_status != after_status
        if changed_status:
            status_changed += 1
        label_entry = after_entry if after_entry is not None else before_entry
        repo_label = str(label_entry.get("label", key)) if label_entry is not None else key
        repo_groups: dict[str, dict[str, dict[str, int]]] = {}

        for group, categories in REPORT_DIFF_CATEGORY_GROUPS.items():
            group_total = _empty_delta()
            group_categories: dict[str, dict[str, int]] = {}
            for category in categories:
                delta = _category_delta(before_report, after_report, category)
                if any(delta.values()):
                    group_categories[category] = delta
                    category_total = category_totals.setdefault(f"{group}.{category}", _empty_delta())
                    _merge_counts(category_total, delta)
                _merge_counts(group_total, delta)
            _merge_counts(totals[group], group_total)
            if group_categories:
                repo_groups[group] = group_categories

        if changed_status or repo_groups:
            repositories.append(
                {
                    "name": repo_label,
                    "before_status": before_status or None,
                    "after_status": after_status or None,
                    "status_changed": changed_status,
                    "categories": repo_groups,
                }
            )

    return {
        "schema_version": REPORT_DIFF_SCHEMA_VERSION,
        "before": {
            "label": before_label,
            "repository_count": len(before_reports),
        },
        "after": {
            "label": after_label,
            "repository_count": len(after_reports),
        },
        "repositories": {
            "before": len(before_reports),
            "after": len(after_reports),
            "added": added_repositories,
            "removed": removed_repositories,
            "unchanged": len(all_keys) - added_repositories - removed_repositories,
            "status_changed": status_changed,
        },
        "totals": totals,
        "category_totals": category_totals,
        "changed_repositories": repositories,
        "next_action": _next_action(totals),
    }


def compare_report_files(
    before_path: Path,
    after_path: Path,
    *,
    before_label: str | None = None,
    after_label: str | None = None,
) -> dict[str, object]:
    return compare_report_payloads(
        load_report_json(before_path),
        load_report_json(after_path),
        before_label=before_label or report_path_label(before_path),
        after_label=after_label or report_path_label(after_path),
    )


def find_previous_report_json(current_report_path: Path) -> Path | None:
    current = current_report_path.resolve()
    current_run_dir = current.parent
    results_dir = current_run_dir.parent
    if not results_dir.exists():
        return None

    candidates: list[tuple[float, str, Path]] = []
    for candidate in results_dir.glob("*/report.json"):
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved == current or not resolved.is_file():
            continue
        try:
            mtime = resolved.stat().st_mtime
        except OSError:
            continue
        candidates.append((mtime, candidate.parent.name, resolved))
    if not candidates:
        return None

    try:
        current_mtime = current.stat().st_mtime
    except OSError:
        current_mtime = float("inf")
    older_candidates = [item for item in candidates if item[0] <= current_mtime or item[1] < current_run_dir.name]
    selected = max(older_candidates or candidates, key=lambda item: (item[0], item[1]))
    return selected[2]


def _format_delta(delta: dict[str, int]) -> str:
    return (
        f"{delta.get('before', 0)} -> {delta.get('after', 0)} "
        f"(resolved {delta.get('resolved', 0)}, added {delta.get('added', 0)}, "
        f"unchanged {delta.get('unchanged', 0)})"
    )


def _object_dict(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _int_delta(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return _empty_delta()
    delta = _empty_delta()
    for key in delta:
        raw_value = value.get(key)
        delta[key] = raw_value if isinstance(raw_value, int) else 0
    return delta


def format_report_diff_summary(diff: dict[str, object]) -> str:
    before = _object_dict(diff.get("before"))
    after = _object_dict(diff.get("after"))
    repo_counts = _object_dict(diff.get("repositories"))
    totals = _object_dict(diff.get("totals"))
    category_totals = _object_dict(diff.get("category_totals"))
    lines = [
        f"Report diff: {before.get('label', 'before')} -> {after.get('label', 'after')}",
        (
            "Repositories: "
            f"{repo_counts.get('before', 0)} -> {repo_counts.get('after', 0)} "
            f"(added {repo_counts.get('added', 0)}, removed {repo_counts.get('removed', 0)}, "
            f"unchanged {repo_counts.get('unchanged', 0)}, status changed {repo_counts.get('status_changed', 0)})"
        ),
    ]
    for group in ("blocking", "manual_review", "fixture_documentation", "accepted_risk"):
        delta = _int_delta(totals.get(group))
        lines.append(f"{group}: {_format_delta(delta)}")

    changed_categories: list[tuple[str, dict[str, int]]] = []
    for key, value in category_totals.items():
        if isinstance(key, str) and isinstance(value, dict):
            typed_value = _int_delta(value)
            if typed_value.get("resolved", 0) or typed_value.get("added", 0):
                changed_categories.append((key, typed_value))
    changed_categories.sort(key=lambda item: (item[1].get("added", 0), item[1].get("resolved", 0), item[0]), reverse=True)
    if changed_categories:
        lines.append("Changed categories:")
        for key, delta in changed_categories[:10]:
            lines.append(f"- {key}: {_format_delta(delta)}")

    next_action = diff.get("next_action")
    lines.append(f"Next action: {next_action if isinstance(next_action, str) else 'Review report artifacts.'}")
    return "\n".join(lines)
