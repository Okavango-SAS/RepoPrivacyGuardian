# ENGINEERING DECISIONS

This file captures key design decisions and their rationale.

## DEC-001 - Dual interface (CLI + GUI)

- Status: accepted
- Decision: provide both CLI and simple desktop GUI.
- Rationale: CLI is better for automation; GUI lowers adoption barrier for manual operators.

## DEC-002 - JSON report as source of truth

- Status: accepted
- Decision: every run writes a machine-readable JSON report.
- Rationale: enables reproducibility, post-processing, and audit trail.

## DEC-003 - Explicit risk gates for destructive actions

- Status: accepted
- Decision: history rewrites and broad purges require explicit flags.
- Rationale: minimizes accidental destructive operations.

## DEC-004 - Conservative secret auto-purge policy

- Status: accepted
- Decision: auto-purge only safe filename candidates by default.
- Rationale: reduces risk of deleting legitimate files with ambiguous names.

## DEC-005 - Local policy and local output defaults

- Status: accepted
- Decision: default policy path points to docs/POLICY.md and default outputs to local Audit_Results.
- Rationale: self-contained repo behavior and fewer environment-specific assumptions.

## DEC-006 - Keep backups as first-class fix step

- Status: accepted
- Decision: create bundle backup before any rewrite/fix operation.
- Rationale: guarantees rollback option even in disconnected scenarios.

## DEC-007 - GUI/CLI parity through a shared execution pipeline

- Status: accepted
- Decision: move GUI and CLI runtime to a single shared pipeline function and keep run settings symmetric across interfaces.
- Rationale: removes duplicated flow logic and prevents future feature drift.

### Parity matrix (before)

| Capability | CLI | GUI | Gap |
| --- | --- | --- | --- |
| Audit/fix flow and re-audit | Yes | Yes | No |
| Dry-run behavior | Yes | Yes | No |
| Secret purge flags | Yes | Yes | Minor (different warning text path) |
| Report artifacts JSON/LOG/HTML | Yes | Yes | No |
| `public_only` default | False | True | Yes |
| Repo scope when filters are omitted | All repos under root | Required explicit selection | Yes |
| `max_matches` configurability | Yes (`--max-matches`) | No (fixed at 50) | Yes |
| Extra JSON export | Yes (`--report-json`) | No | Yes |
| Report output directory selection | Yes (`--report-dir`) | No | Yes |
| Runtime pipeline implementation | Dedicated CLI code path | Dedicated GUI code path | Yes |

### Parity matrix (after)

| Capability | CLI | GUI | Gap |
| --- | --- | --- | --- |
| Audit/fix flow and re-audit | Yes | Yes | No |
| Dry-run behavior | Yes | Yes | No |
| Secret purge flags | Yes | Yes | No |
| Report artifacts JSON/LOG/HTML | Yes | Yes | No |
| `public_only` default | False | False | No |
| Repo scope when filters are omitted | All repos under root | All repos under root (with explicit confirmation) | No |
| `max_matches` configurability | Yes | Yes | No |
| Extra JSON export | Yes | Yes | No |
| Report output directory selection | Yes | Yes | No |
| Runtime pipeline implementation | Shared | Shared | No |

### Implementation summary

- Added `GuardRunConfig` and `execute_guard_pipeline()` as the canonical execution path for both interfaces.
- Added `build_run_settings()` to normalize persisted run metadata.
- Added `parse_positive_int()` so GUI and CLI validate `max_matches` with the same rule.
- Extended GUI inputs with:
  - results directory
  - optional extra JSON export path
  - max matches
- Aligned GUI `public_only` default with CLI default.
- Aligned GUI repository scope behavior with CLI: if no repository filter is provided, run all repositories under root after explicit confirmation.
- Added parity regression tests for argument validation, defaults, confirmation gate, fix/re-audit flow, and runtime error handling.

### Residual risk and follow-up

- GUI still depends on Tkinter widgets and thread scheduling; functional behavior is aligned but direct widget-level tests remain out of scope.
- Keep parity tests mandatory on every change touching parser flags or execution flow.

## Future candidates

- DEC-008: scoped allowlists to reduce false positives.
- DEC-009: optional HTML report renderer.
- DEC-010: policy profiles by organization.
