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

## Future candidates

- DEC-007: scoped allowlists to reduce false positives.
- DEC-008: optional HTML report renderer.
- DEC-009: policy profiles by organization.
