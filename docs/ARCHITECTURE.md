# ARCHITECTURE

## Overview

Repo Privacy Guardian is a local-first auditing and remediation utility.

It has two execution surfaces:
- CLI entrypoint for scripted and repeatable runs.
- Simple GUI wrapper for interactive operation.

## Main components

1. Repository discovery
- Enumerates git repositories under a root path.
- Supports explicit repo filters.

2. Audit engine
- Scans tracked content and history patches.
- Detects secret patterns, personal paths, email leakage, and ignore drift.
- Produces normalized report model per repository.

3. Remediation planner
- Converts findings into actionable fix candidates.
- Classifies secret file candidates into safe auto-purge and manual review.

4. Fix executor
- Applies selected remediations:
  - .gitignore updates
  - stop tracking ignored/sensitive files
  - optional history rewrite via git-filter-repo
- Creates backup bundles before destructive operations.

5. Reporting layer
- Prints human-readable summary.
- Persists machine-readable JSON report.

## Data flow

1. Input arguments (CLI/GUI) define scope and behavior.
2. Auditor builds `RepoReport` objects.
3. Optional fixer mutates repository state based on explicit flags.
4. Re-audit confirms resulting state.
5. JSON output is written for traceability.

## Safety model

- Explicit opt-in for destructive actions.
- Dry-run support for planning.
- Conservative defaults.
- Backup-first strategy.

## Extension points

- New detection patterns (regex-based).
- Additional policy profiles.
- Alternate output formats (HTML/CSV).
- Test harness and CI gate integration.
