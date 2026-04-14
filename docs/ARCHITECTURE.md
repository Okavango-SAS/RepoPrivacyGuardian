# ARCHITECTURE

## Overview

Repo Privacy Guardian is a local-first auditing and remediation utility.

It has two execution surfaces:
- CLI entrypoint for scripted and repeatable runs.
- Simple GUI wrapper for interactive operation.

GUI interaction is phase-based: operators run `Audit` first, and `Repair` is visually locked until audit state is valid and actionable.

Local-first remains the default execution model. The only built-in network lookup in the normal audit path is the optional `--public-only` GitHub visibility check, which performs a read-only unauthenticated request against the GitHub repository API for GitHub remotes.

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

6. GUI interaction layer
- Separates audit and remediation actions into `Audit` and `Repair` tabs.
- Applies a visual lock overlay in `Repair` until audit context allows safe remediation actions.

## Data flow

1. Input arguments (CLI/GUI) define scope and behavior.
2. If `--public-only` is enabled, discovery performs a read-only GitHub visibility lookup for GitHub remotes before a repository is included.
3. In GUI mode, `Audit` establishes audit context before remediation is available.
4. Auditor builds `RepoReport` objects.
5. Optional fixer mutates repository state based on explicit flags.
6. Re-audit confirms resulting state.
7. JSON output is written for traceability.

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
