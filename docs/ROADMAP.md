# ROADMAP

This roadmap reflects the current stable `1.5.x` stage of the repository instead of the early pre-`1.0` milestone labels that no longer describe reality.

## Current baseline

The repository is already stable in these areas:

- CLI-first audit and remediation workflow
- optional GUI parity on the shared execution pipeline
- tracked regression suite plus release smoke scripts
- package build and install smoke for `wheel` and `sdist`
- local tooling readiness checks and optional install helpers
- opt-in GitHub owner/org remote audits with temporary local clones
- companion-style GUI with Audit, Reports, Prompts, Settings, and gated Repair views on the shared CLI backend
- internal `repo_privacy_guardian/` package with compatibility facades for stable `1.x` entry paths
- agent-summary, strict-profile, suppression, Decision-first report, GitHub fix-guide, and performance-metrics surfaces
- stable repo-owned `ruff check` gate
- local release harness and operator runbooks
- documented versioning, release checklist, and public changelog

## Near-term improvements with real value

These are the next improvements that still fit the current product scope:

- expand synthetic integration coverage for rewrite-planning and redaction edge cases
- expand target-resolution and preflight regression coverage further as local and GitHub owner/org repo-selection modes evolve
- keep GUI companion screenshots, prompt registry, and locale coverage aligned with the CLI contract
- keep docs, help text, packaged policy, and smoke fixtures aligned as defaults evolve
- continue extracting `repo_privacy_guardian/core.py` by CLI/config domains and deeper scanner execution seams without breaking compatibility shims; redaction, tooling, reporting, policy, remediation, scanner, GUI app, and GUI locale already use explicit dependencies or local constants

## Deprioritized for this repository phase

These ideas may still be useful later, but they are not the current focus:

- organization-scoped allowlists beyond the current versioned suppression file
- batched fleet execution profiles for many repositories at once
- GUI-only workflows that bypass the shared CLI backend
- provider-specific secret rotation integrations

## Out of scope

- hosted backend service
- automatic secret rotation against third-party providers
- remote telemetry as a default behavior
- making the GUI the primary product surface
