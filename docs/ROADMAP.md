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
- pinned GitHub Actions updated to Node.js 24-compatible revisions while preserving SHA pins
- GUI dialog, navigation, background-worker adapters, and setup option-menu specs extracted behind focused tests
- CLI and GUI cleanup path for old local `Audit_Results` run folders
- repeatable large-history benchmark coverage that compares `run_state.json` timings
- synthetic integration coverage for redacted JSON/HTML report surfaces and local target-resolution/preflight edge cases

## Near-term improvements with real value

These are the next improvements that still fit the current product scope:

- continue extracting remaining GUI widget construction helpers behind focused tests, especially larger Audit/Repair card assembly blocks
- keep target-resolution, preflight, and redaction regression coverage aligned as local and GitHub owner/org repo-selection modes evolve
- keep GUI companion screenshots, prompt registry, and locale coverage aligned with the CLI contract
- keep docs, help text, packaged policy, and smoke fixtures aligned as defaults evolve
- continue extracting `repo_privacy_guardian/core.py` and remaining GUI widget construction helpers without breaking compatibility shims; config, redaction, tooling, evidence taxonomy, execution, history parsing, reporting, policy, remediation, scanner, GUI app, GUI background, GUI dialogs, GUI locale, GUI navigation, and GUI state already use explicit dependencies or local constants, remediation owns pure `git-filter-repo` command planning, execution owns the side-effecting Git/subprocess adapters, history parsing owns pure `git log -p` parsing/formatting helpers, evidence taxonomy owns tracked/history secret bucket aggregation, GUI background owns worker/UI-thread scheduling, GUI dialogs owns browse-dialog targeting, GUI navigation owns flow-tab selection/rename behavior, and GUI state owns pure Audit/Repair flow state, setup option-menu specs, collapsible-section visibility, and Reports/Prompts responsive layout decisions

## Deprioritized for this repository phase

These ideas may still be useful later, but they are not the current focus:

- organization-scoped allowlists beyond the current versioned suppression file
- batched fleet execution profiles for many repositories at once
- GUI-only workflows that bypass the shared CLI backend
- provider-specific secret rotation integrations
- hosted persistence beyond local file artifacts

## Out of scope

- hosted backend service
- automatic secret rotation against third-party providers
- remote telemetry as a default behavior
- making the GUI the primary product surface
