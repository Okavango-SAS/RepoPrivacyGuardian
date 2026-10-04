# ROADMAP

This roadmap reflects the current stable `1.5.x` stage of the repository instead of the early pre-`1.0` milestone labels that no longer describe reality.

## Current baseline

The 2026-10-04 [repository and Codex skill audit](REPO_SKILL_IMPROVEMENT_PLAN.md) is the current improvement baseline. The default tracked suite passed with 457 tests and reported 85.86% coverage; the scanner class's broad coverage exclusion limits what that percentage establishes. The audit also confirmed open report-completion, installed-prompt, stream-lifecycle, and skill-reliability defects. This is an audit and implementation plan, not a completed release gate or a claim that the planned fixes have shipped.

Established product surfaces include:

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
- GUI dialog, navigation, background-worker adapters, setup option-menu specs, and card specs for Audit, Settings, Reports, Prompts, Repair, repository list shells, and empty states extracted behind focused tests
- CLI and GUI cleanup path for old local `Audit_Results` run folders
- maintainer branch/worktree hygiene documented for public-repository cleanup and handoff work
- repeatable large-history benchmark coverage that compares `run_state.json` timings
- synthetic integration coverage for redacted JSON/HTML report surfaces and local target-resolution/preflight edge cases
- maintained repo-linked Codex skill with local-only installation metadata and CLI backend resolution

## Near-term improvements with real value

Apply the [detailed implementation plan](REPO_SKILL_IMPROVEMENT_PLAN.md) in reviewed stages, preserving the stable `1.x` interfaces and shared CLI/GUI behavior. No runtime or skill changes are included in the audit documentation delivery.

1. Make summary, HTML, and GUI decisions account for failed, aborted, empty, and incomplete runs; retain policy status separately from execution completion.
2. Package the eight bilingual GUI prompts and validate installed wheel/sdist behavior outside the source checkout.
3. Bound streaming subprocess deadlines, drain stderr safely, and clean up child processes; then improve cooperative cancellation at safe audit boundaries.
4. Validate skill Python candidates, make forced skill refresh transactional, and resolve relative PowerShell paths from the shell location. Isolate fallback tests from checkout ancestors.
5. Remove the blanket scanner coverage exclusion and add meaningful behavior tests while retaining the existing coverage gate; correct the direct-import cycles in redaction/tooling and investigate the location-sensitive lock test result before prescribing a fix.
6. Measure incremental scanner optimizations: reuse audit-scoped metadata and tracked-file work before consolidating history passes, preserving finding taxonomy, limits, and report parity.
7. Align CI event path filters and strengthen package-install validation, then run the complete tracked release checks and desktop parity checks before release.

Continue maintenance alongside these stages:

- monitor the public `v1.5.1` release for real installation, audit, GUI, and documentation feedback
- choose the next user-facing improvement from observed operator friction, using measured audit results rather than extraction size alone
- keep GUI companion screenshots, prompt registry, and locale coverage aligned with the CLI contract
- keep docs, help text, packaged policy, and smoke fixtures aligned as defaults evolve
- keep branch/worktree cleanup boring and explicit: prune remotes, fast-forward `main`, delete only merged local branches, and prune stale worktree metadata after review
- keep shrinking `repo_privacy_guardian/core.py` and the broad `GuiApp` coordinator only when a behavior-bearing boundary is clear, testable, and useful to users; extraction by itself is no longer a near-term release goal

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
