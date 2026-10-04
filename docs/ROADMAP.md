# ROADMAP

This roadmap reflects the current stable `1.5.x` stage of the repository instead of the early pre-`1.0` milestone labels that no longer describe reality.

## Current baseline

The 2026-10-04 [repository and Codex skill audit and implementation record](REPO_SKILL_IMPROVEMENT_PLAN.md) is the current improvement baseline. Its authorized follow-up implements shared completion-aware decisions, packaged prompts and isolated artifact checks, bounded stream lifecycles, and skill reliability corrections. The scanner coverage exclusion is removed, audit work is shared, metrics are expanded, and cancellation is cooperative within read-only local work. Final validation passes with 655 tracked tests, one POSIX-specific skip, and 84.49% coverage; static, artifact, smoke, dependency, and installed-skill checks pass. Repeated timing/report-parity comparisons include an explicit concurrent-reader memory tradeoff. Fresh screenshot review is unavailable in this capture environment. The original 457-test/85.86% audit result remains historical evidence. Version `1.5.1` is unchanged, and no new release is announced.

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

Keep the completed [implementation plan](REPO_SKILL_IMPROVEMENT_PLAN.md) as a
measured baseline while preserving stable `1.x` interfaces and shared CLI/GUI
behavior.

1. Preserve corrected-denominator coverage and the 80% gate, with completed, failed, aborted, and legacy CLI/GUI guidance covered by behavior tests.
2. Continue isolated wheel/sdist resource and entry-point checks; exercise the skipped POSIX signal path in supported-platform validation and obtain usable screenshot review in a working desktop-capture environment.
3. Preserve finding taxonomy, scopes, and independent limits through future scanner changes; repeat the accepted multi-corpus report-parity and median/memory comparisons instead of extrapolating the current speedup to all repositories.
4. Keep the verified installed skill aligned with maintained source and preserve local metadata outside Git; retain rollback and abrupt-termination recovery checks when installer behavior changes.
5. Keep supported-platform validation separate from local evidence, and run the complete release gate before a future version or tag.

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
