# Development Audit - 2026-05-18

This audit records the current development state of Repo Privacy Guardian on
`main` after the 1.5.x modularization work and before the documentation update
that introduced this file.

## Scope and evidence

Audited surfaces:

- CLI audit, remediation preview, reporting, policy, GitHub hardening, and
  release-contract surfaces.
- GUI companion flow across Audit, Reports, Prompts, Settings, and gated
  Repair tabs.
- Local persistence and generated artifacts.
- Dependency, packaging, static-analysis, smoke, visual, and self-audit
  evidence.

Validation evidence from this audit:

- `python -m ruff check .`: passed.
- `python -m pyright -p pyrightconfig.json`: passed with 0 errors.
- `python scripts/check_release_contract.py`: passed.
- `python tests/release_smoke_cli.py`: passed.
- `python tests/release_smoke_gui.py`: passed.
- `python scripts/release_readiness.py`: passed.
- Tracked `pytest` suite from the release-readiness run: 414 passed, 85.08%
  coverage.
- `pip-audit` from release readiness: no known vulnerabilities found in the
  development, GUI, or remediation requirement sets at audit time.
- `python scripts/visual_qa_gui.py`: passed and produced non-empty light, dark,
  and system-mode screenshots for the main GUI tabs.
- Self-audit artifact: `Audit_Results/20260518-160114/` stayed in ignored local
  evidence and was not committed.
- Visual QA artifact: `.local-meta/visual-qa/20260518-160135/` stayed in ignored
  local evidence and was not committed.

## Executive status

Current phase: stable `1.5.x` CLI-first product with an optional desktop GUI
companion.

Status: release-ready for the current public scope, with advisory or accepted
operational risks documented below.

No blocking functional, security, persistence, packaging, or test failures were
found in the tracked validation suite. The remaining work is mostly hardening,
continued modular extraction, performance baselining for very large histories,
and operational polish.

## Cybersecurity audit

Findings:

- The self-audit reported zero blocking findings, zero dirty-tree findings,
  zero path leaks, zero fsck failures, zero execution errors, and zero
  high-confidence tracked, history, or Git metadata secrets.
- Fixture and documentation examples were classified into safe fixture or
  documentation buckets instead of blocking release status.
- Repo-owned GitHub API probes and the Windows App Installer bootstrap path were
  classified as reviewed network context, not generic exfiltration indicators.
- Dependency audit found no known vulnerabilities in the audited optional
  requirement sets at audit time.
- Base package installation keeps Python runtime dependencies empty; optional
  GUI, remediation, test, and development dependencies remain isolated.
- GitHub hardening surfaced administrator branch-protection bypass as an
  advisory finding when the accepted-risk flag is not set. For this public
  solo-maintainer repository, admin bypass is an intentional operating model
  only when explicitly recorded with `--accept-github-admin-bypass`.
- GitHub Actions emitted a Node.js 20 deprecation warning for pinned actions in
  the latest remote CI run reviewed during the audit. Follow-up hardening
  updated the workflow to `actions/checkout` v6.0.2 and `actions/setup-python`
  v6.2.0, both pinned by SHA and declaring Node.js 24 runtime support.

Residual risk:

- Repo Privacy Guardian cannot rotate provider secrets by itself. Rotation
  remains an external mandatory post-remediation action after any confirmed
  leak.
- Generated audit artifacts are redacted where designed, but they can still
  contain sensitive operational context. They must remain ignored local evidence
  unless explicitly sanitized for publication.
- Advisory exfiltration and low-confidence identity heuristics still require
  operator classification by design.

Recommended next actions:

- Keep pinned GitHub Actions current with Node.js runtime migrations while
  preserving SHA pins.
- Keep self-audit release runs paired with the explicit accepted-risk flag when
  this solo-maintainer admin-bypass model is intentional.
- Keep `pip-audit`, release readiness, and self-audit in the release checklist.

## Functionality audit

Findings:

- CLI help, module entry point, direct script entry point, packaging, wheel,
  sdist, and install smoke paths all passed release readiness.
- CLI/GUI parity remains the product invariant. The GUI uses the shared backend
  pipeline and keeps the staged flow: Audit first, then gated Repair.
- Recent extractions moved scanner subprocess execution, history parsing,
  taxonomy aggregation, GUI state, theme, assets, and window lifecycle logic
  into narrower modules with contract tests.
- Report comparison, agent summary, strict profiles, suppression handling,
  GitHub hardening, remote owner/org audit controls, and release smoke scripts
  remain covered by tracked tests.
- No functional regression was found against the current 1.5.x release contract.

Known functional limitations:

- GUI cancellation is cooperative and stops after the active repository step
  completes; there is still no pause/resume model.
- `repo_privacy_guardian/core.py` remains a compatibility nexus and should keep
  shrinking behind stable `1.x` facades.
- `repo_privacy_guardian/gui/app.py` remains the largest runtime module and is
  the main remaining GUI extraction target.

## UX audit

Findings:

- Visual QA passed for System, Light, and Dark modes across Audit, Reports,
  Prompts, and Repair views.
- README screenshots now include dark-mode context, and local screenshot
  generation uses neutral visible paths.
- The desktop GUI continues to present itself as a companion for manual review
  rather than a separate product path. This matches the CLI-first agentic use
  case.
- Repair remains visually locked until audit context exists, which preserves the
  reviewed-write workflow.

UX limitations:

- Visual QA checks non-empty, stable screenshots, but it is not a pixel-perfect
  regression system.
- Linux GUI support still depends on optional desktop/Tk prerequisites.
- Long-running GUI audits still benefit from CLI use when tighter execution
  control is needed.

Recommended next actions:

- Keep README screenshots refreshed only when the user-visible GUI changes.
- Continue extracting remaining GUI widget construction helpers behind tests.
- Keep the artifact-retention cleanup affordance aligned across CLI, GUI, and
  docs as artifact outputs evolve.

## Databases and persistence audit

Findings:

- The application does not use a hosted backend, database server, SQLite file,
  or remote telemetry by default.
- Persistence is local and file-based:
  - GUI settings JSON.
  - `Audit_Results/<run_id>/report.json`.
  - `Audit_Results/<run_id>/report.html`.
  - `Audit_Results/<run_id>/run.log`.
  - `Audit_Results/<run_id>/run_state.json`.
  - `Audit_Results/<run_id>/agent_summary.json`.
  - Optional suppression and report-comparison JSON files.
- Existing tests verify that GUI settings persist user preferences without
  persisting Git identity secrets.
- Artifact directories are ignored by the repository guardrails.

Persistence risks:

- Audit artifacts can accumulate and may retain sensitive operational context
  even when secrets are redacted; the CLI/GUI cleanup path now removes old
  timestamp-named local runs after preview or confirmation.
- Suppression files are powerful policy inputs and must stay narrow, reviewed,
  and versioned when committed.

Recommended next actions:

- Keep retention guidance visible and use `--cleanup-audit-results --dry-run`
  before deleting old ignored audit artifacts.
- Keep suppression schema validation and release-contract checks strict.

## Optimization audit

Findings:

- The release-readiness harness now validates static analysis, package build,
  install smoke, dependency audit, self-audit, CLI smoke, GUI smoke, and tracked
  tests in one repeatable flow.
- Performance metrics are already emitted in `run_state.json`.
- `scripts/benchmark_large_history.py` now creates a synthetic many-commit
  repository, runs the real audit pipeline, and compares `run_state.json`
  timings against an optional baseline.
- The product has useful fast paths such as scoped `--repos`, GitHub fast mode,
  and bounded remote clone worker settings.

Optimization risks:

- Very large repositories can still spend significant time in history patch
  scanning.
- There is no enforced release-blocking performance budget for worst-case Git
  history scans.
- More module extraction is still needed before the largest runtime modules are
  easy to profile and optimize in isolation.

Recommended next actions:

- Use the large-history benchmark before and after performance-sensitive
  scanner changes.
- Preserve and compare phase timings from `run_state.json` during performance
  work, and promote a budget only after enough local baselines are collected.
- Continue extracting pure planning/parsing code away from side-effecting
  adapters so hotspots can be tested and profiled independently.

## Technical debt

Highest-value debt to pay down next:

- `repo_privacy_guardian/gui/app.py` is still about 4,000 lines and should keep
  losing remaining widget-construction logic to narrower modules.
- `repo_privacy_guardian/core.py` is still about 2,700 lines and remains the
  main compatibility aggregation surface.
- CI pinned action revisions now target Node.js 24-compatible action releases,
  but they still need normal dependency-review cadence.
- Large-history performance now has a repeatable benchmark path, but release
  thresholds are still advisory until enough baselines exist.
- Artifact retention/cleanup is now an ergonomic CLI/GUI workflow, but it
  should stay scoped to local ignored run artifacts only.
- Provider-specific secret rotation is intentionally out of scope, but the docs
  should keep making that operator responsibility explicit.

## Roadmap recommendation

Suggested priority order:

1. Expand synthetic integration coverage for redaction edge cases and
   target-resolution/preflight paths.
2. Continue extracting remaining GUI widget-construction helpers behind focused
   tests.
3. Continue shrinking `core.py` while preserving stable `1.x` compatibility
   facades.
4. Defer provider-specific secret rotation and hosted backend features unless
   the product scope changes.
