# KNOWN ISSUES

## Follow-up to the 2026-10-04 audit

The identified decision-context, installed-prompt, stream-lifecycle, skill
interpreter/refresh/path, fallback-test, CI-filter, and standalone-import
corrections are implemented. Scanner coverage now uses its actual statements,
and isolated artifact checks verify installed origins and resources. The
location-sensitive lock assertion was caused by an empty `.git` test fixture
discovering an enclosing checkout; initialized isolated fixtures correct it
without a speculative production locking change.

See the [repository and skill improvement plan](REPO_SKILL_IMPROVEMENT_PLAN.md)
for the original evidence, implementation details, and final gate results.
The corrections pass final local validation: 655 tracked tests passed, one
POSIX-specific skip, and 84.49% statement coverage with the 80% gate unchanged.
Static, artifact, smoke, dependency, installed-skill, and repeated timing/report-
parity checks pass as recorded in the plan. Historical baseline counts remain
separate evidence. No release or tag is announced by these corrections.

Remaining operational limits:

- Legacy artifact sets without completion context show REVIEW. Re-audit with
  current tooling before interpreting them as publication readiness.
- Skill refresh rolls back handled errors, but abrupt process/machine termination
  between moves can leave a sibling `.repo-privacy-guardian.backup-*` directory.
  Inspect and preserve that local backup until the installed skill and link have
  been verified; `-WhatIf` remains the write-free preview path.
- A concurrent destination created during skill replacement can prevent safe
  automatic restoration. The installer preserves that destination and the prior
  copy's backup for reviewed recovery instead of overwriting either.
- Read-only local audits poll cancellation within work and waits. Active repair
  writes wait for the next Git-safe boundary, and optional remote checks retain
  their own bounded timeouts. Ordinary CLI Ctrl+C records an aborted partial run;
  repeated Ctrl+C during active repair writes is deferred. External forced
  termination remains outside cooperative cancellation.
- Local Windows/PowerShell checks do not substitute for supported-platform CI
  and a fresh release gate. Performance claims require the recorded benchmark
  workloads and comparison evidence.
- Concurrent stream readers add traced Python memory compared with the original
  implementation. The measured scanner sharing reduces that cost versus bounded
  unoptimized execution and improves synthetic audit medians; it does not claim
  universally lower memory or total process RSS. See the plan's tradeoff table.
- Fresh screenshot review is unavailable in the current execution environment:
  the attempted visual QA capture was uniformly black. Initialization, layout,
  callbacks, and GUI smoke pass, but usable desktop capture still
  requires a working graphical capture environment.

## Current limitations

1. Real-shaped examples outside test/fixture contexts may still require manual classification.

Impact: low.
Workaround: use ignored placeholder domains such as `.invalid` or `.example` in docs/examples so findings do not look like real contact data and can stay in non-blocking fixture or safe-documentation buckets; verify context before applying destructive fixes. Test and fixture email examples are preserved in safe fixture buckets.

1. Exfil indicator heuristic is keyword-based and can over-report in backend/service repos.

Impact: medium.
Workaround: treat exfil hits as advisory/manual-review signals; validate by code intent before remediation. They do not change PASS/FAIL by default. Repo Privacy Guardian's own narrow, reviewed GitHub API and Windows App Installer bootstrap code paths are separated into `reviewed_network_indicators` so self-audits stay traceable without forcing manual exfil review.

1. Safe secret auto-purge is intentionally conservative.

Impact: medium.
Workaround: use `--purge-all-detected-secret-files` only after manual review.

1. Large repositories can take significant time during history patch scanning.

Impact: medium.
Workaround: audit specific repos first with `--repos`, use staged execution, and run `python scripts/benchmark_large_history.py` before/after scanner changes to compare `run_state.json` timing deltas.

1. History rewrite changes commit SHAs and requires force push.

Impact: high.
Workaround: always create bundle backups and coordinate with collaborators.

1. GUI does not include pause/resume controls.

Impact: low.
Workaround: GUI supports cooperative cancellation through the shared CLI pipeline during read-only local audit phases, file/history iteration, and command waits. Active repair writes stop at the next Git-safe boundary. Optional remote checks keep their own bounded timeouts.

1. `repo_privacy_guardian/core.py` and `repo_privacy_guardian/gui/app.py` are still large after the package split and recent GUI helper extractions.

Impact: medium.
Workaround: continue extracting by domain behind the internal package while preserving the stable `1.x` facade and CLI/GUI parity tests. GUI dialog, navigation, background-worker adapters, setup option menus, card specs across Audit/Settings/Reports/Prompts/Repair, local artifact cleanup, synthetic redaction/reporting edges, target resolution, and large-history benchmark paths now have focused coverage; the next useful seams are broader `GuiApp` coordinator logic and compatibility aggregation in `core.py`, but only when the boundary is behavior-bearing and testable.

1. Linux GUI support depends on optional desktop prerequisites.

Impact: low.
Workaround: use the supported CLI path in headless or minimal Linux environments; for GUI use, install Tk support and run from a graphical session.

1. No built-in integration with provider APIs for secret rotation.

Impact: medium.
Workaround: treat rotation as an external mandatory post-remediation step.

## Known false-positive patterns

- Email-like tokens in code comments that are not personal data.
- Local paths in synthetic test fixtures.
- Security examples intentionally containing placeholder token shapes.
- Generic terms such as "webhook" or "telemetry" used in legitimate service code.
- Lookalike package paths in repositories that are not Repo Privacy Guardian stay advisory instead of being auto-classified as reviewed network context.

## Intentional behavior (not a bug)

- GUI uses a staged flow: run `Audit` first, then `Repair`.
- `Repair` is intentionally visually locked until a valid audit produces actionable remediation context.
- Malformed/non-email author/committer email-field values are treated as suspicious commit identity tokens.
- `exfil_code_indicators` is advisory by default. It elevates review guidance, but it does not automatically fail a repository.
- `reviewed_network_indicators` is non-blocking safe context for narrow Repo Privacy Guardian self-audit network paths, not a general allowlist.
- `pytest` release validation intentionally ignores untracked/local-only `tests/test_*.py` files so the release signal matches a clean clone.
- Suppression files are intentionally narrow: high-confidence secrets, path leaks, dirty tree state, fsck failures, execution errors, fix errors, and Git metadata blocking secrets cannot be suppressed.
- Administrator branch-protection bypass can be an accepted GitHub hardening risk only when a solo-maintainer repository explicitly records that posture with `--accept-github-admin-bypass`.

## Tracking policy

- Keep this file updated when a recurring issue appears in two or more repositories.
- Record mitigation and expected fix milestone.
