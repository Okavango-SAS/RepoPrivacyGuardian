# KNOWN ISSUES

## Open defects from the 2026-10-04 audit

These findings are pending implementation. Evidence, priorities, affected code, and acceptance checks are recorded in the [repository and skill improvement plan](REPO_SKILL_IMPROVEMENT_PLAN.md).

| Finding | Impact | Current mitigation |
| --- | --- | --- |
| Agent summary and HTML decisions derive from finding counts without consistently accounting for execution failure or completion. An empty, interrupted, or failed run can appear as `PASS`. | High: an operator or agent may interpret incomplete evidence as publication readiness. | Check the CLI exit code, `run_state.json`, expected target count, and individual repository status before accepting a summary decision. |
| Built packages omit the eight English/Spanish prompt files consumed by the GUI Prompts actions. | Medium: copying or opening a prompt from an installed wheel fails even when checkout-based smoke tests pass. | Use the maintained prompt files from a source checkout until package-resource loading is implemented. |
| History streaming checks deadlines after stdout delivers a line, while stderr is not drained concurrently. | Medium: a blocked reader or full stderr pipe can prevent the intended timeout from bounding a run. | Supervise long audits and inspect process/run progress; the existing stream timeout alone is not a complete wall-clock guarantee. This finding comes from code inspection. |
| The skill resolver selects Python candidates by file/command existence without proving they run a supported Python version. | Medium: a broken local environment or Python older than 3.10 can shadow a usable interpreter. | Repair the selected environment and verify Python 3.10 or newer before invoking the skill. |
| Forced skill installation removes the existing installed copy before all replacement files and metadata are successfully written. | Medium: a failed refresh can leave no working installed skill. | Keep a local backup before refresh and inspect `-WhatIf`; transactional replacement and rollback are planned. |
| Relative paths in the PowerShell installer/resolver use process-level path normalization, which can differ from the current `Set-Location` directory. | Medium: a path can resolve to the wrong backend or installation location. | Pass absolute paths when setting the checkout or Codex installation location. |
| Skill fallback tests depend on temporary-directory placement: a temporary directory inside this checkout triggers the intended workspace-ancestor resolution before fallback. | Low: an in-checkout `--basetemp` produces failures that do not reproduce with the default external temporary directory. | Use external temporary directories for fallback scenarios; preserve workspace-first runtime behavior when isolating the tests. |
| Fresh-process imports of the internal `redaction` and `tooling` modules fail through circular dependencies on `core`. | Low: standalone helper reuse depends on import order; supported CLI/facade paths still work. | Use the supported facade until the narrow import-boundary correction and isolated import regressions are implemented. |

Validation follow-ups also remain open. The scanner class has a blanket `# pragma: no cover`, so the reported 85.86% coverage does not measure most scanner behavior. A Windows lock-metadata assertion failed only in the in-checkout temporary-directory run; the default suite passed all 457 tests, so its reproducibility must be established before describing it as a general runtime defect. Installed-artifact module checks can import the source checkout because they run from it; those checks need an external working directory and import-origin assertions.

The audit did not run the complete release harness or a new visual GUI smoke, and Pyright was unavailable in that environment. These are validation limits, not passing release evidence.

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
Workaround: GUI supports cooperative cancellation, but it only stops after the active repository step completes. Use CLI for tighter control over long runs.

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
