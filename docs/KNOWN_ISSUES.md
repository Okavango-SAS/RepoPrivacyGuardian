# KNOWN ISSUES

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
Workaround: audit specific repos first with `--repos` and use staged execution.

1. History rewrite changes commit SHAs and requires force push.

Impact: high.
Workaround: always create bundle backups and coordinate with collaborators.

1. GUI does not include pause/resume controls.

Impact: low.
Workaround: GUI supports cooperative cancellation, but it only stops after the active repository step completes. Use CLI for tighter control over long runs.

1. `repo_privacy_guardian/core.py` and `repo_privacy_guardian/gui/app.py` are still large after the package split and recent GUI helper extractions.

Impact: medium.
Workaround: continue extracting by domain behind the internal package while preserving the stable `1.x` facade and CLI/GUI parity tests. GUI dialog, navigation, and background-worker adapters now have focused helper coverage; the next useful seams are local artifact-retention cleanup and remaining compatibility aggregation in `core.py`.

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
