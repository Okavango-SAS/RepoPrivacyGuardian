# KNOWN ISSUES

## Current limitations

1. Content scans may flag test fixtures and documentation examples.

Impact: medium.
Workaround: verify context before applying destructive fixes.

1. Exfil indicator heuristic is keyword-based and can over-report in backend/service repos.

Impact: medium.
Workaround: treat exfil hits as advisory/manual-review signals; validate by code intent before remediation. They do not change PASS/FAIL by default.

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

1. Linux GUI support depends on optional desktop prerequisites.

Impact: low.
Workaround: use the supported CLI path in headless or minimal Linux environments; for GUI use, install Tk support and run from a graphical session.

1. No built-in integration with provider APIs for secret rotation.

Impact: medium.
Workaround: treat rotation as an external mandatory post-remediation step.

1. Commit metadata checks are email-format driven and may ignore malformed non-email identity tokens.

Impact: low.
Workaround: add manual `git log --all --pretty=format:%an\ <%ae\>` review for strict identity hygiene.

## Known false-positive patterns

- Email-like tokens in code comments that are not personal data.
- Local paths in synthetic test fixtures.
- Security examples intentionally containing placeholder token shapes.
- Generic terms such as "webhook" or "telemetry" used in legitimate service code.

## Intentional behavior (not a bug)

- GUI uses a staged flow: run `Audit` first, then `Repair`.
- `Repair` is intentionally visually locked until a valid audit produces actionable remediation context.
- `exfil_code_indicators` is advisory by default. It elevates review guidance, but it does not automatically fail a repository.
- `pytest` release validation intentionally ignores untracked/local-only `tests/test_*.py` files so the release signal matches a clean clone.

## Tracking policy

- Keep this file updated when a recurring issue appears in two or more repositories.
- Record mitigation and expected fix milestone.
