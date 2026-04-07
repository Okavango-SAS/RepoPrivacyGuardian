# KNOWN ISSUES

## Current limitations

1. Content scans may flag test fixtures and documentation examples.
- Impact: medium.
- Workaround: verify context before applying destructive fixes.

2. Safe secret auto-purge is intentionally conservative.
- Impact: medium.
- Workaround: use `--purge-all-detected-secret-files` only after manual review.

3. Large repositories can take significant time during history patch scanning.
- Impact: medium.
- Workaround: audit specific repos first with `--repos` and use staged execution.

4. History rewrite changes commit SHAs and requires force push.
- Impact: high.
- Workaround: always create bundle backups and coordinate with collaborators.

5. GUI does not include pause/resume or cancellation controls.
- Impact: low.
- Workaround: run long operations from CLI for better control.

6. No built-in integration with provider APIs for secret rotation.
- Impact: medium.
- Workaround: treat rotation as an external mandatory post-remediation step.

## Known false-positive patterns

- Email-like tokens in code comments that are not personal data.
- Local paths in synthetic test fixtures.
- Security examples intentionally containing placeholder token shapes.

## Tracking policy

- Keep this file updated when a recurring issue appears in two or more repositories.
- Record mitigation and expected fix milestone.
