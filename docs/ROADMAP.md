# ROADMAP

## Vision

Provide a safe, repeatable, and auditable workflow to prepare repositories for public release.

## Guiding priorities

- Safety first: no destructive operation without explicit opt-in.
- Reproducibility: the same input should produce the same findings.
- Auditability: keep machine-readable outputs and clear operator actions.
- Portability: keep defaults generic and avoid personal hardcoded values.

## Milestone 0.1 - Stabilization

- Keep CLI and GUI parity for core audit and fix options.
- Align GUI interaction flow with parity safety gates (`Audit` -> `Repair`, with `Repair` visually locked until valid audit context).
- Improve report readability and failure grouping.
- Expand documentation and release checklist.
- Harden defaults around local policy and local result directory.

## Milestone 0.2 - Secret remediation hardening

- Improve secret-file classification (safe vs manual review).
- Add preview of candidate files and remediation plan in reports.
- Add optional confirmation gates for high-risk purge actions.
- Add clearer guidance for credential rotation after history rewrite.

## Milestone 0.3 - Quality and automation

Current baseline in repo:

- tracked pytest coverage for publication-gate regressions
- CLI CI on Windows, Linux, and macOS
- Python 3.10 through 3.13 validated in CI
- package build plus `wheel` and `sdist` install smoke in CI
- Windows GUI smoke in CI

Next hardening steps:

- expand synthetic integration coverage for rewrite planning and artifact redaction edge cases
- add a small release notes template and versioning policy
- add optional lint/static checks once they are stable enough to avoid release noise

## Milestone 0.4 - Advanced operations

- Add scoped suppression/allowlist support for known safe matches.
- Add batched execution profiles for large repository fleets.
- Add optional HTML summary report.
- Add optional policy profiles per organization.

## Out of scope (for now)

- Automatic secret rotation against external providers.
- Hosted backend service.
- Cross-platform GUI redesign beyond the current simple desktop interface.
