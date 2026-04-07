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
- Improve report readability and failure grouping.
- Expand documentation and release checklist.
- Harden defaults around local policy and local result directory.

## Milestone 0.2 - Secret remediation hardening

- Improve secret-file classification (safe vs manual review).
- Add preview of candidate files and remediation plan in reports.
- Add optional confirmation gates for high-risk purge actions.
- Add clearer guidance for credential rotation after history rewrite.

## Milestone 0.3 - Quality and automation

- Add unit tests for parser, path resolution, and remediation planning.
- Add integration tests for dry-run and report generation behavior.
- Add CI pipeline for lint, syntax checks, and smoke tests.
- Add release notes template and semantic versioning policy.

## Milestone 0.4 - Advanced operations

- Add scoped suppression/allowlist support for known safe matches.
- Add batched execution profiles for large repository fleets.
- Add optional HTML summary report.
- Add optional policy profiles per organization.

## Out of scope (for now)

- Automatic secret rotation against external providers.
- Hosted backend service.
- Cross-platform GUI redesign beyond the current simple desktop interface.
