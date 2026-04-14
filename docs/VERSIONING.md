# VERSIONING

Repo Privacy Guardian uses semantic versioning with the CLI contract, packaging behavior, and local-first safety model as the main compatibility surface.

## Current stage

- Current public line: `1.2.x`
- Maturity: stable for the CLI, packaging, and release-engineering surface
- Goal of this stage: preserve the `1.x` contract while continuing additive hardening and documentation improvements

`1.0.0` is a stability milestone, not an architecture change. The project remains a local-first publication gate with an optional desktop GUI.

`1.1.0` is an additive release on top of that stable baseline. It adds reusable GitHub release-hardening audit support and related operator playbooks without changing the local-first contract.

`1.2.0` is another additive release within the same stable line. It strengthens local environment readiness with GUI-assisted tooling setup, optional GitHub CLI installation flows, and Windows `winget` bootstrap support without changing the core audit/fix model.

`1.2.1` is a security-maintenance patch on top of `1.2.0`. It keeps the same feature surface while raising the development/test `pytest` floor to a non-vulnerable line.

## Versioning rules

- Major: breaking CLI contract changes, incompatible report/schema changes, or supported-platform changes that require explicit upgrade guidance
- Minor: backward-compatible features, new checks, new flags with safe defaults, packaging improvements, and additive documentation
- Patch: bug fixes, small hardening changes, doc corrections, CI fixes, and low-risk behavior corrections

## Release discipline

- Avoid casual breaking changes after `1.0.0`.
- If a CLI flag, default, exit-code path, or report field changes in a user-visible way, call it out in release notes.
- Keep README, CLI help, tests, changelog, and package metadata aligned in the same change set.

## Stable release baseline

- Tracked tests are green.
- `python -m build` is green.
- Installed `wheel` and `sdist` smoke paths are green.
- Entry point, module execution, and direct script compatibility path are all verified.
- Public support claims remain backed by CI.
- README, release docs, and CLI help describe the real behavior without overpromising.
- The local-first contract remains intact and network behavior stays explicitly documented.

## Support expectations after `1.0.0`

- Patch releases should not break established CLI usage.
- Minor releases should stay additive unless an incompatibility is clearly documented.
- Major releases should be rare and reserved for deliberate contract changes.
