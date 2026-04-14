# VERSIONING

Repo Privacy Guardian uses semantic versioning with the CLI contract, packaging behavior, and local-first safety model as the main compatibility surface.

## Current stage

- Current public line: `0.2.x`
- Maturity: late beta for the CLI and packaging surface
- Goal of this stage: make the repository credible and easy to adopt before the first `1.0.0` tag

`1.0.0` is a stability milestone, not an architecture change. The project remains a local-first publication gate with an optional desktop GUI.

## Versioning rules

- Major: breaking CLI contract changes, incompatible report/schema changes, or supported-platform changes that require explicit upgrade guidance
- Minor: backward-compatible features, new checks, new flags with safe defaults, packaging improvements, and additive documentation
- Patch: bug fixes, small hardening changes, doc corrections, CI fixes, and low-risk behavior corrections

## Pre-1.0 discipline

- Avoid casual breaking changes even before `1.0.0`.
- If a CLI flag, default, exit-code path, or report field changes in a user-visible way, call it out in release notes.
- Keep README, CLI help, tests, and package metadata aligned in the same change set.

## `1.0.0` exit criteria

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
