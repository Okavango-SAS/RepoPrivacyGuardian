# VERSIONING

Repo Privacy Guardian uses semantic versioning with the CLI contract, packaging behavior, and local-first safety model as the main compatibility surface.

## Current stage

- Current public line: `1.3.x`
- Maturity: stable for the CLI, packaging, and release-engineering surface
- Goal of this stage: preserve the `1.x` contract while continuing additive hardening and documentation improvements

`1.0.0` is a stability milestone, not an architecture change. The project remains a local-first publication gate with an optional desktop GUI.

`1.1.0` is an additive release on top of that stable baseline. It adds reusable GitHub release-hardening audit support and related operator playbooks without changing the local-first contract.

`1.2.0` is another additive release within the same stable line. It strengthens local environment readiness with GUI-assisted tooling setup, optional GitHub CLI installation flows, and Windows `winget` bootstrap support without changing the core audit/fix model.

`1.2.1` is a security-maintenance patch on top of `1.2.0`. It keeps the same feature surface while raising the development/test `pytest` floor to a non-vulnerable line.

`1.2.2` is an operations/readiness patch on top of `1.2.1`. It adds a repository-owned local release harness plus operator troubleshooting/runbook documentation without changing the CLI or local-first scope.

`1.2.3` is a public-release stabilization patch on top of `1.2.2`. It restores release-governance alignment, tightens local/remote hardening audits, improves GUI onboarding and screenshot evidence, and preserves CLI/GUI parity without changing the CLI contract or report schema.

`1.3.0` is an additive minor release on top of `1.2.3`. It adds opt-in GitHub owner/org remote audit mode, expands high-confidence secret detection, and restores GUI/CLI parity for the new remote-audit inputs while preserving the local-first default path.

`1.3.1` is a release-readiness hardening patch on top of `1.3.0`. It bounds GitHub CLI auth probes, owner/org discovery pagination, clone worker fan-out, temp cleanup retries, atomic report writes, and subprocess-based smoke/test helpers without changing the CLI contract.

`1.3.2` is a secret-taxonomy hardening patch on top of `1.3.1`. It broadens modern provider/webhook/credentialed-URL/Git-metadata detection, separates low-confidence generic assignments from blocking high-confidence findings, and classifies synthetic fixtures and safe documentation examples without changing default remediation safety.

`1.3.3` is a GUI/UX hardening patch on top of `1.3.2`. It clarifies remote GitHub owner/org audit mode in the repository picker, keeps local Root errors from competing with audit-only remote targets, and makes the Repair review summary distinguish blocking categories, manual-review signals, and non-blocking fixture/documentation context without changing CLI behavior or report schema.

`1.3.4` is a GUI contextual-help patch on top of `1.3.3`. It adds hover help and visible info badges for non-obvious setup, GitHub remote audit, identity, repair, and run-control options without changing CLI behavior or report schema.

`1.3.5` is a GUI localization patch on top of `1.3.4`. It adds a persisted English / Spanish (Latin America) GUI language selector and locale catalogs while keeping CLI flags, reports, and `GuardRunConfig` mappings unchanged.

`1.3.6` is a first-run onboarding patch on top of `1.3.5`. It adds a concise README quick path and clearer CLI help guidance for new users while keeping audit behavior, remediation defaults, and report schema unchanged.

`1.3.7` is a CLI/GUI parity hardening patch on top of `1.3.6`. It adds a testable CLI parser-to-runtime adapter and field-level regression coverage that compares every shared `GuardRunConfig` field from equivalent CLI and GUI inputs while keeping behavior, report schema, and GUI locale presentation unchanged.

`1.3.8` is an agentic onboarding documentation patch on top of `1.3.7`. It documents agentic IDE and coding-agent usage as the primary automation use case and adds reusable prompts for post-clone environment preparation plus reviewed audit-and-repair workflows without changing CLI behavior, report schema, or GUI parity.

## Versioning rules

- Major: breaking CLI contract changes, incompatible report/schema changes, or supported-platform changes that require explicit upgrade guidance
- Minor: backward-compatible features, new checks, new flags with safe defaults, packaging improvements, and additive documentation
- Patch: bug fixes, small hardening changes, doc corrections, CI fixes, and low-risk behavior corrections

## Release discipline

- Avoid casual breaking changes after `1.0.0`.
- If a CLI flag, default, exit-code path, or report field changes in a user-visible way, call it out in release notes.
- Keep README, CLI help, tests, changelog, and package metadata aligned in the same change set.

## Validation tiers

- automatic CI smoke: cheapest push-time signal for help paths, release-contract drift, and CLI smoke
- manual extended CI: `workflow_dispatch` suite for `ruff`, `pyright`, tracked `pytest`, package smoke, and Windows GUI smoke
- local maintainer release gate: `python scripts/release_readiness.py` before a public release

## Stable release baseline

- Tracked tests are green.
- `python -m ruff check .` is green.
- `python -m build` is green.
- Installed `wheel` and `sdist` smoke paths are green.
- Entry point, module execution, and direct script compatibility path are all verified.
- Public support claims remain aligned with the documented validation tiers instead of overclaiming continuous CI coverage.
- README, release docs, and CLI help describe the real behavior without overpromising.
- The local-first contract remains intact and network behavior stays explicitly documented.

## Support expectations after `1.0.0`

- Patch releases should not break established CLI usage.
- Minor releases should stay additive unless an incompatibility is clearly documented.
- Major releases should be rare and reserved for deliberate contract changes.
