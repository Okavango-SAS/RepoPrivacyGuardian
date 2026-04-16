# ROADMAP

This roadmap reflects the current stable `1.2.x` stage of the repository instead of the early pre-`1.0` milestone labels that no longer describe reality.

## Current baseline

The repository is already stable in these areas:

- CLI-first audit and remediation workflow
- optional GUI parity on the shared execution pipeline
- tracked regression suite plus release smoke scripts
- package build and install smoke for `wheel` and `sdist`
- local tooling readiness checks and optional install helpers
- local release harness and operator runbooks
- documented versioning, release checklist, and public changelog

## Near-term improvements with real value

These are the next improvements that still fit the current product scope:

- expand synthetic integration coverage for rewrite-planning and redaction edge cases
- keep docs, help text, packaged policy, and smoke fixtures aligned as defaults evolve
- improve internal code navigation further if the single-file module grows materially
- add a stable lint/static gate only when it is quiet enough to improve signal instead of adding release noise

## Deprioritized for this repository phase

These ideas may still be useful later, but they are not the current focus:

- organization-scoped allowlists or suppression profiles
- batched fleet execution profiles for many repositories at once
- broader GUI redesign beyond the current staged desktop wrapper
- provider-specific secret rotation integrations

## Out of scope

- hosted backend service
- automatic secret rotation against third-party providers
- remote telemetry as a default behavior
- making the GUI the primary product surface
