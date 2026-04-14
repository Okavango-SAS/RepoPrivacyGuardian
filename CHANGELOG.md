# CHANGELOG

All notable public-release changes to this project are documented here.

## [1.0.0] - 2026-04-14

Initial stable public release.

### Highlights

- Stabilized the CLI-first publication-gate workflow for local-first repository audits and controlled remediation.
- Locked the public contract around `PASS`/`FAIL`, dry-run-first behavior, explicit destructive flags, and advisory-only `exfil_code_indicators`.
- Validated packaging and release engineering across source installs, built `wheel` installs, and built `sdist` installs.
- Backed the public Python support claim (`3.10` through `3.13`) with CI coverage.
- Documented stable scope, limitations, versioning policy, release checklist, and release-notes workflow without widening product scope.

### Validation

- `python -m pytest -q`
- `python -m Repo_Privacy_Guardian --help`
- `python Repo_Privacy_Guardian.py --help`
- `python tests/release_smoke_cli.py`
- `python tests/release_smoke_gui.py`
- `python -m build`
- clean install from `python -m pip install .`
- clean install from built `wheel`
- clean install from built `sdist`
- self-audit on the repository with `PASS`

### Scope notes

- The stable surface is the local-first CLI and packaging contract.
- The GUI remains optional and best-effort outside the Windows path covered by CI smoke.
- Network behavior remains limited to the documented optional GitHub visibility lookup used by `--public-only`.
