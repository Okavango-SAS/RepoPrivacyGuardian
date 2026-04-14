# CHANGELOG

All notable public-release changes to this project are documented here.

## [1.1.0] - 2026-04-14

Release-hardening and operator-playbook update.

### Highlights

- Added optional `--audit-github-hardening` checks for GitHub-hosted repositories, with read-only remote inspection and token-gated admin checks.
- Surfaced GitHub hardening findings and warnings consistently in CLI guidance, JSON exports, HTML reports, and the optional GUI path.
- Documented a reusable GitHub public-release hardening playbook for operators and coding agents without changing the local-first product model.
- Preserved the existing `PASS`/`FAIL` contract by keeping GitHub hardening signals advisory/manual-review by default.

### Validation

- `python -m pytest -q`
- `python -m Repo_Privacy_Guardian --help`
- `python tests/release_smoke_cli.py`
- `python tests/release_smoke_gui.py`
- `python -m build`
- self-audit with `python -m Repo_Privacy_Guardian --root <repos> --repos <repo> --dry-run --yes --audit-github-hardening`

### Scope notes

- GitHub hardening remains opt-in and advisory unless a future strict mode is introduced.
- Default local audits still work without network access or GitHub credentials.

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
