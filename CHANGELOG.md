# CHANGELOG

All notable public-release changes to this project are documented here.

## [Unreleased]

Repository consolidation and developer-experience cleanup.

### Highlights

- Re-based the release contract around the intended cost-first validation tiers: automatic CI smoke stays cheap, broader validation remains manual or local, and docs/tests no longer overclaim continuous matrix coverage.
- Added `scripts/check_release_contract.py` and wired it into automatic CI smoke plus the local release harness so workflow/docs/version drift fails fast without enabling the full manual suite.
- Tightened GUI stop semantics in operator-facing UX/docs by renaming the button to `Stop After Current Step`, documenting the cooperative-stop behavior explicitly, and extending the cheap contract guard to cover that wording.
- Extracted run-artifact creation, run-state persistence, and log-writing helpers into `repo_privacy_guardian_artifacts.py` while preserving the existing `Repo_Privacy_Guardian.py` surface for callers and tests.
- Extracted the shared root-validation/target-discovery and run-exit primitives into `repo_privacy_guardian_runtime.py` so CLI and GUI preflight contracts stay aligned without growing the main pipeline surface.
- Extracted GitHub remote parsing, API probing, and release-hardening audit logic into `repo_privacy_guardian_github.py` while preserving the existing `Repo_Privacy_Guardian.py` API surface for callers and tests.
- Hardened operator-facing abort semantics: confirmation denials and user cancellations now finish as explicit `ABORTED` runs with stable exit code/state tracking instead of looking like a clean `PASS 0/0`.
- Added basic GUI cancellation so long-running audits/repairs can stop after the active repository step completes, while keeping artifacts and `run_state.json` consistent.
- Added a low-noise repo-owned `pyright` gate for the extracted runtime/GitHub/artifacts helpers plus repo-owned support scripts, and wired it into local validation plus CI.
- Fixed repository target resolution so CLI now audits `Current Root` when `--root` points directly at a git checkout and `--repos` is omitted.
- Requested `--repos` targets that do not resolve now fail cleanly instead of returning a false `PASS 0/0`.
- Empty `--root` selections and `--public-only` runs that resolve to zero repositories now fail cleanly instead of returning a false `PASS 0/0`.
- Invalid `--root` paths now return operator-facing validation errors without falling through to an unhandled traceback path.
- Added a repo-owned `ruff check` gate to the development extras, release-readiness harness, and CI workflow.
- Aligned the default `.gitignore` baseline, policy docs, and smoke fixtures so tracked `.env.example` files are supported without creating tracked-but-ignored drift.
- Added `.env.example` plus `docs/LOCAL_DEVELOPMENT.md` to make optional auth variables, local setup, validation loops, and repository navigation explicit.
- Tightened the release harness with an explicit CLI tooling preflight and clearer step boundaries before the build/install validation path.
- Hardened local file handling so reports and exports refuse symlink targets, rewrite helper files are removed after use, and tracked-file scans skip symlinked or oversized text files.
- Added checkout bootstrap in `tests/conftest.py` so `pytest -q` and `python -m pytest -q` behave the same from a repository checkout.
- Hardened automatic fix preconditions so dirty worktrees, `git fsck` failures, or incomplete audits fail closed instead of mutating a repository mid-recovery.
- Replaced PID/timestamp stale-lock reclamation with OS-backed repository execution locks, disabled inherited stdin on repo-owned subprocesses, and isolated release-readiness temp/coverage artifacts per run.
- Reduced `exfil_code_indicators` advisory noise by preferring active outbound sinks and contextual review terms while ignoring detector scaffolding, import-only lines, and test-meta fixture content.
- Tightened Windows lock release diagnostics to read owner metadata from the active lock FD, and made release-readiness cleanup retry transient `dist/`/build artifact removal failures instead of aborting on the first file-handle race.

## [1.2.2] - 2026-04-15

Operations/readiness runbook update.

### Highlights

- Added a repository-owned `scripts/release_readiness.py` harness to run the practical local release path end-to-end from one command.
- Added `docs/OPERATIONS.md` and `docs/TROUBLESHOOTING.md` so local preflight, validation, recovery, and common failure handling are documented in one place.
- Moved temporary install-smoke virtual environments out of the repository tree so interrupted release checks do not leave stray working-tree noise behind.

### Validation

- `python -m pytest -q`
- `python scripts/release_readiness.py --skip-self-audit`
- `python -m Repo_Privacy_Guardian --help`
- `python Repo_Privacy_Guardian.py --help`
- `python -m build`

## [1.2.1] - 2026-04-14

Release-hardening dependency update.

### Highlights

- Raised the development/test `pytest` floor to `9.0.3` in both `pyproject.toml` and `config/requirements/requirements-dev.txt`.
- Cleared the open Dependabot alert for `CVE-2025-71176` / `GHSA-6w46-j5rx-g56g` affecting older `pytest` releases in development tooling.
- Preserved the runtime/local-first contract; this is a release-hygiene and security-maintenance patch only.

### Validation

- `python -m pytest -q`
- `python -m Repo_Privacy_Guardian --help`
- `python -m build`
- `python tests/release_smoke_cli.py`
- `python tests/release_smoke_gui.py`
- clean install of `config/requirements/requirements-dev.txt` in an isolated venv
- self-audit with `python -m Repo_Privacy_Guardian --root <repos> --repos <repo> --dry-run --yes --audit-github-hardening`

## [1.2.0] - 2026-04-14

Tooling readiness and bootstrap update.

### Highlights

- Expanded preflight checks so the tool can detect missing local prerequisites more explicitly across CLI and GUI paths.
- Added GUI-assisted optional installation flows for GitHub hardening helpers, including `gh` when GitHub hardening is enabled.
- Added Windows App Installer / `winget` bootstrap support so system-tool installation can remain as automatic as possible on end-user machines.
- Preserved the local-first and advisory defaults: GitHub hardening remains opt-in, and no remote service was introduced.

### Validation

- `python -m pytest -q`
- `python tests/release_smoke_cli.py`
- `python tests/release_smoke_gui.py`
- `python -m Repo_Privacy_Guardian --help`
- `python -m Repo_Privacy_Guardian --check-tooling --audit-github-hardening`
- `python -m build`

### Scope notes

- `gh` remains optional unless the operator wants fuller GitHub hardening coverage.
- On Windows, automatic system-tool installation now depends first on a healthy `winget` / App Installer path and can bootstrap that path when the platform supports it.

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
