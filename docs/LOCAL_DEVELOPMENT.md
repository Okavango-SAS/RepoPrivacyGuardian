# LOCAL DEVELOPMENT

This guide is the shortest practical path to understand, run, and change Repo Privacy Guardian from a repository checkout.

## 1. Setup

Install the local development dependencies from the repository root:

```sh
python -m pip install ".[dev]"
```

If you are validating a fresh machine or a new shell, start with:

```sh
python -m Repo_Privacy_Guardian --help
python -m Repo_Privacy_Guardian --check-tooling
```

Optional GitHub hardening auth variables are documented in the tracked `.env.example` reference file, but the tool does not auto-load it.

## 2. Fast local loops

Useful commands during day-to-day work:

```sh
pytest -q
python -m pytest -q
python tests/release_smoke_cli.py
python -m Repo_Privacy_Guardian --help
```

Both `pytest -q` and `python -m pytest -q` are supported from a repository checkout.

Use the GUI smoke path only when a desktop session is available:

```sh
python tests/release_smoke_gui.py
```

## 3. Full repository-owned validation

Before tagging or shipping artifacts, run the repository harness:

```sh
python scripts/release_readiness.py
```

Helpful variants:

```sh
python scripts/release_readiness.py --skip-gui-smoke
python scripts/release_readiness.py --skip-self-audit
```

The harness currently validates:

- CLI tooling preflight
- byte-compilation of the main module
- tracked pytest suite
- CLI and GUI smoke scripts
- module and direct-script help paths
- `wheel` and `sdist` builds
- install smoke for both built artifacts
- `pip check` inside each isolated install-smoke environment
- final self-audit when the worktree is clean

## 4. Repository map

Start here when changing behavior:

- `Repo_Privacy_Guardian.py`: main CLI, audit engine, remediation flow, reporting, and optional GUI
- `tests/`: tracked regression tests plus release smoke coverage
- `scripts/release_readiness.py`: owned end-to-end validation harness for local release readiness
- `repo_privacy_guardian_resources/POLICY.md`: packaged policy resource used by installed builds
- `docs/`: runbooks, architecture notes, policy, prompts, and release guidance

## 5. Where to document changes

Update the docs that are closest to the real behavior you changed:

- `README.MD`: entrypoint, install, usage, and repo-level navigation
- `docs/ARCHITECTURE.md`: code navigation and subsystem boundaries
- `docs/OPERATIONS.md`: release/readiness runbook
- `docs/TROUBLESHOOTING.md`: operator failure modes and recovery
- `docs/ENGINEERING_DECISIONS.md`: behavior changes that settle a design tradeoff
- `CHANGELOG.md`: public release notes only; use an `Unreleased` section until a version is cut

## 6. Current validation contract

The tracked repo-owned quality gate today is intentionally practical:

- `pytest`
- smoke scripts
- packaging/build checks
- self-audit

There is no separate repo-owned lint or typecheck command yet. If you add one in the future, keep it stable enough that it improves release confidence instead of adding noise.
