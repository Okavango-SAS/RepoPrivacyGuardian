# LOCAL DEVELOPMENT

This guide is the shortest practical path to understand, run, and change Repo Privacy Guardian from a repository checkout.

## Public checkout rule

RepoPrivacyGuardian is already public. Treat every local change as a potential public internet artifact once it is committed or pushed.

Before staging, check `git status --short` and `git diff --check`. Stage only intentional source, test, documentation, and sanitized asset changes. Keep generated evidence and scratch material in ignored paths such as `Audit_Results/`, `.local-meta/`, `dist/`, `build/`, `*.egg-info/`, and `*-pre-publication-fix-*.bundle`.

Never commit raw secrets, private emails, internal hostnames, private URLs, personal absolute paths, unredacted logs, real tokens in examples, or screenshots that reveal private local context. Use `.env.example` for non-secret variable names and obvious placeholder values in tests/docs.

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
python scripts/check_release_contract.py
python -m ruff check .
pyright -p pyrightconfig.json
python -m pip_audit -r config/requirements/requirements-dev.txt
python -m pip_audit -r config/requirements/requirements-gui.txt
python -m pip_audit -r config/requirements/requirements-remediation.txt
python tests/release_smoke_cli.py
python -m Repo_Privacy_Guardian --help
```

Both `pytest -q` and `python -m pytest -q` are supported from a repository checkout.
Repo-owned smoke and subprocess-backed tests run non-interactively with bounded timeouts; keep new helper scripts the same way so local validation cannot hang an agent or CI runner.

Use the GUI smoke path only when a desktop session is available:

```sh
python tests/release_smoke_gui.py
```

For visual QA after desktop GUI changes, capture non-pixel-perfect screenshots:

```sh
python scripts/visual_qa_gui.py
```

Screenshots are written under `.local-meta/visual-qa/<run_id>/` and cover Audit, Reports, Prompts, and Repair in System, Light, and Dark modes.

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
- release contract alignment via `python scripts/check_release_contract.py`
- isolated pytest temp/coverage artifacts per validation run
- byte-compilation of packaged Python modules and release helper scripts
- `ruff check`
- `pyright -p pyrightconfig.json`
- tracked pytest suite
- CLI and GUI smoke scripts
- module and direct-script help paths
- `wheel` and `sdist` builds
- install smoke for both built artifacts
- `pip check` inside each isolated install-smoke environment
- final self-audit when the worktree is clean

## 4. Repository map

Start here when changing behavior:

- `Repo_Privacy_Guardian.py`: compatibility facade for entry points, direct execution, and `import Repo_Privacy_Guardian as rpg`
- `repo_privacy_guardian/`: internal implementation package for core orchestration, scanner/remediation, reporting, policy, redaction, tooling, GUI app/locale, runtime, artifacts, GitHub helpers, agent summary, strict profiles, suppressions, metrics, and prompts
- `repo_privacy_guardian_*.py`: root compatibility shims for imports kept stable in the `1.x` line
- `repo_privacy_guardian_assets/`: packaged raster assets used only by the optional GUI
- `tests/`: tracked regression tests plus release smoke coverage
- `scripts/release_readiness.py`: owned end-to-end local validation harness
- `repo_privacy_guardian_resources/POLICY.md`: packaged policy resource used by installed builds
- `docs/`: runbooks, architecture notes, policy, prompts, and release guidance

The repository root is intentionally small and allowlisted by release-hygiene tests. Keep support docs, prompts, requirements, scripts, screenshots, generated reports, build outputs, and agent scratch material in their documented subfolders instead of adding new tracked root files.

One-off maintenance prompts and scratch instructions should stay under `.local-meta/`, which is intentionally ignored. Keep only reusable operator prompts under `docs/prompts/`.

## 5. Where to document changes

Update the docs that are closest to the real behavior you changed:

- `README.MD`: entrypoint, install, usage, and repo-level navigation
- `docs/ARCHITECTURE.md`: code navigation and subsystem boundaries
- `docs/DOGFOODING.md`: audit-only workflow for using this repo against other repositories
- `docs/OPERATIONS.md`: operations and validation runbook
- `docs/TROUBLESHOOTING.md`: operator failure modes and recovery
- `docs/ENGINEERING_DECISIONS.md`: behavior changes that settle a design tradeoff
- `CHANGELOG.md`: public release notes only; use an `Unreleased` section until a version is cut

## 6. Current validation contract

The tracked repo-owned quality gate today is intentionally practical:

- `ruff check`
- `pyright` (runtime, artifacts, GitHub, and repo-owned support-script scope from `pyrightconfig.json`)
- `pip-audit` against dev, GUI, and remediation requirement files
- `pytest`
- smoke scripts
- packaging/build checks
- self-audit

The repo-owned typecheck command is `pyright -p pyrightconfig.json`. Keep any future typecheck expansion stable enough that it improves release confidence instead of adding noise.
