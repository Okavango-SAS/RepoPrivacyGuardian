# LOCAL DEVELOPMENT

This guide is the shortest practical path to understand, run, and change Repo Privacy Guardian from a repository checkout.

## Public checkout rule

RepoPrivacyGuardian is already public. Treat every local change as a potential public internet artifact once it is committed or pushed.

Before staging, check `git status --short` and `git diff --check`. Stage only intentional source, test, documentation, and sanitized asset changes. Keep generated evidence and scratch material in ignored paths such as `Audit_Results/`, `.local-meta/`, `.coverage*`, `dist/`, `build/`, `*.egg-info/`, and `*-pre-publication-fix-*.bundle`.

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

### Repo-linked Codex skill

The maintained [Codex skill](../codex/skills/repo-privacy-guardian/SKILL.md) is an adapter to the existing CLI. From the repository root, install or refresh it with PowerShell:

```powershell
./scripts/dev/install_codex_skill.ps1 -WhatIf
./scripts/dev/install_codex_skill.ps1
./scripts/dev/install_codex_skill.ps1 -Force -WhatIf
./scripts/dev/install_codex_skill.ps1 -Force
```

The installer uses `CODEX_HOME/skills` when configured, otherwise the user profile's `.codex/skills`; `-CodexHome` selects another Codex home. Relative filesystem inputs follow the current PowerShell `Set-Location` location. `-WhatIf` previews without changing files. Existing installations require `-Force`, which prepares and validates a sibling staging copy before replacing this skill's installed files. Handled copy, metadata, or swap failures preserve or restore the previous copy. The checkout link belongs only in the installed `.local/install.json`; never copy personal paths or that metadata into tracked files.

An abrupt process or machine termination between directory moves can leave a
sibling `.repo-privacy-guardian.backup-*` directory. Inspect and preserve that
local backup until the installed skill and link have been verified. Replacement
handles normal failures with rollback; it does not claim crash-atomic recovery.
If another process creates a destination during the swap, the installer preserves
that destination and the previous copy's recovery backup rather than overwriting
either. Unicode paths and interpreter-probe output use UTF-8 consistently.

The resolver prefers a RepoPrivacyGuardian checkout in the current workspace or its parents, then valid installed metadata, then `REPO_PRIVACY_GUARDIAN_REPO`, then the console CLI on PATH. After installation, open a new Codex chat and invoke `$repo-privacy-guardian` with an explicit target and audit-only scope. See the [README setup](../README.MD#codex-skill-linked-to-this-checkout) and [dogfooding runbook](DOGFOODING.md#codex-skill-targets-and-evidence) for usage and artifact placement.

For checkout execution, the resolver probes local virtual-environment and PATH
Python candidates non-interactively with a bounded timeout and requires Python
3.10 or newer. A broken or unsupported candidate is skipped in favor of the next
usable candidate. Resolution does not install dependencies or change persistent
configuration; run the resulting argument array from the returned working
directory.

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

Active CLI repair batches defer repeated Ctrl+C until the next Git-safe boundary
and preserve abort evidence after the batch returns. Read-only audits retain
ordinary interruption cleanup and cooperative cancellation polling. Keep native
process signal/boundary regressions platform-aware; a skipped POSIX case on
Windows is not evidence that the POSIX path passed locally.

`tests/test_codex_skill.py` covers installer previews, staged replacement and
rollback, checkout linking, provider-relative paths, interpreter probes, and
resolver precedence/fallbacks. Its subprocess regressions exercise available
`pwsh` and `powershell` runtimes and skip when neither is available. Fallback
fixtures explicitly isolate checkout ancestry, so an in-checkout `--basetemp`
does not change the expected backend priority.

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
- isolated install smoke for both built artifacts, from empty working directories outside the source checkout with source-injecting `PYTHONPATH` removed
- installed import-origin, module/console entry-point, packaged-policy, and all eight bilingual prompt-hash checks
- `pip check` inside each isolated install-smoke environment
- final self-audit when the worktree is clean

## 4. Repository map

Start here when changing behavior:

- `Repo_Privacy_Guardian.py`: compatibility facade for entry points, direct execution, and `import Repo_Privacy_Guardian as rpg`
- `repo_privacy_guardian/`: internal implementation package for core orchestration, CLI/config normalization, scanner execution, remediation planning, reporting, policy, redaction, tooling, GUI app/locale, runtime, artifacts, GitHub helpers, agent summary, strict profiles, suppressions, metrics, and prompts
- `repo_privacy_guardian_*.py`: root compatibility shims for imports kept stable in the `1.x` line
- `repo_privacy_guardian_assets/`: packaged raster assets used only by the optional GUI
- `tests/`: tracked regression tests plus release smoke coverage
- `codex/skills/repo-privacy-guardian/`: portable Codex skill, backend resolver, and reviewed-operation reference
- `scripts/dev/install_codex_skill.ps1`: installs the maintained skill and creates its local-only checkout link
- `scripts/benchmark_large_history.py`: local synthetic benchmark for history-scan timings from `run_state.json`
- `scripts/release_readiness.py`: owned end-to-end local validation harness
- `repo_privacy_guardian_resources/POLICY.md`: packaged policy resource used by installed builds
- `build_helpers.py`: deterministic build support that generates packaged prompts from the canonical registry-selected files under `docs/prompts/`; do not maintain a second tracked copy of those texts
- `scripts/check_artifact_install.py`: isolated artifact-install origin/resource/entry-point validator shared by CI and the local harness
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

Scanner statement coverage includes `RepoPublicationGuard`; keep the existing
80% global gate and use behavior tests rather than broad exclusions. Isolate
coverage output for concurrent validation runs. `run_state.json` metrics add
metadata/tracked/history/fsck timings and bounded numeric workload counters;
elapsed failed or cancelled work remains recorded without storing finding values
or file bodies.

Automatic CI keeps equal, unique push/PR filters. Broad docs-only edits remain
local-first, while the eight canonical packaged prompt documents are explicit
runtime inputs and trigger smoke. Full tracked tests, package checks, and desktop
smoke retain their manual/local validation tiers.

### Scanner performance changes

Use synthetic workloads and preserve the baseline `run_state.json` path printed
by the benchmark. For a subsequent run, replace the quoted placeholder below with
that actual local evidence path:

```sh
python scripts/benchmark_large_history.py --commits 120 --files 8
python scripts/benchmark_large_history.py --commits 120 --files 8 --baseline-run-state "baseline-run-state-path" --max-regression-percent 25
```

Run at least three repetitions per baseline and changed corpus, use matched
commit/file counts, and compare medians. The helper checks timing regressions
against an optional percentage budget; it does not itself prove finding parity
or collect a complete memory profile. Compare normalized full reports and policy
outcomes separately, record peak-memory evidence alongside timings, and retain
optimization only when findings remain equivalent and measurements justify it.
Keep fixtures, profiling output, and benchmark artifacts under ignored local
paths. Audit-scoped caches must be rebuilt after repair and before re-audit;
never persist tracked bodies or detected values as a performance cache.
