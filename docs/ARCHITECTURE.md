# ARCHITECTURE

Repo Privacy Guardian is still intentionally centered on one Python module: `Repo_Privacy_Guardian.py`.

That is a tradeoff, not an accident. The repository optimizes for a self-contained CLI/Desktop tool with a small packaging surface. Maintainability depends on keeping clear section boundaries inside that file and documenting where each concern lives.

## Runtime surfaces

The project exposes three practical entry paths:

- installed console script: `repo-privacy-guardian`
- module execution: `python -m Repo_Privacy_Guardian`
- direct compatibility path: `python Repo_Privacy_Guardian.py`

All of them converge on the same parser and shared execution pipeline.

## Code map inside `Repo_Privacy_Guardian.py`

Read the file in this order when orienting yourself:

1. Defaults and policy constants
- default paths, ignore baseline, network/auth constants, and core regex rules

2. Tooling readiness and install helpers
- `ToolingCheck`
- `build_cli_tooling_checks()`
- `build_gui_tooling_checks()`
- install/bootstrap helpers for Git, `git-filter-repo`, `gh`, and Windows `winget`

3. Core report and runtime models
- `CommandResult`
- `RunArtifacts`
- `GuardRunConfig`
- `RunLogger`
- `RepoReport`

4. Audit and remediation engine
- `RepoPublicationGuard`
- repository discovery
- content/history scanning
- `.gitignore` baseline enforcement
- remediation planning and execution

5. Reporting and export layer
- CLI summaries
- JSON sanitization
- HTML report rendering
- run artifact persistence

6. Shared execution pipeline
- `build_guard_run_config()`
- `execute_guard_pipeline()`

7. Optional GUI wrapper
- `GuiApp`
- GUI state management, audit/repair staging, and parity wiring

8. CLI/parser entrypoint
- `make_parser()`
- `run_cli()`
- `main()`

## Responsibility boundaries

Keep these boundaries intact when editing:

- Detection logic should stay separate from presentation logic.
- Shared runtime/config normalization should happen before CLI and GUI diverge.
- GUI behavior should call the same pipeline used by CLI instead of re-implementing audit/fix logic.
- Repository root validation and target discovery should stay shared between CLI and GUI to preserve `Current Root` parity and error semantics.
- Policy defaults should be expressed once in code and reused by smoke tests or fixtures where possible.

## Execution flow

Normal CLI flow:

1. parser builds arguments
2. arguments normalize into `GuardRunConfig`
3. tooling preflight runs when requested
4. run artifacts are created under `Audit_Results/<run_id>/`
   a local `run_state.json` manifest is updated as phases progress so interrupted runs still leave diagnosable state
5. `execute_guard_pipeline()` instantiates `RepoPublicationGuard`
6. repositories are discovered, execution-locked one at a time with an OS-backed lock file, and audited
7. optional fix path executes only when explicitly requested
8. reports are persisted and optionally opened

GUI flow uses the same backend pipeline, but keeps the visible staged contract:

1. `Audit`
2. review findings and plan
3. `Repair` only after audit context unlocks it

## Operationally important files outside the main module

- `tests/`: tracked regression and release smoke coverage
- `scripts/release_readiness.py`: repository-owned end-to-end local validation harness
- `docs/POLICY.md`: source-of-truth policy document in the repo
- `repo_privacy_guardian_resources/POLICY.md`: packaged copy of the policy for installed builds
- `config/requirements/`: compatibility requirement manifests for users who prefer requirements files over extras

## Design constraints worth preserving

- Local-first behavior is the default.
- Network access stays opt-in and documented.
- Destructive operations require explicit flags.
- Reports are treated as sensitive local artifacts.
- CLI remains the primary contract; GUI is a parity wrapper, not a separate product surface.

## Current technical debt

The largest structural debt is still the single-file implementation. That is acceptable for the current scope, but future refactors should only extract modules when they improve clarity without splitting tightly coupled policy/runtime logic across too many files.
