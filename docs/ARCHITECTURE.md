# ARCHITECTURE

Repo Privacy Guardian is still intentionally centered on one Python module: `Repo_Privacy_Guardian.py`.

That is a tradeoff, not an accident. The repository optimizes for a self-contained CLI/Desktop tool with a small packaging surface. Maintainability depends on keeping clear section boundaries inside that file and documenting where each concern lives.

There are now three intentionally small support modules:

- `repo_privacy_guardian_runtime.py` for shared run-exit semantics plus root/target discovery helpers used by both CLI and GUI
- `repo_privacy_guardian_artifacts.py` for run-artifact creation, run-state persistence, and log-writing helpers shared by CLI and GUI flow
- `repo_privacy_guardian_github.py` for GitHub remote parsing, API access, and release-hardening audit helpers

They exist to remove high-risk runtime/preflight and network helper glue from the monolith without fragmenting the core audit/remediation engine.

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

2. Shared runtime helpers
- `repo_privacy_guardian_runtime.py`
- root validation, target discovery, cancellation token, and stable exit-code/status mapping

3. Run artifact and state helpers
- `repo_privacy_guardian_artifacts.py`
- run directory creation, `run_state.json` persistence, and report/log export helpers

4. GitHub/network helpers
- `repo_privacy_guardian_github.py`
- GitHub remote parsing, auth token resolution, API request helpers, and hardening audit logic

5. Tooling readiness and install helpers
- `ToolingCheck`
- `build_cli_tooling_checks()`
- `build_gui_tooling_checks()`
- install/bootstrap helpers for Git, `git-filter-repo`, `gh`, and Windows `winget`

6. Core report and runtime models
- `CommandResult`
- `GuardRunConfig`
- `RepoReport`

7. Audit and remediation engine
- `RepoPublicationGuard`
- repository discovery
- content/history scanning
- `.gitignore` baseline enforcement
- remediation planning and execution

8. Reporting and export layer
- CLI summaries
- JSON sanitization
- HTML report rendering
- run artifact persistence

9. Shared execution pipeline
- `build_guard_run_config()`
- `execute_guard_pipeline()`

10. Optional GUI wrapper
- `GuiApp`
- GUI state management, audit/repair staging, and parity wiring

11. CLI/parser entrypoint
- `make_parser()`
- `run_cli()`
- `main()`

## Responsibility boundaries

Keep these boundaries intact when editing:

- Detection logic should stay separate from presentation logic.
- Shared runtime/config normalization should happen before CLI and GUI diverge.
- GUI behavior should call the same pipeline used by CLI instead of re-implementing audit/fix logic.
- Repository root validation and target discovery should stay shared between CLI and GUI to preserve `Current Root` parity and error semantics.
- Run cancellation and exit-code/status semantics should stay shared between CLI and GUI so `run_state.json`, logs, and operator expectations do not drift.
- GitHub/network logic should stay isolated from local audit/remediation flow so transport/typecheck changes do not churn unrelated CLI/GUI code.
- GUI localization is a presentation layer only. Locale catalogs translate desktop labels, dialogs, and help copy while shared config names, CLI flags, report fields, and policy keys remain canonical.
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
- CLI/GUI parity is a repository rule: new behavior must stay mapped through the shared runtime/config/report path or be documented as a non-behavioral presentation/launcher exception.

## Current technical debt

The largest structural debt is still the single-file implementation. That is acceptable for the current scope, but future refactors should only extract modules when they improve clarity without splitting tightly coupled policy/runtime logic across too many files.
