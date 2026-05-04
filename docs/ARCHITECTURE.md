# ARCHITECTURE

Repo Privacy Guardian now uses an internal package with compatibility facades for the stable `1.x` entry paths.

There are now four intentionally small support modules: the root compatibility shims for artifacts, GitHub, prompts, and runtime; their implementation lives inside the package.

The public compatibility contract remains:

- installed console script: `repo-privacy-guardian`
- module execution: `python -m Repo_Privacy_Guardian`
- direct script execution: `python Repo_Privacy_Guardian.py`
- import compatibility: `import Repo_Privacy_Guardian as rpg`
- root shim imports: `repo_privacy_guardian_artifacts`, `repo_privacy_guardian_github`, `repo_privacy_guardian_prompts`, and `repo_privacy_guardian_runtime`

`Repo_Privacy_Guardian.py` is now a facade. For imports, it aliases the real `repo_privacy_guardian.core` module so existing tests, scripts, and monkeypatch workflows still operate on the actual runtime globals. Direct execution still calls `main()`.

## Package Map

- `repo_privacy_guardian/core.py`: current CLI parser, shared pipeline, scanner/remediation engine, reporting, and optional desktop GUI coordinator
- `repo_privacy_guardian/artifacts.py`: run directories, `run.log`, `run_state.json`, report persistence helpers, and `agent_summary.json` path wiring
- `repo_privacy_guardian/runtime.py`: exit codes, run-status names, cancellation token, root validation, and target discovery
- `repo_privacy_guardian/github.py`: GitHub remote parsing, API access, owner/org discovery, clone orchestration, and release-hardening audit helpers
- `repo_privacy_guardian/prompts.py`: GUI/README prompt-card registry without importing desktop GUI dependencies
- `repo_privacy_guardian/agent_summary.py`: safe, compact agent handoff artifact and CLI handoff formatting
- `repo_privacy_guardian/strict_profiles.py`: documented `audit-only`, `internal`, and `release` profile normalization
- `repo_privacy_guardian/suppressions.py`: versioned advisory/manual-review suppression parsing and traceable application
- `repo_privacy_guardian/github_fix_guide.py`: non-mutating GitHub hardening checklist generation
- `repo_privacy_guardian/metrics.py`: phase and per-repository performance timing snapshots
- `repo_privacy_guardian_assets/`: packaged GUI raster assets
- `repo_privacy_guardian_resources/`: packaged policy resource used by installed builds

The package extraction is intentionally compatibility-first. The largest implementation surface still lives in `core.py` while behavior-sensitive seams are being extracted by domain. New logic should prefer small package modules when it has a clean boundary, but detection, policy, and GUI parity must remain coordinated through shared `GuardRunConfig`, `RepoReport`, and pipeline code.

## Execution Flow

Normal CLI flow:

1. `make_parser()` builds CLI arguments.
2. arguments normalize into `GuardRunConfig` through `build_cli_guard_run_config()` and `build_guard_run_config()`.
3. optional tooling preflight runs.
4. run artifacts are created under `Audit_Results/<run_id>/`.
5. `execute_guard_pipeline()` instantiates `RepoPublicationGuard`.
6. repositories are discovered, execution-locked one at a time, audited, optionally fixed, and re-audited.
7. strict profile and suppression post-processing is applied before status finalization.
8. JSON, HTML, log, `agent_summary.json`, and `run_state.json` are persisted.
9. `run_state.json` records phase timings and per-repository timing snapshots.

GUI flow uses the same backend pipeline, but keeps the companion-style staged contract:

1. `Audit`
2. review local evidence in `Reports`
3. copy CLI-first agentic workflows from `Prompts`
4. keep advanced parity controls in `Settings`
5. unlock `Repair` only after audit context exists

## Reporting Artifacts

Each run writes:

- `agent_summary.json`: privacy-safe summary for coding agents with status, counts, relative artifact names, blocking/advisory/fixture/suppression counts, and next action
- `report.json`: redacted structured report with full traceability, including `suppressed_findings` and GitHub hardening fix guide data when present
- `report.html`: human review report that starts with `Decision first`
- `run.log`: redacted execution log
- `run_state.json`: status manifest with phase and performance diagnostics

## Policy Surfaces

- Defaults remain unchanged when new flags are omitted.
- `--strict-profile audit-only` rejects `--fix` and `--push`.
- `--strict-profile internal` documents the current default policy posture.
- `--strict-profile release` treats low-confidence emails as blocking and treats GitHub hardening findings as blocking only when `--audit-github-hardening` was explicitly enabled.
- `--strict-profile release` does not enable network access by itself.
- `--suppressions PATH` can suppress only advisory/manual-review categories and always records redacted `suppressed_findings`.
- High-confidence secrets, path leaks, dirty worktrees, fsck failures, Git metadata blocking secrets, execution errors, and fix errors cannot be suppressed.

## Responsibility Boundaries

- Detection logic should stay separate from presentation logic.
- Shared runtime/config normalization should happen before CLI and GUI diverge.
- GUI behavior must call the same pipeline used by CLI instead of re-implementing audit/fix logic.
- Repository root validation and target discovery must stay shared between CLI and GUI.
- Run cancellation and exit-code/status semantics must stay shared so `run_state.json`, logs, and operator expectations do not drift.
- GitHub/network logic stays isolated from local audit/remediation flow.
- GUI localization and theme are presentation layers only.
- CLI/GUI parity is a repository rule and release-blocking for audit, report, GitHub hardening, remote-audit, locale-visible, and repair behavior.

## Visual QA

Desktop GUI changes should be visually checked with real screenshots, not only smoke tests. Use:

```sh
python scripts/visual_qa_gui.py
```

The script captures Audit, Reports, Prompts, and Repair tabs in System, Light, and Dark modes under `.local-meta/visual-qa/<run_id>/`, validates dimensions, and rejects blank screenshots. It is intentionally not a pixel-perfect CI gate.

## GitHub Hardening Governance

Repo Privacy Guardian does not mutate GitHub repository settings. Hardening findings include a non-mutating checklist in JSON, HTML, and agent summary context. Branch protection and rulesets must be configured manually in GitHub, then re-audited.

## Current Technical Debt

`repo_privacy_guardian/core.py` is still large. The refactor has moved import/runtime/artifact/GitHub/prompt/summary/profile/suppression/metrics responsibilities behind package boundaries while preserving the `1.x` public contract. Future extraction should continue by domain, with regression tests after each slice and no behavior drift in CLI/GUI parity.
