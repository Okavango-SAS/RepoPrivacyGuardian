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

- `repo_privacy_guardian/core.py`: compatibility runtime, shared dataclasses, CLI parser/config normalization, pipeline orchestration, GitHub remote-audit preparation, Git identity helpers, LiteLLM supply-chain helpers, and public reexports for compatibility
- `repo_privacy_guardian/artifacts.py`: run directories, `run.log`, `run_state.json`, report persistence helpers, and `agent_summary.json` path wiring
- `repo_privacy_guardian/runtime.py`: exit codes, run-status names, cancellation token, root validation, and target discovery
- `repo_privacy_guardian/github.py`: GitHub remote parsing, API access, owner/org discovery, clone orchestration, and release-hardening audit helpers
- `repo_privacy_guardian/prompts.py`: GUI/README prompt-card registry without importing desktop GUI dependencies
- `repo_privacy_guardian/config.py`: CLI parser construction, argument value parsing, comma/text normalization, GitHub owner/job normalization, and shared `GuardRunConfig` construction helpers
- `repo_privacy_guardian/evidence_taxonomy.py`: pure secret finding bucket classification and aggregation for tracked and historical scanner findings
- `repo_privacy_guardian/tooling.py`: CLI/GUI tooling preflight, optional local installer prompts, Windows App Installer / `winget` bootstrap helpers, and GitHub hardening auth readiness checks
- `repo_privacy_guardian/execution.py`: side-effecting subprocess and Git execution adapters for scanner operations, including checked commands, streaming `git log` process lifecycle, and `git-filter-repo` availability probes
- `repo_privacy_guardian/history_parsing.py`: pure Git history patch parsing and finding-format helpers for scanner history scans
- `repo_privacy_guardian/scanner.py`: `RepoPublicationGuard`, repository discovery, execution locks, deterministic scans, mechanical remediation execution, and re-audit behavior
- `repo_privacy_guardian/remediation.py`: replace-text rule planning, explicit operator mapping loading, history rewrite/purge planning, `git-filter-repo` command construction, and dry-run rewrite preview text
- `repo_privacy_guardian/redaction.py`: finding-context classification and redaction helpers for emails, email fixtures, identity tokens, secrets, URLs, and local paths
- `repo_privacy_guardian/reporting.py`: redacted JSON export, `Decision first` HTML rendering, report persistence, and sensitive-artifact warnings
- `repo_privacy_guardian/policy.py`: report severity classification, user-facing guidance, fix precondition checks, email remediation decisions, and LiteLLM incident severity helpers
- `repo_privacy_guardian/agent_summary.py`: safe, compact agent handoff artifact and CLI handoff formatting
- `repo_privacy_guardian/report_diff.py`: count-only `report.json` comparison for re-audit regression checks shared by CLI and GUI Reports
- `repo_privacy_guardian/strict_profiles.py`: documented `audit-only`, `internal`, and `release` profile normalization
- `repo_privacy_guardian/suppressions.py`: versioned advisory/manual-review suppression parsing and traceable application
- `repo_privacy_guardian/github_fix_guide.py`: non-mutating GitHub hardening checklist generation
- `repo_privacy_guardian/metrics.py`: phase and per-repository performance timing snapshots
- `repo_privacy_guardian/gui/app.py`: desktop `GuiApp` coordinator and staged Audit/Reports/Prompts/Settings/Repair workflow
- `repo_privacy_guardian/gui/locale.py`: GUI text catalogs, tooltips, and font-selection helpers
- `repo_privacy_guardian/gui/state.py`: pure Audit/Repair flow state helpers for GUI button labels, gate notes, repair summaries, collapsible-section visibility, and responsive Reports/Prompts layout decisions
- `repo_privacy_guardian_assets/`: packaged GUI raster assets
- `repo_privacy_guardian_resources/`: packaged policy resource used by installed builds

The package extraction is intentionally compatibility-first. `core.py` still reexports public names so existing tests, scripts, and monkeypatch workflows keep working, but behavior-sensitive seams now live in domain modules. New logic should prefer these package modules when it has a clean boundary, while detection, policy, and GUI parity remain coordinated through shared `GuardRunConfig`, `RepoReport`, and pipeline code.

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

`--compare-reports BEFORE_REPORT_JSON AFTER_REPORT_JSON` is a separate CLI utility path: it loads two existing redacted `report.json` artifacts, compares category fingerprints in memory, prints count-only deltas, and exits without creating a new audit run directory or touching repositories.

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

Re-audit comparison is derived from existing `report.json` artifacts. The public CLI/GUI summary contains repository counts, category deltas, status-change counts, and next action only; raw finding values are not printed or copied.

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

Repo Privacy Guardian does not mutate GitHub repository settings. Hardening findings include a non-mutating checklist in JSON, HTML, and agent summary context. Branch protection and rulesets must be configured manually in GitHub, then re-audited. The protected-branch baseline is explicit: pull request review, CODEOWNERS review when present, stale-review dismissal, conversation resolution, strict automatic CI status checks, admin enforcement, and disabled force-push/deletion.

## Current Technical Debt

`repo_privacy_guardian/core.py` is no longer the 12k-line monolith, but it remains the compatibility nexus for the `1.x` public API. The bridge cleanup moved `config`, `redaction`, `tooling`, `reporting`, `policy`, `remediation`, `scanner`, and `gui/app` from broad core star imports or core-owned helpers to explicit dependencies, and `gui/locale` now owns its locale identifiers and shared GUI text constants. Config, evidence taxonomy, execution, history parsing, reporting, policy, remediation, scanner, GUI app, GUI locale, and GUI state also import cleanly as standalone modules instead of relying on partially initialized core cycles. Remediation now owns the pure `git-filter-repo` rewrite command plan, execution owns the side-effecting subprocess/Git adapters used by scanner, history parsing owns pure `git log -p` line parsing and finding formatting, evidence taxonomy owns the bucket aggregation for high-confidence, low-confidence, fixture, and documentation secret findings, and GUI state owns pure Audit/Repair button, gate-state, collapsible-section visibility, and Reports/Prompts responsive layout decisions. The remaining debt is to keep moving GUI widget construction helpers out of the compatibility nexus once each slice has domain-level tests. Future extraction should continue by small slices with regression tests after each slice and no behavior drift in CLI/GUI parity.
