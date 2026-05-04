# ENGINEERING DECISIONS

This file captures key design decisions and their rationale.

## DEC-001 - Dual interface (CLI + GUI)

- Status: accepted
- Decision: provide both CLI and simple desktop GUI.
- Rationale: CLI is better for automation; GUI lowers adoption barrier for manual operators.

## DEC-002 - JSON report as source of truth

- Status: accepted
- Decision: every run writes a machine-readable JSON report.
- Rationale: enables reproducibility, post-processing, and audit trail.

## DEC-003 - Explicit risk gates for destructive actions

- Status: accepted
- Decision: history rewrites and broad purges require explicit flags.
- Rationale: minimizes accidental destructive operations.

## DEC-004 - Conservative secret auto-purge policy

- Status: accepted
- Decision: auto-purge only safe filename candidates by default.
- Rationale: reduces risk of deleting legitimate files with ambiguous names.

## DEC-005 - Local policy and local output defaults

- Status: accepted
- Decision: default policy path points to docs/POLICY.md and default outputs to local Audit_Results.
- Rationale: self-contained repo behavior and fewer environment-specific assumptions.

## DEC-006 - Keep backups as first-class fix step

- Status: accepted
- Decision: create bundle backup before any rewrite/fix operation.
- Rationale: guarantees rollback option even in disconnected scenarios.

## DEC-007 - GUI/CLI parity through a shared execution pipeline

- Status: accepted
- Decision: move GUI and CLI runtime to a single shared pipeline function and keep run settings symmetric across interfaces. CLI/GUI parity is a repository rule and release-blocking invariant.
- Rationale: removes duplicated flow logic, prevents future feature drift, and preserves operator choice without creating separate product semantics.

### Repo Rule

Every new audit, report, GitHub hardening, remote-audit, locale-visible, or repair behavior must:

- expose equivalent operator control in CLI and GUI;
- map to the same internal configuration, policy, and report fields;
- preserve the same artifact semantics for JSON, HTML, and log output;
- keep destructive-action guardrails equivalent across interfaces;
- add or update regression coverage for parser/config mapping and GUI run-config mapping.

Presentation-only GUI features and launcher-only CLI flags are permitted only when they are documented as non-behavioral exceptions and cannot affect `GuardRunConfig`, policy keys, report schemas, or remediation semantics.

### Parity matrix (before)

| Capability | CLI | GUI | Gap |
| --- | --- | --- | --- |
| Audit/fix flow and re-audit | Yes | Yes | No |
| Dry-run behavior | Yes | Yes | No |
| Secret purge flags | Yes | Yes | Minor (different warning text path) |
| Report artifacts JSON/LOG/HTML | Yes | Yes | No |
| `public_only` default | False | True | Yes |
| Repo scope when filters are omitted | All repos under root | Required explicit selection | Yes |
| `max_matches` configurability | Yes (`--max-matches`) | No (fixed at 50) | Yes |
| Extra JSON export | Yes (`--report-json`) | No | Yes |
| Report output directory selection | Yes (`--report-dir`) | No | Yes |
| Runtime pipeline implementation | Dedicated CLI code path | Dedicated GUI code path | Yes |

### Parity matrix (after)

| Capability | CLI | GUI | Gap |
| --- | --- | --- | --- |
| Audit/fix flow and re-audit | Yes | Yes | No |
| Dry-run behavior | Yes | Yes | No |
| Secret purge flags | Yes | Yes | No |
| Report artifacts JSON/LOG/HTML | Yes | Yes | No |
| `public_only` default | False | False | No |
| Repo scope when filters are omitted | All repos under root | All repos under root (with explicit confirmation) | No |
| `max_matches` configurability | Yes | Yes | No |
| Extra JSON export | Yes | Yes | No |
| Report output directory selection | Yes | Yes | No |
| Runtime pipeline implementation | Shared | Shared | No |
| `GuardRunConfig` runtime fields | Shared builder + parser adapter | Shared builder + GUI adapter | No |
| GitHub owner/org remote audit inputs | Yes | Yes | No |
| GitHub owner/org audit-only enforcement | Yes | Yes | No |

### Implementation summary

- Added `GuardRunConfig` and `execute_guard_pipeline()` as the canonical execution path for both interfaces.
- Added `build_run_settings()` to normalize persisted run metadata.
- Added `parse_positive_int()` so GUI and CLI validate `max_matches` with the same rule.
- Added shared `build_guard_run_config()` so CLI and GUI normalize/infer run options through one path.
- Added `build_cli_guard_run_config()` so parser-to-runtime mapping is testable without executing a run.
- Added field-level regression coverage that compares every shared `GuardRunConfig` dataclass field from CLI and GUI repair inputs; `mode` is the only intentional value difference.
- Extended GUI inputs with:
  - results directory
  - optional extra JSON export path
  - max matches
- Extended GUI parity controls with:
  - open report toggle (`open_report` parity with CLI `--open-report`)
  - per-repository repair confirmation toggle (`confirm_each_repo_fix` parity)
  - push owner guardrail options (`allow_non_owner_push` and `allowed_remote_owners` parity)
  - GitHub owner/org remote audit controls (`github_owner`, remote repo filters, include forks, shallow clone, clone workers, and public-only filtering parity)
- Updated GUI interaction model with:
  - tabbed workflow (`Audit` and `Repair`) to reduce single-page overload
  - action separation (audit button in `Audit`, repair button in `Repair`)
  - visual repair-tab lock overlay until a valid audit has produced actionable context
- Explicit GUI interaction contract:
  - `Audit` is the mandatory first step of every GUI run.
  - `Repair` remains visually locked until audit context is valid and actionable.
  - Once unlocked, repair behavior preserves CLI-equivalent remediation semantics.
- Aligned GUI `public_only` default with CLI default.
- Aligned GUI repository scope behavior with CLI: if no repository filter is provided, run all repositories under root after explicit confirmation.
- Aligned GUI GitHub owner/org mode with CLI: remote audits are opt-in, use the shared scanner pipeline through temporary clones, and remain audit-only with repair locked in the GUI.
- Reduced first-screen overload without changing parity by persisting non-secret GUI setup preferences, collapsing policy/output/GitHub/identity controls into Settings, and keeping all run-config mappings unchanged.
- Added optional repository-folder drag-and-drop as a target-selection shortcut; Browse/Refresh and CLI `--root/--repos` remain the canonical fallback paths.
- Clarified the GUI target surface for GitHub owner/org mode so local repository validation errors do not compete with an active remote audit target, and the Repair review summary distinguishes blocking, advisory/manual-review, and safe fixture/documentation context.
- Added centralized contextual help for non-obvious GUI controls, using hover tooltips and visible `i` badges in advanced Settings and Repair areas without changing run-config mappings.
- Added presentation-only GUI localization with English and Spanish (Latin America) catalogs. Locale is persisted as non-secret GUI state and must not rename CLI flags, report fields, policy keys, or shared `GuardRunConfig` mappings.
- Added parity regression tests for argument validation, defaults, confirmation gate, fix/re-audit flow, runtime error handling, and full shared run-config mapping.

### Residual risk and follow-up

- GUI still depends on Tkinter widgets and thread scheduling; functional behavior is aligned but direct widget-level tests remain out of scope.
- Keep parity tests mandatory on every change touching parser flags or execution flow.

## DEC-008 - Exfil indicators stay advisory by default

- Status: accepted
- Decision: `exfil_code_indicators` remains a manual-review advisory signal by default.
- Rationale: outbound/exfil heuristics intentionally cast a wide net (`requests`, `urllib`, telemetry/webhook keywords, literal URLs). They are useful to raise operator attention but too broad to change PASS/FAIL safely without stricter semantics and narrower signal quality.
- Implementation notes:
  - report guidance and severity highlights must mention the advisory/manual-review contract;
  - JSON, HTML, CLI and GUI views must surface the signal consistently;
  - a future strict mode can promote the signal, but the default release contract does not.

## DEC-009 - Pytest release signal must come only from tracked tests

- Status: accepted
- Decision: release validation must be reproducible from a clean clone, and `pytest` collection must ignore local-only/untracked test files.
- Rationale: local ignored tests can make the workspace look healthier than `HEAD`, which breaks release trust and CI parity.
- Implementation notes:
- meaningful coverage must live under tracked `tests/`;
- collection should not depend on editor scratch tests or ignored local files;
- minimal CI must execute the same tracked suite from a clean checkout.

## DEC-010 - Default entrypoints are CLI-first and side-effect free

- Status: accepted
- Decision: running the tool without flags prints CLI help instead of launching the GUI, and CLI browser opening is opt-in via `--open-report`.
- Rationale: the primary automation target is desktop and headless CLI use. Auto-launching a GUI or browser from the default path is surprising, harder to script, and brittle in CI or remote shells.
- Implementation notes:
  - `--gui` is required for desktop mode;
  - GUI dependencies remain optional and lazily imported;
  - missing GUI or display prerequisites must fail with actionable messages instead of stack traces or hangs.

## DEC-011 - Packaging separates CLI, GUI, remediation, and development concerns

- Status: accepted
- Decision: the base install is CLI-only, with separate extras for GUI and remediation.
- Rationale: CLI users should not be forced to install desktop dependencies, and rewrite dependencies should only be required when destructive remediation is explicitly requested.
- Implementation notes:
  - base install remains minimal;
  - `gui` extra enables desktop dependencies;
  - `remediation` extra enables rewrite tooling;

## DEC-012 - GUI is a CLI companion, not a second control plane

- Status: accepted
- Decision: rebuild the GUI presentation around `Audit`, `Reports`, `Prompts`, `Settings`, and gated `Repair` tabs while preserving the same backend pipeline and `GuardRunConfig` parity.
- Rationale: the primary automation use case is agentic CLI execution. The desktop UI should make manual audit, evidence review, prompt copying, and reviewed repair easier without exposing a separate product semantics surface.
- Implementation notes:
  - `Audit` keeps target selection, drag-and-drop, run, stop, refresh, and execution log visible;
  - `Reports` opens the latest local JSON/HTML/log/run-state artifacts without rendering raw sensitive evidence in the GUI;
  - `Prompts` reads the tracked bilingual prompt registry and copies CLI-first workflows for agentic IDEs;
  - `Settings` contains advanced parity controls that still map to the same internal fields;
  - `Repair` remains locked until a valid audit context exists, and advanced write toggles start collapsed.
  - `dev` bundles test and release tooling.

## DEC-013 - Internal package with compatibility facades

- Status: accepted
- Decision: move implementation behind the internal `repo_privacy_guardian/` package while keeping `Repo_Privacy_Guardian.py` and root support modules as compatibility facades/shims.
- Rationale: the previous single-file/root-module shape made domain extraction difficult, but `1.x` users and tests rely on stable entry paths and imports.
- Implementation notes:
  - `import Repo_Privacy_Guardian as rpg` aliases the real `repo_privacy_guardian.core` module so monkeypatch and scripting workflows still affect runtime globals;
  - root shim modules alias their package modules for the same reason;
  - new bounded domains live in package modules for artifacts, GitHub, prompts, runtime, agent summary, strict profiles, suppressions, metrics, and GitHub fix-guide generation;
  - `Repo_Privacy_Guardian.py` remains valid for direct script execution and `python -m Repo_Privacy_Guardian`.

## DEC-014 - Agent summary, strict profiles, and traceable suppressions are additive policy surfaces

- Status: accepted
- Decision: add `agent_summary.json`, `--agent-summary`, `--strict-profile`, `--suppressions`, `Decision first`, GitHub hardening fix guide, and performance timings without changing defaults when flags are omitted.
- Rationale: agent-first workflows need a compact safe handoff, release workflows need documented stricter presets, and accepted advisory findings need traceability rather than disappearing from reports.
- Implementation notes:
  - `agent_summary.json` is written for every run and uses relative artifact names;
  - `--agent-summary` prints a compact safe handoff;
  - `--strict-profile release` does not enable network access by itself;
  - suppressions can affect only advisory/manual-review categories and keep redacted `suppressed_findings`;
  - high-confidence secrets, path leaks, dirty trees, fsck failures, Git metadata blocking findings, execution errors, and fix errors are not suppressible;
  - GitHub hardening remains read-only and produces a manual fix guide instead of mutating repository settings.

## Future candidates

- Scoped allowlists to reduce false positives beyond suppression files.
- Further extraction of `repo_privacy_guardian/core.py` into scanner, policy, remediation, reporting, and GUI subpackages.
- Optional policy profiles by organization.
