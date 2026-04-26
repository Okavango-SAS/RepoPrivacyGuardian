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
- Decision: move GUI and CLI runtime to a single shared pipeline function and keep run settings symmetric across interfaces.
- Rationale: removes duplicated flow logic and prevents future feature drift.

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
| GitHub owner/org remote audit inputs | Yes | Yes | No |
| GitHub owner/org audit-only enforcement | Yes | Yes | No |

### Implementation summary

- Added `GuardRunConfig` and `execute_guard_pipeline()` as the canonical execution path for both interfaces.
- Added `build_run_settings()` to normalize persisted run metadata.
- Added `parse_positive_int()` so GUI and CLI validate `max_matches` with the same rule.
- Added shared `build_guard_run_config()` so CLI and GUI normalize/infer run options through one path.
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
- Added parity regression tests for argument validation, defaults, confirmation gate, fix/re-audit flow, and runtime error handling.

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

## DEC-010 - Public release defaults are CLI-first and side-effect free

- Status: accepted
- Decision: running the tool without flags prints CLI help instead of launching the GUI, and CLI browser opening is opt-in via `--open-report`.
- Rationale: the public release target is automation-friendly desktop and headless CLI use. Auto-launching a GUI or browser from the default path is surprising, harder to script, and brittle in CI or remote shells.
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
  - `dev` bundles test and release tooling.

## Future candidates

- DEC-012: scoped allowlists to reduce false positives.
- DEC-013: optional HTML report renderer.
- DEC-014: policy profiles by organization.
