# CHANGELOG

All notable user-facing changes to this project are documented here.

## [Unreleased]

### Added

- Added a reviewed network-context bucket so Repo Privacy Guardian's own GitHub API probes and Windows App Installer bootstrap command remain traceable without keeping self-audits in manual-review state.
- Added a count-only report comparison workflow for re-audits: CLI `--compare-reports` and a GUI Reports action compare the latest `report.json` with an earlier run without exposing raw finding evidence.
- Added dark-mode GUI screenshots to the README desktop preview with neutral visible paths.
- Added safe email fixture buckets for tracked and historical test/fixture email examples so strict release profiles keep traceability without blocking on intentional test data.
- Added `--accept-github-admin-bypass` and matching GUI control so solo-maintainer repositories can record administrator branch-protection bypass as an accepted GitHub hardening risk.
- Clarified the GitHub hardening fix guide and release docs around the exact protected-branch baseline, including admin enforcement and the current automatic CI smoke check.

### Changed

- Consolidated the historical UX/UI audit notes into a current visual QA record and removed obsolete tracked before-state screenshots.
- Reduced compatibility-bridge coupling in the config, redaction, tooling, reporting, policy, remediation, scanner, GUI app, and GUI locale modules by replacing broad core star imports or core-owned constants with explicit dependencies while preserving public facades.
- Moved `git-filter-repo` rewrite command construction into remediation planning helpers so dry-run previews and real rewrite commands stay covered by focused contract tests.
- Extracted scanner Git/subprocess execution into a dedicated adapter with contract coverage for cwd, stdin, checked failures, streaming `git log` process lifecycle, `git-filter-repo` probing, and dry-run rewrite behavior.
- Extracted pure scanner history patch parsing and finding formatting into a dedicated helper module with edge-case coverage for diff targets, patch line filtering, email findings, and active secret-file detection.
- Extracted tracked/history secret taxonomy bucket aggregation into a dedicated helper module with parity coverage for high-confidence, low-confidence, fixture, and documentation findings.
- Extracted pure GUI Audit/Repair flow state helpers for button labels, gate notes, and repair summaries while preserving the existing widget behavior.
- Extracted pure GUI collapsible-section state helpers for Settings, Repair options, and advanced identity visibility while preserving widget layout behavior.
- Extracted pure GUI responsive layout helpers for Reports decision steps, Reports artifact-action visibility, and the Prompts workflow guide while preserving widget behavior.
- Extracted pure GUI option checkbox specs for GitHub remote settings and Repair option rows while preserving labels, tooltips, bindings, and layout.
- Extracted pure GitHub hardening payload classifiers for findings, warnings, accepted risks, and redacted normalization while preserving the read-only audit behavior.
- Ignored Windows coverage shard files such as `.coverage.<host>.<pid>.*` so local pytest/coverage runs do not leave publishable root clutter.
- Run the automatic CI smoke workflow for protected-branch pull requests as well as `main` pushes when executable, packaging, resource, test, or validation-tooling surfaces change.
- Kept docs-only changes out of automatic CI; they now rely on local release-contract validation plus manual `workflow_dispatch` smoke only when branch protection needs the check.

## [1.5.0] - 2026-05-04

### Added

- Added the internal `repo_privacy_guardian/` package while keeping stable entry paths and root shim imports compatible.
- Split the former monolith into a modular architecture with domain modules for scanner/remediation, reporting, redaction, tooling, GUI app/locale, artifacts, GitHub, runtime, prompts, agent summary, profiles, suppressions, and metrics while keeping `1.x` compatibility facades.
- Added `agent_summary.json` for every run plus `--agent-summary` for safe CLI handoff output.
- Added `--strict-profile audit-only|internal|release` and versioned `--suppressions` files for traceable advisory/manual-review suppressions.
- Added HTML `Decision first`, GitHub hardening fix guide output, and phase/per-repository timings in `run_state.json`.
- Added `scripts/visual_qa_gui.py` for desktop screenshots across System, Light, and Dark GUI modes.

### Changed

- Hardened the release-contract checker so stale README "current release" references are detected generically instead of through a manually maintained list of old versions.
- Hardened CI path filters and release-contract coverage for the modular package, GUI assets, packaged resources, and visual QA helper so future runtime changes trigger validation.
- Clarified the README agent-first mental model, GUI companion role, screenshot context, and SSH remote pseudo-email noise policy.
- Updated architecture, policy, operations, release, and versioning docs for the modular package and agent-first artifacts.

### Fixed

- Reduced email false positives by ignoring known SSH remote pseudo-users such as `git@github.com`, `git@gitlab.com`, and `git@bitbucket.org` while keeping real custom-domain emails reportable.
- Reworked compatibility facades so monkeypatch/import workflows operate on the real internal modules.

## [1.4.7] - 2026-05-04

System-aware GUI theme and agent-first UX hardening update.

### Changed

- Kept the GUI Reports empty state focused on the safe `Go to Audit` action instead of showing disabled artifact buttons before a run exists.
- Added a Reports next-action panel, safe agent handoff summary counts, and staged Prompt-card guidance so the desktop companion better matches the agent-first CLI workflow.
- Polished Spanish prompt-library copy in the GUI to avoid avoidable English UX fragments while preserving CLI flags and file names.
- Refined the desktop GUI visual flow after screenshot QA: Reports now reads as latest-run review, checklist guidance no longer looks like disabled controls, and invalid Root empty states include a direct folder-selection action.
- Improved compact desktop behavior for the GUI Reports and Prompts tabs so handoff steps stack cleanly and prompt descriptions use the available one-column width.
- Added visible `(i)` contextual-help badges to agent-first GUI sections and improved tooltip positioning near screen edges.
- Added a GUI `System` theme option, made it the default, and updates the desktop palette immediately when the OS or selector changes.

### Fixed

- Reflowed GUI Reports artifact actions on compact desktop widths so localized button text stays readable without competing with first-run guidance.

## [1.4.6] - 2026-05-01

Post-release GUI, locale, and cleanup hardening update.

### Changed

- Reframed the GUI first-screen hierarchy around the agent-first workflow: local audit, redacted evidence review, agent handoff, and gated repair.
- Added an Audit-screen shortcut into the GUI Prompts tab and a prompt-library guide that makes the agentic orchestration layer visible without changing CLI behavior.
- Made GUI prompt cards stack on compact widths so the agentic workflow remains readable near the minimum desktop size.
- Refreshed tracked GUI screenshots after the agent-first visual QA pass, keeping visible paths sanitized.
- Added a packaged GUI raster asset set for the window icon, header watermark, repository empty state, reports, prompts, repair gate visuals, and DPI-aware action icons.
- Adjusted the GUI Refresh action to secondary-button styling so its icon remains readable and added smoke coverage for visible Prompt cards.
- Added a presentation-only GUI theme selector for Light and Dark startup modes with settings persistence, locale-aware labels, dark-mode icon contrast, and parity coverage that keeps CLI flags, reports, and policy behavior unchanged.
- Blended themeable GUI pictogram backgrounds in memory on dark startup so packaged assets sit cleanly on dark panels without adding duplicate image files.
- Polished GUI scrollbar theming and the locked Repair state so light/dark screenshots stay quieter and the first Repair view no longer clips guidance.
- Added a localized empty state to the GUI execution log so the primary Audit screen is easier to read before the first run.
- Added a localized `Go to Audit` empty-state action in the GUI Reports tab so first-time users have a clear next step before any artifacts exist.
- Added a GUI Reports action to copy a privacy-safe agent handoff prompt with local artifact references for Codex, Claude Code, Cursor, GitHub Copilot, and similar IDE sessions.
- Changed GUI Reports artifact labels to prefer repository-relative paths, keeping the screen cleaner and avoiding visible personal absolute paths when artifacts live under the repo.
- Clarified the README opening and bilingual quick description so the agent-first CLI workflow is visible before deeper documentation sections.
- Refreshed the tracked GUI Reports screenshot and added it to the README preview so the public docs show the local evidence and agent-handoff workflow.
- Updated README attribution to reflect Okavango SAS as the project maintainer while preserving original author and CTO credit.
- Added a sanitized desktop GUI preview screenshot to the README.
- Refreshed the README desktop GUI preview screenshot against the current light-mode companion UI with neutral visible paths.
- Reordered and simplified README onboarding so audit scope appears earlier and repeated first-run guidance is reduced.
- Compacted the README agentic section into a prompt library to avoid repeating the first-run flow.
- Clarified README start paths by role and when optional installation extras are needed.
- Removed overly internal launch-preparation wording from public docs while preserving publication-gate guidance.
- Documented the desktop-adapted visual QA method for GUI work: keep `customtkinter`, use design tokens and real desktop screenshots, and reject web-app/React migration as a default path.

### Fixed

- Polished the Spanish (Latin America) GUI locale so visible labels, dialogs, contextual help, and agent handoff copy no longer mix avoidable English UX terms while preserving CLI flags, report fields, and technical product names.
- Fixed the GUI execution-log empty state so it renders above the log textbox in both light and dark mode.
- Fixed GUI responsive width detection on high-DPI Windows by normalizing Tk physical geometry back to one logical UI width.
- Deduplicated equivalent local repository targets so repeated `--repos` entries or absolute/relative aliases do not audit the same checkout more than once.
- Stopped automatic local repository discovery from following symlinked child directories outside the visible root.
- Hardened release-readiness build cleanup so stale output removal refuses symlinked output path components before resolving paths.
- Hardened report-directory enforcement so symlinked results paths fail closed and CLI reports artifact creation failures without entering the audit pipeline.
- Hardened temporary clone cleanup so recursive removal refuses symlinked path components.
- Hardened run logging so a failed UI/console sink cannot prevent durable `run.log` writes.

## [1.4.5] - 2026-04-28

Root layout allowlist hardening update.

### Changed

- Documented the intentional root layout, including why the direct script and support `py-modules` stay in the repository root for the current stable line.
- Expanded the repository map so all root-level support modules and ignored local artifact homes are accounted for.

### Fixed

- Added release-hygiene regression coverage that fails when unexpected tracked root entries are introduced.

## [1.4.4] - 2026-04-28

Public prompt-library hygiene hardening update.

### Changed

- Kept reusable agentic operator prompts under `docs/prompts/` while moving one-off maintenance prompts out of the tracked public documentation tree.
- Documented `.local-meta/` as the ignored home for scratch instructions and local-only maintenance notes.

### Fixed

- Added release-hygiene regression coverage so local-only maintenance prompts do not get republished as public user workflows.

## [1.4.3] - 2026-04-28

GUI parity and agentic publication workflow hardening update.

### Changed

- Updated the first-run README path so agentic CLI delegation is the primary onboarding flow, with manual CLI and GUI review kept as fallback paths.
- Documented the CLI/GUI parity interpretation for GUI confirmation gates versus CLI-only prompt-bypass affordances.
- Updated package project URLs for the Okavango-SAS organization repository location.

### Fixed

- Fixed GUI locale switching so the gated Repair button and initial Repair status text relocalize when changing between English and Spanish.
- Hardened the GUI smoke test to verify first-screen workflow tabs, active Audit action, locked Repair action, and localized initial Repair status.

## [1.4.2] - 2026-04-27

Release harness byte-compile coverage hardening update.

### Fixed

- Updated the local release harness byte-compile gate to cover every packaged Python module, including the GUI prompt registry module.
- Corrected architecture documentation to reflect the four support modules currently extracted from the monolith.

## [1.4.1] - 2026-04-27

Release-contract roadmap and CI trigger hardening update.

### Changed

- Updated the roadmap to the `1.4.x` stage and documented the GUI companion baseline after the `1.4.0` rebuild.
- Expanded automatic CI path filters so release-contract docs, roadmap, design guidance, and CODEOWNERS changes trigger the smoke/release-contract gate.

## [1.4.0] - 2026-04-26

GUI companion reconstruction update.

### Added

- Added a GUI Reports tab for the latest local `report.json`, `report.html`, `run.log`, and `run_state.json` artifacts.
- Added a GUI Prompts tab backed by a versioned agentic prompt registry for CLI-first environment setup, audit-only, audit-and-repair, and compact CLI delegation workflows.
- Added English prompt files under `docs/prompts/en/` while keeping the existing Spanish prompt library.

### Changed

- Rebuilt the GUI information architecture around `Audit`, `Reports`, `Prompts`, `Settings`, and gated `Repair` tabs.
- Moved advanced parity controls into Settings and kept advanced Repair write options collapsed by default without changing `GuardRunConfig`, CLI flags, report fields, or remediation semantics.
- Updated release contract, docs, and tests for the `1.4.0` minor release line.

## [1.3.10] - 2026-04-26

CLI/GUI parity repository-rule documentation update.

### Added

- Documented CLI/GUI parity as a release-blocking repository rule in AGENTS, README, architecture notes, and engineering decisions.
- Added regression coverage requiring the parity rule to stay present in public/operator docs.

## [1.3.9] - 2026-04-26

DESIGN.md supply-chain hygiene documentation update.

### Added

- Documented `google-labs-code/design.md` as the upstream DESIGN.md format reference pinned to release `0.1.0`.
- Added least-privilege guidance for optional upstream DESIGN.md validation: no floating `latest`, no repository or package-publish secrets in the environment, and read-only execution only.

## [1.3.8] - 2026-04-26

Agentic IDE onboarding and prompt-library documentation update.

### Added

- Documented agentic IDE and coding-agent usage as the primary automation use case, including Codex, Claude Code, Antigravity, GitHub Copilot, Cursor, and equivalent tools.
- Added reusable prompts for environment preparation after cloning Repo Privacy Guardian and for reviewed audit-and-repair workflows.
- Added prompt-library references to README, AGENTS, and dogfooding documentation.

## [1.3.7] - 2026-04-26

CLI/GUI parity regression hardening update.

### Added

- Added a testable CLI parser-to-runtime config adapter so CLI and GUI `GuardRunConfig` mapping can be compared without executing a full audit.
- Added field-level parity regression coverage that compares GUI repair inputs against equivalent CLI flags for every shared `GuardRunConfig` field.

### Changed

- Documented the current field-level CLI/GUI parity guard in the engineering decisions matrix.

## [1.3.6] - 2026-04-26

First-run onboarding and CLI help clarity update.

### Added

- Added a concise README 60-second first-run path for skim-reading users, including install, tooling preflight, safe audit, GUI launch, and PASS/REVIEW/FAIL interpretation.
- Added clearer CLI help epilog guidance so `--help` now shows the safe no-write first run and explains result meanings before advanced examples.
- Added contract coverage for the first-run README path and CLI help decision guidance.

## [1.3.5] - 2026-04-26

GUI locale selector and parity hardening update.

### Added

- Added a persisted GUI language selector with English and Spanish (Latin America) support for labels, dialogs, contextual help, and safety copy.
- Added locale catalogs with key-parity tests so future languages can be added without changing the CLI contract or GUI run-config mappings.

### Changed

- Kept CLI output, flags, report schemas, and backend pipeline behavior unchanged; GUI localization now changes only presentation text.

## [1.3.4] - 2026-04-26

GUI contextual-help UX hardening update.

### Added

- Added centralized GUI tooltip copy for non-obvious setup, GitHub remote audit, identity, repair, and run-control options.
- Added hover help and visible `i` badges across advanced Settings and Repair options so operators can inspect intent, safety impact, and scope without expanding docs.
- Added regression coverage for the GUI contextual-help catalog so future UI controls cannot silently lose explanatory copy.

## [1.3.3] - 2026-04-26

GUI target-mode and repair-review UX hardening update.

### Changed

- Clarified the GUI repository target surface when GitHub owner/org remote audit is active: the local repository list now shows an audit-only remote state instead of competing Root errors, and the Settings hint explicitly says remote mode ignores the local list.
- Improved the staged Repair summary so operators see blocking failure categories, manual-review advisory signals, and fixture/documentation matches that were intentionally kept non-blocking before confirming write actions.
- Documented the remote-audit GUI state and the updated Repair review guidance for operators.

### Fixed

- Prevented stale local repository entries from remaining visible underneath the drag/drop list when switching into GitHub owner/org remote audit mode.

## [1.3.2] - 2026-04-26

Secret taxonomy and evidence-classification hardening update.

### Added

- Added a tracked `DESIGN.md` design-token guide for future GUI changes.
- Added GUI drag-and-drop support for local repository folders through the optional GUI drag-and-drop runtime.
- Added a dogfooding audit-only runbook and agent prompt for using Repo Privacy Guardian defensively on other repositories while preserving redacted evidence.
- Added broader audit-only GitHub hardening coverage for repository visibility, secret scanning and push protection, open secret/Dependabot alert presence, private vulnerability reporting, and immutable releases.
- Expanded high-confidence secret detection for modern GitHub, GitLab, Cloudflare, OpenAI, Anthropic, Google, Slack, Discord, Stripe, Datadog, Twilio, Mailgun, provider assignment, auth-header, webhook, credentialed URL, and Git metadata credential patterns.
- Added explicit non-blocking buckets for low-confidence generic secret assignments, synthetic fixtures, and safe documentation examples in CLI, JSON, and HTML reports.
- Expanded sensitive filename coverage for provider credential files such as `.npmrc`, `.pypirc`, `.netrc`, `.docker/config.json`, `.aws/credentials`, `.kube/config`, `kubeconfig`, and modern SSH key names.
- Added `pip-audit` dependency vulnerability checks to the local validation harness for dev, GUI, and remediation requirement files.

### Changed

- Simplified the GUI first screen by keeping only the normal Audit path prominent after setup and moving policy/output/GitHub/identity controls into a collapsible Settings area with local non-secret preference persistence.
- Tightened agentic audit guidance to require finding classification before remediation and to avoid pasting raw sensitive evidence.
- Clarified GitHub hardening operator messages and documentation so unauthenticated checks, token-gated checks, and required admin/security permissions are explicit.
- Kept generic `password`, `api_key`, token, DSN, connection-string, and webhook assignments advisory unless they also match a provider-specific high-confidence pattern.
- Clarified the local validation contract so `pyright -p pyrightconfig.json` is documented as the repo-owned typecheck command.

### Fixed

- Removed the last host-PID liveness assertion from the regression suite so process-liveness behavior is covered with deterministic mocks instead of probing the active pytest/Codex process.
- Bounded run-artifact directory collision handling so report initialization fails visibly instead of looping indefinitely under pathological timestamp/name collisions.
- Report optional GUI drag-and-drop dependency readiness separately so `--check-tooling --gui` diagnoses missing DnD support without blocking the desktop fallback path.
- Redacted credentialed remote URLs and low-confidence assignment values consistently in logs, JSON, and HTML artifacts.
- Included `config/requirements/**` in CI path filters so dependency policy changes trigger the automatic smoke/release-contract workflow.

## [1.3.1] - 2026-04-25

Reliability validation hardening update.

### Highlights

- Bounded GitHub CLI auth probing, owner/org repository pagination, and clone worker fan-out so opt-in remote audits fail closed instead of hanging or oversubscribing the host.
- Hardened local persistence and cleanup paths with full lock-metadata writes, parent-directory fsync after atomic report writes, explicit symlink refusal for temp tree cleanup, and bounded cleanup retries.
- Tightened repo-owned smoke/test subprocess helpers with non-interactive stdin and timeouts, and covered the tracked-test collection hook directly instead of relying on nested runner behavior.
- Broadened CI path filters so changes to tests and validation scripts still trigger the automatic smoke/release-contract signal.

### Validation

- `python scripts/check_release_contract.py`
- `python -m ruff check .`
- `pyright -p pyrightconfig.json`
- `python -m pytest -q`
- `python scripts/release_readiness.py --skip-self-audit`

## [1.3.0] - 2026-04-25

GitHub owner audit mode and GUI/CLI parity update.

### Highlights

- Expanded high-confidence secret detection with additional provider-specific token patterns inspired by Git-Secrets, including GitHub OAuth tokens, Slack webhooks, Stripe secret keys, SendGrid, NPM, Telegram/Discord bot tokens, Heroku API keys, Azure storage keys, AWS secret-key assignments, and credentialed database URIs.
- Added an opt-in GitHub owner/org audit mode that discovers repositories through the GitHub API, clones matching repos into a temporary private directory, audits them with the existing pipeline, and removes the clones after the run.
- Added GUI controls for the GitHub owner/org audit mode so GUI and CLI expose the same remote-audit inputs: owner/org, remote repo filters, include forks, fast shallow clone, clone workers, and public-only filtering.
- Hardened temporary cleanup on Windows so read-only Git pack files and release-runtime artifacts do not leave stale local workspaces behind.
- Tightened GitHub remote parsing so only real GitHub hosts or GitHub SCP-style remotes are treated as GitHub repositories, while preserving support for dotted repository names such as `repo.name` and `.github`.
- Kept remote GitHub auditing audit-only: `--github-owner` cannot be combined with `--fix` or `--push`, and default local audits remain local-first with no remote discovery.

## [1.2.3] - 2026-04-24

Publication-gate stabilization and GUI UX update.

### Highlights

- Re-based the release contract around the intended cost-first validation tiers: automatic CI smoke stays cheap, broader validation remains manual or local, and docs/tests no longer overclaim continuous matrix coverage.
- Added `scripts/check_release_contract.py` and wired it into automatic CI smoke plus the local release harness so workflow/docs/version drift fails fast without enabling the full manual suite.
- Tightened GUI stop semantics in operator-facing UX/docs by renaming the button to `Stop After Current Step`, documenting the cooperative-stop behavior explicitly, and extending the cheap contract guard to cover that wording.
- Commit metadata audits now also catch malformed/non-email author/committer email-field values, classify them by repo ownership, and feed them into the existing rewrite/mailmap remediation path.
- GitHub hardening audit now reports stale branch-protection required checks that no current automatic workflow job can satisfy.
- Extracted run-artifact creation, run-state persistence, and log-writing helpers into `repo_privacy_guardian_artifacts.py` while preserving the existing `Repo_Privacy_Guardian.py` surface for callers and tests.
- Extracted the shared root-validation/target-discovery and run-exit primitives into `repo_privacy_guardian_runtime.py` so CLI and GUI preflight contracts stay aligned without growing the main pipeline surface.
- Extracted GitHub remote parsing, API probing, and release-hardening audit logic into `repo_privacy_guardian_github.py` while preserving the existing `Repo_Privacy_Guardian.py` API surface for callers and tests.
- Hardened operator-facing abort semantics: confirmation denials and user cancellations now finish as explicit `ABORTED` runs with stable exit code/state tracking instead of looking like a clean `PASS 0/0`.
- Added basic GUI cancellation so long-running audits/repairs can stop after the active repository step completes, while keeping artifacts and `run_state.json` consistent.
- Simplified GUI audit onboarding with a visible recommended path, collapsed advanced identity controls by default, improved `Audit` / `Repair` tab contrast, and refreshed sanitized screenshot evidence.
- Added a low-noise repo-owned `pyright` gate for the extracted runtime/GitHub/artifacts helpers plus repo-owned support scripts, and wired it into local validation plus CI.
- Fixed repository target resolution so CLI now audits `Current Root` when `--root` points directly at a git checkout and `--repos` is omitted.
- Requested `--repos` targets that do not resolve now fail cleanly instead of returning a false `PASS 0/0`.
- Empty `--root` selections and `--public-only` runs that resolve to zero repositories now fail cleanly instead of returning a false `PASS 0/0`.
- Invalid `--root` paths now return operator-facing validation errors without falling through to an unhandled traceback path.
- Added a repo-owned `ruff check` gate to the development extras, validation harness, and CI workflow.
- Aligned the default `.gitignore` baseline, policy docs, and smoke fixtures so tracked `.env.example` files are supported without creating tracked-but-ignored drift.
- Added `.env.example` plus `docs/LOCAL_DEVELOPMENT.md` to make optional auth variables, local setup, validation loops, and repository navigation explicit.
- Tightened the release harness with an explicit CLI tooling preflight and clearer step boundaries before the build/install validation path.
- Hardened local file handling so reports and exports refuse symlink targets, rewrite helper files are removed after use, and tracked-file scans skip symlinked or oversized text files.
- Added checkout bootstrap in `tests/conftest.py` so `pytest -q` and `python -m pytest -q` behave the same from a repository checkout.
- Hardened automatic fix preconditions so dirty worktrees, `git fsck` failures, or incomplete audits fail closed instead of mutating a repository mid-recovery.
- Replaced PID/timestamp stale-lock reclamation with OS-backed repository execution locks, disabled inherited stdin on repo-owned subprocesses, and isolated validation temp/coverage artifacts per run.
- Reduced `exfil_code_indicators` advisory noise by preferring active outbound sinks and contextual review terms while ignoring detector scaffolding, import-only lines, and test-meta fixture content.
- Tightened Windows lock release diagnostics to read owner metadata from the active lock FD, and made validation cleanup retry transient `dist/`/build artifact removal failures instead of aborting on the first file-handle race.

### Validation

- `python scripts/release_readiness.py`
- `python scripts/check_release_contract.py`
- `python -m ruff check .`
- `pyright -p pyrightconfig.json`
- `python -m pytest -q`
- `python tests/release_smoke_cli.py`
- `python tests/release_smoke_gui.py`

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
- Documented a reusable GitHub publication-hardening playbook for operators and coding agents without changing the local-first product model.
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
