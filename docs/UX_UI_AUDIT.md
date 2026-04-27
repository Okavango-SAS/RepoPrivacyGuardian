# UX/UI Audit

Audit date: 2026-04-24

## Scope

Screens audited in the running GUI:

- Audit view on desktop with the current repo as the only target
- Audit view with an invalid Root path
- Repair tab while the staged repair gate is still locked
- Repair tab immediately after an audit, during the review cooldown
- Compact desktop width near the minimum supported GUI size

## Method

- Launched the shipped `customtkinter` GUI locally from `main`
- Captured the real Tk window by HWND to avoid desktop/toast overlays in screenshots
- Neutralized visible screenshot paths to non-user placeholder paths before saving docs assets
- Walked the main `Audit -> review -> Repair` flow in the running app
- Applied corrective UX/UI copy, hierarchy, color, and responsive-layout changes in the GUI code
- Re-audited the first screen after the previous pass to reduce form overload for non-technical users
- Re-ran the app and captured after screenshots from the same states

## Main Findings

1. The GUI remained functionally aligned with the CLI and passed the automated contract tests, but the first screen still read more like a settings form than a workflow.
   A non-technical user could miss that the intended path is simply: confirm Root, run Audit, review, then Repair only if needed.

2. The owner profile and Git identity controls were correct, but showing them by default made the initial Audit screen feel heavier than the common user path requires.
   These controls are still necessary for repair/parity, but they should not compete with the primary `Run Audit` path on first launch.

3. Several labels were accurate for maintainers but still needed stronger visual grouping for public desktop users.
   Examples: `Artifacts Directory`, `Extra JSON Export`, `Max matches per check`, and repair options that did not clearly separate review toggles from write actions.

4. The blue-heavy release UI was readable but visually generic.
   Primary actions, neutral support actions, review options, and destructive repair actions benefited from a more modern teal/slate/amber palette with clearer state meaning.

5. The desktop header benefited from explicit workflow chips, but those chips consumed too much vertical space near the compact supported width.
   The compact layout needed responsive treatment so guidance does not push the operational cards too far down.

6. The tab selector for `Audit` and `Repair` had insufficient contrast in inactive states after the palette update.
   The labels were present but too easy to miss, especially on the locked Repair screen.

7. The tracked screenshot artifacts contained local machine paths in visible form fields in an earlier pass.
   This is not detected by the text-based self-audit because the data is embedded in PNG pixels, so the docs assets needed to be regenerated with neutral paths before public release.

## Corrections Applied

- Reframed the header around the staged workflow: Audit first, Repair only after the safety gate unlocks.
- Renamed the first setup card to `1. Audit Setup` and added simpler guidance for the default path.
- Added a `Recommended path` callout directly inside Audit setup so a new user sees the intended workflow before reading any configuration fields.
- Renamed technical fields to user-facing labels: `Audit Results Folder`, `Optional JSON Copy`, and `Max findings per check`.
- Clarified owner metadata as `Owner Profile (repair defaults)` and explained that it is used by Repair for identity rewrite/redaction.
- Marked Git identity controls as optional and clarified when a user should touch them.
- Collapsed advanced identity/profile controls by default while keeping every underlying GUI control and CLI-equivalent setting available through `Show advanced identity settings`.
- Renamed Repair groups to `Review & Output Options` and `Repair Write Actions` to reduce ambiguity.
- Tightened destructive-option labels while preserving the same underlying CLI-equivalent settings.
- Kept `Refresh` available when Root is invalid so users can correct the path and retry without restarting the GUI.
- Rendered unavailable audit actions in a neutral disabled state instead of primary-button blue.
- Updated the GUI palette from generic blue to a more deliberate teal/slate/amber system:
  primary audit actions use teal, support actions use slate, review panels use soft teal, and repair/write-risk panels use amber.
- Added a compact workflow strip in the desktop header: `1 Audit`, `2 Review findings`, `3 Repair if needed`, and `CLI parity: same backend`.
- Hid the workflow strip at compact width while preserving the concise header sentence, so the compact view keeps more vertical room for the main form.
- Changed the `Audit` / `Repair` tab selector to dark text on light segmented states so both tabs stay readable in active and inactive states.
- Regenerated all tracked UX screenshots with neutral visible paths and without external desktop overlays.

## Screenshots

### Audit View, Desktop Baseline

Before:

![Audit default desktop before](ux-audit/before/audit-default-desktop-before.png)

After:

![Audit default desktop after](ux-audit/after/audit-default-desktop-after.png)

### Audit View, Invalid Root State

Before:

![Audit invalid root before](ux-audit/before/audit-invalid-root-before.png)

After:

![Audit invalid root after](ux-audit/after/audit-invalid-root-after.png)

### Repair Locked State

Before:

![Repair locked before](ux-audit/before/repair-locked-desktop-before.png)

After:

![Repair locked after](ux-audit/after/repair-locked-desktop-after.png)

### Repair State After Audit

Before:

![Repair post-audit before](ux-audit/before/repair-post-audit-before.png)

After:

![Repair post-audit after](ux-audit/after/repair-post-audit-after.png)

### Reports Dashboard

After:

![Reports desktop after](ux-audit/after/reports-desktop-after.png)

### Prompts Library

After:

![Prompts desktop after](ux-audit/after/prompts-desktop-after.png)

### Compact Desktop Layout

Before:

![Audit compact before](ux-audit/before/audit-compact-before.png)

After:

![Audit compact after](ux-audit/after/audit-compact-after.png)

## Parity Notes

- No GUI-only execution path was added.
- No CLI flag was removed or changed.
- GUI controls still map into the same `build_guard_run_config()` fields used by CLI execution.
- Collapsing advanced identity controls changes only visibility; the variables and run-config mapping remain unchanged.
- Audit and Repair still run through the shared `execute_guard_pipeline()` backend.
- The staged GUI contract remains: `Audit` first, `Repair` locked until a valid audit context and review window exist.

## Validation

- `python -m ruff check .`
- `pyright -p pyrightconfig.json`
- `python -m pytest -q`
- `python tests/release_smoke_gui.py`
- `python tests/release_smoke_cli.py`
- Manual GUI walkthrough with fresh before/after screenshots from the live app

## Remaining Limits

- The GUI remains desktop-first and intentionally secondary to the CLI release contract.

## 2026-04-25 Follow-Up

The next UX pass reduces first-screen load further:

- Added root-level `DESIGN.md` tokens and rules so future GUI work has a durable visual/interaction contract.
- Kept the main Audit screen focused on Root, repository selection/drop target, Audit controls, and the log.
- Moved policy, report export, GitHub owner/org remote audit, clone tuning, and identity setup into a collapsible Settings area.
- Persisted only non-secret GUI setup preferences locally; tokens, private owner email lists, replacement files, and push bypass choices are not stored.
- Added drag-and-drop repository-folder targeting when the optional desktop DnD runtime is available, with Browse/Refresh still available as the fallback.
- The compact layout is clearer, but naturally denser than the primary desktop width.
- The app still does not have automated visual regression coverage; `docs/ux-audit/` remains the maintained screenshot evidence for UI review.

## 2026-04-26 Follow-Up

The release-readiness UX pass focused on target-state clarity and safer review language:

- When GitHub owner/org remote audit is active, the repository list now switches to a dedicated remote audit state instead of showing stale local repositories or Root validation errors.
- The remote state explains that repositories are discovered through GitHub, cloned temporarily, cleaned up after the run, and remain audit-only with Repair locked.
- The hidden Settings hint now calls out that remote mode ignores the local repository list.
- The Repair summary and confirmation prompt now separate blocking failure categories, manual-review advisory signals, and fixture/documentation matches kept non-blocking.
- Regression tests cover the remote target-state surface and the richer Repair review summary.

## 2026-04-26 Contextual-Help Pass

The next GUI pass focused on reducing uncertainty without reopening the first-screen overload:

- Added hover help for non-obvious controls in the main target picker, Settings, GitHub owner/org remote audit, identity setup, Repair options, and run controls.
- Added visible `i` badges next to advanced Settings and Repair options where hover affordance alone would be too easy to miss.
- Kept the primary Audit path unchanged: repository selection, Audit, Stop, Refresh, and log remain the visible first-screen workflow.
- Centralized tooltip copy in code and added regression coverage so future UI options must keep explanatory text.

## 2026-04-26 GUI Locale Pass

The localization pass added a presentation-only language selector without widening the CLI contract:

- Added English and Spanish (Latin America) locale catalogs for GUI labels, dialogs, safety copy, and contextual help.
- Persisted the locale as non-secret GUI setup state while keeping tokens, identity secrets, and repair bypass controls out of saved settings.
- Kept CLI parity by mapping localized labels back to the same internal variables and `GuardRunConfig` fields; tests assert locale changes do not alter run-config payloads.
- Left CLI help, report field names, JSON/HTML schema, policy keys, and backend log semantics unchanged.

## 2026-04-26 GUI Companion Reconstruction

The next GUI pass re-centered the desktop app around the primary agentic CLI use case:

- Rebuilt the information architecture as `Audit`, `Reports`, `Prompts`, `Settings`, and gated `Repair`.
- Kept the first Audit path focused on local target selection, drag-and-drop, run/stop/refresh, and execution log.
- Added a Reports dashboard for the latest local `report.json`, `report.html`, `run.log`, and `run_state.json` paths, with quick-open actions but no raw sensitive evidence rendering.
- Added a Prompts tab backed by a tracked bilingual prompt registry for environment setup, audit-only, reviewed audit-and-repair, and compact CLI delegation workflows.
- Moved policy/output/GitHub/identity parity controls into Settings and kept advanced Repair write options collapsed by default.
- Preserved the shared backend and `GuardRunConfig` mapping; the change is presentation and workflow organization, not a new execution engine.
