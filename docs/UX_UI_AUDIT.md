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
- Applied corrective UX/UI copy and hierarchy changes in the GUI code
- Re-ran the app and captured after screenshots from the same states

## Main Findings

1. The GUI was functionally aligned with the CLI, but the first screen still looked like a settings form before it looked like a workflow.
   A non-technical user could miss that the intended path is simply: confirm Root, run Audit, review, then Repair only if needed.

2. Several labels were accurate for maintainers but too implementation-oriented for a public desktop user.
   Examples: `Artifacts Directory`, `Extra JSON Export`, `Max matches per check`, and repair options that did not clearly separate review toggles from write actions.

3. Optional identity controls competed visually with the primary audit path.
   The Git identity and owner metadata sections were useful, but they needed clearer "optional" and "repair defaults" framing.

4. The tracked screenshot artifacts contained local machine paths in visible form fields.
   This is not detected by the text-based self-audit because the data is embedded in PNG pixels, so the docs assets needed to be regenerated with neutral paths before public release.

## Corrections Applied

- Reframed the header around the staged workflow: Audit first, Repair only after the safety gate unlocks.
- Renamed the first setup card to `1. Audit Setup` and added simpler guidance for the default path.
- Renamed technical fields to user-facing labels: `Audit Results Folder`, `Optional JSON Copy`, and `Max findings per check`.
- Clarified owner metadata as `Owner Profile (repair defaults)` and explained that it is used by Repair for identity rewrite/redaction.
- Marked Git identity controls as optional and clarified when a user should touch them.
- Renamed Repair groups to `Review & Output Options` and `Repair Write Actions` to reduce ambiguity.
- Tightened destructive-option labels while preserving the same underlying CLI-equivalent settings.
- Kept `Refresh` available when Root is invalid so users can correct the path and retry without restarting the GUI.
- Rendered unavailable audit actions in a neutral disabled state instead of primary-button blue.
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

### Compact Desktop Layout

Before:

![Audit compact before](ux-audit/before/audit-compact-before.png)

After:

![Audit compact after](ux-audit/after/audit-compact-after.png)

## Parity Notes

- No GUI-only execution path was added.
- No CLI flag was removed or changed.
- GUI controls still map into the same `build_guard_run_config()` fields used by CLI execution.
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
- The compact layout is clearer, but naturally denser than the primary desktop width.
- The app still does not have automated visual regression coverage; `docs/ux-audit/` remains the maintained screenshot evidence for UI review.
