# UX/UI Audit

Audit date: 2026-04-16

## Scope

Screens audited in the running GUI:

- Audit view on desktop with the current repo as the only target
- Audit view with an invalid Root path
- Repair tab while the staged repair gate is still locked
- Repair tab immediately after an audit, during the review cooldown
- Compact desktop width near the minimum supported GUI size

## Method

- Launched the shipped `customtkinter` GUI locally from `main`
- Walked the main `Audit -> review -> Repair` flow in the running app
- Captured before screenshots from the rendered interface
- Applied corrective UX/UI changes in the GUI code
- Re-ran the app and captured after screenshots from the same states

## Main Findings

1. Invalid or empty repo targets still looked too close to a broken blank state.
   The list area could read like empty whitespace instead of a deliberate state with next-step guidance, and the main CTA still competed visually with that failure mode.

2. Compact desktop widths were stacking too aggressively.
   The responsive breakpoints pushed the repositories panel and execution log lower than necessary, so the main workflow was harder to discover near the minimum supported width.

3. Repair status lacked hierarchy once an audit finished.
   The cooldown and pass/fail summary existed, but the information was visually flat and easy to miss relative to the larger options cards around it.

4. The locked Repair screen used space inefficiently.
   The blocker content sat too passively in the middle of a large blank area and did not feel anchored to the next action strongly enough.

## Corrections Applied

- Reworked the repo empty state into a visible overlay card with separate warning and neutral treatments for invalid Root vs. no repositories found.
- Disabled repo-selection controls when there are no available targets and changed the primary CTA copy to `Audit unavailable` in that state.
- Tightened the responsive thresholds so desktop widths around `1280px` keep the primary cards and results area visible sooner.
- Strengthened the `Repair Flow` section with a dedicated status panel, clearer badge states, and better hierarchy for cooldown vs. ready states.
- Kept the staged Repair guardrail, but moved the lock card higher in the canvas so the tab feels less visually abandoned.
- Preserved the earlier current-root inclusion and repo-summary behavior while making the visible error and empty states much easier to understand.

## Screenshots

### Audit View, Desktop Baseline

Before:

![Audit default desktop before](/<redacted-path>)

After:

![Audit default desktop after](/<redacted-path>)

### Audit View, Invalid Root State

Before:

![Audit invalid root before](/<redacted-path>)

After:

![Audit invalid root after](/<redacted-path>)

### Repair Locked State

Before:

![Repair locked before](/<redacted-path>)

After:

![Repair locked after](/<redacted-path>)

### Repair State After Audit

Before:

![Repair post-audit before](/<redacted-path>)

After:

![Repair post-audit after](/<redacted-path>)

### Compact Desktop Layout

Before:

![Audit compact before](/<redacted-path>)

After:

![Audit compact after](/<redacted-path>)

## Validation

- `python -m pytest -q`
- `python tests/release_smoke_gui.py`
- `python tests/release_smoke_cli.py`
- Manual GUI walkthrough with fresh before/after screenshots from the live app

## Remaining Limits

- The GUI is still desktop-first. The compact layout is materially clearer now, but it is naturally denser than the primary desktop width.
- The app still does not have automated visual regression coverage; `docs/ux-audit/` remains the current screenshot artifact for UI review.
