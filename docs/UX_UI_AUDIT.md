# UX/UI Audit

This file is the maintained visual QA record for the optional desktop GUI companion. It intentionally documents the current release surface instead of preserving every historical before/after pass.

## Scope

Screens audited in the running GUI:

- Audit view in the normal desktop layout
- Audit view at compact desktop width
- Audit view with an invalid Root path
- Reports latest-run review and agent handoff
- Prompts staged agentic workflow
- Repair tab while locked
- Repair tab immediately after an audit, during the review cooldown
- Light and dark desktop themes for the primary Audit and Reports surfaces

## Current Method

- Launch the shipped `customtkinter` GUI locally from the repository checkout.
- Capture the real desktop window rather than synthetic widget fragments.
- Neutralized visible screenshot paths to non-user placeholder paths before saving docs assets.
- Keep UI text code-native and locale-driven; do not embed labels in raster assets.
- Verify that GUI behavior remains a CLI companion: Audit first, Reports for local evidence, Prompts for agentic workflows, Settings for parity controls, and gated Repair for reviewed writes.
- Keep screenshot evidence under `docs/ux-audit/after/` and local scratch captures under ignored `.local-meta/` paths.

## Current Findings

The current desktop GUI matches the intended agent-first workflow:

- Audit stays focused on local target selection, run controls, and the execution log.
- Reports reads as a latest-run review surface, shows decision guidance, opens redacted artifacts, and can copy a privacy-safe agent handoff.
- Prompts exposes the maintained staged prompt library for environment setup, audit-only dogfooding, reviewed repair, and compact CLI delegation.
- Settings holds advanced parity controls without making the first Audit screen feel like a settings form.
- Repair remains visually locked until a valid audit context exists and the review cooldown completes.
- Light and dark themes use the same local assets, with in-memory tinting/blending where needed.
- Compact layouts reflow Reports and Prompts actions so localized button text remains readable near the minimum supported desktop width.

## Maintained Screenshots

### Audit

![Audit default desktop](ux-audit/after/audit-default-desktop-after.png)

![Audit dark desktop](ux-audit/after/audit-dark-desktop-after.png)

![Audit compact desktop](ux-audit/after/audit-compact-after.png)

![Audit invalid root](ux-audit/after/audit-invalid-root-after.png)

### Reports

![Reports desktop with agent handoff](ux-audit/after/reports-desktop-after.png)

![Reports dark desktop](ux-audit/after/reports-dark-desktop-after.png)

### Prompts And Repair

![Prompts desktop](ux-audit/after/prompts-desktop-after.png)

![Repair locked](ux-audit/after/repair-locked-desktop-after.png)

![Repair post-audit cooldown](ux-audit/after/repair-post-audit-after.png)

## Hygiene Notes

- Historical before-state screenshots were removed from the tracked documentation set because they showed defects that are already corrected and no longer add release-review value.
- Dated pass-by-pass notes were consolidated into this current-state record; durable design rules live in `DESIGN.md`, and public behavior changes belong in `CHANGELOG.md`.
- Local visual QA runs should remain ignored under `.local-meta/visual-qa/<run_id>/` unless a screenshot is intentionally promoted to sanitized public documentation.

## Parity Notes

- No GUI-only execution path is accepted.
- No CLI flag, policy key, report field, or remediation default changes for visual-only work.
- GUI controls continue to map into the same `build_guard_run_config()` fields used by CLI execution.
- Audit, Reports, GitHub hardening, remote audit, and Repair still run through the shared backend.
- The staged GUI contract remains: `Audit` first, then reviewed evidence, then gated `Repair`.

## Validation

Use these checks for GUI-impacting changes:

```sh
python -m ruff check .
pyright -p pyrightconfig.json
python -m pytest -q
python tests/release_smoke_gui.py
python tests/release_smoke_cli.py
python scripts/visual_qa_gui.py
```

`scripts/visual_qa_gui.py` is a non-pixel-perfect desktop visual QA helper. It verifies screenshot dimensions and rejects blank captures, but browser-only QA as the GUI acceptance gate is intentionally out of scope. React/Vite or web-app migration as a default path is also out of scope; the maintained target is the local `customtkinter` desktop companion.
