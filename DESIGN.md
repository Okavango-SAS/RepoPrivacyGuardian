---
version: alpha
name: Repo Privacy Guardian Desktop
description: A calm, local-first security utility interface for auditing repositories before public release.
colors:
  primary: "#0F766E"
  primary-hover: "#0B5F59"
  support: "#334155"
  support-hover: "#1E293B"
  background: "#EEF5F2"
  surface: "#FBFEFC"
  surface-alt: "#F5FAF8"
  border: "#CFE0DA"
  heading: "#0B2F32"
  body: "#132F36"
  muted: "#526A70"
  warning-bg: "#FFF7ED"
  warning-border: "#F5C58B"
  warning-text: "#7A3E05"
  log-bg: "#0B1720"
  log-text: "#DDEDEA"
typography:
  heading-md:
    fontFamily: Inter
    fontSize: 1rem
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: 0
  body-sm:
    fontFamily: Inter
    fontSize: 0.75rem
    fontWeight: 400
    lineHeight: 1.45
    letterSpacing: 0
  label-sm:
    fontFamily: Inter
    fontSize: 0.75rem
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: 0
  mono-xs:
    fontFamily: JetBrains Mono
    fontSize: 0.625rem
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: 0
rounded:
  sm: 8px
  md: 10px
  lg: 12px
spacing:
  xs: 4px
  sm: 8px
  md: 12px
  lg: 16px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.sm}"
    height: 34px
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "{colors.surface}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.heading}"
    rounded: "{rounded.sm}"
    height: 32px
  panel-default:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.body}"
    rounded: "{rounded.lg}"
  panel-warning:
    backgroundColor: "{colors.warning-bg}"
    textColor: "{colors.warning-text}"
    rounded: "{rounded.md}"
  log-output:
    backgroundColor: "{colors.log-bg}"
    textColor: "{colors.log-text}"
    rounded: "{rounded.md}"
---

## Overview

Repo Privacy Guardian is a security utility, not a dashboard or marketing page. The desktop UI should feel quiet, compact, and operational: a user chooses repositories, runs Audit, reviews results, and only then enters Repair.

The main screen should optimize for the default path. Setup, GitHub owner/org audit, output overrides, identity controls, and repair write options are available but should not compete with the primary Audit action. The GUI is a CLI companion: it should make manual audit, artifact review, prompt copying, settings, and gated repair easy without becoming a second scanner control plane.

## Colors

The palette uses soft green-gray surfaces with teal primary actions and slate secondary actions. Amber is reserved for repair/write-risk areas. Light and dark GUI themes should share semantic palette tokens so presentation changes never alter audit behavior or operator choices. Avoid decorative gradients, large hero artwork, and single-hue saturation.

## Typography

Use system UI fonts with Inter-style proportions where available. Headings should be modest because most surfaces are tools, not hero sections. Monospace is reserved for logs and command-like output.

## Layout

Keep the first viewport simple after setup:

- visible: repository root, repository list/drop target, Audit action, stop/refresh controls, and execution log
- separate tabs: Reports for latest artifacts, Prompts for agentic CLI workflows, Settings for advanced parity controls, and Repair for reviewed write actions
- collapsed: policy path, report paths, GitHub owner/org discovery, clone worker tuning, identity setup, and repair write actions
- staged: Repair remains locked until a completed Audit creates review context; advanced repair toggles remain collapsed until needed

## Components

Buttons should be short and action-oriented. Cards should be shallow, with 8-12px radius and clear grouping. Do not nest cards unless the inner element is a bounded tool area such as the repository drop/list shell or log output.

Runtime image assets are allowed when they improve scanability without becoming decoration. Keep them small, local, and packaged with the GUI: app icon, subtle header watermark, empty-state visuals, evidence/prompt/repair pictograms. Do not embed text in images; labels must remain locale-driven.

Scrollbars should use low-contrast semantic theme colors. They must remain discoverable, but should not compete with the primary Audit, Reports, Prompts, Settings, or Repair actions in either light or dark mode.

Large operational panes such as logs should have a quiet empty state before data exists. Empty-state copy must stay short, localized, and removable as soon as real run output appears.

Empty states that represent a normal first-run path should include a safe next action when one exists. Prefer a single primary action such as `Run Audit` / `Go to Audit` over extra explanatory copy.

## Do's and Don'ts

- Do keep the common Audit path visible and brief.
- Do persist non-secret GUI setup preferences locally so returning users see a cleaner screen.
- Do keep advanced/security-sensitive options explicit and collapsed.
- Do not persist tokens, private owner email lists, or push guardrail bypass settings in GUI setup preferences.
- Do not make remote GitHub audit feel like the default local-first path.
- Do not use full-window background images, QR codes, marketing banners, or image-only buttons inside the desktop GUI.

## External Spec Hygiene

This file follows the public Google Labs `google-labs-code/design.md` format at pinned release `0.1.0` with `version: alpha`.

Repo Privacy Guardian vendors only this local `DESIGN.md` contract. Do not fetch a moving branch, install a floating `latest` package, or execute remote design tooling during normal GUI work.

If maintainers choose to validate this file with the upstream CLI, use an explicitly pinned package version and a sanitized environment:

```sh
npx --yes @google/design.md@0.1.0 lint DESIGN.md
```

Before running that optional command, remove repository or GitHub secrets from the process environment, especially `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, and `NPM_TOKEN`. The validation should run read-only, from a clean checkout, without elevated filesystem, package-publish, or repository-write permissions.
