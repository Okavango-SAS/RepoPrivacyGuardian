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

The main screen should optimize for the default path. Setup, GitHub owner/org audit, output overrides, identity controls, and repair write options are available but should not compete with the primary Audit action.

## Colors

The palette uses soft green-gray surfaces with teal primary actions and slate secondary actions. Amber is reserved for repair/write-risk areas. Avoid decorative gradients, large hero artwork, and single-hue saturation.

## Typography

Use system UI fonts with Inter-style proportions where available. Headings should be modest because most surfaces are tools, not hero sections. Monospace is reserved for logs and command-like output.

## Layout

Keep the first viewport simple after setup:

- visible: repository root, repository list/drop target, Audit action, stop/refresh controls, and execution log
- collapsed: policy path, report paths, GitHub owner/org discovery, clone worker tuning, identity setup, and repair write actions
- staged: Repair remains locked until a completed Audit creates review context

## Components

Buttons should be short and action-oriented. Cards should be shallow, with 8-12px radius and clear grouping. Do not nest cards unless the inner element is a bounded tool area such as the repository drop/list shell or log output.

## Do's and Don'ts

- Do keep the common Audit path visible and brief.
- Do persist non-secret GUI setup preferences locally so returning users see a cleaner screen.
- Do keep advanced/security-sensitive options explicit and collapsed.
- Do not persist tokens, private owner email lists, or push guardrail bypass settings in GUI setup preferences.
- Do not make remote GitHub audit feel like the default local-first path.
