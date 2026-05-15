# AGENTS

This document defines how coding agents should use Repo Privacy Guardian from CLI.

## Scope

- Use CLI for automation, reproducibility, and stable artifacts.
- GUI and CLI are parity paths for checks and policy logic.
- GUI parity includes staged interaction: `Audit` first, then `Repair` after audit context unlocks the visual repair gate.
- CLI/GUI parity is a repository rule and release-blocking invariant. New audit, report, hardening, remote-audit, or repair behavior must be exposed in both CLI and GUI, mapped through the same internal configuration/policy keys, and covered by regression tests.
- The GUI is a CLI companion for manual use: `Audit` for targets/runs, `Reports` for local evidence, `Prompts` for agentic CLI workflows, `Settings` for advanced parity controls, and `Repair` for gated reviewed writes.
- Prefer CLI in agentic IDE workflows (Codex, Claude Code, Antigravity, GitHub Copilot, Cursor, and similar tools). This is the primary automation use case.

## Public Repository Operating Rule

RepoPrivacyGuardian itself is already a public GitHub repository. Treat every commit, branch push, PR, tag, screenshot, and documentation edit as immediately internet-visible.

- Inspect `git status --short` and `git diff --check` before staging.
- Stage only intentional tracked source, test, and documentation changes.
- Keep local run artifacts, generated screenshots, release builds, coverage files, scratch prompts, logs, and audit evidence in ignored paths such as `Audit_Results/`, `.local-meta/`, `dist/`, `build/`, `*.egg-info/`, and `*-pre-publication-fix-*.bundle`.
- Do not commit raw secrets, private emails, internal hostnames, private URLs, personal absolute paths, unredacted logs, tokens in command examples, or screenshots that reveal private local context.
- Do not add secrets to Git remotes, command-line arguments, CI config, docs, tests, or examples. Use obvious placeholders and `.env.example` for non-secret variable names.
- If a sensitive value ever reaches a commit, stop normal work, preserve only redacted evidence, rotate the affected credential outside this repo, and plan a reviewed history cleanup before pushing more changes.

## CLI First Workflow

1. Start with help.
2. Run `--check-tooling` when the target environment is not known.
3. Run audit in dry-run mode.
4. Review findings with user-facing guidance: risk, possible consequence, and suggested action.
5. Authorize only the remediations that were reviewed.
6. Re-run audit until policy status is PASS.

Notes:

- Dogfooding runs for other repositories should follow `docs/DOGFOODING.md`: audit-only first, classify findings, preserve redacted evidence, and avoid pasting raw sensitive values into chat or tickets.
- Treat `exfil_code_indicators` as advisory/manual-review by default. Review them, but do not expect them to flip PASS/FAIL on their own.
- Treat low-confidence secret assignment fields (`tracked_secret_low_confidence`, `history_secret_low_confidence`, `git_metadata_secret_low_confidence`) as advisory/manual-review by default. `tracked_secret_matches`, `history_secret_matches`, and `git_metadata_secret_matches` are the high-confidence blocking buckets; fixture and documentation buckets are separated to reduce false positives.
- Treat `github_hardening_findings` and `github_hardening_warnings` as advisory/manual-review by default. Use `--audit-github-hardening` when the target repo lives on GitHub and you want to inspect repository settings before publication.
- Use `--agent-summary` when a compact safe handoff is useful; every run writes `agent_summary.json` even without the flag.
- Use `--strict-profile audit-only|internal|release` only when the operator wants an explicit documented posture. `release` does not enable network checks by itself.
- Use `--suppressions PATH` only for reviewed advisory/manual-review findings. High-confidence secrets, path leaks, dirty tree, fsck, execution errors, fix errors, and Git metadata blocking findings cannot be suppressed.
- For GitHub hardening token-gated checks, support either token environment variables or an authenticated GitHub CLI session. GitHub MCP is not required for standalone CLI/Desktop use.
- Use `--github-owner` only for opt-in remote audit discovery. It clones matching GitHub repos into temporary local directories, audits them with the same pipeline, and remains audit-only; do not combine it with `--fix` or `--push`.
- Release validation should come from tracked tests only so a clean clone reproduces the same `pytest` signal.
- Let the tool automate mechanical Git-safe remediation, but keep semantic source edits under review.
- Use `--replace-text-file` when the repository contains a known literal that must be rewritten but the replacement cannot be inferred safely from the finding alone.

## Agentic IDE Use Case

Repo Privacy Guardian is meant to be easy to delegate to coding agents while preserving operator control.

- For a fresh clone of this tool, use `docs/prompts/06_PREPARACION_ENTORNO_AGENTICA.prompt.md`.
- For audit-only dogfooding against another repository, use `docs/prompts/05_DOGFOODING_AUDIT_ONLY.prompt.md`.
- For reviewed audit-and-repair work, use `docs/prompts/07_AUDITORIA_REPARACION_AGENTICA.prompt.md`.
- English equivalents live under `docs/prompts/en/`, and the GUI `Prompts` tab exposes the locale-matched library without changing CLI behavior.
- Keep the first pass audit-only and classify findings before requesting writes.
- Do not paste raw secrets, private paths, private hostnames, or unredacted logs into agent chat.

## Recommended Commands

Use one of these command styles:

- `repo-privacy-guardian ...`
- `python -m Repo_Privacy_Guardian ...`
- `python Repo_Privacy_Guardian.py ...` (compatibility path)

Minimal safe audit for one repository:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes
```

Tooling preflight:

```sh
repo-privacy-guardian --check-tooling
repo-privacy-guardian --check-tooling --install-missing-tools
```

Use `--install-missing-tools` only when you explicitly want the tool to attempt local dependency installation.

On Windows, the readiness flow can bootstrap App Installer / `winget` when supported, then continue with `git` or `gh` installation.

Fix preview (no destructive write):

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --dry-run --yes
```

Advanced fix with explicit replace-text mappings:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --yes --replace-text-file /path/to/replace-text.txt
```

Low-confidence email policy selection:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --low-confidence-email-mode informational
repo-privacy-guardian --root /path/to/repos --repos MyRepo --low-confidence-email-mode blocking
```

Optional GitHub release-hardening audit:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --audit-github-hardening
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --audit-github-hardening --accept-github-admin-bypass
```

Optional GitHub owner/org remote audit:

```sh
repo-privacy-guardian --github-owner MyOrg --dry-run --yes
repo-privacy-guardian --github-owner MyOrg --repos ServiceA ServiceB --github-fast --github-jobs 4 --dry-run --yes
repo-privacy-guardian --github-owner MyOrg --github-include-forks --public-only --dry-run --yes
```

Notes:

- Admin-only GitHub checks require `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`.
- Use `--accept-github-admin-bypass` only for reviewed solo-maintainer repositories where admin branch-protection bypass is an intentional operating model; it moves only that signal to `github_hardening_accepted_risks`.
- GitHub owner/org audit reuses `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, or an authenticated `gh` session when private repository clones are needed.
- Remote discovery and clone work are bounded: auth probes are non-interactive with a timeout, repository pagination fails closed at the page limit, and clone workers are capped.
- The GitHub hardening audit inspects repository settings only; it does not push configuration changes.
- The GUI exposes the same GitHub owner/org remote-audit controls as the CLI, but CLI remains preferred for agentic automation.
- GUI locale is presentation-only. English and Spanish (Latin America) labels must keep the same CLI flags, policy keys, report fields, and run-config mappings.

Platform notes:

- Use `py` instead of `python` on Windows if preferred.
- Use `--gui` explicitly for the desktop interface; the default entry path is CLI help.

## Push Guardrails

- Do not use `--push` without prior dry-run review.
- If push is required, keep owner guardrails enabled.
- Prefer explicit owner allowlist when needed:

```sh
repo-privacy-guardian --fix --push --allow-remote-owner <expected-owner>
```

## User Experience Contract

When reporting findings, keep outputs actionable and brief.

- State risk level.
- State possible consequence.
- State one suggested next action.
- Classify each finding as confirmed leak, intentional fixture/example, indeterminate/manual-review, advisory hardening, or tooling/runtime issue before proposing remediation.
- Reference `agent_summary.json`, `report.json`, `report.html`, and `run.log` by path, but do not paste raw secrets, private emails, internal URLs, hostnames, or personal absolute paths.

Avoid dumping all raw findings first. Start with decision guidance, then show details only if needed.

## Agentic Prompt Template

Use this prompt style when delegating execution to an agent:

```text
Act as a release/security engineer. Work only on <target-repo>.
Use Repo Privacy Guardian from CLI, not GUI.
Start with --help, then run a dry-run audit, review whether findings are real leaks or intentional fixtures,
classify each finding with redacted evidence references, apply only safe reviewed fixes,
use --replace-text-file only for explicit operator-approved substitutions, re-run until PASS,
and preserve artifacts under Audit_Results.
Do not push or rewrite history without explicit approval.
```

## Artifacts

- Reports are written under `Audit_Results/<run_id>/`.
- Use `agent_summary.json`, `report.json`, `report.html`, and `run.log` as the audit record.
- Treat artifacts as sensitive operational outputs even when redacted.
