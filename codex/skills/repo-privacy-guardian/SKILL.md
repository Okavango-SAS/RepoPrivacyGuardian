---
name: repo-privacy-guardian
description: Operate RepoPrivacyGuardian from CLI to audit Git repositories for privacy leaks and public release readiness, classify redacted findings, and prepare reviewed repairs. Use when the user mentions RepoPrivacyGuardian or asks to audit a repository before publication, including auditoria de privacidad and preparar un repo para publicarlo.
---

# Repo Privacy Guardian

Use this skill as an adapter to the maintained RepoPrivacyGuardian CLI. Keep scanning, policy, report generation, and mechanical repair logic in the backend. Pure skill editing or repository maintenance does not require auditing unrelated repositories.

## Resolve the backend

Use `scripts/resolve_repo_privacy_guardian.ps1` relative to this skill's directory. From an installed Codex skill:

```powershell
$skillsRoot = if ($env:CODEX_HOME) { Join-Path $env:CODEX_HOME 'skills' } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex/skills' }
$resolver = Join-Path $skillsRoot 'repo-privacy-guardian/scripts/resolve_repo_privacy_guardian.ps1'
$backend = & $resolver -Json | ConvertFrom-Json
```

Inside this tool's checkout, the same resolver lives at `codex/skills/repo-privacy-guardian/scripts/resolve_repo_privacy_guardian.ps1`.

Resolution order:

1. Current directory and its parents, when they identify a RepoPrivacyGuardian checkout.
2. Installed skill metadata in `.local/install.json`.
3. `REPO_PRIVACY_GUARDIAN_REPO`, when it points to a valid checkout.
4. The `repo-privacy-guardian` executable on PATH.

The result contains `kind`, `repoRoot`, `cwd`, and a `command` argument array. Set the shell tool's working directory to `cwd` and execute that array with additional CLI arguments. Avoid concatenating it into a shell command string. For example, after setting that working directory:

```powershell
$command = @($backend.command)
$prefixArgs = @($command | Select-Object -Skip 1)
& $command[0] @prefixArgs --help
```

Checkout resolution probes local virtual environments, then PATH launchers, for runnable Python 3.10 or newer. Each probe has a three-second deadline and bounded process cleanup; broken, unsupported, or stalled candidates are skipped without printing their diagnostics. A checkout without a supported interpreter requires environment setup. Relative `-StartPath` and environment checkout paths follow the current PowerShell filesystem location. On systems without PowerShell, use a known checkout with `python -m Repo_Privacy_Guardian` from its root, or the installed console CLI; do not guess a backend path. If resolution fails, ask for the checkout location or CLI setup. Do not silently clone, install dependencies, or change persistent environment variables.

Record the requested target before changing working directory. Always pass explicit `--root` and `--repos`; the backend checkout is not implicitly the audit target. Artifacts are written under `<backend.cwd>/Audit_Results/<run_id>/`. `--root` selects targets and does not relocate artifacts; `--report-dir` is restricted to that working directory's `Audit_Results` tree.

## Audit and review

Start with `--help`, then `--check-tooling` when readiness is unknown. Do not add `--install-missing-tools` without operator authorization for dependency installation.

First audit only the requested repositories:

```text
--root <repos-root> --repos <target-repo> --dry-run --yes --agent-summary
```

`--repos` accepts names under the root or absolute checkout paths. Omitting it expands discovery. `--yes` suppresses CLI prompts and does not grant operator authorization. A dry run still writes local evidence and uses the normal execution lock.

Review `agent_summary.json` first, then relevant redacted details in `report.json`, `report.html`, and `run.log`. Check `run_state.json`, the exit code, expected repository selection, and execution errors before calling a scan complete. A completed policy failure can have run-state status `failed`; use phase `finished`, repository counts, and execution errors to distinguish it from incomplete execution. Keep evidence local and reference its paths without pasting raw secrets, private emails, hostnames, internal URLs, personal paths, or unredacted logs.

Distinguish policy status from publication guidance: repository `status` in `report.json` is `PASS` or `FAIL`; the agent summary decision can be `PASS`, `REVIEW`, or `FAIL`. Advisory findings can leave policy `PASS` while publication guidance remains `REVIEW`.

Classify findings before suggesting changes:

| Class | Next action |
| --- | --- |
| Confirmed leak | Block publication, preserve redacted evidence, recommend credential rotation outside the tool when relevant, and prepare reviewed remediation. |
| Intentional fixture/example or safe documentation | Explain the intended context; prefer obvious placeholders if clarification is needed. |
| Indeterminate/manual-review | Request an owner decision when context is insufficient; avoid automatic repair. |
| Advisory hardening | Review the consequence and decide whether action is warranted. |
| Tooling/runtime issue | Resolve the incomplete run and repeat the audit. |

For each relevant group, report risk level, possible consequence, one next action, and a redacted artifact reference. Blocking counts can include aggregate failure reasons; do not describe the total as a count of distinct leaks. Low-confidence secret assignments, `exfil_code_indicators`, and GitHub hardening findings are advisory/manual-review by default. High-confidence secret buckets are blocking.

## Reviewed repair and optional modes

For an audit-only request, finish with classified findings and next actions. When the user requests repair planning, produce a concrete preview with `--fix --dry-run --yes` for the selected targets after classifying findings. Apply only reviewed, authorized remediations. Existing explicit authorization remains valid; do not request it again unnecessarily. Audit or skill-installation requests alone do not authorize live repair, history rewriting, or push.

Before live repair or optional policy/network modes, read [references/advanced-operations.md](references/advanced-operations.md). Re-run the audit after approved changes until policy `PASS` or a documented remaining blocker requires an owner decision. Report any remaining `REVIEW` decision explicitly.

When backend documentation is available, use its current `AGENTS.MD`, `docs/DOGFOODING.md`, and maintained prompt library for details. Spanish prompts 05, 06, and 07 cover audit-only, environment setup, and repair; English equivalents are under `docs/prompts/en/`. Resolve those files relative to `backend.repoRoot` rather than the audit target.

## Maintaining the public tool repository

RepoPrivacyGuardian is already public. Read its `AGENTS.MD` and `README.MD` before changing the backend. New audit, report, hardening, remote-audit, or repair behavior must preserve CLI/GUI parity through shared configuration/policy keys and regression tests. Skill installation and resolution operate the existing CLI.

Keep skill source and examples portable. Personal backend paths belong only in the installed `.local/install.json`, never in tracked files. Keep evidence, logs, screenshots, scratch materials, and builds in ignored locations such as `Audit_Results/` and `.local-meta/`. Inspect `git status --short` and `git diff --check` before staging intentional changes. Do not push or publish artifacts unless the user authorized that action.

Refresh with `scripts/dev/install_codex_skill.ps1 -Force` after validating the maintained adapter; `-WhatIf` previews without writes. The installer validates a sibling staging copy and UTF-8 linkage metadata before replacement. Preparation failures preserve the previous skill; a failed replacement restores it when its destination remains free. If another process recreates that destination, the installer preserves both the concurrent contents and the previous backup for reviewed local recovery. It preserves neighboring skills and refuses overlapping or linked paths. Relative `-CodexHome` inputs follow the current PowerShell filesystem location. A process or system interruption can also leave a sibling backup for local recovery; keep that private metadata outside Git.
