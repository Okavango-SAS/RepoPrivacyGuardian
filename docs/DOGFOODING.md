# DOGFOODING AUDIT RUNBOOK

Use this runbook when Repo Privacy Guardian is used defensively to prepare another repository for publication or deployment.

The default posture is audit-only. Do not enable destructive fixes by default.

## Primary Agentic Use Case

The main automation use case is running Repo Privacy Guardian from an agentic IDE or coding agent such as Codex, Claude Code, Antigravity, GitHub Copilot, Cursor, or an equivalent local agent.

Use the CLI as the durable contract:

- agents can run repeatable commands
- artifacts are stable and inspectable
- GUI labels/locales cannot change backend semantics
- the operator keeps approval authority for destructive fixes

Prompt library:

- environment preparation after cloning this tool: `docs/prompts/06_PREPARACION_ENTORNO_AGENTICA.prompt.md`
- audit-only dogfooding: `docs/prompts/05_DOGFOODING_AUDIT_ONLY.prompt.md`
- reviewed audit and repair: `docs/prompts/07_AUDITORIA_REPARACION_AGENTICA.prompt.md`
- English equivalents: `docs/prompts/en/06_AGENTIC_ENVIRONMENT_SETUP.prompt.md`, `docs/prompts/en/05_DOGFOODING_AUDIT_ONLY.prompt.md`, and `docs/prompts/en/07_AGENTIC_AUDIT_AND_REPAIR.prompt.md`

## CLI Contract

The maintained automation contract is CLI-first:

1. start with `repo-privacy-guardian --help`
2. run `repo-privacy-guardian --check-tooling` when the target environment is unknown
3. run a local dry-run audit
4. review `Audit_Results/<run_id>/agent_summary.json`, `report.json`, `report.html`, and `run.log`
5. classify findings before proposing any fix
6. run fix preview only after review
7. run real fixes only with explicit operator approval
8. re-run audit until `PASS` or until the remaining blocker is documented

The GUI is a parity companion for manual use. Agentic dogfooding should prefer CLI so commands, artifacts, and outcomes are reproducible; the GUI `Prompts` tab exists to copy the same maintained CLI-first workflows into agentic IDE sessions.

## Baseline Commands

Safe local audit:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes
```

Optional GitHub release-hardening audit for GitHub-hosted targets:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --audit-github-hardening
```

Safe agent handoff summary:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --agent-summary
```

Strict release profile:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --strict-profile release
```

Reviewed advisory/manual-review suppression file:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --suppressions suppressions.json
```

Optional owner/org discovery audit:

```sh
repo-privacy-guardian --github-owner MyOrg --repos ServiceA ServiceB --github-fast --github-jobs 4 --dry-run --yes
```

Fix preview only after review:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --dry-run --yes
```

Do not run these without explicit approval and an already-reviewed dry-run plan:

```sh
repo-privacy-guardian --fix --yes
repo-privacy-guardian --fix --push
repo-privacy-guardian --purge-all-detected-secret-files
```

## Finding Classification

Classify each finding before proposing action:

| Classification | Evidence pattern | Default action |
| --- | --- | --- |
| Confirmed leak | High-confidence provider token, webhook, auth header, credentialed URL, Git metadata credential, private identity metadata, real local path, or sensitive file with production context | Block release, preserve redacted evidence, rotate affected secret outside this tool, then prepare reviewed remediation |
| Intentional fixture/example | `tracked_secret_fixture_matches`, `history_secret_fixture_matches`, `tracked_email_fixture_matches`, `history_email_fixture_matches`, synthetic values in tests, examples, mocks, screenshots, or placeholder-only content | Mark as fixture. Rewrite to a clearer placeholder only if it can confuse scanners or users |
| Safe documentation | `tracked_secret_documentation_matches`, `history_secret_documentation_matches`, placeholder-like values in docs, README-style files, policies, runbooks, or changelogs | Keep non-blocking. Prefer obvious placeholders and avoid real credential shapes unless the example requires them |
| Reviewed project context | `reviewed_network_indicators` | Keep as traceability. Re-open exfil review only if the repository identity or reviewed code path changed |
| Indeterminate/manual review | `tracked_secret_low_confidence`, `history_secret_low_confidence`, `git_metadata_secret_low_confidence`, context-incomplete values, or generic assignments that may be sample data | Keep audit-only, ask for owner decision, and do not auto-fix |
| Advisory hardening | `github_hardening_findings`, `github_hardening_warnings`, or `exfil_code_indicators` | Review manually. These signals are advisory/manual-review by default |
| Tooling/runtime issue | `execution_errors`, clone/auth warnings, timeout, or partial scan evidence | Treat the run as incomplete until the issue is resolved and the audit is re-run |

## Evidence Hygiene

Keep evidence useful without leaking sensitive data:

- cite artifact paths, counts, categories, file names, and line references
- use redacted report fields from `report.json` or the generated HTML report
- do not paste raw secret values, private emails, private hostnames, internal URLs, absolute personal paths, or unredacted log lines into tickets or chat
- quote only the minimum redacted snippet needed to identify the finding
- treat `Audit_Results/<run_id>/` as sensitive local evidence even when redacted
- use `agent_summary.json` for compact handoff when an agent needs status, counts, artifact names, and next action without raw findings
- do not upload report artifacts to public issue trackers unless they have been separately reviewed

## Agent Output Template

Use this shape when reporting a dogfooding run:

```text
Decision: PASS | FAIL | REVIEW
Commands run:
- repo-privacy-guardian --help
- repo-privacy-guardian --root ... --repos ... --dry-run --yes
- optional: repo-privacy-guardian --root ... --repos ... --dry-run --yes --audit-github-hardening

Artifacts:
- Audit_Results/<run_id>/agent_summary.json
- Audit_Results/<run_id>/report.json
- Audit_Results/<run_id>/report.html
- Audit_Results/<run_id>/run.log

Findings:
- [classification] [category] [redacted evidence reference] [risk] [next action]

False-positive/fixture decisions:
- [finding reference] [why it is intentional] [whether any placeholder cleanup is recommended]

No destructive changes were applied.
```

## Safe Escalation Path

If a confirmed leak exists:

1. stop at audit evidence
2. document affected category and redacted location
3. rotate or revoke the credential outside this tool
4. run a fix preview with `--fix --dry-run --yes`
5. use `--replace-text-file` only for explicit operator-approved literal substitutions
6. execute real fixes only after review
7. re-run audit and preserve the new artifact paths
