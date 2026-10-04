# Optional modes and reviewed repair

Use the resolved command prefix and working directory from `SKILL.md`. All examples below are additional CLI arguments, with neutral placeholders.

## Live repair

`--fix` can change tracked content, untrack files, commit mechanical changes, rewrite history, expire reflogs, and garbage-collect. Review the preview and actual options before approval; do not assume a generic repair request authorizes every operation.

```text
--root <repos-root> --repos <target-repo> --fix --dry-run --yes
```

Apply only the approved plan. For a known literal that cannot be inferred safely, use `--replace-text-file <local-mapping-file>` with explicit operator-approved substitutions. Keep mapping files private and outside tracked source. Do not expose sensitive literals in command arguments, chat, examples, or Git remotes.

Before history rewriting, explain changes to commit SHAs and preserve the tool's backup bundle in a local ignored location. History rewrite, `--purge-all-detected-secret-files`, and push require explicit authorization. Dirty trees, fsck failures, or execution errors must be resolved rather than bypassed. Rotate/revoke confirmed credentials outside this tool.

Push only after dry-run review and explicit approval. Keep owner verification enabled; use `--allow-remote-owner <expected-owner>` where needed. Do not select `--allow-non-owner-push` by default. Push can force-update rewritten history.

After approved changes, repeat the same target audit and reference the new evidence. If the remaining issue needs credentials, owner context, or an unresolved runtime fix, report that blocker rather than looping or claiming `PASS`.

## Policy choices

- `--strict-profile audit-only` rejects `--fix` and `--push`.
- `--strict-profile internal` selects the documented default posture.
- `--strict-profile release` makes low-confidence emails blocking and promotes GitHub hardening findings only if that audit was explicitly enabled; it does not enable networking.
- `--low-confidence-email-mode informational|blocking` selects the email policy explicitly.
- `--suppressions <reviewed-file>` is for reviewed advisory/manual-review findings. It cannot suppress high-confidence secrets, path leaks, dirty trees, fsck failures, Git metadata blockers, execution errors, or fix errors.

Use these choices when the operator requests the corresponding posture. Do not weaken policy merely to obtain `PASS`. `--accept-github-admin-bypass` is only for a reviewed solo-maintainer operating model; it moves that specific signal to accepted risks.

## Network opt-ins

Default local audits do not enable GitHub network checks. `--public-only` performs GitHub visibility requests. `--audit-github-hardening` makes read-only GitHub settings requests. Enable them when the requested task includes that check.

```text
--root <repos-root> --repos <target-repo> --dry-run --yes --audit-github-hardening
```

Token-gated checks use `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, or an authenticated `gh` session. GitHub MCP is not required. Never print tokens or place them in command arguments/remotes.

Owner/org discovery is opt-in, downloads temporary clones, and remains audit-only:

```text
--github-owner <owner-or-org> --repos <repo-a> <repo-b> --dry-run --yes
```

Do not combine it with `--fix` or `--push`. `--github-fast` uses shallow clones; disclose the available-history limitation instead of asserting a complete history audit. Missing auth, discovery limits, failed clones, or partial runs require explicit reporting.

## Evidence lifecycle

`--compare-reports <before-report> <after-report>` compares existing redacted reports without a new audit. `--report-json` writes an extra export and does not relocate standard run artifacts.

Audit evidence remains sensitive even when redacted. Artifact cleanup is a separate requested operation: preview `--cleanup-audit-results --dry-run` before approved deletion. Do not clean evidence as a side effect of installation, auditing, or repair.
