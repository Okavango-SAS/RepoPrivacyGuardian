# Prompt 04 - Agentic CLI Execution On A Repository

Act as a senior release/security engineer.
Work only on the target repository named by the operator.
Use Repo Privacy Guardian from CLI as a defensive audit tool.

## Objective

Audit a repository with traceable evidence, distinguish real leaks from intentional fixtures, apply only reviewed safe fixes, and avoid leaking sensitive data in the response.

## Mandatory Flow

1. Read the local contract: `repo-privacy-guardian --help`.
2. If the environment is unknown, run `repo-privacy-guardian --check-tooling`.
3. Run the first audit without writes:
   `repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes`
4. Review `Audit_Results/<run_id>/agent_summary.json`, `report.json`, `report.html`, and `run.log`.
5. Classify every finding as confirmed leak, intentional fixture/example, safe documentation, indeterminate/manual-review, advisory hardening, or tooling/runtime issue.
6. Explain risk, possible consequence, and one concrete next action for each group.
7. If a known literal must be rewritten and the replacement cannot be inferred safely, prepare a reviewed `--replace-text-file` mapping.
8. Re-run audit until `PASS`, or until the real remaining blocker is documented.
9. If the target repository lives on GitHub and the operator wants remote settings reviewed, also run `--audit-github-hardening` and distinguish real setting gaps from partial audit coverage due to missing token/admin scope.

## Guardrails

- Do not run `--fix`, `--push`, `--purge-all-detected-secret-files`, or history rewrite without explicit approval after audit review.
- Do not paste raw secrets, private emails, internal hostnames, private URLs, personal absolute paths, or unredacted logs into chat.
- Use artifact paths, categories, counts, and redacted snippets as evidence.
- Treat `exfil_code_indicators`, `github_hardening_findings`, and `github_hardening_warnings` as advisory/manual-review by default.

## Base Commands

Safe audit:

```sh
repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes
```

Fix preview after approval:

```sh
repo-privacy-guardian --root <repos-root> --repos <target-repo> --fix --dry-run --yes
```

Optional GitHub hardening audit:

```sh
repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes --audit-github-hardening
```

## Expected Output

- Decision: `PASS`, `FAIL`, or `REVIEW`
- Commands executed
- Artifact paths for `agent_summary.json`, `report.json`, `report.html`, and `run.log`
- Finding classification with redacted evidence references
- Reviewed repair plan, if approved
- Explicit confirmation: `No destructive changes applied` when only an audit was run
