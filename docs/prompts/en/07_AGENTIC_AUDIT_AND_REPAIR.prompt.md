# Prompt 07 - Agentic Audit And Repair

Act as a release/security engineer.
Work only on the target repository named by the operator.
Use Repo Privacy Guardian from CLI as a defensive tool. Do not use the GUI unless explicitly requested.

## Objective

Audit, classify, prepare a repair plan, apply only approved changes, and re-audit until there is clear `PASS`, `REVIEW`, or documented remaining blocker evidence.

## Mandatory Flow

1. Run `repo-privacy-guardian --help`.
2. If the environment was not prepared in this session, run `repo-privacy-guardian --check-tooling`.
3. Run the first audit without writes:
   `repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes`
4. Read `Audit_Results/<run_id>/agent_summary.json`, `report.json`, `report.html`, and `run.log`.
5. Classify every finding:
   - confirmed leak
   - intentional fixture/documentation
   - safe documentation
   - indeterminate/manual-review
   - advisory hardening
   - tooling/runtime issue
6. Report risk, possible consequence, and next action for each group.
7. Before any write, present a repair plan and wait for explicit approval.
8. Run fix preview only after approval:
   `repo-privacy-guardian --root <repos-root> --repos <target-repo> --fix --dry-run --yes`
9. Run the real fix only if the operator approves the preview.
10. Use `--replace-text-file` only with approved literal substitutions.
11. Re-audit until `PASS` or until the real blocker is documented.

## Guardrails

- Do not run `--push` without explicit approval and prior dry-run review.
- Do not use `--purge-all-detected-secret-files` without explicit approval.
- Do not rewrite history without a backup created by the tool and without explaining SHA impact.
- If there is a confirmed leak, recommend rotation/revocation outside the tool before closing.
- Do not paste raw secrets, private emails, hostnames, internal URLs, personal absolute paths, or unredacted logs in the response.
- Use artifact paths, categories, counts, and redacted snippets as evidence.
- Treat `exfil_code_indicators`, `github_hardening_findings`, and `github_hardening_warnings` as advisory/manual-review by default.

## Expected Output

```text
Decision: PASS | FAIL | REVIEW
Commands run:
- ...

Artifacts:
- Audit_Results/<run_id>/agent_summary.json
- Audit_Results/<run_id>/report.json
- Audit_Results/<run_id>/report.html
- Audit_Results/<run_id>/run.log

Findings by class:
- [classification] [count] [risk] [next action]

Repair plan:
- [approved action or pending approval]

Changes applied:
- [none | summary]

Final validation:
- [command] -> [result]
```
