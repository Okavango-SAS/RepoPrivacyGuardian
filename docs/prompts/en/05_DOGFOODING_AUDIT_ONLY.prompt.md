# Prompt 05 - Dogfooding Audit-Only For External Repositories

Act as a release/security engineer.
Work only on the target repository named by the operator.
Use Repo Privacy Guardian from CLI as a defensive audit tool.

## Objective

Prepare a repository for publication or deployment with traceable evidence, without enabling destructive fixes by default and without leaking sensitive data in the response.

## Mandatory Flow

1. Read the local contract: `repo-privacy-guardian --help`.
2. If the environment is unknown, run `repo-privacy-guardian --check-tooling`.
3. Run a local audit-only pass:
   `repo-privacy-guardian --root <root> --repos <repo> --dry-run --yes`
4. Locate `Audit_Results/<run_id>/agent_summary.json`, `report.json`, `report.html`, and `run.log`.
5. Classify every finding:
   - confirmed leak
   - intentional fixture/documentation
   - indeterminate/manual-review
   - advisory hardening
   - tooling/runtime issue
6. If the repository lives on GitHub and the operator requested a pre-publication settings review, run:
   `repo-privacy-guardian --root <root> --repos <repo> --dry-run --yes --audit-github-hardening`
7. Do not run `--fix`, `--push`, `--purge-all-detected-secret-files`, or `--replace-text-file` without explicit approval after review.

## Safe Evidence

- Cite artifact paths and counts.
- Use only redacted evidence from `report.json` or `report.html`.
- Do not paste raw secrets, private emails, hostnames, internal URLs, personal absolute paths, or complete unredacted `run.log` lines.
- Treat `Audit_Results/<run_id>/` as sensitive local evidence.

## Required Output

```text
Decision: PASS | FAIL | REVIEW
Commands run:
- ...

Artifacts:
- Audit_Results/<run_id>/agent_summary.json
- Audit_Results/<run_id>/report.json
- Audit_Results/<run_id>/report.html
- Audit_Results/<run_id>/run.log

Findings:
- [classification] [category] [redacted evidence reference] [risk] [next action]

False-positive / fixture decisions:
- [finding reference] [reason] [recommended action]

No destructive changes applied.
```

## Escalation

If there is a confirmed leak:

1. stop at audit-only
2. recommend rotation/revocation outside the tool
3. prepare a fix preview only if the operator approves
4. execute the real fix only with explicit approval
5. re-audit and record the new artifacts
