# RELEASE CHECKLIST

Use this checklist before tagging a public release.

## 1. Pre-flight

- Confirm clean working tree.
- Confirm target branch and remote.
- Confirm local git identity is correct for release commits.

## 2. Audit run

- Run audit on target repositories.
- Save JSON report artifact.
- Review FAIL reasons by severity.

## 3. Remediation plan

- Run dry-run fix first.
- Confirm secret file candidates.
- Classify manual-review candidates.
- Confirm backup bundle location.

## 4. Controlled fix execution

- Execute fix with explicit flags.
- Re-run audit immediately after fix.
- Confirm no new regressions introduced.

## 5. Post-rewrite controls (if applicable)

- Expire reflog and run garbage collection.
- Force push with lease only when required.
- Share sync instructions for collaborators.
- Rotate leaked credentials/tokens.

## 6. Documentation and governance

- Update KNOWN_ISSUES if new recurring patterns are found.
- Update LEARNED_LESSONS with reusable insights.
- Add/update ENGINEERING_DECISIONS when behavior changes.

## 7. Release criteria

- Required checks pass.
- Risk exceptions are documented and approved.
- License and notice files are present and correct.
- Final report artifacts are stored in the expected local path.
