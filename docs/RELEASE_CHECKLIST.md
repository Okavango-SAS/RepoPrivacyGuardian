# RELEASE CHECKLIST

Use this checklist before tagging a public release.

## 1. Pre-flight

- Confirm clean working tree.
- Confirm target branch and remote.
- Confirm local git identity is correct for release commits.
- Confirm public support matrix in README still matches validated platforms.
- Review GitHub Actions workflows for least-privilege permissions, explicit timeouts, and SHA-pinned actions.

## 2. Audit run

- Run audit on target repositories.
- Save JSON report artifact.
- Review FAIL reasons by severity.
- Review advisory/manual-review findings separately from blockers, including `exfil_code_indicators`.
- If using GUI, confirm `Audit` is the first executable step and `Repair` is visually locked before audit context is available.

## 3. Remediation plan

- Run dry-run fix first.
- Confirm secret file candidates.
- Classify manual-review candidates.
- Confirm backup bundle location.
- If using GUI, confirm `Repair` unlocks only after a valid audit provides actionable remediation context.

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
- Draft the release notes from `docs/RELEASE_NOTES_TEMPLATE.md`.
- Confirm `docs/VERSIONING.md` still matches the intended release semantics.
- Confirm README, POLICY and CLI help still match real PASS/FAIL semantics.

## 7. Release criteria

- Required checks pass.
- Clean-clone validation passes: `python -m pip install -e ".[test]"`, `python -m pytest`, `repo-privacy-guardian --help`.
- Package build succeeds (`python -m build`) and both `wheel` and `sdist` installs complete cleanly.
- CI is green on the tracked CLI test suite for Windows, Linux, and macOS plus Windows GUI smoke.
- Supported Python claims remain aligned with the Python versions that CI actually validates.
- Risk exceptions are documented and approved.
- License and notice files are present and correct.
- Final report artifacts are stored in the expected local path.
