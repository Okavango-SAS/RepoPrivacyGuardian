# RELEASE CHECKLIST

Use this checklist before tagging a public release.

## 1. Pre-flight

- Confirm clean working tree.
- Confirm target branch and remote.
- Confirm local git identity is correct for release commits.
- Clear stale local build outputs (`dist/`, `build/`, and `*.egg-info/`) before the final package build if you are reusing a workspace.
- Prefer `python scripts/release_readiness.py` as the final local pre-tag validation path.
- Confirm the public repository keeps `main` protected with pull-request-only changes and code-owner review.
- Confirm issues remain enabled if public issue intake is desired.
- Confirm public support matrix in README still matches validated platforms.
- Confirm README still distinguishes automatic CI smoke, manual extended CI, and the local release harness.
- Confirm branch protection required status checks match the current automatic CI smoke job names.
- Review GitHub Actions workflows for least-privilege permissions, explicit timeouts, and SHA-pinned actions.

## 2. Audit run

- Run audit on target repositories.
- Save JSON report artifact.
- For dogfooding another repository, follow `docs/DOGFOODING.md` and keep the first pass audit-only.
- Review FAIL reasons by severity.
- Review advisory/manual-review findings separately from blockers, including `exfil_code_indicators`.
- Classify each finding as confirmed leak, intentional fixture/example, indeterminate/manual-review, advisory hardening, or tooling/runtime issue before proposing fixes.
- Reference redacted evidence only; do not paste raw secrets, private emails, hostnames, internal URLs, or personal absolute paths into public notes.
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

- Update `CHANGELOG.md` or the current release notes.
- Update KNOWN_ISSUES if new recurring patterns are found.
- Update LEARNED_LESSONS with reusable insights.
- Add/update ENGINEERING_DECISIONS when behavior changes.
- Draft the release notes from `docs/RELEASE_NOTES_TEMPLATE.md`.
- Confirm `docs/VERSIONING.md` still matches the intended release semantics.
- Confirm README, POLICY and CLI help still match real PASS/FAIL semantics.

## 7. Release criteria

- Required checks pass.
- `python -m ruff check .` passes locally.
- `python scripts/release_readiness.py` passes locally, or any intentionally skipped parts are documented.
- Clean-clone validation passes: `python -m pip install .`, `repo-privacy-guardian --help`, `python -m pip install ".[test]"`, `python -m pytest`.
- Package build succeeds (`python -m build`) and both `wheel` and `sdist` installs complete cleanly.
- Automatic CI smoke is green.
- If the release depends on broader packaging/test/platform evidence, the manual extended CI suite has been run and recorded.
- Supported Python and platform claims remain aligned with the validation tiers documented in README.
- Risk exceptions are documented and approved.
- License and notice files are present and correct.
- Final report artifacts are stored in the expected local path.
