# Repo Privacy Guardian 🛡️

[![Policy](https://img.shields.io/badge/policy-publication%20gate-blue)](#policy)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20PowerShell-lightgrey)](#quick-start)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](#quick-start)

A practical toolkit to audit and harden repositories before public release.

It helps you detect and remediate:
- leaked identity metadata in git history 👤
- exposed secrets/tokens/keys 🔐
- local machine path leaks 🧭
- risky tracked artifacts and ignore drift 🧹
- suspicious outbound/exfil patterns in code 🌐

## Why this project exists ✨

Public repositories are permanent records. One bad push can expose personal data or credentials, even if files are deleted later.

Repo Privacy Guardian gives you:
- repeatable audit checklist
- policy-driven decisions (PASS/FAIL)
- optional automated remediation flow

## Repository layout 📁

- Repo_Privacy_Guardian.py: main CLI + GUI auditor/fixer
- docs/POLICY.md: generic rector publication policy template
- docs/ROADMAP.md: short-term and medium-term product plan
- docs/KNOWN_ISSUES.md: current limitations and safe workarounds
- docs/LEARNED_LESSONS.md: lessons captured from audits and remediations
- docs/ENGINEERING_DECISIONS.md: rationale behind core architecture choices
- docs/RELEASE_CHECKLIST.md: pre-release operational gate
- .gitignore: baseline local/sensitive ignore rules

## Quick start ⚡

### 1) Run audit (CLI)

```powershell
py Repo_Privacy_Guardian.py --help
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo
```

### 2) Run guided fix preview (safe)

```powershell
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo --fix --dry-run --yes
```

### 3) Run GUI mode

```powershell
py Repo_Privacy_Guardian.py --gui
```

## Policy 📜

The repository includes a generic governance baseline in docs/POLICY.md.

Recommended workflow:
1. Audit first.
2. Review findings.
3. Run dry-run fix.
4. Apply real fix only when validated.
5. Re-audit until PASS.

## Safety notes 🚨

- History rewrites are destructive for commit hashes.
- Always create backup bundles before rewriting history.
- If secrets were leaked, rotate them even after cleanup.
- Use force push only with clear team communication.

## Status criteria ✅

A repository is considered safe-to-publish only when all required checks pass:
- metadata identity hygiene
- no sensitive leak indicators
- no tracked-but-ignored artifacts
- policy-aligned ignore coverage

## Contributing 🤝

Ideas and improvements are welcome.

When proposing changes:
- keep checks deterministic
- avoid project-specific hardcoding
- prefer secure defaults
