# Prompt 06 - Agentic Environment Setup

Act as a release/security engineer.
Work only on the freshly cloned local checkout of Repo Privacy Guardian.
Use the CLI to prepare and validate the environment. Do not audit other repositories yet.

## Objective

Leave Repo Privacy Guardian ready for use from an agentic IDE or coding agent such as Codex, Claude Code, Antigravity, GitHub Copilot, Cursor, or equivalent tools, without destructive changes and without installing system tooling unless explicitly approved.

## Mandatory Flow

1. Skim `README.MD`, `AGENTS.MD`, and `docs/DOGFOODING.md` to understand the contract.
2. Confirm Python version and git branch/status.
3. Create or reuse a local virtual environment only if it is needed and safe in context.
4. Install the package locally:
   - minimum CLI use: `python -m pip install .`
   - optional GUI use: `python -m pip install ".[gui]"`
   - development/full validation use: `python -m pip install ".[dev,gui,remediation]"`
5. Run:
   - `repo-privacy-guardian --help`
   - `repo-privacy-guardian --check-tooling`
6. If validating the checkout for contribution, also run:
   - `python scripts/check_release_contract.py`
   - `python -m pytest -q`
7. If tooling is missing, report the blocker and ask for approval before using `--install-missing-tools` or installing system dependencies.

## Optional Codex Integration

When the operator requested Codex skill installation, use the maintained source
at `codex/skills/repo-privacy-guardian/SKILL.md` and run
`./scripts/dev/install_codex_skill.ps1` from this checkout. `-WhatIf` previews
installation; `-Force` refreshes an installed copy. The checkout link is stored
only in `.local/install.json` inside the installed skill, outside the repository.
See `docs/LOCAL_DEVELOPMENT.md` for resolution, updates, and validation.

## Guardrails

- Do not run `--fix`, `--push`, `--github-owner`, or audits against other repositories in this prompt.
- Do not read, print, or request tokens. Use only existing environment variables or an authenticated `gh` session when a later flow requires it.
- Do not open the GUI unless explicitly requested.
- Do not delete artifacts, caches, branches, or untracked files without explicit approval.
- Keep output brief and actionable.

## Expected Output

```text
Environment readiness: PASS | REVIEW | FAIL
Commands run:
- ...

Tooling:
- git: ready | missing | warning
- gui extras: ready | optional | missing
- remediation extras: ready | optional | missing

Next recommended command:
- repo-privacy-guardian --root <repos-root> --repos <target-repo> --dry-run --yes

Notes:
- [concrete blockers or warnings]
```
