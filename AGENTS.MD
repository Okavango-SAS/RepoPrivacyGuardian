# AGENTS

This document defines how coding agents should use Repo Privacy Guardian from CLI.

## Scope

- Use CLI for automation, reproducibility, and stable artifacts.
- GUI and CLI are parity paths for checks and policy logic.
- GUI parity includes staged interaction: `Auditar` first, then `Reparar` after audit context unlocks visual repair gate.
- Prefer CLI in agentic IDE workflows (Codex, Cursor, Antigravity, VS Code with GitHub Copilot, and similar tools).

## CLI First Workflow

1. Start with help.
2. Run audit in dry-run mode.
3. Review findings with user-facing guidance: risk, possible consequence, and suggested action.
4. Authorize only the remediations that were reviewed.
5. Re-run audit until policy status is PASS.

Notes:

- Treat `exfil_code_indicators` as advisory/manual-review by default. Review them, but do not expect them to flip PASS/FAIL on their own.
- Release validation should come from tracked tests only so a clean clone reproduces the same `pytest` signal.

## Recommended Commands

Use one of these command styles:

- `py Repo_Privacy_Guardian.py ...`
- `.venv/Scripts/python.exe Repo_Privacy_Guardian.py ...`

Minimal safe audit for one repository:

```powershell
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo --dry-run --yes
```

Fix preview (no destructive write):

```powershell
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo --fix --dry-run --yes
```

Low-confidence email policy selection:

```powershell
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo --low-confidence-email-mode informational
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo --low-confidence-email-mode blocking
```

## Push Guardrails

- Do not use `--push` without prior dry-run review.
- If push is required, keep owner guardrails enabled.
- Prefer explicit owner allowlist when needed:

```powershell
py Repo_Privacy_Guardian.py --fix --push --allow-remote-owner axeljackal
```

## User Experience Contract

When reporting findings, keep outputs actionable and brief.

- State risk level.
- State possible consequence.
- State one suggested next action.

Avoid dumping all raw findings first. Start with decision guidance, then show details only if needed.

## Artifacts

- Reports are written under `Audit_Results/<run_id>/`.
- Use `report.json`, `report.html`, and `run.log` as the audit record.
- Treat artifacts as sensitive operational outputs even when redacted.
