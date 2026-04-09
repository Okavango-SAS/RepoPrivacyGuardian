# LEARNED LESSONS

## Operational lessons

1. `.gitignore` is preventive, not curative.

If a file was committed once, history rewrite is still required.

1. Dry-run must be the default behavior in sensitive environments.

Preview first, execute second.

1. Backup bundles are non-negotiable before rewrite.

Recovery needs to be immediate and offline.

1. Identity leaks are not only in code.

Commit metadata, logs, reports, and docs can all contain private data.

1. A clean report location matters.

Audit outputs can themselves contain sensitive references and must stay local and ignored.

## Engineering lessons

1. Safe auto-remediation should be conservative.

Ambiguous files should remain manual-review candidates.

1. Explicit operator intent reduces risk.

Dangerous actions should require dedicated flags.

1. Phase-separated GUI flow reduces unsafe remediation attempts.

Keeping `Reparar` visually locked until `Auditar` yields valid context prevents premature fix actions and mirrors CLI safety gating.

1. Reports should include action guidance, not only findings.

Operators need concrete next steps and command-level hints.

1. Generic defaults improve public readiness.

Remove personal paths, names, and private emails from defaults.

1. Redaction must handle escaped and unescaped path variants.

JSON-style escaped paths (for example `C:\\Users\\...`) and plain paths must both be sanitized in artifacts.

1. Release tests must come from tracked files only.

If `pytest` can see local-only test files that are not in `HEAD`, the workspace can report a false green state that CI and clean clones cannot reproduce.

## Documentation lessons

1. Governance docs are part of the product.

Policy, checklist, known issues, and decisions must evolve with code.

1. Keep rationale close to implementation.

Decision logs avoid re-discussing already settled tradeoffs.
