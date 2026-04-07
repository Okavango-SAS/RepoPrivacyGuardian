# LEARNED LESSONS

## Operational lessons

1. `.gitignore` is preventive, not curative.
- If a file was committed once, history rewrite is still required.

2. Dry-run must be the default behavior in sensitive environments.
- Preview first, execute second.

3. Backup bundles are non-negotiable before rewrite.
- Recovery needs to be immediate and offline.

4. Identity leaks are not only in code.
- Commit metadata, logs, reports, and docs can all contain private data.

5. A clean report location matters.
- Audit outputs can themselves contain sensitive references and must stay local and ignored.

## Engineering lessons

1. Safe auto-remediation should be conservative.
- Ambiguous files should remain manual-review candidates.

2. Explicit operator intent reduces risk.
- Dangerous actions should require dedicated flags.

3. Reports should include action guidance, not only findings.
- Operators need concrete next steps and command-level hints.

4. Generic defaults improve public readiness.
- Remove personal paths, names, and private emails from defaults.

## Documentation lessons

1. Governance docs are part of the product.
- Policy, checklist, known issues, and decisions must evolve with code.

2. Keep rationale close to implementation.
- Decision logs avoid re-discussing already settled tradeoffs.
