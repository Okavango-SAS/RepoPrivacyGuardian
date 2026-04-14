# Repository Publication Policy (Rector Document)

> Generic baseline policy to prepare repositories for safe public publication.
> This template is intentionally identity-agnostic and does not contain personal data.

Shell note:

- Commands below are written in a shell-neutral form where possible.
- In PowerShell, `py` may be used instead of `python`.
- Adapt path quoting to your shell when repository paths contain spaces.

## Scope

- Applies to every repository maintained by this workspace/team.
- Must be executed before creating a public repository or switching from private to public.

## Goal

Prevent exposure of:

- personal identity metadata
- secrets and credentials
- local machine paths
- production logs/evidence
- uncontrolled network exfil paths

Final decision must be: PASS or FAIL.

## 1) Git identity policy (mandatory)

Rules:

- Public commits must use a GitHub noreply email.
- Personal/private emails must not appear in commit metadata.

Suggested global config:

```sh
git config --global user.name "<YOUR_NAME>"
git config --global user.email "<YOUR_GITHUB_NOREPLY_EMAIL>"
```

Verification:

```sh
git config --show-origin --global --get user.name
git config --show-origin --global --get user.email
```

Repo-specific override (only when required by organization policy):

```sh
git config --local user.name "<REQUIRED_NAME>"
git config --local user.email "<REQUIRED_EMAIL>"
```

## 2) Pre-publication gate checklist (mandatory)

### A) Clean local state

```sh
git status --short --branch
```

No unexpected changes should exist.

### B) Commit history audit

Review all historical author/committer emails:

```sh
git shortlog -sne --all
git log --all --pretty=format:"%h %ae %ce"
```

Search for secrets in patch history:

```sh
git log --all -p --no-color | rg -n "ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[A-Za-z0-9-]+|Authorization:\\s*(Bearer|token)\\s+[A-Za-z0-9._-]+|BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"
```

Search for personal/local paths in history:

```sh
git log --all -p --no-color | rg -n "C:\\\\Users\\\\|/Users/|/home/|AppData\\\\|Documents\\\\"
```

Detect sensitive filenames ever added:

```sh
git log --all --diff-filter=A --name-only --pretty=format: | rg -n -i "^\.env$|^\.env\.|\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|id_rsa|secrets?\\.|credentials?\\.|token"
```

Detect sensitive filenames later deleted (still a historical leak risk):

```sh
git log --all --diff-filter=D --name-only --pretty=format: | rg -n -i "^\.env$|^\.env\.|\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|id_rsa|secrets?\\.|credentials?\\.|token"
```

### C) Current tracked tree audit

Search secrets in current tracked files:

```sh
git grep -n -I -E "ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[A-Za-z0-9-]+|Authorization: Bearer|Authorization: token|BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"
```

Search personal/local paths:

```sh
git grep -n -I -E "C:\\\\Users\\\\|/Users/|/home/"
```

Search emails in tracked content:

```sh
git grep -n -I -E "[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
```

### D) Exfiltration surface review

```sh
rg -n --hidden -S "Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|HttpClient|WebClient|curl\\b|wget\\b|socket|upload|webhook|telemetry|analytics|http://|https://" src scripts playbooks docs/prompts tools
```

Action:

- Keep only justified network calls.
- Default to opt-in for outbound operations whenever possible.
- Treat heuristic exfil/outbound findings as mandatory manual review.
- Repo Privacy Guardian reports these indicators as advisory by default; they do not change PASS/FAIL on their own.

### E) .gitignore policy and effectiveness

Critical notes:

- .gitignore does not clean git history.
- .gitignore does not stop tracking files already committed.

Minimum baseline:

- .venv/
- .pkg-venv/
- __pycache__/
- .pytest_cache/
- .mypy_cache/
- .ruff_cache/
- .env
- .env.*
- wsa-config.local.yaml
- Audit_Results/
- sessions/*
- artifacts/
- exports/
- *.log
- *.tmp
- *.bak
- *-pre-publication-fix-*.bundle
- .vscode/
- .idea/
- .DS_Store
- Thumbs.db
- desktop.ini

Check currently ignored sensitive paths:

```sh
git status --short --ignored | rg -n "^!! (\.venv/|\.pkg-venv/|sessions/|\.env|\.env\.|.*-pre-publication-fix-.*\.bundle)"
```

Detect tracked-but-ignored files:

```sh
git ls-files -ci --exclude-standard
```

If output exists, fix immediately:

```sh
git rm --cached <path>
git commit -m "chore: stop tracking ignored sensitive/local file"
```

Review .gitignore evolution to catch late-added protections:

```sh
git log --all -- .gitignore
```

### F) Samples and fixtures

- Ensure examples, fixtures, screenshots, and logs are synthetic/anonymized.
- Never publish raw production artifacts with usernames, hostnames, or internal URLs.

### G) Technical final validation

Run project validators/tests before publication:

```sh
# Examples, adapt to each project
python -m pip install -e ".[test]"
pytest
```

Validation must be reproducible from a clean clone. Test collection must not depend on ignored or local-only test files outside the tracked repository tree.

## 3) If sensitive data already exists in history

Preferred tool: git-filter-repo.

1. Create full backup bundle:

```sh
git bundle create ../<repo>-pre-redaction.bundle --all
```

1. Install if missing:

```sh
python -m pip install git-filter-repo
```

1. Rewrite private emails in metadata (example):

```sh
git filter-repo --email-callback "return b'<NOREPLY_EMAIL>' if email == b'<PRIVATE_EMAIL>' else email"
```

1. Remove sensitive files from all history (example):

```sh
git filter-repo --path .env --path-glob "*.pem" --path-glob "*.key" --invert-paths
```

1. Replace leaked values in historical file content using a mapping file:

```sh
# replacements.txt format:
# literal:old_value==>redacted_value
git filter-repo --replace-text replacements.txt
```

1. Push safely:

```sh
git push --force-with-lease origin main
```

1. Re-audit after rewrite:

```sh
git shortlog -sne --all
```

1. Rotate real secrets even after rewrite.

## 4) Default licensing policy

Recommended default for public repositories: Apache License 2.0.

Why:

- permissive usage and redistribution
- clear attribution requirements
- stronger patent framework than minimal permissive licenses

Recommended implementation:

- include LICENSE (Apache-2.0 official text)
- include NOTICE (attribution)
- use SPDX metadata where applicable (Apache-2.0)

## 5) Non-negotiable operational rule

No repository can be published publicly without:

1. history audit
2. secrets/path audit
3. exfiltration review
4. verified .gitignore effectiveness
5. defined license

Important:

- `exfil_code_indicators` requires explicit review, but it is advisory by default and does not automatically force FAIL on its own.
- A dirty working tree is a blocking publication-gate failure until it is reviewed and cleaned.

If a sensitive file was ever committed and later ignored/deleted,
status remains FAIL until:

- history rewrite is completed
- impacted secrets are rotated
