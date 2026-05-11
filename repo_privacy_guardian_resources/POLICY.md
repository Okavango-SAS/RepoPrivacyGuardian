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
- Personal/private emails and malformed non-email identity tokens must not appear in author/committer email fields.

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

Review all historical author/committer email-field values:

```sh
git shortlog -sne --all
git log --all --pretty=format:"%h %an <%ae> | %cn <%ce>"
```

Search for secrets in patch history:

```sh
git log --all -p --no-color | rg -n "gh[opsru]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|gl(pat|dt|rt|ptt|ft)-[A-Za-z0-9_-]{16,}|cf(k|ut|at)_[A-Za-z0-9]{40,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|x(ox[baprs]|app|wfp)-[A-Za-z0-9-]+|hooks\.slack\.com/services|discord(app)?\.com/api/webhooks|Authorization:\\s*(Bearer|token|Basic)\\s+[A-Za-z0-9._~+/=-]+|BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"
```

Repo Privacy Guardian's built-in scanner separates secret evidence into confidence buckets:

- Blocking high-confidence patterns include GitHub and GitLab tokens, prefixed Cloudflare tokens, OpenAI and Anthropic key shapes, Google API/OAuth tokens, Slack tokens and webhooks, Discord webhooks and bot tokens, Stripe live/restricted keys, SendGrid keys, NPM tokens, Telegram tokens, Heroku API keys, Azure storage keys, AWS secret-key assignments, selected provider-key assignments, authorization headers, private-key headers, and credentialed URLs.
- Advisory low-confidence patterns include generic `password = ...`, `api_key = ...`, `client_secret = ...`, token, connection-string, webhook, and DSN assignments that do not match a provider-specific high-confidence pattern.
- Fixture and safe-documentation matches are separated when the value is placeholder-like and appears in tests, fixtures, mocks, samples, demos, docs, examples, README-style files, changelogs, policies, or runbooks. These buckets do not block publication by default.
- Email addresses found in tracked or historical tests, fixtures, mocks, samples, demos, benchmarks, and specs are preserved as safe fixture context in `tracked_email_fixture_matches` and `history_email_fixture_matches`. Real-looking emails in README/docs/contact examples remain low-confidence review items unless they use ignored placeholder domains such as `.invalid` or `.example`.
- Git metadata is included: credentialed remotes, URL rewrite rules, credential-related local config, and HTTP extra headers are scanned and redacted in reports.

Report fields preserve that taxonomy: `tracked_secret_matches`, `history_secret_matches`, and `git_metadata_secret_matches` are high-confidence blocking buckets; `tracked_secret_low_confidence`, `history_secret_low_confidence`, and `git_metadata_secret_low_confidence` are advisory; `tracked_secret_fixture_matches`, `history_secret_fixture_matches`, `tracked_secret_documentation_matches`, `history_secret_documentation_matches`, `tracked_email_fixture_matches`, `history_email_fixture_matches`, and `reviewed_network_indicators` are safe/reviewed context buckets.

Search for personal/local paths in history:

```sh
git log --all -p --no-color | rg -n "C:\\\\Users\\\\|/Users/|/home/|AppData\\\\|Documents\\\\"
```

Detect sensitive filenames ever added:

```sh
git log --all --diff-filter=A --name-only --pretty=format: | rg -n -i "^\.env$|^\.env\.|\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|id_(rsa|dsa|ecdsa|ed25519)|(^|/)\.(npmrc|pypirc|netrc|dockercfg)$|(^|/)\.docker/config\.json$|(^|/)\.aws/credentials$|(^|/)\.kube/config$|(^|/)kubeconfig$|secrets?\\.|credentials?\\.|token"
```

Detect sensitive filenames later deleted (still a historical leak risk):

```sh
git log --all --diff-filter=D --name-only --pretty=format: | rg -n -i "^\.env$|^\.env\.|\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|id_(rsa|dsa|ecdsa|ed25519)|(^|/)\.(npmrc|pypirc|netrc|dockercfg)$|(^|/)\.docker/config\.json$|(^|/)\.aws/credentials$|(^|/)\.kube/config$|(^|/)kubeconfig$|secrets?\\.|credentials?\\.|token"
```

### C) Current tracked tree audit

Search secrets in current tracked files:

```sh
git grep -n -I -E "gh[opsru]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|gl(pat|dt|rt|ptt|ft)-[A-Za-z0-9_-]{16,}|cf(k|ut|at)_[A-Za-z0-9]{40,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|x(ox[baprs]|app|wfp)-[A-Za-z0-9-]+|hooks\.slack\.com/services|discord(app)?\.com/api/webhooks|Authorization: (Bearer|token|Basic)|BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY"
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
- Repo Privacy Guardian may classify its own narrow, reviewed GitHub API and Windows App Installer bootstrap code paths as `reviewed_network_indicators`; this does not apply to lookalike paths in other repositories.

### E) GitHub repository hardening (recommended for public GitHub repos)

Recommended baseline:

- Protect the default branch.
- Require at least one pull request review.
- Require code owner review when `CODEOWNERS` is present.
- Require conversation resolution before merge.
- Disable force pushes and branch deletion on the protected branch.
- Require status checks for CI before merge.
- Restrict GitHub Actions, require SHA pinning, keep default workflow permissions at `read`, and do not allow Actions to approve pull requests.
- Enable Dependabot vulnerability alerts, automated security fixes, secret scanning, and secret scanning push protection.
- Enable immutable releases when the repository publishes release assets.
- Keep issues enabled if you want community reports; disable wiki/projects when they are not intentionally part of the repository workflow.

Optional Repo Privacy Guardian command:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --audit-github-hardening
```

GitHub hardening is audit-only. Repo Privacy Guardian does not change remote repository settings.

Checks that can run without authentication:

- local `.github/CODEOWNERS`
- public repository metadata, including visibility, archived/disabled state, issues, wiki, projects, and auto-merge
- private vulnerability reporting for public repositories when GitHub allows unauthenticated metadata reads

Token-gated checks:

- default branch protection and stale required status checks
- Actions policy, SHA pinning, and default `GITHUB_TOKEN` workflow permissions
- Dependabot vulnerability alerts, Dependabot security updates, and open Dependabot alert presence
- secret scanning configuration, push protection, and open secret-scanning alert presence
- immutable releases

Use one of these token sources for token-gated checks:

- `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`
- `GITHUB_TOKEN`
- `GH_TOKEN`
- authenticated GitHub CLI session via `gh auth login`

GitHub determines coverage from the token permissions. Branch protection, Actions, Dependabot security updates, and immutable releases typically require repository `Administration` read access. Dependabot and secret-scanning alert listing require security-alert access such as `security_events`, `Dependabot alerts` read, or an equivalent admin/security-manager role. Alert findings stay redacted: reports count/open-state risk only and do not include raw secret values or dependency names from GitHub API alert payloads.

Optional GitHub owner/org remote audit:

```sh
repo-privacy-guardian --github-owner MyOrg --dry-run --yes
repo-privacy-guardian --github-owner MyOrg --repos ServiceA ServiceB --github-fast --github-jobs 4 --dry-run --yes
```

Remote owner/org audit mode is opt-in and audit-only. It discovers repositories through the GitHub API, clones matches into a temporary private directory, audits them with the same policy pipeline, then removes the temporary clones. It must not be combined with `--fix` or `--push`. Discovery and clone work are bounded with a GitHub CLI auth timeout, a pagination limit that fails closed, and a clone-worker cap.

The GUI exposes the same remote-audit controls as CLI: GitHub owner/org, optional remote repository filters, include forks, shallow clone mode, clone workers, and public-only filtering.

Local repository discovery note: when `--repos` is omitted, local auto-discovery scans the root itself and direct child Git checkouts, but it does not follow symlinked child directories. If a symlinked checkout must be audited, select that target explicitly so the operator intent is clear.

GUI localization is presentation-only. Switching between English and Spanish (Latin America) changes visible desktop labels, dialogs, and contextual help, but it must not rename CLI flags, report fields, policy keys, or shared run-config mappings.

### F) Strict profiles and suppressions

Default behavior is unchanged when no strict profile is passed.

Strict profiles:

- `--strict-profile audit-only` rejects `--fix` and `--push`.
- `--strict-profile internal` documents the current default posture.
- `--strict-profile release` treats low-confidence emails as blocking and treats GitHub hardening findings as blocking only when `--audit-github-hardening` was explicitly enabled.
- `--strict-profile release` must not enable network access by itself.
- `exfil_code_indicators` remains advisory/manual-review in all profiles.
- `reviewed_network_indicators` remains non-blocking safe/reviewed context and does not require exfil review.

Suppression files:

- Use `--suppressions PATH` only for documented, reviewed advisory/manual-review findings.
- The JSON format is versioned with top-level `schema_version: 1` and a `suppressions` array.
- Each suppression requires `id`, `category`, `pattern`, `reason`, `owner`, and `expires`.
- Suppressed findings are retained in redacted `suppressed_findings`; they do not disappear silently.
- High-confidence secrets, path leaks, dirty tree state, fsck failures, execution errors, fix errors, and Git metadata blocking secrets cannot be suppressed.

Example:

```json
{
  "schema_version": 1,
  "suppressions": [
    {
      "id": "fixture-exfil-doc-2026-05",
      "category": "exfil_code_indicators",
      "pattern": "docs/examples/*requests.post*",
      "reason": "Documented fixture used to verify scanner guidance.",
      "owner": "security",
      "expires": "2026-12-31"
    }
  ]
}
```

### G) .gitignore policy and effectiveness

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
- !.env.example
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

### G) Samples and fixtures

- Ensure examples, fixtures, screenshots, and logs are synthetic/anonymized.
- Never publish raw production artifacts with usernames, hostnames, or internal URLs.

### H) Technical final validation

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
