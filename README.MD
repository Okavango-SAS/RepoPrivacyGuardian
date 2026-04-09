# Repo Privacy Guardian

![Policy](https://img.shields.io/badge/policy-publication%20gate-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20PowerShell-lightgrey)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)

Repo Privacy Guardian is a local-first publication gate for Git repositories before public release.

It audits and optionally remediates:

- leaked Git identity metadata
- secrets in tracked content and history
- personal/local absolute paths
- sensitive filenames in history
- tracked-but-ignored files and `.gitignore` drift
- advisory outbound/exfil code indicators
- LiteLLM March 2026 supply-chain indicators

## Product contract

Blocking checks that can change `PASS` to `FAIL`:

- dirty working tree
- Git fsck failures
- private/unexpected commit metadata emails
- tracked or historical secret indicators
- tracked or historical personal path leaks
- blocking email findings when configured
- sensitive filenames in history
- tracked-but-ignored files
- missing required `.gitignore` rules
- LiteLLM `HIGH` or `CRITICAL` incident evidence
- any remediation execution error during `--fix`

Advisory checks that do not change `PASS`/`FAIL` by default:

- `exfil_code_indicators`

`exfil_code_indicators` is intentionally manual-review only by default. It is reported in CLI, JSON, HTML and severity highlights, but it does not fail the repository unless a future strict mode is introduced.

## Interfaces

- CLI for automation, reproducibility and agentic workflows.
- GUI for guided/manual operation with the same execution pipeline.

GUI and CLI share:

- the same audit logic
- the same remediation logic
- the same JSON/HTML/LOG artifacts
- the same guardrails

The GUI keeps the staged contract:

1. `Auditar`
2. review results
3. `Reparar` only after the audit context unlocks it

## Installation

Base package plus test extras:

```powershell
py -m pip install -e .[test]
```

GUI support:

```powershell
py -m pip install -e .[gui]
```

Optional history rewrite support:

```powershell
py -m pip install -e .[rewrite]
```

Compatibility convenience files:

- `requirements.txt`: GUI + optional rewrite support
- `requirements-dev.txt`: local dev/test dependencies

## Quick start

CLI help:

```powershell
py Repo_Privacy_Guardian.py --help
repo-privacy-guardian --help
```

Safe audit:

```powershell
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo --dry-run --yes
```

Safe fix preview:

```powershell
py Repo_Privacy_Guardian.py --root C:/path/to/repos --repos MyRepo --fix --dry-run --yes
```

GUI:

```powershell
py Repo_Privacy_Guardian.py --gui
```

## Artifacts

Each run writes local artifacts under `Audit_Results/<run_id>/`:

- `report.json`
- `report.html`
- `run.log`

Artifacts are redacted, but they still contain operational security context and should be treated as sensitive local outputs.

## What `--fix` does

When applicable and explicitly requested, the fix flow can:

- create a backup bundle first
- append missing `.gitignore` rules
- stop tracking ignored files
- generate `mailmap` and `replace-text` inputs
- rewrite history with `git-filter-repo`
- run post-rewrite cleanup
- optionally push with owner guardrails

It does not:

- rotate leaked credentials for you
- make outbound review decisions automatically
- bypass destructive safeguards by default

## Clean-clone validation

Release validation is designed to be reproducible from a clean clone:

```powershell
py -m pip install -e .[test]
py -m pytest
repo-privacy-guardian --help
```

Pytest collection is restricted to tracked test files so local ignored test files do not change the release signal.

## Repository layout

- `Repo_Privacy_Guardian.py`: main CLI + GUI implementation
- `docs/`: policy, release docs and engineering rationale
- `tests/`: tracked regression and smoke coverage
- `.github/workflows/ci.yml`: minimal Windows CI

## Safety notes

- history rewrites are destructive for commit SHAs
- backup bundles are mandatory before rewrite
- leaked secrets still require rotation after cleanup
- `--push` should only be used after a reviewed dry-run

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
