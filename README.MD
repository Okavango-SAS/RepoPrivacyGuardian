# Repo Privacy Guardian

![Policy](https://img.shields.io/badge/policy-publication%20gate-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20CLI%20%7C%20Linux%20CLI-lightgrey)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)

Repo Privacy Guardian is a local-first publication gate for Git repositories before public release.

Its primary value is the repeatable CLI audit/remediation engine. The desktop GUI is optional and uses the same pipeline, but it is not required to operate the product.

## Support matrix

- Windows CLI: supported
- Linux CLI: supported
- macOS CLI: best-effort; not fully validated for this release
- Windows GUI: supported as an optional interface
- Linux GUI desktop: best-effort and depends on Tk availability plus a graphical session
- macOS GUI: not a release priority
- Headless and CI environments: CLI only

## What it audits

- leaked Git identity metadata
- secrets in tracked content and history
- personal or local absolute paths
- sensitive filenames in history
- tracked-but-ignored files and `.gitignore` drift
- advisory outbound or exfil-capable code indicators
- LiteLLM March 2026 supply-chain indicators

## Product contract

Blocking checks that can change `PASS` to `FAIL`:

- dirty working tree
- Git fsck failures
- private or unexpected commit metadata emails
- tracked or historical secret indicators
- tracked or historical personal path leaks
- low-confidence email findings when configured as blocking
- sensitive filenames in history
- tracked-but-ignored files
- missing required `.gitignore` rules
- LiteLLM `HIGH` or `CRITICAL` incident evidence
- remediation execution errors during `--fix`

Advisory checks that do not change `PASS` or `FAIL` by default:

- `exfil_code_indicators`

`exfil_code_indicators` is intentionally manual-review only by default. It is surfaced in CLI guidance, JSON, HTML, and severity highlights, but it does not fail a repository unless a future strict mode is introduced.

## CLI-first behavior

- Running the program without flags shows CLI help and exits successfully.
- Use `--gui` for the desktop interface.
- CLI does not open a browser automatically.
- Use `--open-report` if you explicitly want the HTML report opened after a CLI run.
- GUI can still open the report naturally as part of the desktop flow.

## Installation

Base CLI install:

```sh
python -m pip install .
```

Base CLI plus tests:

```sh
python -m pip install ".[test]"
```

Optional GUI support:

```sh
python -m pip install ".[gui]"
```

Optional remediation extras for history rewrite workflows:

```sh
python -m pip install ".[remediation]"
```

Developer environment:

```sh
python -m pip install ".[dev]"
```

Compatibility requirement files:

- `requirements.txt`: base CLI has no extra Python runtime dependencies
- `requirements-gui.txt`: optional GUI dependency set
- `requirements-remediation.txt`: optional remediation dependency set
- `requirements-dev.txt`: local development and test dependencies

External requirements:

- Git must be installed and available on `PATH`
- `git-filter-repo` is required only for remediation that rewrites history
- Linux desktop GUI use may require a Tk package such as `python3-tk`

## Quick start

Installed entry point:

```sh
repo-privacy-guardian --help
```

Installed module:

```sh
python -m Repo_Privacy_Guardian --help
```

Direct script execution remains available for compatibility:

```sh
python Repo_Privacy_Guardian.py --help
```

Safe audit:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes
```

Safe fix preview:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --dry-run --yes
```

Open the HTML report explicitly after a CLI run:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --open-report
```

Launch the optional GUI:

```sh
repo-privacy-guardian --gui
```

Windows note:

- `py` can be used instead of `python`
- `C:/path/to/repos` is accepted as a path form in PowerShell

## GUI contract

GUI and CLI share:

- the same audit logic
- the same remediation logic
- the same JSON, HTML, and log artifacts
- the same destructive-action guardrails

The GUI keeps the staged safety contract:

1. `Auditar`
2. review findings
3. `Reparar` only after audit context unlocks it

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

## Headless and desktop diagnostics

- If Git is missing, the CLI exits with an actionable error before the audit starts.
- If `--gui` is requested without GUI extras, the program reports how to install them.
- If `--gui` is requested in a headless Linux environment, the program exits with a desktop-session message instead of hanging.
- Browser opening is opt-in in CLI mode and warnings stay non-fatal if a browser cannot be launched.

## Release validation from a clean clone

```sh
python -m pip install ".[test]"
python -m pytest
repo-privacy-guardian --help
python tests/release_smoke_cli.py
```

Pytest collection is restricted to tracked test files so local ignored test files do not change the release signal.

## Repository layout

- `Repo_Privacy_Guardian.py`: core CLI and optional GUI implementation
- `docs/`: policy, release docs, and engineering rationale
- `tests/`: tracked regression, packaging, and smoke coverage
- `.github/workflows/ci.yml`: cross-platform CLI and packaging CI

## Safety notes

- history rewrites are destructive for commit SHAs
- backup bundles are mandatory before rewrite
- leaked secrets still require rotation after cleanup
- `--push` should only be used after a reviewed dry-run

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
