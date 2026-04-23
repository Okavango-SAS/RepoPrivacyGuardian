# OPERATIONS

This runbook covers the local operator path for validating, shipping, and recovering Repo Privacy Guardian.

## Local preflight

Install the tool and the local validation dependencies you need:

```sh
python -m pip install .[dev]
```

If the environment is not known yet, run the built-in tooling preflight first:

```sh
repo-privacy-guardian --check-tooling
repo-privacy-guardian --check-tooling --install-missing-tools
```

Use `--install-missing-tools` only when you want the tool to attempt local installation for supported prerequisites.

If you are working from this repository checkout instead of a packaged install, [LOCAL_DEVELOPMENT](LOCAL_DEVELOPMENT.md) is the shortest maintained setup guide.

Cheap contract-drift check from a repository checkout:

```sh
python scripts/check_release_contract.py
```

## Preferred local release validation

Run the repository-owned release harness before tagging or publishing package artifacts:

```sh
python scripts/release_readiness.py
```

By default the script:

- runs the CLI tooling preflight first
- checks workflow/docs/version alignment via `python scripts/check_release_contract.py`
- removes stale `dist/`, `build/`, and `*.egg-info/` outputs before the final build
- byte-compiles `Repo_Privacy_Guardian.py`
- runs `ruff check`
- runs tracked `pytest`
- runs CLI and GUI smoke scripts
- verifies module help and direct-script help
- builds the `wheel` and `sdist`
- installs both artifacts in isolated virtual environments, runs `pip check`, and verifies the console entry point plus module execution
- runs a final self-audit when the worktree is clean

Useful flags:

- `--skip-gui-smoke`: skip the GUI smoke path when a desktop session is not available
- `--skip-self-audit`: skip the final self-audit, useful while the worktree still has local changes
- `--skip-clean-build-artifacts`: keep existing build outputs if you intentionally want to inspect them

## Environment variables

Repo Privacy Guardian does not auto-load a `.env` file. Configure environment variables explicitly in the shell or execution environment.

The tracked `.env.example` file is only a reference template for the optional variables below.

Supported GitHub hardening auth variables:

- `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`
- `GITHUB_TOKEN`
- `GH_TOKEN`

These variables are optional unless you want fuller admin visibility for `--audit-github-hardening`.

## Artifacts and outputs

Operational outputs remain local by default:

- audit reports: `Audit_Results/<run_id>/report.json`, `report.html`, `run.log`
- execution state manifest: `Audit_Results/<run_id>/run_state.json`
- build outputs: `dist/`
- rewrite safety bundle: `<repo>-pre-publication-fix-<timestamp>.bundle`

Treat audit artifacts and backup bundles as sensitive local outputs even when report content is redacted.

The tool also applies a few local-safety defaults during normal operation:

- report and export writes avoid symlink targets
- run artifacts are created with private directory/file permissions where the platform supports them
- repository execution is guarded by an OS-backed lock file in the Git metadata directory to prevent overlapping runs on the same checkout without relying on PID/timestamp stale-lock reclamation
- automatic `--fix` refuses to mutate a repository when the worktree is dirty, `git fsck` has already failed, or the audit recorded runtime/timeout errors
- history scan startup failures and stream timeouts are promoted into `execution_errors` so partial scans do not look like a clean PASS
- generated rewrite helper files are temporary and removed after the rewrite step finishes

## Recovery and rollback

Before destructive rewrite work, the tool creates a bundle backup in the parent root of the target repository.

Practical recovery options:

1. Restore into a separate directory for inspection:

```sh
git clone path/to/<repo>-pre-publication-fix-<timestamp>.bundle recovered-repo
```

2. Compare refs before restoring anything to the main checkout:

```sh
git bundle verify path/to/<repo>-pre-publication-fix-<timestamp>.bundle
```

3. If a rewrite must be undone, recover from the bundle into a clean clone and only then replace or re-push intentionally.

## Operator guardrails

- Use dry-run audit before `--fix`.
- Use dry-run fix before a real rewrite.
- Keep `--push` off unless the remediation plan has already been reviewed.
- Prefer the local release harness over ad hoc manual command sequences when validating a public release candidate.
