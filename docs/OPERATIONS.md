# OPERATIONS

This runbook covers the local operator path for validating, shipping, and recovering Repo Privacy Guardian.

## Public repository posture

RepoPrivacyGuardian itself is already public on GitHub. Operational discipline must assume that every pushed branch, commit, tag, PR, release artifact reference, screenshot, and documentation change may be read by anyone on the internet.

Public-repo hygiene for maintainers:

- inspect `git status --short` and `git diff --check` before staging
- commit only intentional tracked source, tests, docs, and sanitized public assets
- keep generated reports, GUI QA captures, build outputs, coverage files, logs, local notes, and release backup bundles in ignored paths such as `Audit_Results/`, `.local-meta/`, `dist/`, `build/`, `*.egg-info/`, and `*-pre-publication-fix-*.bundle`
- do not commit raw secrets, private emails, internal hostnames, private URLs, personal absolute paths, unredacted logs, credentials in examples, or screenshots that reveal private local context
- if sensitive material reaches a commit, pause release work, preserve only redacted evidence, rotate affected credentials outside this repository, and coordinate reviewed history cleanup before pushing additional work

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

## External design-spec hygiene

The root `DESIGN.md` follows the public Google Labs `google-labs-code/design.md` format, pinned to release `0.1.0` while the upstream spec is still `alpha`.

Supply-chain guardrails for maintainers:

- treat the checked-in `DESIGN.md` as the source of truth for GUI work
- do not fetch a moving branch, install `@latest`, or execute remote design tooling during normal development
- if upstream validation is needed, use only a pinned package version: `npx --yes @google/design.md@0.1.0 lint DESIGN.md`
- run that optional validation read-only, from a clean checkout, without elevated filesystem or repository-write permissions
- remove secrets from the command environment before running external tooling, especially `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, and `NPM_TOKEN`
- do not grant package-publish, GitHub-write, or admin credentials to design-spec tooling

## Preferred local release validation

Run the repository-owned release harness before tagging or publishing package artifacts:

```sh
python scripts/release_readiness.py
```

By default the script:

- runs the CLI tooling preflight first
- checks workflow/docs/version alignment via `python scripts/check_release_contract.py`
- removes stale `dist/`, `build/`, and `*.egg-info/` outputs before the final build
- refuses symlinked build-output path components before path resolution, so stale-output cleanup does not delete through a symlink
- byte-compiles every packaged Python module and release helper script
- captures optional desktop GUI visual QA with `python scripts/visual_qa_gui.py` when a maintainer needs screenshot evidence for UI changes
- runs `ruff check`
- runs `pyright -p pyrightconfig.json`
- runs `pip-audit` against dev, GUI, and remediation requirement files
- runs tracked `pytest`
- runs CLI and GUI smoke scripts
- verifies module help and direct-script help
- builds the `wheel` and `sdist`
- installs both artifacts in isolated virtual environments, runs `pip check`, and verifies the console entry point plus module execution
- runs a final self-audit when the worktree is clean

Useful flags:

- `--skip-gui-smoke`: skip the GUI smoke path when a desktop session is not available
- `--skip-dependency-audit`: skip vulnerability checks for dependency files when the advisory service is unavailable or the environment is intentionally offline
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

GitHub hardening coverage is tiered:

- no auth: local `CODEOWNERS`, public repository metadata, and public private-vulnerability-reporting metadata when GitHub allows it
- token-gated: branch protection, Actions permissions, default `GITHUB_TOKEN` workflow permissions, Dependabot alerts/security updates, secret scanning alerts/configuration, and immutable releases

Use a token or authenticated `gh` session with repository admin/security permissions for the complete audit. The check remains audit-only and does not mutate GitHub settings.

Manual GitHub hardening fix guide:

- enable private vulnerability reporting for public repositories when desired
- enable secret scanning and secret scanning push protection
- protect `main` with a branch protection rule or ruleset
- require one approving pull request review, code-owner review when `CODEOWNERS` exists, stale-review dismissal, conversation resolution, strict current automatic CI checks, admin enforcement, and disabled force-push/deletion
- for solo-maintainer repositories, use `--accept-github-admin-bypass` to record the intentional admin-bypass exception as `github_hardening_accepted_risks`
- keep GitHub Actions workflow permissions least-privilege
- re-run `--audit-github-hardening` after changes

RepoPrivacyGuardian's own public repository should keep the automatic required check aligned to `CLI smoke + release contract (automatic, ubuntu-latest, py3.13)`. That smoke workflow is path-gated for protected-branch pull requests and `main` pushes that touch executable, packaging, resource, test, or validation-tooling surfaces. Docs-only changes stay local-first: run `python scripts/check_release_contract.py`, and if branch protection needs the smoke check for a docs-only PR, run `workflow_dispatch` without extended checks on that branch/commit. Manual extended workflow jobs remain maintainer-invoked release evidence and are not required on every push.

## Artifacts and outputs

Operational outputs remain local by default:

- audit reports: `Audit_Results/<run_id>/agent_summary.json`, `report.json`, `report.html`, `run.log`
- execution state manifest: `Audit_Results/<run_id>/run_state.json`
- build outputs: `dist/`
- rewrite safety bundle: `<repo>-pre-publication-fix-<timestamp>.bundle`

Treat audit artifacts and backup bundles as sensitive local outputs even when report content is redacted.

The tool also applies a few local-safety defaults during normal operation:

- report and export writes avoid symlink targets
- report-directory creation preserves symlinked paths long enough to fail closed instead of silently writing to a resolved destination
- temporary clone cleanup refuses symlinked path components before recursive removal
- local auto-discovery skips symlinked child directories unless the operator selects that target explicitly
- run artifacts are created with private directory/file permissions where the platform supports them
- `agent_summary.json` is written as a privacy-safe compact handoff for coding agents
- `report.html` starts with `Decision first` so blockers, advisory/manual-review signals, fixtures/docs, suppressions, and next action are visible before details
- `--compare-reports Audit_Results/<old>/report.json Audit_Results/<new>/report.json` compares re-audits with count-only category deltas and does not create a new run directory
- run artifact directory collision handling is bounded and fails visibly instead of looping indefinitely
- repository execution is guarded by an OS-backed lock file in the Git metadata directory to prevent overlapping runs on the same checkout without relying on PID/timestamp stale-lock reclamation
- automatic `--fix` refuses to mutate a repository when the worktree is dirty, `git fsck` has already failed, or the audit recorded runtime/timeout errors
- history scan startup failures and stream timeouts are promoted into `execution_errors` so partial scans do not look like a clean PASS
- GitHub owner/org remote audits use bounded auth probes, paginated discovery limits, and capped clone workers so network or scheduler failures stay diagnosable instead of hanging a release run
- atomic report/state writes fsync their replacement file and parent directory where the platform supports it, so interrupted runs are less likely to leave partially durable artifacts
- `run_state.json` records total, phase, and per-repository performance timing snapshots
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
- Prefer the local release harness over ad hoc manual command sequences when validating a release candidate.
