# TROUBLESHOOTING

This page covers the most common local failures when running Repo Privacy Guardian or preparing a release from the repository checkout.

## `git` is missing

Symptoms:

- CLI exits before the audit starts
- tooling preflight reports `git` as missing or blocking

What to do:

- run `repo-privacy-guardian --check-tooling`
- rerun with `--install-missing-tools` if you want the tool to try a supported local installation path
- on Windows, the readiness flow can bootstrap App Installer / `winget` first when supported

## GUI will not start

Symptoms:

- `--gui` exits immediately
- desktop startup reports missing GUI dependencies
- Linux desktop path reports a headless-session error

What to do:

- install the GUI extras: `python -m pip install ".[gui]"`
- rerun with `repo-privacy-guardian --check-tooling --gui`
- on Linux, confirm both Tk and a graphical session are available

## GUI drag-and-drop is unavailable

Symptoms:

- the repository list says drag-and-drop is unavailable
- dropping a repository folder does nothing, but Browse / Refresh still works

What to do:

- install or repair the GUI extras: `python -m pip install ".[gui]"`
- run `repo-privacy-guardian --check-tooling --gui`; missing `tkinterdnd2` is reported as optional because the GUI can still run without drag-and-drop
- restart the GUI so `tkinterdnd2` can initialize the native Tk drag-and-drop bridge
- use Browse / Refresh as the supported fallback on desktop runtimes that do not expose Tk DnD

## GitHub hardening is partial or warning-only

Symptoms:

- `github_hardening_warnings` mention missing authentication
- admin-only GitHub settings are not fully inspected

What to do:

- set `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`
- or authenticate GitHub CLI with `gh auth login`
- rerun `--audit-github-hardening`

## `gh` is installed but still not enough

Symptoms:

- preflight says GitHub CLI exists, but auth is still missing

What to do:

- run `gh auth status`
- if needed, run `gh auth login`
- rerun the audit or the release harness after authentication succeeds

## Release harness skips the self-audit

Symptoms:

- `python scripts/release_readiness.py` prints that self-audit is being skipped because the worktree is not clean

What to do:

- finish or stash local edits
- rerun the script after `git status --short` is empty
- if you intentionally want to validate only the build/test path while still editing, use `--skip-self-audit`

## Automatic fix is blocked before making changes

Symptoms:

- `fix_errors` mention a dirty worktree, `git fsck`, or earlier execution/runtime failures
- the audit re-runs, but no rewrite/untrack/commit step was attempted

What to do:

- make the repository clean first with `git status --short`
- resolve repository integrity issues if `git fsck --full` is already failing
- rerun a plain dry-run audit and review any `execution_errors` for lock, timeout, or git/runtime failures before trying `--fix` again

## Build artifacts look stale

Symptoms:

- `dist/` contains older package files than expected
- a local install appears to come from an earlier build

What to do:

- rerun `python scripts/release_readiness.py` without `--skip-clean-build-artifacts`
- if you are building manually, remove `dist/`, `build/`, and `*.egg-info/` before rebuilding

## GUI stop feels delayed

Symptoms:

- you click `Stop After Current Step` and the run does not stop immediately
- the GUI shows `Stopping after current step...` while work is still finishing

What to do:

- expect cooperative cancellation: the current repository step is allowed to finish cleanly before the run ends
- review `run.log` or `run_state.json` under `Audit_Results/<run_id>/` if you need to confirm which phase was still active
- prefer the CLI path for long-running operations if you need tighter operator control

## Browser behavior is different between CLI and GUI

Expected behavior:

- CLI does not open the HTML report unless `--open-report` is set
- GUI keeps `Open HTML report automatically` opt-in and off by default

If a report fails to open:

- treat the audit as successful if the JSON/HTML/log artifacts were still written locally
- open `Audit_Results/<run_id>/report.html` manually

## Recovering after a bad rewrite

What to do:

- locate the generated `<repo>-pre-publication-fix-<timestamp>.bundle`
- verify it with `git bundle verify`
- restore it into a clean directory with `git clone <bundle> recovered-repo`
- inspect the recovered refs before replacing or force-pushing anything
