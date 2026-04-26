# Repo Privacy Guardian

![Policy](https://img.shields.io/badge/policy-publication%20gate-14532d)
![Support](https://img.shields.io/badge/support-Windows%20CLI%2FGUI%20%7C%20Linux%20CLI%20%7C%20macOS%20CLI-1d4ed8)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![License](https://img.shields.io/badge/license-Apache%202.0-f97316)

🔒 Repo Privacy Guardian is a local-first publication gate for auditing and hardening Git repositories before public release.

It is designed for repeatable CLI execution first, with an optional desktop GUI that runs on the same underlying pipeline. Built and maintained by **Axel E. Sacca**.

## ✨ Why This Exists

- Catch sensitive Git identity metadata before it leaks.
- Detect secrets, personal paths, tracked-but-ignored files, and risky history artifacts.
- Keep remediation explicit, reviewable, and safe-by-default.
- Generate local JSON, HTML, and log artifacts for release traceability.

**GUI is optional.** The core product value is the reproducible CLI audit and remediation workflow.

## 🧭 Start Here

Choose the path that matches what you need right now:

- First-time operator: read `--help`, run `--check-tooling`, then do a dry-run audit.
- Contributor working from a checkout: use [LOCAL_DEVELOPMENT](docs/LOCAL_DEVELOPMENT.md) for setup, validation loops, and repo map.
- Maintainer preparing a release: use [OPERATIONS](docs/OPERATIONS.md), [RELEASE_CHECKLIST](docs/RELEASE_CHECKLIST.md), and `python scripts/release_readiness.py`.

## 🧭 Support Matrix

- Linux CLI: supported; automatic CI smoke runs on Ubuntu with Python `3.13`
- Windows CLI: supported target; validate through the manual extended CI suite plus local release validation before public release
- macOS CLI: supported target; validate through local/manual release validation before public release
- Windows GUI: supported; manual extended CI smoke runs on `windows-latest` with Python `3.11`
- Linux GUI desktop: best-effort and depends on Tk availability plus a graphical session
- macOS GUI: best-effort / not a release priority
- Headless and CI environments: CLI only

## 📈 Release Posture

- Current release line: `v1.3.x`.
- `v1.0.0` established the stable CLI, packaging, and release contract within the current local-first scope.
- `v1.1.0` adds reusable GitHub release-hardening audit support and operator playbooks without widening the product scope.
- `v1.2.0` adds stronger environment readiness checks, optional GitHub CLI setup from the GUI, and Windows `winget` bootstrap support for local tool installation.
- `v1.2.3` is the public-release stabilization and GUI UX update.
- `v1.3.2` is the current patch release with secret taxonomy and evidence-classification hardening.
- Python `3.10` through `3.13` remain compatibility targets, but validation is tiered: automatic CI smoke is intentionally selective, broader checks live in manual extended CI and the local release harness.
- Built package validation covers both `sdist` and `wheel` install paths.
- GUI remains intentionally best-effort outside the Windows desktop path that has CI smoke coverage.
- Stable does not mean "does everything"; it means the current publication-gate scope, defaults, and operator expectations are now intentionally stable for `1.x`.

## 🧪 Validation Tiers

- automatic CI smoke: push-time Ubuntu/Python `3.13` checks for help paths, `python scripts/check_release_contract.py`, and CLI smoke
- manual extended CI: `workflow_dispatch` validation for `ruff`, `pyright`, tracked `pytest`, package smoke, and Windows GUI smoke
- local maintainer release gate: `python scripts/release_readiness.py` before public release or tag creation

## 🔍 What It Audits

- leaked Git identity metadata
- secrets in tracked content, history, and Git metadata, including high-confidence provider tokens, webhooks, auth headers, and credentialed URLs
- low-confidence generic secret assignments as advisory review items, with synthetic fixtures and safe documentation examples separated from blocking findings
- personal or local absolute paths
- sensitive filenames in history
- tracked-but-ignored files and `.gitignore` drift
- advisory outbound or exfil-capable code indicators
- optional GitHub repository hardening posture for public GitHub remotes
- LiteLLM March 2026 supply-chain indicators

## ✅ Product Contract

Blocking checks that can change `PASS` to `FAIL`:

- dirty working tree
- Git fsck failures
- private or unexpected commit metadata emails or malformed non-email identity tokens
- tracked, historical, or Git metadata high-confidence secret indicators
- tracked or historical personal path leaks
- low-confidence email findings when configured as blocking
- sensitive filenames in history
- tracked-but-ignored files
- missing required `.gitignore` rules
- LiteLLM `HIGH` or `CRITICAL` incident evidence
- remediation execution errors during `--fix`

Advisory checks that do not change `PASS` or `FAIL` by default:

- `exfil_code_indicators`
- `tracked_secret_low_confidence`, `history_secret_low_confidence`, and `git_metadata_secret_low_confidence`
- `tracked_secret_fixture_matches`, `history_secret_fixture_matches`, `tracked_secret_documentation_matches`, and `history_secret_documentation_matches`
- `github_hardening_findings`
- `github_hardening_warnings`

`exfil_code_indicators` is intentionally manual-review only by default. It is surfaced in CLI guidance, JSON, HTML, and severity highlights, but it does not fail a repository unless a future strict mode is introduced.

Generic `password = ...`, `api_key = ...`, `client_secret = ...`, and similar assignments are separated as low-confidence advisory findings unless they also match a high-confidence provider pattern. Placeholder-looking values in tests, fixtures, docs, examples, and README-style files are surfaced separately as safe fixture/documentation evidence instead of blocking publication.

GitHub hardening findings and warnings are also advisory/manual-review only by default when `--audit-github-hardening` is enabled.

## 🌐 Network Behavior

- Default audits, fix planning, and report generation operate on local Git metadata, local tracked files, and local history.
- `--public-only` performs a read-only unauthenticated GitHub REST API request for GitHub remotes to decide whether a repository is publicly accessible.
- `--audit-github-hardening` performs read-only GitHub REST API requests against GitHub remotes to inspect repository settings. Admin-only checks require `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`.
- `--github-owner` is an opt-in remote audit mode. It uses the GitHub REST API to discover repositories for a user/org, clones matches into a temporary private directory, audits those clones with the normal pipeline, and removes the clones after the run.
- Remote GitHub auditing is audit-only: it cannot be combined with `--fix` or `--push`. Public repositories are cloned with `git`; private repositories require an authenticated GitHub CLI session for `gh repo clone` so tokens are not placed in Git remote URLs or process arguments.
- The default CLI/GUI paths do not upload repository contents, reports, or telemetry to a remote service.

## 🔒 Local Security Posture

- Run artifacts are kept local and are written with private file permissions where the platform supports them.
- Each run writes a local `run_state.json` manifest so a partial, cancelled, or interrupted execution still leaves phase/exit diagnostics behind.
- Generated rewrite inputs such as temporary `mailmap` and `replace-text` files are removed after use instead of being left behind in temp storage.
- Tracked-file scanners skip symlinked files and oversized text candidates to reduce accidental local file disclosure and unbounded memory reads.
- Report/export writes and `.gitignore` remediation refuse symlinked target paths instead of following them.
- Repository execution is serialized with an OS-backed lock file in the Git metadata directory so overlapping audits/fixes do not mutate the same checkout concurrently, and crashed owners do not need PID/timestamp stale-lock reclamation.
- GitHub owner/org discovery and clone work are bounded: `gh auth token` probes use a short non-interactive timeout, paginated repository discovery fails closed at the page limit, and clone parallelism is capped.

## 🧰 Tooling Readiness

- `--check-tooling` verifies the local tools needed for the selected mode before you start a run.
- `--install-missing-tools` attempts to install supported missing tools automatically.
- The current readiness flow checks Git, GUI dependencies, rewrite tooling, Windows App Installer / `winget`, and GitHub hardening auth helpers when those features are relevant.
- In `--gui` mode, when the desktop preflight detects supported missing prerequisites, the app offers a popup to install them and retry startup automatically.
- In the GUI, enabling GitHub hardening also offers optional installation/repair of `gh`, and on Windows it can bootstrap App Installer / `winget` from the official Microsoft bundle when possible.
- For GitHub hardening token-gated checks, the supported helpers are token environment variables or an authenticated GitHub CLI (`gh auth login`).
- GitHub MCP is not a prerequisite for the standalone CLI/Desktop tool and is not required for end-user installations.
- `.env.example` is tracked as a reference for optional GitHub auth variables, but the tool does not auto-load it.

## 🖥️ CLI-First Behavior

- Running the program without flags shows CLI help and exits successfully.
- Use `--gui` for the desktop interface.
- CLI does not open a browser automatically.
- Use `--open-report` only when you explicitly want the HTML report opened after a CLI run.
- GUI runs can be cancelled; cancellation stops after the active repository step completes and the run is recorded as `ABORTED`.
- In the GUI, `Open HTML report automatically` is opt-in and off by default.
- The GUI keeps the staged `Audit -> Repair` interaction so operators cannot jump straight to write actions.
- The GUI stores non-secret setup preferences locally after setup, then collapses policy/output/GitHub/identity controls into Settings so the main screen stays focused on repository selection, Audit, and the log.
- The GUI repository list accepts drag-and-drop of local repository folders when the optional desktop drag-and-drop runtime is available; the Browse/Refresh path remains the fallback.
- `--check-tooling --gui` reports drag-and-drop readiness as an optional warning, not as a GUI startup blocker.
- GUI and CLI expose the same audit inputs for local repositories, GitHub owner/org remote audits, GitHub hardening, LiteLLM incident checks, report outputs, low-confidence email mode, and repair-only write options. GitHub owner/org remote audit remains audit-only in both paths.
- The tracked `DESIGN.md` defines the desktop visual tokens and UX constraints used for GUI changes.

## 📦 Installation

Recommended verified path for a cloned checkout:

```sh
python -m pip install .
```

Verified path from a locally built artifact:

```sh
python -m build
python -m pip install dist/<wheel-file.whl>
```

If you reuse the same workspace for multiple builds, clear old `dist/`, `build/`, and `*.egg-info/` outputs before relying on a fresh local package artifact.

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

Optional environment reference:

- `.env.example`: tracked reference for optional GitHub auth variables used by `--audit-github-hardening`

Compatibility requirement files:

- `config/requirements/requirements.txt`: base CLI has no extra Python runtime dependencies
- `config/requirements/requirements-gui.txt`: optional GUI dependency set
- `config/requirements/requirements-remediation.txt`: optional remediation dependency set
- `config/requirements/requirements-dev.txt`: local development and test dependencies

External requirements:

- Git must be installed and available on `PATH`
- `git-filter-repo` is required only for remediation that rewrites history
- GitHub CLI (`gh`) is optional for local audits, can supply admin auth for `--audit-github-hardening`, and is required for cloning private repositories in `--github-owner` mode
- Linux desktop GUI use may require a Tk package such as `python3-tk`
- Desktop drag-and-drop uses `tkinterdnd2`, included in the optional GUI dependency set. If that runtime cannot initialize, the GUI keeps working with Browse/Refresh.

Recommended support target:

- Python `3.10` through `3.13`

## 🛠️ Local Developer Flow

From a repository checkout:

```sh
python -m pip install ".[dev]"
python -m Repo_Privacy_Guardian --help
python -m Repo_Privacy_Guardian --check-tooling
python scripts/check_release_contract.py
python -m ruff check .
python -m pytest -q
python scripts/release_readiness.py --skip-self-audit
```

Use [LOCAL_DEVELOPMENT](docs/LOCAL_DEVELOPMENT.md) for the maintained contributor workflow, repository map, and validation variants.

## 🚀 Quick Start

Main script in this repository:

- `Repo_Privacy_Guardian.py`

Recommended execution order:

- `repo-privacy-guardian ...`: installed console entry point
- `python -m Repo_Privacy_Guardian ...`: module execution
- `python Repo_Privacy_Guardian.py ...`: direct compatibility path from the repository root

Typical first run for a new user:

1. install the base CLI
2. run `repo-privacy-guardian --check-tooling`
3. verify `--help`
4. run a dry-run audit against one repository
5. inspect the generated JSON, HTML, and log artifacts
6. run a dry-run fix preview before any destructive action

Tooling preflight:

```sh
repo-privacy-guardian --check-tooling
```

Attempt automatic installation of supported missing tools:

```sh
repo-privacy-guardian --check-tooling --install-missing-tools
```

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

If `--root` already points at a git repository and `--repos` is omitted, the CLI audits that checkout as `Current Root`.

Optional GitHub hardening audit for public-release settings:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --dry-run --yes --audit-github-hardening
```

This mode is audit-only: it reports advisory `github_hardening_findings` and `github_hardening_warnings`, but it does not change repository settings.

Coverage without authentication:

- local `.github/CODEOWNERS`
- public repository metadata such as visibility, archived/disabled state, wiki/projects/issues, and auto-merge
- private vulnerability reporting for public repositories when GitHub allows unauthenticated metadata reads

Token-gated coverage:

- default branch protection and required status-check drift
- Actions repository policy, SHA pinning, and default `GITHUB_TOKEN` workflow permissions
- Dependabot vulnerability alerts, Dependabot security updates, and open Dependabot alert presence
- secret scanning configuration, push protection, and open secret-scanning alert presence
- immutable releases

Use `REPO_PRIVACY_GUARDIAN_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, or an authenticated `gh auth login` session for token-gated checks. GitHub still decides completion from the token permissions: branch protection, Actions, Dependabot security updates, and immutable releases typically require repository `Administration` read access; Dependabot and secret-scanning alert listing require security-alert permissions such as `security_events`, `Dependabot alerts` read, or an equivalent admin/security-manager role. Reports only state that open alerts exist; they do not copy secret values or dependency names from GitHub alert payloads.

Opt-in GitHub owner/org remote audit:

```sh
repo-privacy-guardian --github-owner MyOrg --dry-run --yes
```

Remote audit filters:

```sh
repo-privacy-guardian --github-owner MyOrg --repos ServiceA ServiceB --github-fast --github-jobs 4 --dry-run --yes
repo-privacy-guardian --github-owner MyOrg --github-include-forks --public-only --dry-run --yes
```

The GUI exposes the same GitHub owner/org fields: owner/org, comma-separated remote repo filters, include forks, fast shallow clone, clone workers, and public-only filtering.

Safe fix preview:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --dry-run --yes
```

Advanced fix with explicit history replacements supplied by the operator or an agent:

```sh
repo-privacy-guardian --root /path/to/repos --repos MyRepo --fix --yes --replace-text-file /path/to/replace-text.txt
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

## 🧪 Expected CLI Outcome

Illustrative clean summary:

```text
[SUMMARY] PASS 1/1
[INFO] JSON report written to Audit_Results/<run_id>/report.json
[INFO] HTML report written to Audit_Results/<run_id>/report.html
[INFO] LOG report written to Audit_Results/<run_id>/run.log
```

Illustrative blocking summary:

```text
[SUMMARY] FAIL 1/1
risk: High risk: tracked or historical sensitive content was detected.
suggestion: Review the cited findings, run a dry-run fix preview, and authorize only the remediations you intend to keep.
```

Use the CLI summary for the operator decision, then open the JSON or HTML artifact only if you need the detailed finding list.

## 🧩 GUI Contract

GUI and CLI share:

- the same audit logic
- the same remediation logic
- the same JSON, HTML, and log artifacts
- the same destructive-action guardrails
- the same advanced replace-text remediation path for reviewed substitutions

The GUI keeps the staged safety contract:

1. `Audit`
2. review findings
3. `Repair` only after audit context unlocks it

After setup is saved, the GUI keeps advanced parity controls collapsed in Settings. This changes visibility only; GUI runs still build the same `GuardRunConfig` fields as CLI runs.

The GUI is intentionally privacy-first for public release. Maintained screenshots live under `docs/ux-audit/` and must use neutral visible paths so local usernames, private roots, and internal repository lists are not published in image pixels.

## 🗂️ Artifacts

Each run writes local artifacts under `Audit_Results/<run_id>/`:

- `report.json`
- `report.html`
- `run.log`
- `run_state.json`

Artifacts are redacted, but they still contain operational security context and should be treated as sensitive local outputs.

## 🛠️ What `--fix` Can Do

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
- mutate a dirty or diagnostically incomplete repository before the operator stabilizes it
- bypass destructive safeguards by default

## 🚫 What It Does Not Try To Be

- a hosted service or remote scanner
- a credential rotation platform
- a generic DLP suite for every repository risk
- an automatic authority for whether a network-capable code path is acceptable
- a cross-platform desktop product with identical GUI support on every OS

## 🧪 Automatic vs Reviewed Remediation

The tool can already remediate several classes of findings safely once you explicitly request `--fix`:

- create a mandatory backup bundle before rewrite
- append required `.gitignore` baseline rules
- stop tracking ignored files
- rewrite commit metadata email values, including malformed non-email tokens, to approved noreply or placeholder addresses
- rewrite detected personal paths when `--rewrite-personal-paths` is explicitly enabled
- merge an explicit `--replace-text-file` for known literals that cannot be inferred safely
- re-audit after remediation and fail the run if fix execution itself errors

Human or agent review is still required when the tool cannot safely infer intent from the finding alone:

- deciding whether a match in tests/docs/examples is a real leak or an intentional fixture
- rewriting source fixtures so the working tree stops re-seeding the same secret or personal path
- deciding whether a sensitive file should be purged conservatively or only reviewed
- rotating real credentials after cleanup

Practical rule: let the tool perform mechanical Git-safe rewrites, but keep semantic source edits and any non-obvious substitution under reviewed operator control.

## 🤖 Agentic CLI Workflow

Repo Privacy Guardian works well as an agent-driven CLI tool. A safe default pattern is:

1. `repo-privacy-guardian --help`
2. dry-run audit
3. reviewed dry-run fix plan
4. real fix only for the reviewed repos
5. re-run until `PASS`

For dogfooding against another repository, use [DOGFOODING](docs/DOGFOODING.md). That runbook keeps the first pass audit-only, requires classification of confirmed leaks versus intentional fixtures/examples, and treats `Audit_Results/<run_id>/` artifacts as sensitive local evidence even when redacted.

### Recommended agent prompt template

```text
Act as a release/security engineer. Work only on <target-repo>.
Use Repo Privacy Guardian from CLI, not GUI.
Start with --help, then run a dry-run audit, classify findings as confirmed leaks, intentional fixtures/examples,
indeterminate/manual-review, advisory hardening, or tooling/runtime issues. Reference redacted evidence from
Audit_Results/<run_id>/report.json, report.html, and run.log without pasting raw secrets or private paths.
Apply only safe reviewed fixes, use --replace-text-file only when an explicit literal replacement is required,
re-run the audit until the repository is PASS, and preserve audit artifacts under Audit_Results.
Do not push or rewrite history without explicit approval.
```

The repository also includes reusable prompt files under `docs/prompts/`, including `05_DOGFOODING_AUDIT_ONLY.prompt.md`, for agentic audit and parity workflows.

## 🧰 Headless and Desktop Diagnostics

- If Git is missing, the CLI exits with an actionable error before the audit starts.
- If `--gui` is requested without GUI extras, the program reports how to install them.
- If `--gui` is requested in a headless Linux environment, the program exits with a desktop-session message instead of hanging.
- Browser opening is opt-in in CLI mode and warnings stay non-fatal if a browser cannot be launched.

## 🧾 Release Validation From a Clean Clone

```sh
python -m pip install .
repo-privacy-guardian --help
python -m pip install ".[test]"
python -m pytest
python tests/release_smoke_cli.py
python -m build
```

Preferred local pre-tag validation for this repository:

```sh
python scripts/release_readiness.py
```

Pytest collection is restricted to tracked test files so local ignored test files do not change the release signal.

Validation tiers for this repository:

- automatic CI smoke: `repo-privacy-guardian --help`, module/direct-script help, `python scripts/check_release_contract.py`, and `python tests/release_smoke_cli.py`
- manual extended CI: `ruff`, `pyright`, tracked `pytest`, package smoke for `wheel` and `sdist`, plus Windows GUI smoke
- local maintainer release gate: `python scripts/release_readiness.py`

## 📚 Release Engineering Docs

- [CHANGELOG](CHANGELOG.md): shipped release notes and public version history
- [LOCAL_DEVELOPMENT](docs/LOCAL_DEVELOPMENT.md): contributor setup, validation loops, and repository map
- [ARCHITECTURE](docs/ARCHITECTURE.md): code navigation and subsystem boundaries inside the single-file implementation
- [VERSIONING](docs/VERSIONING.md): versioning policy, stable-baseline notes, and `1.x` release discipline
- [RELEASE_CHECKLIST](docs/RELEASE_CHECKLIST.md): pre-tag release checklist
- [OPERATIONS](docs/OPERATIONS.md): local runbook for preflight, release validation, and recovery
- [DOGFOODING](docs/DOGFOODING.md): audit-only workflow for using the tool defensively on other repositories
- [TROUBLESHOOTING](docs/TROUBLESHOOTING.md): common operator failures and fast diagnosis paths
- [RELEASE_NOTES_TEMPLATE](docs/RELEASE_NOTES_TEMPLATE.md): lightweight notes template for public releases
- [ROADMAP](docs/ROADMAP.md): current maturity, next hardening steps, and out-of-scope boundaries

## 🏗️ Repository Layout

- `Repo_Privacy_Guardian.py`: main script, core CLI, and optional GUI implementation
- `repo_privacy_guardian_artifacts.py`: typed run-artifact and run-state helpers shared by CLI and GUI flow
- `repo_privacy_guardian_resources/`: packaged policy resource used by installed builds
- `config/requirements/`: compatibility dependency manifests
- `docs/`: policy, dogfooding runbook, prompts, release docs, and engineering rationale
- `tests/`: tracked regression, packaging, smoke coverage, and release hygiene
- `.github/workflows/ci.yml`: cost-first automatic CLI smoke plus manual extended validation and Windows GUI smoke

Files that intentionally remain in the repository root:

- `CHANGELOG.md`
- `README.MD`
- `Repo_Privacy_Guardian.py`
- `pyproject.toml`
- `AGENTS.MD`
- `LICENSE`
- `NOTICE`

## ⚠️ Limitations

- Linux GUI support is still desktop-dependent and best-effort.
- macOS GUI is not a release priority for the current stable line.
- History rewrites are destructive for commit SHAs and require careful coordination.
- Leaked secrets still need rotation after cleanup.
- `--push` should only be used after a reviewed dry-run.

## 👤 Developer

Repo Privacy Guardian is developed by **Axel E. Sacca**.

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
