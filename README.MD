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

## 🧭 Support Matrix

- Windows CLI: supported and CI-validated
- Linux CLI: supported and CI-validated
- macOS CLI: supported and CI-validated
- Windows GUI: supported with CI smoke coverage
- Linux GUI desktop: best-effort and depends on Tk availability plus a graphical session
- macOS GUI: best-effort / not a release priority
- Headless and CI environments: CLI only

## 📈 Release Posture

- Public maturity: the CLI and packaging surface are in late public beta and are being prepared for a credible `1.0.0` cut.
- Python support claims (`3.10` to `3.13`) are backed by CI coverage.
- Built package validation covers both `sdist` and `wheel` install paths.
- GUI remains intentionally best-effort outside the Windows desktop path that has CI smoke coverage.

## 🔍 What It Audits

- leaked Git identity metadata
- secrets in tracked content and history
- personal or local absolute paths
- sensitive filenames in history
- tracked-but-ignored files and `.gitignore` drift
- advisory outbound or exfil-capable code indicators
- LiteLLM March 2026 supply-chain indicators

## ✅ Product Contract

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

## 🌐 Network Behavior

- Default audits, fix planning, and report generation operate on local Git metadata, local tracked files, and local history.
- `--public-only` performs a read-only unauthenticated GitHub REST API request for GitHub remotes to decide whether a repository is publicly accessible.
- The default CLI/GUI paths do not upload repository contents, reports, or telemetry to a remote service.

## 🖥️ CLI-First Behavior

- Running the program without flags shows CLI help and exits successfully.
- Use `--gui` for the desktop interface.
- CLI does not open a browser automatically.
- Use `--open-report` only when you explicitly want the HTML report opened after a CLI run.
- The GUI keeps the staged `Audit -> Repair` interaction so operators cannot jump straight to write actions.

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

- `config/requirements/requirements.txt`: base CLI has no extra Python runtime dependencies
- `config/requirements/requirements-gui.txt`: optional GUI dependency set
- `config/requirements/requirements-remediation.txt`: optional remediation dependency set
- `config/requirements/requirements-dev.txt`: local development and test dependencies

External requirements:

- Git must be installed and available on `PATH`
- `git-filter-repo` is required only for remediation that rewrites history
- Linux desktop GUI use may require a Tk package such as `python3-tk`

Recommended support target:

- Python `3.10` through `3.13`

## 🚀 Quick Start

Main script in this repository:

- `Repo_Privacy_Guardian.py`

Recommended execution order:

- `repo-privacy-guardian ...`: installed console entry point
- `python -m Repo_Privacy_Guardian ...`: module execution
- `python Repo_Privacy_Guardian.py ...`: direct compatibility path from the repository root

Typical first run for a new user:

1. install the base CLI
2. verify `--help`
3. run a dry-run audit against one repository
4. inspect the generated JSON, HTML, and log artifacts
5. run a dry-run fix preview before any destructive action

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

The GUI is intentionally privacy-first for public release. This repository does not ship desktop screenshots by default to avoid publishing local paths, usernames, or internal repository lists in documentation assets.

## 🗂️ Artifacts

Each run writes local artifacts under `Audit_Results/<run_id>/`:

- `report.json`
- `report.html`
- `run.log`

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
- rewrite commit metadata emails to approved noreply or placeholder addresses
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

### Recommended agent prompt template

```text
Act as a release/security engineer. Work only on <target-repo>.
Use Repo Privacy Guardian from CLI, not GUI.
Start with --help, then run a dry-run audit, analyze whether findings are real leaks or intentional fixtures,
apply only safe reviewed fixes, use --replace-text-file only when an explicit literal replacement is required,
re-run the audit until the repository is PASS, and preserve audit artifacts under Audit_Results.
Do not push or rewrite history without explicit approval.
```

The repository also includes reusable prompt files under `docs/prompts/` for agentic audit and parity workflows.

## 🧰 Headless and Desktop Diagnostics

- If Git is missing, the CLI exits with an actionable error before the audit starts.
- If `--gui` is requested without GUI extras, the program reports how to install them.
- If `--gui` is requested in a headless Linux environment, the program exits with a desktop-session message instead of hanging.
- Browser opening is opt-in in CLI mode and warnings stay non-fatal if a browser cannot be launched.

## 🧾 Release Validation From a Clean Clone

```sh
python -m pip install ".[test]"
python -m pytest
repo-privacy-guardian --help
python tests/release_smoke_cli.py
python -m build
```

Pytest collection is restricted to tracked test files so local ignored test files do not change the release signal. CI additionally validates built `wheel` and `sdist` installs plus Windows GUI smoke.

## 📚 Release Engineering Docs

- [VERSIONING](docs/VERSIONING.md): versioning policy and `1.0.0` exit criteria
- [RELEASE_CHECKLIST](docs/RELEASE_CHECKLIST.md): pre-tag release checklist
- [RELEASE_NOTES_TEMPLATE](docs/RELEASE_NOTES_TEMPLATE.md): lightweight notes template for public releases
- [ROADMAP](docs/ROADMAP.md): current maturity, next hardening steps, and out-of-scope boundaries

## 🏗️ Repository Layout

- `Repo_Privacy_Guardian.py`: main script, core CLI, and optional GUI implementation
- `repo_privacy_guardian_resources/`: packaged policy resource used by installed builds
- `config/requirements/`: compatibility dependency manifests
- `docs/`: policy, prompts, release docs, and engineering rationale
- `tests/`: tracked regression, packaging, smoke coverage, and release hygiene
- `.github/workflows/ci.yml`: cross-platform CLI/package CI plus Windows GUI smoke

Files that intentionally remain in the repository root:

- `README.MD`
- `Repo_Privacy_Guardian.py`
- `pyproject.toml`
- `AGENTS.MD`
- `LICENSE`
- `NOTICE`

## ⚠️ Limitations

- Linux GUI support is still desktop-dependent and best-effort.
- macOS GUI is not a release priority for this version.
- History rewrites are destructive for commit SHAs and require careful coordination.
- Leaked secrets still need rotation after cleanup.
- `--push` should only be used after a reviewed dry-run.

## 👤 Developer

Repo Privacy Guardian is developed by **Axel E. Sacca**.

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
