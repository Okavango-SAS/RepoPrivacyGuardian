# Repository and Codex skill audit and implementation plan

Audit date: **2026-10-04**. Audited baseline: public `main` at
`9f9355cd2add14a01e50c2cef3ef9a3d73ca02ca`, stable `1.5.x`.

The initial delivery recorded the audit and the staged implementation plan. The
operator subsequently authorized implementation, documentation, commit, and push
on **2026-10-04**, preserving the `1.x` contract and the documented solo-maintainer
operating model. The implementation record below is separate from the original
audit evidence. Version `1.5.1` remains unchanged; this work does not announce a
tag or release, rewrite history, or change remote repository settings.

## Implementation record — 2026-10-04

The table records the completed corrections and their acceptance checks. The
final tracked suite passes with **655 tests passed, one POSIX-specific test
skipped, and 84.54% statement coverage**, including the scanner, in an isolated
`[gui,test]` environment without system packages. The clean-worktree
release-profile self-audit also passes with zero blocking or manual-review entries
and one previously accepted administrator-bypass risk.
The historical 457-test/85.86% result below describes the original audited
baseline, not this implementation.

| Finding | Implementation | Current acceptance evidence |
| --- | --- | --- |
| F01 | One shared decision helper combines policy findings with explicit exit, completion, and target context. CLI handoff, agent summary, HTML, and GUI Reports use it. Late finalization errors refresh summary/HTML guidance without replaying JSON export. GUI worker errors clear stale PASS guidance before or after artifact creation. Legacy context is unknown and gives REVIEW. | Complete: decision, partial/error, advisory, legacy, artifact-persistence, and CLI/GUI regressions pass. The 74 focused GUI/reporting cases include four worker-error scenarios. |
| F02 | The build helper generates eight bilingual prompt resources from canonical `docs/prompts/` files. Checkout reads remain authoritative; installed reads use package resources. GUI Copy/Open share resolution, and materialized Open files live until GUI shutdown. | Complete: source/resource parity, controlled GUI callbacks, and current wheel/sdist isolated installs pass with all eight prompt resources. |
| F03 | Artifact validation runs outside the checkout with source-injecting `PYTHONPATH` removed. It checks import origin, entry points, policy, all eight prompt hashes, and `pip check`. CI and the local harness use this validator. | Complete: isolated validator regressions and both current built-artifact checks pass. |
| F04 | The streaming adapter owns deadlines and concurrent readers, caps stderr diagnostics at 16,384 characters, and cleans up processes, readers, and pipes on success, timeout, cancellation, or early exit. Reader/finalization failures preserve cleanup as well as the original error. Native explicit-input commands avoid conflicting subprocess stdin/input arguments. | Complete: controlled lifecycle/deadline/cleanup cases and four benign native input tests pass, including empty/nonempty input under normal and protected execution. |
| F05 | The skill probes interpreter readiness and Python 3.10+ support with a bounded non-interactive child process before selecting a candidate. | Complete: 66 skill cases pass with available Windows PowerShell 5.1 and PowerShell 7 using an in-checkout temporary root; 20 focused cases also pass with normal temporary placement. |
| F06 | Skill refresh validates a sibling staging copy before replacement, retains the previous copy until the swap succeeds, and rolls back handled failures. Cleanup validates containment and reparse safety. Unicode paths use native directory moves, and collisions preserve concurrently created destinations and recovery backups. | Failure-injection, byte-preserving rollback, destination/staging collisions, neighbor safety, Unicode paths, successful refresh, and write-free preview cases pass. The installed refresh is complete; four public files match source hashes. Abrupt termination can leave a recovery backup; replacement is not crash-atomic. |
| F07 | Installer/resolver shell inputs use PowerShell provider paths before filesystem containment checks, so relative inputs follow `Set-Location`. | Complete: relative-location, spaces, nonexistent destination, and provider rejection cases pass in the skill suite. |
| F08 | Fallback scenarios use explicitly external temporary roots and assert checkout-ancestor isolation; workspace-first product precedence is unchanged. | Complete: in-checkout and normal-temp skill cases pass. Independent installed-metadata resolution from a neutral external workspace passes with both PowerShell versions; help/tooling and explicit-target audit-only execution return zero with complete PASS guidance. |
| F09 | The scanner-wide coverage exclusion is removed; the global 80% gate is unchanged. Behavior tests cover audit, lifecycle, remediation, and failure boundaries. Temporary mapping creation cleans its owned directory on failure and preserves the original error, refusing replaced-directory traversal. | Complete: the final isolated tracked suite passes at 84.54% coverage with the scanner included. Twelve focused mapping-helper cases include eight new creation-failure/cleanup cases. |
| F10 | Metadata fields and tracked-file inventory are collected once per audit, eligible text is decoded once, and history detectors share a traversal while preserving independent scopes and caps. Caches remain per-audit. | Complete: eighteen repeated clean-corpus runs show equivalent normalized reports and median improvements of 26.2% and 17.3% over the audited implementation. Finding-bearing reports match in six bounded-baseline cases and two original-baseline cases. Concurrent readers increase peak traced memory; comparison limits are recorded below. |
| F11 | Scanner subphase timings and bounded numeric workload counters are additive metrics. Timing records survive errors and cancellation through `finally` paths. | Complete: success/error/cancellation metric tests pass. Three 10,000-call samples measure median overhead of 0.554 microseconds per counter call and 0.604 microseconds per phase call. |
| F12 | Local read-only phases, file/history loops, and command waits poll the shared cancellation signal. CLI interruption records an aborted partial run. Repeated Ctrl+C during active CLI repair writes is deferred until the batch returns, with child-process signal isolation and preserved abort evidence. | Complete: 56 focused cancellation/signal/boundary cases and integrated CLI/GUI tests pass. Read-only cases target a response within two seconds. One POSIX-specific case is explicitly skipped locally. |
| F13 | Push/PR filters are equal and unique, include typecheck/build/skill/benchmark inputs, and explicitly include the eight packaged prompt documents as runtime inputs. Broad documentation-only changes keep the local-first tier. | Complete: per-event equality, uniqueness, registry-input regressions, and the final release-contract check pass. |
| F14 | Shared constants and type-only imports remove the eager redaction/tooling dependency on the coordinator, retaining facade aliases and override behavior. | Complete: eight fresh-process import-order cases and full facade/parity regressions pass. |
| O01 | Investigation demonstrated fixture leakage: an empty `.git` directory let Git discover the enclosing checkout. Fixtures now initialize real isolated repositories; no held-descriptor production fix was needed. | Complete: six focused lock lifecycle cases pass with external and in-checkout temporary roots. |

### Final integrated validation

The final product tree was checked after the last native stdin/input correction:

| Validation | Final local result | Scope |
| --- | --- | --- |
| Full tracked pytest | 655 passed, one POSIX-specific skip; 656 collected; 152.74 seconds | Isolated `[gui,test]` environment without system packages; the POSIX-specific path is not claimed as locally executed |
| Statement coverage | 84.54%; global 80% gate unchanged | Scanner class included; original blanket exclusion removed |
| Ruff, Pyright, release contract | All exited with zero | Current product tree after the last native input correction |
| Local release harness | `release_readiness.py --skip-self-audit` exited with zero | Final artifact/smoke steps ran after the last correction; the final full pytest above supersedes the harness's earlier test collection |
| CLI/GUI smoke; module/direct-script help | Passed | Current product/artifact checks; visual capture is qualified separately below |
| Wheel/sdist build and isolated installs | Passed | Current artifacts; module origin, entry points, policy, all eight prompt hashes, materialization cleanup, and `pip check` verified outside the checkout |
| Three resolved requirement audits | No known vulnerabilities | Development, GUI, and remediation sets at validation time; not a guarantee about all allowed versions |
| Installed skill refresh and forward check | Passed | Four public source hashes match. Both PowerShell runtimes resolve installed metadata from a neutral external workspace; help/tooling exit with zero and an explicit-target audit-only fixture returns policy/summary PASS, complete/finished, and zero blocking/advisory entries; local metadata and artifacts remain unpublished |
| Finding-bearing scanner parity | Eight cases passed | Six bounded-baseline cap/incident combinations and two original-baseline cap-50 combinations; comparison limits are recorded below |
| Clean-worktree self-audit | Policy/summary PASS, complete, exit zero; no blocking or manual-review entries | Release profile and opt-in GitHub hardening at implementation commit `3fc400156cea804a8b2a7c4f8b13498e1662fac9`; one documented administrator-bypass risk remains accepted |
| Automatic GitHub CI | Passed | [Push run at the dependency correction](https://github.com/Okavango-SAS/RepoPrivacyGuardian/actions/runs/37180277345), commit `c99bb2ffea123ebf7327f87c99107d656d466cf9` |
| Extended GitHub CI | All five jobs passed | [Configured Linux/Windows validation](https://github.com/Okavango-SAS/RepoPrivacyGuardian/actions/runs/37180333448): Ubuntu Python 3.13 pytest, Ruff/Pyright, package/CLI checks, and Windows Python 3.11 GUI smoke |

Earlier passing harness snapshots are superseded by the final tracked-suite
result above. The self-audit record is
`Audit_Results/implementation-final/20261004-022305/`; its operational artifacts
remain local and ignored. Redaction fixtures build synthetic path values at
runtime, and import guards patch blocked APIs through explicit attribute lists;
42 focused regressions verify those public-fixture refinements. The implementation
and dependency correction are published on `main`; automatic and configured
extended CI pass at the dependency-correction commit. Final documentation receives
a clean-worktree self-audit and normal push before the delivery is closed.
Local checks do not claim a new tag, release, or successful visual capture.

The clean Linux CI exposed a missing test dependency on `setuptools` for the
build-helper regressions. It is now explicit in the test/dev extras and developer
requirements, matching the build-system requirement. A fresh environment without
system packages installs the declared extras, passes `pip check`, imports the
helper, and passes all 655 tests. The updated developer requirement audit resolves
43 packages with no known vulnerabilities. The earlier 84.49% Windows result
used a system-package-enabled environment and is superseded by the isolated run.

Fresh screenshot review is unavailable in this execution environment. Visual QA
was attempted, but its capture was uniformly black rather than usable desktop
evidence. GUI initialization, callbacks, layout tests, and the final GUI smoke
passed; they do not replace human review of a captured screen. Keep this capture
limit distinct from a product defect and from a passing visual gate.

### Measured scanner tradeoff

The clean-corpus comparison uses three repetitions for each of three
implementations across two synthetic corpus sizes: **18 timed runs**. Normalized
full reports and policy decisions match for those runs. The audited implementation
is the original comparison; the bounded unoptimized implementation adds the
required stream lifecycle without the subsequent scanner work sharing.

| Synthetic corpus | Audited median | Implemented median | Change from audited | Improvement over bounded unoptimized |
| --- | --- | --- | --- | --- |
| 120 commits, 8 files | 1.0163 seconds | 0.7501 seconds | 26.2% faster | 56.7% faster |
| 480 commits, 32 files | 1.8184 seconds | 1.5038 seconds | 17.3% faster | 65.3% faster |

| Median peak traced memory | Audited | Bounded unoptimized | Implemented |
| --- | --- | --- | --- |
| 120 commits, 8 files | 66.7 KB | 392 KB | 370.3 KB |
| 480 commits, 32 files | 67.7 KB | 395 KB | 370.7 KB |

These are `tracemalloc` measurements of Python allocations, not complete process
RSS. Concurrent readers required to enforce deadlines increase memory relative to
the audited implementation. Scanner sharing reduces that cost relative to the
bounded unoptimized variant, and the implemented peak stays approximately stable
when this history corpus grows fourfold. This is an explicit correctness/speed
tradeoff, not a claim of lower overall memory than the original implementation or
bounded total memory for every repository shape.

Independent finding-bearing comparisons preserve normalized full reports in six
cases against the bounded unoptimized baseline: match caps 1, 2, and 50, each
with optional incident audit off/on. Two additional cases match the original
audited baseline at cap 50 with incident audit off/on. The original low-cap
reader stalled until timeout, so its low-cap cases use the bounded baseline
instead. This comparison boundary is explicit; the timed clean-corpus comparison
above does not imply that all original-reader cases completed.

Instrumentation was measured in three samples of 10,000 calls: median counter
overhead is 0.554 microseconds per call and phase overhead 0.604 microseconds per
call. Timing and memory conclusions apply only to these recorded local workloads.

### Operational limits retained

- Legacy artifacts without completion context remain REVIEW; run a fresh audit
  before treating their guidance as publication readiness.
- Cancellation is cooperative. Read-only local audit work polls the signal;
  ordinary CLI Ctrl+C records an aborted partial run, and active repair writes
  defer interruption to the next safe boundary. Pause/resume is not added.
  External forced termination is outside the cooperative cancellation scope.
- Handled skill-refresh failures restore the previous installation. An abrupt
  process or machine termination between directory moves can leave a sibling
  `.repo-privacy-guardian.backup-*` directory for reviewed local recovery.
- A destination created concurrently during replacement is preserved alongside
  the prior copy's backup when automatic restoration cannot safely proceed.
- Optional remote discovery and GitHub checks retain their own bounded network
  and command timeouts. They do not become implicit local-audit behavior.
- Measurements apply to their recorded synthetic workloads and platforms.
  Cross-platform CI and fresh release validation remain distinct evidence.
- A usable fresh desktop capture is unavailable in the current execution
  environment. Passing GUI smoke and layout/callback tests do not establish
  screenshot or pixel review.

## Original audit and proposed implementation

The following sections preserve the findings and acceptance decisions from the
original audit. Present-tense defect descriptions refer to the audited commit,
not to the implementation record above.

## Scope and public evidence

The review covered the shared CLI/GUI pipeline, policy and redacted artifacts,
subprocess lifecycle, local persistence and locking, scanner performance,
packaging, dependency checks, CI, documentation, and the maintained and installed
Codex skill. Independent reviews covered runtime/reporting, release/packaging,
scanner performance, and the skill adapter.

RepoPrivacyGuardian is already public. Only sanitized conclusions and portable
repository-relative references belong in this document. Raw logs, audit evidence,
coverage, synthetic benchmark repositories, build outputs, and installed local
metadata remain ignored. Evidence directories include:

- `Audit_Results/planning-audit/20261003-230023/`: self-audit artifacts.
- `.local-meta/planning-audit/`: captured validation, dependency, build, and
  coverage evidence, including `coverage-recount.json`.
- `.local-meta/benchmarks/performance-scanner-20261003-225953/`: synthetic
  performance evidence.

Artifact timestamps retain the execution host's naming; the audit date above is
the operator's local date. These directories are local evidence, not published
attachments.

| Validation | Observed result | Limit |
| --- | --- | --- |
| CLI help and tooling preflight | Passed; Git ready | No dependency installation requested |
| Dry-run self-audit with GitHub hardening | Policy PASS; zero blocking findings; one manual-review advisory; 47 fixture/documentation bucket entries | Administrator branch-protection bypass is the documented intentional solo-maintainer model; guidance remains REVIEW without explicit accepted-risk selection |
| Full tracked pytest suite, normal external temporary directory | 457 passed in 50.93 seconds; reported coverage 85.86% | Statement coverage retains existing exclusions |
| Alternative pytest temporary directory inside the checkout | 452 passed, five failed | Four skill fallback scenarios discover the actual checkout ancestor; one lock metadata failure needs reproduction |
| Ruff, release contract, skill frontmatter validator | Passed | These checks do not establish complete release readiness |
| Installed skill | Four maintained files match source; local metadata links to the intended checkout | Local paths and metadata stay unpublished |
| Fresh-process top-level library imports | `redaction` and `tooling` fail with circular imports; other checked top-level library modules import | Supported facade/CLI paths passed; this is an internal module import-order weakness |
| Wheel build and archive inspection | Build passed; policy present; zero prompt Markdown resources | Build success does not prove installed GUI prompt operations work |
| Dependency audit | No known vulnerabilities in the resolved development, GUI, and remediation sets: 43, 4, and 1 dependencies respectively | Requirement ranges may resolve differently; this is a dated observation |
| Pyright | Unavailable in this environment | Not run; neither executable nor Python module available |
| Full release harness and fresh visual GUI QA | Not run in this audit | Historical release evidence is not a new release gate |

There were no confirmed privacy leaks in the self-audit. Functional defects below
are separate from that policy result. Category totals can overlap through aliases
and aggregate reasons; they must not be described as a count of unique leaks.

## Findings and proposed corrections

Priority P1 means misleading publication guidance should be corrected first. P2
means a correctness or validation weakness; P3 means reliability, ergonomics, or
measured optimization. These priorities are implementation priorities, not CVSS
scores. Static findings are distinguished from executed observations.

### F01 — Completion and failure context can be lost in decision summaries (P1)

Evidence: [agent_summary.py](../repo_privacy_guardian/agent_summary.py),
[reporting.py](../repo_privacy_guardian/reporting.py), and the finalization path in
[core.py](../repo_privacy_guardian/core.py). The agent summary derives its decision
from category counts and stores, but does not use, `exit_code`. Its per-repository
decision can also disagree with an explicit failed report. The HTML decision uses
repository status but lacks overall execution/completion context. Empty or clean
partial results can therefore suggest PASS despite an unsuccessful run.

GUI Reports already distinguishes runtime error, abort, and policy failure from
the exit code. Its participation below consolidates decision guidance with the
shared artifacts; this finding does not claim its existing outcome badges fail.

Consequence: an agent or GUI operator can mistake incomplete evidence for
publication readiness. Until corrected, compare the summary and HTML with the
exit code, expected targets, execution errors, and `run_state.json`.

Implementation:

- Introduce one pure decision helper with exit code, known policy status,
  execution errors, completion phase, expected/completed target counts, and
  advisory counts as inputs. Use it for the CLI handoff, summary, HTML Decision
  section, and GUI Reports guidance.
- Runtime errors (`3`), policy failure (`2`), or a failed repository produce FAIL.
  An aborted run (`1`) produces REVIEW unless known failures require FAIL. Empty,
  incomplete, or unknown completion never produces PASS. PASS requires completed
  selected targets, no blockers, and no unresolved advisories.
- Add optional context parameters and additive completion fields. Preserve exit
  codes, PASS/REVIEW/FAIL values, `report.json`'s array shape, existing fields,
  compatibility facades, and shared configuration keys. Legacy artifacts with
  missing context show completion as unknown rather than inventing success.
- Give execution failures a runtime/tooling next action. Keep policy failure and
  advisory guidance distinct, and describe category totals as bucket entries.
- Thread context through persistence before final run-state output; ensure later
  persistence/cleanup failures remain visible and cannot leave misleading PASS
  guidance in artifacts that can still be updated.

Acceptance: synthetic empty/error, partial cancellation, global policy failure,
explicit failed report with no counted bucket, advisory-only, accepted-risk, and
completed clean cases agree across JSON handoff, HTML, CLI, and GUI. Redaction and
legacy artifact tests pass; Repair remains gated by valid audited context.

### F02 — Installed GUI prompts are missing from the wheel (P2)

Evidence: the built wheel contains zero `.prompt.md` files.
[pyproject.toml](../pyproject.toml) packages policy and images;
[prompts.py](../repo_privacy_guardian/prompts.py) reads checkout-relative docs.
GUI copy/open operations consequently depend on a source checkout. Existing
prompt-card tests do not exercise installed resource reads.

Consequence: an installed GUI can display prompt cards but fail to copy or open
their contents. Use the source checkout for these operations until corrected.

Implementation:

- Keep the eight registry-selected English/Spanish prompt documents as the
  canonical maintained source under `docs/prompts/`.
- Add a small deterministic setuptools build helper that copies those documents
  into package prompt resources during wheel building. Include the canonical
  documents and helper in the sdist so building a wheel from an sdist works.
  Track no second manually maintained set of prompt texts.
- Make prompt reads use the checkout document when available, otherwise
  `importlib.resources`. Preserve registry IDs, locales, commands, public
  compatibility exports, and `AgenticPrompt.path()`'s checkout behavior.
- Route both GUI Copy and Open through the same resource resolver. For opening a
  packaged resource, retain a materialized file for the GUI session and clean its
  dedicated temporary directory on shutdown; do not hand an already-deleted
  resource path to the external opener.

Acceptance: wheel and sdist installations outside the checkout read all eight
texts exactly, resolve both locales, and exercise Copy/Open callbacks with a
controlled opener. Source edits remain authoritative in checkout use. Missing
resources give actionable guidance. The separately installed Codex skill remains
a checkout-managed adapter; its absence from the wheel is intentional.

### F03 — Artifact install checks can import the checkout (P2)

Evidence: [release_readiness.py](../scripts/release_readiness.py),
`install_smoke_for_artifact`, and the package job in
[ci.yml](../.github/workflows/ci.yml) run module/resource checks from the repository
root. Python's current-directory imports can shadow the installed artifact.

Consequence: incomplete distribution contents can pass checks. The console-script
check still provides useful evidence, but does not prove all import/resource
paths are isolated.

Implementation: run wheel and sdist checks in empty temporary working directories
outside the checkout, remove source-injecting `PYTHONPATH` from their child
environment, and assert imported module/resource locations belong to the test
environment's installation. Check module and console entry points, packaged
policy equality, all prompt texts, and `pip check` for each artifact. Reuse this
isolated validation in CI and the local release harness.

Acceptance: a deliberately incomplete synthetic artifact fails the resource check;
a complete artifact passes without source access. Build/install checks retain
bounded timeouts and do not mutate the operator's active environment.

### F04 — Streaming Git work does not enforce the deadline while waiting for output (P2)

Evidence: history scanners in [scanner.py](../repo_privacy_guardian/scanner.py)
check elapsed time after receiving a line; [execution.py](../repo_privacy_guardian/execution.py)
drains stderr only during finalization. A blocking read can delay the deadline,
and stdout/stderr pipes are not drained concurrently. This is a structural
lifecycle finding; no hostile repository or exploit reproduction was used.

Consequence: a stalled Git operation can keep the CLI or GUI worker waiting beyond
the configured limit.

Implementation: make the streaming adapter own concurrent output readers, a
monotonic deadline, capped diagnostic preview, and cleanup. Consumers receive
events with bounded waits instead of blocking directly on `readline`. Drain
stderr throughout; preserve successful scanning to EOF. On deadline/error,
terminate, then kill if required, join readers and close pipes. Preserve the
current default timeout and sanitized runtime-error taxonomy.

Acceptance: benign controlled process/adapter tests cover no-output waits,
partial lines, stderr activity, normal EOF, failed start, early consumer exit,
and timeout. Completion occurs within the deadline plus at most seven seconds
of cleanup; no process, reader, or handle survives. CLI and GUI report the same
runtime outcome.

### F05 — Skill interpreter selection checks existence rather than readiness (P2)

Evidence: [resolve_repo_privacy_guardian.ps1](../codex/skills/repo-privacy-guardian/scripts/resolve_repo_privacy_guardian.ps1)
selects a local virtual-environment executable or PATH launcher without verifying
it runs a supported Python. A stale environment or Python older than 3.10 can
shadow a usable fallback.

Implementation: add a bounded, non-interactive Python/version probe for each
candidate, preferring valid local environments, then supported PATH launchers.
Reject unusable candidates and continue. Keep backend precedence (workspace,
installed metadata, environment, console PATH), JSON-only stdout, argument-array
execution, and no automatic dependency installation.

Acceptance: valid local precedence, broken local environment, old first launcher,
supported later launcher, unavailable interpreters, and console fallback behave
on Windows PowerShell 5.1 and PowerShell 7. Probe failures never expose raw private
diagnostics or silently change persistent configuration.

### F06 — Forced skill refresh removes the working copy before completion (P2)

Evidence: [install_codex_skill.ps1](../scripts/dev/install_codex_skill.ps1) removes
the destination before copying maintained files and writing metadata.

Consequence: an interrupted or failed refresh can leave the skill unavailable.

Implementation: prepare a validated sibling staging directory; copy and validate
all maintained files and generated local metadata before swapping. Retain the
previous destination as a backup until successful replacement, with rollback on
copy, metadata, or swap failure. Validate every cleanup target under the intended
skill parent. Preserve overlap/reparse checks, neighbor protection, `-Force`, and
write-free `-WhatIf` semantics.

Acceptance: controlled failure injection leaves the previous skill byte-identical;
successful refresh removes obsolete files; first-install failure leaves no partial
installed skill. No other skill or checkout is changed. Refresh the installed
skill only after the versioned adapter checks pass.

### F07 — Relative PowerShell inputs can resolve against the wrong directory (P2)

Evidence: the installer and resolver normalize paths with `.NET GetFullPath`,
whose base can differ from PowerShell's location after `Set-Location`.

Implementation: resolve shell-supplied relative paths with the PowerShell provider
path API, then apply existing absolute-path containment and reparse checks.
Require filesystem inputs; preserve already absolute paths. Cover `-CodexHome`,
resolver `-StartPath`, and environment-provided relative checkout paths.

Acceptance: a shell started in directory A and moved to B resolves relative inputs
under B on PowerShell 5.1 and 7. Literal spaces, nonexistent destinations, and
rejected non-filesystem providers behave predictably.

### F08 — Skill fallback tests assume temporary directories have no checkout ancestor (P3)

Evidence: four scenarios in [test_codex_skill.py](../tests/test_codex_skill.py) fail
with an in-checkout `--basetemp`, because the correct workspace-first resolver
finds the real checkout. All tests pass with the normal external temporary root.
The release harness already creates an external temporary root.

Implementation: allocate explicitly isolated external roots for fallback scenarios
and assert their ancestor isolation. Keep separate tests of workspace precedence;
do not change product precedence to satisfy test assumptions.

Acceptance: the tracked suite passes with normal pytest temporary placement and
an in-checkout `--basetemp`, including both available PowerShell versions.

### F09 — The scanner's class-wide coverage exclusion hides substantial code (P2)

Evidence: `RepoPublicationGuard` has a class-wide `# pragma: no cover`. Recounting
the saved full-suite coverage with only that exclusion removed, in memory, gives:

| Statement coverage | Existing exclusion | Reconstructed without that exclusion |
| --- | --- | --- |
| Scanner | 34/35; 97.14% | 621/952; 65.23% |
| Global | 4,415/5,142; 85.86% | 5,002/6,059; 82.55% |

The exclusion hides 917 executable statements, including 330 unexecuted ones.
Both global counts use the same 39 existing reportable checkout files, retain
test/script omissions and other exclusions, and exclude a vanished measured
temporary fixture source. This is statement coverage, not branch coverage; the
reconstruction is diagnostic, not a replacement CI result.

Implementation: remove the scanner-wide exclusion, retain the global 80% gate,
and add behavior-focused coverage for meaningful missing audit, lock, metadata,
remediation sequencing, failed rewrite, and runtime branches. Use synthetic data
and controlled side-effect adapters. Keep GUI widget exclusions a separate
documented decision; do not add blanket exemptions to recover a percentage.

Acceptance: tracked clean-clone tests pass with the corrected denominator and
unchanged threshold. Tests assert outcomes and safety boundaries, not source
wording. Coverage artifacts remain isolated per run.

### F10 — Repeated metadata, file reads, and history traversals add avoidable work (P3)

Evidence: `audit_repo` runs author and committer logs twice each, enumerates
tracked files for multiple detectors, and performs four history patch traversals.
A synthetic 120-commit/eight-file audit measured 1.6777 seconds for audit and
2.0425 seconds for the pipeline. Four patch streams consumed 0.4121 seconds after
process creation, four tracked-file enumerations 0.1938 seconds, metadata logs
0.2438 seconds, and 27 text reads 0.0928 seconds. These small-corpus measurements
identify repeated work; they do not predict a universal speedup.

Implementation, in separate reviewable steps:

1. Collect each author/committer field once and partition emails/identity tokens.
2. Use one per-audit tracked-file inventory and decode each eligible text once,
   dispatching to independent detectors with their existing scope and caps.
3. After parity is established, share the history patch traversal among detectors,
   preserving different secret/path/email scopes, context, stable ordering,
   fixture/documentation taxonomy, and independent match limits. Keep existing
   compatibility methods as wrappers where callers require them.
4. Profile remaining buffered metadata/filename operations before converting them
   to streamed deduplication and bounded diagnostic previews. Drain to completion
   when required; never truncate discovery merely to save memory.

Use only audit-scoped caching, invalidate after repairs and before re-audit, and
persist no file bodies or detected values as a new cache.

Acceptance: compare normalized full reports and policy decisions against the
baseline across small/large histories, binary/oversized files, Unicode paths,
symlinks, deleted files, fixtures, optional incident audit, and independent caps.
Run at least three repetitions per benchmark corpus, compare medians and peak
memory, and investigate regressions over the existing 25% comparator budget.
Merge each optimization only with equivalent findings and measured benefit or a
demonstrated memory bound; otherwise retain the simpler implementation.

### F11 — Phase metrics omit useful failed-work and scanner detail (P3)

Evidence: [metrics.py](../repo_privacy_guardian/metrics.py) and pipeline timing
updates generally record elapsed time after successful work; scanner work lacks
metadata/tracked/history/fsck subphase measurements.

Implementation: record elapsed phases in `finally`, add bounded numeric counters
and scanner subphase timings, and preserve existing `run_state.json` keys with
additive fields. Reuse the same metrics in CLI artifacts and GUI Reports. Store
no secret values, file bodies, personal paths, or command stderr in metrics.

Acceptance: success, error, and cancellation preserve elapsed time; numeric
counters match controlled workloads, redaction remains intact, and older readers
continue to work. Measure instrumentation overhead before performance claims.

### F12 — Audit cancellation waits for the active repository (P3)

Evidence: this documented behavior is intentional today, rather than a regression.
Long history work limits its usefulness in the GUI.

Implementation after F04: pass the existing cancellation signal through shared
read-only phases and the bounded stream loop, checking between phases/files and
during output waits. Target response within two seconds after an observed cancel
request in read-only audit work. During repairs, stop only at a Git-safe boundary;
never interrupt an active history rewrite or push arbitrarily. Preserve lock and
temporary-clone cleanup and mark partial artifacts using F01 completion context.

Acceptance: CLI and GUI cancellation produce equivalent partial guidance and
cleanup; active repair safety boundaries remain tested. Update the limitation
description only after implementation. Pause/resume remains out of scope.

### F13 — CI event filters and documentation need alignment (P3)

Evidence: `benchmark_large_history.py` occurs twice in the pull-request filter and
is absent from the push filter; `pyrightconfig.json` is absent from both. Existing
workflow tests check presence more broadly than per-event equality. The README
also named a different Windows GUI runner, and DEC-009 overstated automatic CI's
full-suite scope.

Implementation: deduplicate and align push/PR filters, including the benchmark,
type-checker configuration, runtime, package, skill, and installer surfaces.
Assert uniqueness and per-event parity in tracked workflow tests. Preserve the
cost-first policy: documentation-only changes do not automatically start expensive
validation; full tracked tests, packaging, and GUI checks retain their documented
manual/local tiers.

Acceptance: relevant source/config paths trigger both events consistently; docs
remain governed by the intended cost policy. The README runner and DEC-009
description were corrected in the initial documentation delivery; workflow
changes were pending at that time.

### F14 — Two internal modules depend on importing the facade first (P3)

Evidence: isolated fresh-process imports of
`repo_privacy_guardian.redaction` and `repo_privacy_guardian.tooling` fail with
partially initialized module errors. Both import dependencies from `core`, which
then binds functions from those modules before their initialization finishes.
Core-first imports and the supported CLI/facade paths work; the full tracked suite
passed. Evidence is recorded in ignored `import-isolation.json`.

Consequence: standalone reuse and future extraction of these helpers depend on
import order, and in-process tests that already loaded the facade can miss it.

Implementation: remove their eager dependency on the coordinator. Put shared
redaction constants/patterns in a small dependency-free module and keep `core`
aliases compatible. Move `ToolingCheck`, static defaults, and the stdin helper to
acyclic shared modules; use type-only imports for `GuardRunConfig` annotations.
Use lower-level GitHub auth helpers, with narrowly scoped runtime facade lookup
where override compatibility requires it. Retain the existing facade override
synchronization and object identities. This is a narrow import-boundary
correction, not a coordinator rewrite.

Acceptance: each module imports first in its own fresh interpreter; reversed and
facade-first imports behave identically. Existing redaction, tooling preflight,
optional-install authorization, monkeypatch/override compatibility, and CLI/GUI
parity regressions pass without installing tools or making network requests during
import.

### O01 — Intermittent lock metadata failure needs bounded investigation

One in-checkout temporary-directory suite failed
`test_repo_execution_lock_reuses_existing_metadata_file`; the subsequent complete
normal-temp suite passed it. This does not establish a general lock defect.
The current code writes metadata through the held file descriptor and uses an OS
advisory lock; an atomic path replacement is not its release mechanism.

Follow-up in Stage 1: run the focused lock lifecycle cases repeatedly with external
and internal temporary roots on Windows and one POSIX platform, capture sanitized
I/O errors, and first verify Git-directory resolution: the test fixture's empty
`.git` directory may allow discovery of an enclosing checkout. Then inspect file
offsets and release metadata if needed. Fix only a demonstrated fixture-isolation
or held-descriptor problem, preserving lock-file identity, contention,
process-death reacquisition, and owner-token handling. If not reproduced, retain
a clearly qualified observation without speculative product changes.

## Implementation order and completion gates

Every stage is a separate reviewable change with its own documentation and
validation. Mark findings completed only after their acceptance evidence exists.
No stage is completed by this plan-only delivery.

| Stage | Work and dependency | Required evidence and documentation |
| --- | --- | --- |
| 0 — Baseline | Start from the documented public commit; ensure tooling for the intended gate is available through reviewed setup | Tracked tests, Ruff, release contract, isolated artifacts; record missing tooling honestly |
| 1 — Trustworthy outcomes | F01 and O01 investigation | Shared decision matrix; CLI/GUI/report parity; runtime and cancellation cases; update report/agent guidance and known issues |
| 2 — Installed distribution | F02 + F03 | Isolated wheel and sdist prompt/policy/entry-point checks; source/install locale parity; update packaging and GUI prompt instructions |
| 3 — Bounded execution | F04, then F12 | Deadline and lifecycle tests; CLI/GUI cancellation parity and repair boundaries; update cancellation/runtime documentation |
| 4 — Reliable skill adapter | F05 + F06 + F07 + F08 | PowerShell 5.1/7 behavioral tests, rollback and path tests, independent forward test; update skill references/setup docs and refresh installed files |
| 5 — Honest validation | F09 + F13 + F14 | Unchanged 80% coverage gate, meaningful missing-path and fresh-import tests, aligned CI filters; update validation tiers and coverage evidence |
| 6 — Measure before optimizing | F11, then successive F10 changes | Timing/error metrics, full-report equivalence, multi-corpus median/memory comparison; update benchmark guide and retained baseline |
| 7 — Integrated readiness | All required acceptance evidence above | Full local release harness; both artifact installs; dependency audit; fresh self-audit; extended supported-platform/GUI checks; finalize changelog and known issues |

Stages 2 and 4 can proceed independently after the baseline; history consolidation
depends on trustworthy outcomes, bounded streams, and corrected coverage. Metrics
can precede optimizations. Optimize repeated metadata/file work before the broader
history consolidation, allowing a stop if measurements do not support it.

For each implementation stage:

1. Confirm intended scope and the current clean baseline. Use CLI help and a
   dry-run audit before reviewed mechanical writes. Classify findings as confirmed
   leak, intentional fixture/example, manual review, advisory hardening, or tooling.
2. Implement the shared backend behavior and both CLI/GUI presentations together,
   preserving `1.x` entry points, policy keys, opt-in network behavior, suppression
   restrictions, reviewed Repair gating, and default owner push guardrails.
3. Run focused behavioral regressions first, then tracked suite and required gates.
   Preserve ignored evidence, compare full reports for scanner changes, and run
   visual QA only when actual desktop presentation changes warrant it.
4. Update the relevant runbook, skill reference, known issue, roadmap, and changelog
   with implemented behavior and limitations. A PASS self-audit alone is not a
   replacement for packaging/runtime/release checks.
5. Inspect `git status --short` and `git diff --check`, review public-safe additions,
   and stage explicit intentional files. Commit and push normally under the
   selected maintainer model; never force-push or rewrite history as part of this
   plan. Verify remote synchronization and the applicable CI tier.

The final readiness evidence must come from tracked tests reproducible in a clean
clone. Audit dependencies at that time again; do not treat today's resolved sets
as a guarantee about all future or minimum allowed versions. Keep Python 3.10+
compatibility, supported CLI platforms, and both documented GUI locales.

## Boundaries retained

No new hosted backend, default telemetry, provider secret rotation, implicit
remote audits, GUI-only policy path, blanket suppression, persistent sensitive
content cache, or wholesale coordinator refactor is proposed. Module extractions
should occur only where the changes above establish useful tested boundaries.
Version bumps, tags, releases, and GitHub settings changes are separate release
decisions. The existing administrator-bypass advisory remains the documented
operator choice; correcting product behavior does not silently change it.
