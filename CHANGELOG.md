# Changelog

## [2.0.0.dev0] - Unreleased (P0 fail-closed, in progress)

Work-in-progress development release. This is P0 of a larger hardening effort (P1 grade-integrity and P2 documentation-honesty are NOT done yet; see `STATE.md`). It makes Gatekeeper fail closed: when the scanner could not actually inspect something, it no longer issues a clean letter grade over the gap. Test suite grew from 345 to 410, all passing. This release contains BREAKING changes to verdicts, exit codes, default trust, and dependencies; do not treat it as a drop-in upgrade.

### BREAKING
- **New `INCOMPLETE` verdict replaces the letter grade whenever coverage was lost.** Excluded/oversized/over-length/unparsed/analyzer-crashed/engine-missing/truncated/unreadable content, hitting the file limit, and any incomplete dependency audit now void the grade instead of scoring around the gap. `INCOMPLETE` exits 1; `--policy` cannot override it.
- **New `SCOPED` verdict for explicit operator narrowing.** `--skip-deps`, `--no-taint`, `--no-yara`, `--diff`, `--exclude`, `--baseline`, `--disable-rules`, and `--trust` keep the letter as a diagnostic for the scanned surface but never emit a whole-target `INSTALL`. Scoped scans exit 1 unless the new `--accept-scoped` flag is passed.
- **Local targets are no longer auto-trusted.** A cloned or downloaded repo is local by scan time, so locality is not provenance. The target's `.gatekeeper` config and inline `gatekeeper:ignore` comments are honored only under an explicit `--trust`, which itself scopes the verdict. Default local scans no longer let a repo suppress its own findings.
- **`yara-python` is now a required dependency**, not optional. Without the signature engine, scans record a coverage gap and grade `INCOMPLETE` unless `--no-yara` is passed explicitly.
- **Exit codes:** `INCOMPLETE` and unaccepted `SCOPED` scans exit 1; failed/invalid `--diff` and missing/malformed/wrong-schema `--baseline` exit 2 (pre-scan refusal, never a silent full scan).

### Added
- First-class coverage ledger (`report.coverage_gaps`) plus `incomplete`, `scoped`, `scoped_grade`, `incomplete_reasons`, `scope_reasons`, and `trust_target` fields on the report and in JSON output.
- Per-ecosystem dependency `audit_status` (`clean`/`vulnerable`/`unavailable`/`timed_out`/`unparseable`/`error`/`no_lockfile`/`unsupported`/`unaudited`/`partial`). Every ecosystem (Python, JavaScript, Go, Rust) is audited independently; `clean` is only reachable after a completed, schema-validated auditor run.
- OSV.dev coverage accounting: pinned-only queries, the 400-package cap, and short batch responses now mark the ecosystem `partial` (fail closed) rather than clean.
- Parse-failure fail-closed for the AST scanner and taint analyzer; analyzer crashes and import failures are recorded, not swallowed.
- YARA runtime fail-closed: engine match errors, unreadable targets, and 2 MB truncation each record a distinct coverage gap.
- `--accept-scoped` flag for CI acceptance of intentionally narrowed scans.

### Fixed
- Dependency audit no longer fails open: missing auditors, timeouts, malformed/wrong-shape auditor JSON, npm error-JSON, and lockfile-less manifests previously read as "no vulnerabilities" now fail closed with distinct states.
- Multi-ecosystem repositories no longer drop an ecosystem because a single `package_manager` value was overwritten.
- Ecosystem audit states no longer cross-contaminate through the shared findings list (per-ecosystem finding deltas).
- OSV 400-package cap and short batch responses now mark the ecosystem `partial` via coverage metadata (requested/queried/responded), never clean.
- pip-audit reads only `requirements.txt`; a dependency declared solely in `pyproject.toml` now makes the Python ecosystem `partial` even on a successful audit.
- Nested auditor-output schema validation: pip `vulns` must be a list of objects, npm `vulnerabilities` must be an object (a list or error-JSON is rejected), cargo `vulnerabilities.list` must be a list, and a single malformed govulncheck JSON line marks the Go audit `unparseable` rather than being skipped.
- Tool-specific acceptable return codes enforced (pip-audit/npm/cargo 0 or 1, govulncheck 0 or 3); valid-looking JSON from an unexplained exit code is no longer read as clean.
- Malformed `pyproject.toml` (real `tomllib` parse failure) and malformed `package-lock.json` now produce `unparseable` audit gaps instead of being silently rescued by the regex fallback or masked as `unavailable`.

### Known gaps (tracked for P1+)
- Grade-integrity heuristics (five-file frequency downgrade, path-class downgrades, B-floor, per-file cap) are still live — P1.
- README/SKILL.md still advertise MCP tool-shadowing / rug-pull / namespace-collision detection with no implementation — P2 (implement-or-strip).
- Detector breadth (taint kwargs, hostname C2, `importlib`, OSV CVSS vector parsing) — P3.
- No end-to-end CLI validation against live targets has been run yet.

## [1.4.1] - 2026-07-10

Bugfix release: `hooks/` findings are no longer silently downgraded. A `hooks/` directory holds install- and invocation-time executable code (Claude Code event hooks, git hooks, package lifecycle), but it was bucketed with `references/` as documentation, so a CRITICAL or HIGH finding inside `hooks/` was reclassified to LOW and dropped out of the CRITICAL score ceiling. The scanner was muting exactly the install-time execution surface it exists to flag. Test suite grew from 342 to 345, all passing; self-scan stays grade A.

### Fixed
- **`hooks/` findings were downgraded like reference docs.** `hooks` was a member of the reference/doc classification set (`is_reference`), so CRITICAL/HIGH findings in a `hooks/` directory were downgraded to LOW and excluded from the undowngraded-CRITICAL score ceiling, silencing real install-time execution risk. `hooks` is removed from that set. A bare `hooks/` path is now neutral: detector severity stands, with no downgrade and no path-based uplift (path alone is not evidence of intent). `references/` behavior is unchanged.

## [1.4.0] - 2026-07-03

Feature release: MCP capability audit. Came out of scanning Google's sec-gemini repo, whose Rust CLI hands the remote model arbitrary process execution, raw TCP, and executable file write through MCP local tools, and the scanner had nothing to say about it. Injection checks look for poisoned words; this release adds the other half: what power an MCP server actually grants the model that connects to it. Test suite grew from 335 to 342, all passing; self-scan stays grade A.

### Added
- **MCP capability audit.** New `GK-MCP-cap-*` rules. Files that define MCP tools are identified per ecosystem (Python FastMCP decorators, the TypeScript SDK's `McpServer`/`server.tool`, Rust `rmcp` tool macros, Go mcp-go) using a two-condition gate (framework marker AND tool-registration marker), so SDK *clients* never trigger. Tool-defining files are then checked for seven host capabilities their handlers grant the connected model: process execution (HIGH), raw network access (HIGH), file deletion (HIGH), executable file creation (HIGH), file write (MEDIUM), outbound HTTP (MEDIUM), and environment variable access (MEDIUM). One finding per file per capability, each with a stable rule ID and CWE.
- **MCP capability manifest in the report.** When any capability is detected, the report prints a plain-English MCP CAPABILITY MANIFEST block ("This package's MCP tools grant the connected model: process execution — src/tool/exec.rs, ..."), and the same data lands in `structure.mcp_capabilities` in the JSON output. The manifest is disclosure and prints even when individual findings are downgraded by context: a legitimate MCP server may grant exec by design, and you should know that before you install it.

### Changed
- `--version` and the version constant are now `1.4.0`.

## [1.3.0] - 2026-07-02

Security-hardening release. Two independent adversarial review passes drove a set of fixes to the verification and trust layers, closing real false negatives where the scanner could be talked out of reporting something it had actually found. No detection capability was removed; the scanner is harder to trick into staying quiet. Test suite grew from 297 to 335, all passing; self-scan stays grade A.

### Fixed
- **Scanner self-detection could silently drop real findings in third-party code.** The false-positive suppression that keeps Gatekeeper's own pattern definitions from grading itself was keyed on filenames (`endswith`), so any third-party repo containing a file named `core.py`, `patterns.py`, etc. had real findings suppressed. Suppression is now gated on a self-identity marker, matched by exact basename, and restricted to the files where signatures are actually defined. When a scanned target self-identifies as Gatekeeper, that is now disclosed in the report so it can never be silent.
- **Leaked secrets could be dismissed as placeholders.** A real credential in git history was dropped when the commit message merely contained a word like "example"; a real key was dropped for containing "example" as an internal substring. The placeholder check now inspects the credential value itself, matches whole-value placeholders rather than substrings, and never runs against commit metadata.
- **Trust cap on target-supplied config.** A locally scanned repo could use its own `.gatekeeper.json` (suppress lists, `exclude`, `severity_weights`) or inline `# gatekeeper: ignore` comments to hide findings. Target-supplied suppression can now only quiet LOW/MEDIUM non-secret findings; it can never suppress a `CRITICAL`, `HIGH`, or `SECRET` finding through any lever, and files a target excludes are disclosed as coverage gaps. Target `severity_weights` can no longer lower CRITICAL/HIGH below their built-in floor.
- **Denial of service in self-scan detection.** The self-identity check read candidate files unbounded, so a file symlinked to `/dev/zero` could hang the scan. It now skips non-regular files and reads a bounded prefix.
- **Silent coverage gaps.** Oversized files (over 500KB) and over-length lines are now disclosed in the report and SARIF (terminal warnings and `toolExecutionNotifications`) instead of being skipped silently, closing a padding-based evasion. Coverage disclosure now covers any scannable file, including extensionless ones (Dockerfile) and active-text formats like SVG, not just a fixed extension list.
- **Phantom dependency reporting.** Fixed cross-ecosystem contamination (Python phantom deps attributed to `package.json` and vice versa) and a display cap that could silently drop the eleventh-and-beyond phantom package; suspicious packages now always surface and the overflow list is named, not just counted.
- **`--skip-deps` is now loud**, stating in the report that dependency checks were disabled.
- **zsh** added to the pipe-to-shell detection (`curl ... | zsh`), which previously matched only `sh` and `bash`.

### Changed
- `--version` and the version constant are now `1.3.0`.

## [1.2.0] - 2026-06-28

Three new detection engines, all additive and degrading gracefully. Nothing in the existing detect/verify/score pipeline changed; new findings flow through verification and scoring like any other. 297 tests.

### Added
- **Intra-function taint analysis (Python).** New `TAINT` category. Follows untrusted input (request data, `sys.argv`, `input()`, `os.environ`, decorated route/tool handler parameters) to a dangerous sink (`eval`/`exec`, `subprocess`, `os.system`, `pickle`/`yaml` deserialization, SQL `execute`, `open`, dynamic import, file deletion, SSRF) within a single function. Two taint levels: strong (remote/attacker-controlled) trips every sink; weak (operator-controlled env vars) trips only high-impact code-exec/deserialization/SQL sinks, not MEDIUM file-path or SSRF sinks. Sanitizers (`int()`, `shlex.quote`, `html.escape`, `...quote`/`...escape`) clear taint. Disable with `--no-taint`. Engine: `gatekeeper_scanner/taint.py`.
- **YARA signature engine.** New `SIGNATURE` category. Matches authored signatures for PHP webshells, reverse shells (bash/nc/python), cryptominers, PowerShell download-and-execute, Python remote droppers, and base64-embedded PE executables across both text and binary files. Optional: requires `yara-python`; skipped with a warning when absent. Rules authored from scratch (MIT), no third-party rules. Disable with `--no-yara`. Engine: `gatekeeper_scanner/yara_engine.py`, rules in `gatekeeper_scanner/yara_rules/`.
- **OSV.dev CVE fallback.** When `pip-audit` / `npm` are not installed, dependency CVE detection now queries the OSV.dev API for pinned packages (requirements.txt `==`, package-lock.json) instead of silently skipping. Pure stdlib, fully offline-safe (network failures warn and continue). Disable with `--no-osv`; auto-disabled by `--skip-deps`. Engine: `gatekeeper_scanner/osv.py`.
- **First-run optional-dependency prompt.** On a real interactive terminal only (never piped, never with `--json`/`--sarif`/`--quiet`), Gatekeeper offers once to install the optional `yara-python` add-on, explains why in plain language, and remembers the choice in `~/.gatekeeper/deps-prompted.json`. Suppress with `GATEKEEPER_NO_PROMPT=1`.

### Changed
- `--version` and the version constant are now `1.2.0`.
- Scanner self-detection extended so the new engine modules (`taint.py`, `yara_engine.py`, `osv.py`) are not flagged for the dangerous-API names they reference in detector logic. Self-scan stays grade A.
- `yara-python` available as an optional install extra: `pip install gatekeeper-scanner[yara]` (or `[all]`).

## [1.0.0] - 2026-04-14

Initial release. Security scanner covering 16 languages (Python, JavaScript, TypeScript, Go, Rust, Java, Kotlin, Ruby, PHP, Swift, C, C++, C#, Lua, Perl, Shell), AST-based Python analysis, AI/MCP-specific detection, four-phase detect/verify/score pipeline, SARIF output, CI/CD integration, trust model, and 267 tests.

### Features
- `--diff <base-ref>` flag: only scan files changed since a base reference (e.g., `main`). Useful for CI PR review.
- `--branch` support via URL fragment: `https://github.com/user/repo#branch-name` scans a specific branch.
- `.gatekeeper-ignore` file support: one glob pattern per line, merged with `--exclude`. Trust-gated (only from trusted targets).
- Cross-platform `--timeout`: uses `threading.Timer` fallback on Windows when `SIGALRM` is unavailable.
- Auto-cleanup of saved reports: keeps last 50 in `~/.gatekeeper/reports/`.
- Expanded vendor detection: `extern/` and `external/` directories classified as vendor.
- File cache size limit (500MB) prevents unbounded memory usage on large repos.
- GitHub Actions CI workflow (Python 3.9/3.11/3.13, Ubuntu/macOS/Windows)
- Modular architecture: detection patterns in `patterns.py`, data models in `models.py`, AST analysis in `ast_scanner.py`, reporting in `reporter.py`. Scanner core in `gatekeeper_scanner/core.py`. `gatekeeper.py` is a thin CLI wrapper for backward compatibility.
- Variable assembly evasion detector optimized from O(n²) to O(n) per file.
- Extracted shared `_check_suspicious_package` method (DRY fix for dependency scanning)
- Dependency scanning returns declared sets explicitly instead of using dict-as-message-bus

### Detection & Scoring
- Verification pass uses path-segment matching for test/example/docs classification (not substring matching)
- Shell scripts only classified as devtools when in `scripts/`, `tools/`, or `build/` directories
- MCP schema poisoning check requires 2+ pattern matches or match in a description field before flagging
- Entropy detector skips pure hex strings (SHA hashes) and standard base64 with padding
- Phantom dependency detection catches `__import__()` calls alongside `importlib.import_module()`
- Scoring floor: 50+ HIGHs with 0 CRITICALs floors at D (40) instead of guaranteed C (50)
- CRITICAL findings can no longer be upgraded to grade B by density floor in large repos
- Secret placeholder check runs on extracted value, not full match (prevents dismissing real secrets in variables named `your_api_key`)
- Policy parser accepts `==` as alias for `=` (prevents silent bypass when users type `--policy "critical==0"`)
- `--disable-rules` and `--baseline` recalculate `severity_summary`, `category_summary`, `verified_count`, `verdict`, and `grade_drivers` after filtering
- Cross-detector dedup preserves suppression reasons on already-dismissed findings
- Lockfile drift: `~` version spec parsing uses `[1:]` instead of `lstrip("~")` to handle edge cases
- Git branch name from URL fragment validated against `[A-Za-z0-9._/-]` to prevent flag injection
- Invalid custom regex patterns in `.gatekeeper.json` emit a warning instead of crashing the scan
- `~/.gatekeeper/reports/` directory only created in modes that save files (not `--json`/`--sarif`/`--quiet`)
