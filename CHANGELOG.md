# Changelog

## [1.0.0] - 2026-04-14

Initial release. Security scanner covering 16 languages (Python, JavaScript, TypeScript, Go, Rust, Java, Kotlin, Ruby, PHP, Swift, C, C++, C#, Lua, Perl, Shell), AST-based Python analysis, AI/MCP-specific detection, four-phase detect/verify/score pipeline, SARIF output, CI/CD integration, trust model, and 267 tests.

### Features
- `--diff <base-ref>` flag — only scan files changed since a base reference (e.g., `main`). Useful for CI PR review.
- `--branch` support via URL fragment — `https://github.com/user/repo#branch-name` scans a specific branch.
- `.gatekeeper-ignore` file support — one glob pattern per line, merged with `--exclude`. Trust-gated (only from trusted targets).
- Cross-platform `--timeout` — uses `threading.Timer` fallback on Windows when `SIGALRM` is unavailable.
- Auto-cleanup of saved reports — keeps last 50 in `~/.gatekeeper/reports/`.
- Expanded vendor detection — `extern/` and `external/` directories classified as vendor.
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
