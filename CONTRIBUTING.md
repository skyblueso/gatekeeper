# Contributing to Gatekeeper

Contributions are welcome: new detection patterns, language coverage, bug fixes, documentation. The bar is: does it make the scanner catch more real threats or produce fewer false positives?

## Getting Started

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR-USERNAME/gatekeeper
cd gatekeeper
git remote add upstream https://github.com/skyblueso/gatekeeper
git checkout -b your-feature-branch
python3 -m unittest test_gatekeeper -v  # Run tests, all must pass
python3 gatekeeper.py --self-scan        # Must still grade A
```

When you're ready, push your branch and open a pull request against `main`.

The scanner lives in the `gatekeeper_scanner` package: `core.py` (scanner engine, CLI, verification, scoring), `ast_scanner.py` (AST-based Python analysis), `patterns.py` (all detection patterns), `models.py` (data models), and `reporter.py` (terminal output, SARIF generation). Three optional engine modules add their own checks: `taint.py` (intra-function Python taint analysis), `yara_engine.py` with `yara_rules/` (YARA signature scanning), and `osv.py` (OSV.dev CVE fallback). Each is wired into the Phase 2 detection list in `core.py` and degrades gracefully when its dependency or network is unavailable. Tests are in `test_gatekeeper.py`.

## Adding a New Language

1. Create a pattern list: `DANGEROUS_YOURLANG = [(regex, category, severity, message), ...]`
2. Add file extensions to `SOURCE_EXTENSIONS` (e.g., `".rs"`)
3. Add language name to `LANG_MAP` (e.g., `".rs": "Rust"`)
4. Register patterns in `_get_patterns_for_ext()` method
5. Add CWE mappings for each rule in `CWE_MAP`
6. Add tests: at minimum: one pattern match test per rule, one integration test
7. Run `python3 -m unittest test_gatekeeper -v`: all tests must pass
8. Run `python3 gatekeeper.py --self-scan`: must still grade A

## Adding Detection Rules

Each rule is a tuple:

```python
(r"regex_pattern", "CATEGORY", "SEVERITY", "Human-readable message")
```

**Categories:** `EXECUTION`, `INJECTION`, `FILESYSTEM`, `NETWORK`, `PERMISSION`, `SECRET`, `OBFUSCATION`, `DEPENDENCY`, `LICENSE`, `MCP`, `SIGNATURE` (YARA), `TAINT` (data flow)

**Severities:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

Every rule generates a stable rule ID automatically (e.g., `GK-EXE-eval`) and should have a CWE mapping in `CWE_MAP`. Reference: [CWE List](https://cwe.mitre.org/).

## Testing

```bash
# Run all tests
python3 -m unittest test_gatekeeper -v

# Run a specific test class
python3 -m unittest test_gatekeeper.TestPatternDetectionPython -v

# Run a specific test
python3 -m unittest test_gatekeeper.TestPatternDetectionPython.test_eval -v
```

Tests use temp directories with synthetic repos, no network access, no real repos, fast execution. The full suite runs in under 10 seconds.

## Project Config

Projects can customize scans via `.gatekeeper.json` in the project root (only loaded for trusted/local scans):

```json
{
  "exclude": ["vendor/**", "generated/**"],
  "suppress": [
    {"rule": "GK-EXE-eval", "files": ["build.py"], "reason": "Build requires eval", "expires": "2026-07-01"}
  ]
}
```

## Contact

For questions, ideas, or collaboration: [@simchabrodsky](https://x.com/simchabrodsky) on X.
