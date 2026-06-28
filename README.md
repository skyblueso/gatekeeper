# Gatekeeper

![Gatekeeper](banner.png)

**Security analysis for GitHub repos, MCP servers, and AI agent packages. One scan, before you install.**

Built by [Simcha Brodsky](https://github.com/skyblueso) ([@simchabrodsky](https://x.com/simchabrodsky))

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue) ![Tests](https://img.shields.io/badge/tests-297%20passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-green)

---

## What it does

Be honest. When was the last time you actually read the code of an MCP server before wiring it into your agent? Or audited that handy GitHub repo before pasting its install command into your terminal? Almost nobody does. We clone, we install, we paste the setup line, and we hope.

That habit is the entire attack surface of modern AI tooling, and it is wide open. A poisoned CLAUDE.md that quietly redirects your assistant. A tool description with a hidden prompt injection. A dependency that exists for no reason except to run a malicious install hook. None of it looks dangerous until it is.

Gatekeeper is the two-minute check you run first. Point it at a repo, an MCP server, an agent package, or a local folder, and it answers one question in plain language: is this safe to install, or not? You get a letter grade, the specific findings behind it, and enough context to make the call.

Semgrep, CodeQL, and Snyk are excellent, but they answer "where are the bugs in my own code?" Gatekeeper answers a different question: "is this stranger's code safe to let into my system?" It is built for the AI-tooling attack surface those traditional scanners were never designed to see.

Under the hood: pattern and AST detection across 16 languages, intra-function taint tracking that follows untrusted input to a dangerous sink, YARA signatures for known-bad payloads like webshells and miners, dependency CVE checks, and the AI-specific surface nobody else covers (CLAUDE.md poisoning, MCP schema poisoning, prompt injection in tool descriptions, phantom dependencies, evasion tricks built to beat regex scanners). One command, zero setup, a clear verdict at the end.

---

## Quick Start

```bash
# Clone
git clone https://github.com/skyblueso/gatekeeper
cd gatekeeper

# Scan a GitHub repo before installing it
python3 gatekeeper.py https://github.com/user/repo

# Scan a specific branch
python3 gatekeeper.py https://github.com/user/repo#branch-name

# Scan a local project
python3 gatekeeper.py /path/to/project

# Scan an MCP server package
python3 gatekeeper.py https://github.com/org/mcp-server
```

---

## Example Output

```
$ python3 gatekeeper.py --self-scan

  Scanning: /path/to/security-scanner...

  Discovered 45 potential vulnerabilities. Investigating...

  ============================================================
    SECURITY SCAN REPORT
  ============================================================
  Target:  /path/to/security-scanner
  Type:    local_dir
  Scan:    1.0s
  ------------------------------------------------------------

  STRUCTURE
  Languages:    Python (100%)
  Files:        10 source, 4 config, 27 total
  Lines:        7,618
  Size:         433.2 KB
  Detected:     SKILL.md, CI/CD

  DISCOVERY (45 potential vulnerabilities: 3 MEDIUM, 42 LOW)
  342 detections dismissed as false positives.

   !   [FILESYSTEM] shutil.rmtree(): recursive directory deletion
       gatekeeper_scanner/core.py:370

   !   [EXECUTION] compile(): compiles code for execution
       gatekeeper_scanner/core.py:2275

   !   [FILESYSTEM] shutil.rmtree(): recursive directory deletion
       gatekeeper_scanner/core.py:2911

   .   [EXECUTION] eval(): executes arbitrary code (was HIGH)
       test_gatekeeper.py:91

   .   [EXECUTION] subprocess with shell=True: command injection risk (was CRITICAL)
       test_gatekeeper.py:99

    ... and 40 more findings (test-file detections, downgraded by context)

  DEPENDENCIES (pip)
  Total:        1
  Vulnerabilities: 0

  RAW SCAN
  ████████████████████  A  SAFE

  NEXT STEP
  [A] Clean. Safe to install.

  LOW RISK
  Minimal patterns detected. Context analysis likely to confirm safe.
```

The scanner grades itself A. It contains the very patterns it detects, eval, exec, pickle, prompt injection strings: but the verification pass correctly identifies them as test fixtures, pattern definitions, and documentation references, downgrading them from CRITICAL/HIGH to LOW.

---

## Requirements

- Python 3.9+
- `git` (for remote repo scanning)

No other dependencies. Runs anywhere Python runs.

**Optional: enables dependency CVE scanning:**
- `pip-audit`: Python dependency CVEs
- `npm`: Node.js dependency CVEs (uses `npm audit` internally)
- When neither is installed, Gatekeeper falls back to the OSV.dev API for pinned packages instead of skipping CVE detection (disable with `--no-osv`).

**Optional: enables YARA signature scanning:**
- `yara-python`: fingerprints known webshells, cryptominers, reverse shells, and droppers. Install with `pip install gatekeeper-scanner[yara]` or `pip install yara-python`. Without it, every other check still runs. On the first interactive run, Gatekeeper offers to install it for you.

---

## Usage

```bash
# Scan a GitHub or GitLab repo
python3 gatekeeper.py https://github.com/user/repo
python3 gatekeeper.py https://gitlab.com/user/repo

# Scan a specific branch
python3 gatekeeper.py https://github.com/user/repo#branch-name

# Scan a local directory or single file
python3 gatekeeper.py /path/to/project
python3 gatekeeper.py /path/to/file.py

# JSON output (for programmatic use or piping)
python3 gatekeeper.py <target> --json

# SARIF v2.1.0 output (GitHub Advanced Security, GitLab, VS Code)
python3 gatekeeper.py <target> --sarif

# Skip dependency audit (offline/air-gapped environments)
python3 gatekeeper.py <target> --skip-deps

# Disable individual engines if needed
python3 gatekeeper.py <target> --no-osv      # no OSV.dev network CVE fallback
python3 gatekeeper.py <target> --no-yara     # no YARA signature scanning
python3 gatekeeper.py <target> --no-taint    # no Python taint analysis

# Exclude paths by glob pattern
python3 gatekeeper.py <target> --exclude "vendor/**,*.min.js,test/**"

# Save report to a specific path
python3 gatekeeper.py <target> --output /path/to/report.json

# Minimal output: grade and exit code only (for CI)
python3 gatekeeper.py <target> --quiet

# Verbose: file-by-file progress and timing
python3 gatekeeper.py <target> --verbose

# Set a scan timeout (seconds)
python3 gatekeeper.py <target> --timeout 120

# Baseline scanning: only report new findings
python3 gatekeeper.py <target> --save-baseline baseline.json
python3 gatekeeper.py <target> --baseline baseline.json

# Policy-based pass/fail gate
python3 gatekeeper.py <target> --policy "critical=0,high<=3"

# Disable specific rules
python3 gatekeeper.py <target> --disable-rules "GK-EXE-eval,GK-NET-raw-socket"

# Scan private repos (token scoped to subprocess, not exported to env)
python3 gatekeeper.py <target> --token ghp_yourtoken

# Only scan files changed since a base ref (useful for CI PR review)
python3 gatekeeper.py <target> --diff main

# Disable color (auto-detected when stdout is not a TTY)
python3 gatekeeper.py <target> --no-color

# Raise the file cap for very large repos
python3 gatekeeper.py <target> --max-files 100000

# Trust the scan target (enables inline suppression, see Suppression)
python3 gatekeeper.py <target> --trust

# Verify Gatekeeper's own source code
python3 gatekeeper.py --self-scan

# Print version
python3 gatekeeper.py --version
```

---

## What It Scans

Every scan runs every check. No tiers, no configuration needed, no "deep mode" that you have to remember to enable.

| Category | What It Catches |
|----------|-----------------|
| **SECRET** | API keys, tokens, passwords, private keys, database connection strings, JWT tokens: AWS, GitHub, Anthropic, OpenAI, Stripe, Slack, GCP, Azure, Twilio, SendGrid, Telegram, and more |
| **EXECUTION** | Shell execution, eval, dynamic code loading, dangerous deserialization, install hooks: across Python, JS/TS, Go, Rust, Java, Ruby, Shell, PHP, C/C++, C# |
| **NETWORK** | Outbound HTTP calls, WebSocket connections, suspicious endpoints, data exfiltration patterns, tunneling services, SSL certificate validation bypasses |
| **FILESYSTEM** | Sensitive path access, directory traversal, recursive deletion, symlink attacks, insecure temp files, permission modification |
| **INJECTION** | Prompt injection in tool descriptions, CLAUDE.md/`.cursorrules` poisoning, SQL injection, NoSQL injection, XSS, SSRF, XXE, SSTI, prototype pollution, log injection, GitHub Actions command injection, C/C++ buffer overflow patterns |
| **DEPENDENCY** | Known CVEs (pip-audit/npm-audit, with an OSV.dev network fallback when those tools are absent), typosquatting candidates, phantom dependencies (declared but never imported), lockfile drift between manifest and lock file, suspicious install scripts |
| **PERMISSION** | Root containers, privilege escalation, Docker socket mounts, SYS_ADMIN capabilities, setuid bits |
| **OBFUSCATION** | Base64/ROT-encoded payloads, string concatenation evasion (`'ev' + 'al'`), chr() chains, variable assembly, aliased imports, invisible Unicode characters, high-entropy strings, minified code, pre-compiled binaries |
| **LICENSE** | Missing LICENSE file, restrictive licenses (AGPL, GPL) that may affect your distribution rights |
| **MCP** | Tool shadowing, schema poisoning across parameter schemas/defaults/required fields (not just descriptions), rug pull indicators, config injection |
| **CI/CD** | GitHub Actions untrusted input injection, `pull_request_target` privilege escalation, outdated action references |
| **DOCKER** | Running as root, secrets in build args or ENV, curl-pipe-bash, privileged containers, socket mounts, host network mode |
| **KUBERNETES** | Privileged pods, hostPath mounts, excessive RBAC permissions, missing security contexts |
| **SIGNATURE** | YARA signature matches for known-bad content: PHP webshells, reverse shells (bash/nc/python), cryptominers, PowerShell download-and-execute, Python remote droppers, base64-embedded PE executables. Scans text and binary files. Optional (requires `yara-python`) |
| **TAINT** | Intra-function data flow (Python): untrusted input (request data, `sys.argv`, `input()`, `os.environ`, decorated route/tool handler params) reaching a dangerous sink (`eval`/`exec`, `subprocess`, `os.system`, `pickle`/`yaml` deserialization, SQL `execute`, `open`, dynamic import, file deletion, SSRF). Sanitizers like `int()`, `shlex.quote`, `html.escape` clear taint |

**Language coverage:** Python, JavaScript, TypeScript, Go, Rust, Java, Kotlin, Ruby, PHP, Swift, C, C++, C#, Lua, Perl, Shell, plus Dockerfile, Kubernetes YAML, GitHub Actions, and AI configuration files (CLAUDE.md, `.cursorrules`, Copilot instructions, Cursor configs).

Note: Python, JavaScript/TypeScript, Go, Rust, Java, Ruby, PHP, and Shell have deep coverage. Swift, C/C++, Perl, Lua, and C# have foundational coverage: common patterns are caught, but these are not comprehensive audits.

**CWE mapping:** 105 rule-to-CWE mappings across all categories. Every finding includes its CWE identifier in SARIF output and JSON reports.

---

## How It Works

Gatekeeper runs a four-phase pipeline on every scan:

**Phase 1: Walk:** A single pass through the file tree categorizes every file by type (source, config, AI config, binary, Dockerfile, Kubernetes manifest, CI pipeline, etc.) and builds an index. The walk respects `.gitignore` conventions and skips standard noise directories (`node_modules`, `.git`, `__pycache__`, `vendor`, `dist`, etc.).

**Phase 2: Detect:** All detection modules run against the categorized index in parallel. Single-line pattern matching, multi-line pattern matching (for vulnerabilities that span function calls), secret detection with entropy scoring, network behavior analysis, MCP schema inspection, dependency audit, binary detection, symlink analysis, obfuscation detection, aliased import tracing, and git history scanning on local repos.

**Phase 3: Verify:** Every raw finding goes through a contextual verification pass before scoring. Findings in test files, vendor directories, documentation, example code, and fixture directories are downgraded: they're lower risk by context. This pass is the primary mechanism for false positive reduction without rules tuning.

**Phase 4: Score:** Verified findings are weighted by severity (CRITICAL: 15, HIGH: 7, MEDIUM: 3, LOW: 1) and aggregated into a numerical score. The score maps to a letter grade via configurable bands.

---

## Grading System

| Grade | Verdict | Meaning |
|-------|---------|---------|
| **A** | INSTALL | Clean. No meaningful findings. |
| **B** | INSTALL | Low risk. Minor findings worth noting, nothing blocking. |
| **C** | REVIEW BEFORE INSTALLING | Contains patterns worth checking. Likely safe, but verify the specific findings against the tool's stated purpose. |
| **D** | DO NOT INSTALL: VULNERABLE | Exploitable security holes. Sloppy code, hardcoded credentials, unsafe deserialization, exposed admin surfaces. Probably unintentional, still dangerous. |
| **F** | DO NOT INSTALL | Critical vulnerabilities or malicious patterns. Data exfiltration, prompt injection targeting AI assistants, obfuscated backdoors, supply chain attacks. |

**Exit codes for CI:** `0` for grades A/B/C, `1` for grades D/F. Override the threshold with `--policy` if you want stricter or looser gates.

The distinction between D and F matters. A D-grade repo has dangerous holes, the developer was probably careless. An F-grade repo may be trying to harm you.

---

## Configuration

Drop a `.gatekeeper.json` file in your project root to configure project-level behavior. Gatekeeper only reads this file from trusted scan targets (local directories, or remote repos scanned with `--trust`). It is never read from an untrusted scan target, the config cannot be weaponized by a repo you're evaluating.

```json
{
  "exclude": ["vendor/**", "tests/**", "*.min.js"],
  "severity_weights": {
    "CRITICAL": 15,
    "HIGH": 7,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0
  },
  "suppress": [
    {
      "rule": "GK-EXE-eval",
      "files": ["src/template-engine.py"],
      "reason": "Eval is intentional: sandboxed template evaluation"
    }
  ],
  "custom_patterns": [
    {
      "pattern": "internal_secret_var\\s*=",
      "category": "SECRET",
      "severity": "HIGH",
      "message": "Internal secret variable detected",
      "languages": [".py", ".js"]
    }
  ]
}
```

**`exclude`**: glob patterns to skip entirely during the walk phase.

**`severity_weights`**: override the default scoring weights if your risk model differs.

**`suppress`**: suppress specific findings by rule ID and path. Requires a `reason`. Trust-gated: only active when Gatekeeper trusts the scan target.

**`custom_patterns`**: add your own detection rules on top of the built-in set.

**`.gatekeeper-ignore`**: Drop a `.gatekeeper-ignore` file in your project root (one glob pattern per line, `#` for comments). Patterns are merged with `--exclude`. Only honored for trusted scan targets.

---

## Suppression

Two suppression mechanisms exist. Both are trust-gated: they only work when Gatekeeper trusts the scan target. They have no effect when scanning an untrusted remote repo, which prevents a malicious repo from suppressing its own findings.

**Inline suppression**: add a comment on the line with the finding:

```python
secret_key = load_from_vault()  # gatekeeper: ignore
```

```javascript
exec(command, options)  // gatekeeper: ignore
```

```yaml
privileged: true  # gatekeeper: ignore
```

**Config suppression**: suppress by rule ID and path in `.gatekeeper.json` (shown above). This is preferred for anything you're suppressing intentionally across an entire file, since it keeps the reason documented.

---

## CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Gatekeeper Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Clone Gatekeeper
        run: |
          git clone https://github.com/skyblueso/gatekeeper /tmp/gatekeeper
          cd /tmp/gatekeeper && git checkout v1.2.0  # Pin to a release tag

      - name: Run Gatekeeper
        run: python3 /tmp/gatekeeper/gatekeeper.py . --sarif --output results.sarif
        continue-on-error: true

      - name: Upload to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

**Baseline scanning**: scan once to establish a baseline, then only report new findings in subsequent runs:

```bash
# First run: establish baseline
python3 gatekeeper.py . --save-baseline .gatekeeper-baseline.json

# Subsequent runs: only new findings
python3 gatekeeper.py . --baseline .gatekeeper-baseline.json
```

**Policy gates**: fail CI on specific thresholds without being tied to letter grades:

```bash
# Fail on any critical, allow up to 3 high
python3 gatekeeper.py . --policy "critical=0,high<=3"
```

---

## API Usage

Gatekeeper exposes a `SecurityScanner` class for programmatic use:

```python
from gatekeeper_scanner import SecurityScanner

# Instantiate with options
scanner = SecurityScanner(
    skip_deps=False,
    exclude_patterns=["vendor/**", "tests/**"],
    # config dict accepts same keys as .gatekeeper.json
    config={
        "severity_weights": {"CRITICAL": 20, "HIGH": 8, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    }
)

# Run a scan: accepts GitHub URL, GitLab URL, local path, or single file
report = scanner.scan("https://github.com/user/repo")

# Access results
print(report.grade)          # "A", "B", "C", "D", "F", or "ERROR"
print(report.score)          # Numerical score (0: 100)
print(report.verdict)        # "INSTALL", "REVIEW BEFORE INSTALLING", "DO NOT INSTALL", etc.

for finding in report.findings:
    print(finding.category)  # "SECRET", "EXECUTION", "NETWORK", etc.
    print(finding.severity)  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    print(finding.message)   # Human-readable description
    print(finding.file)      # Relative file path
    print(finding.line)      # Line number
    print(finding.rule_id)   # Stable rule ID (e.g. "GK-EXE-eval")
    print(finding.cwe)       # CWE identifier (e.g. "CWE-95")
    print(finding.snippet)   # Code context around the finding

# Dependency report (if not skipped)
if report.dependency_report:
    print(report.dependency_report["audit_findings"])

# Serialization
import json
print(json.dumps(report.to_dict(), indent=2, default=str))
```

**SARIF generation:**

```python
from gatekeeper_scanner import SecurityScanner, generate_sarif
import json

scanner = SecurityScanner()
report = scanner.scan("/path/to/project")
sarif = generate_sarif(report)
print(json.dumps(sarif, indent=2))
```

---

## Known Limitations

Be honest with yourself about what this tool is and isn't.

**Taint tracking is intra-function only.** Gatekeeper now follows untrusted input from a source to a dangerous sink WITHIN a single Python function (see the TAINT category), with two trust levels and sanitizer awareness. It does NOT follow a tainted value ACROSS function call boundaries or module imports. If a dangerous value originates in one function or file and gets executed in another, Gatekeeper will not connect those dots. Semgrep and CodeQL do full inter-procedural data flow; Gatekeeper does not. For pre-install triage the intra-function pass catches the common cases. For in-production review of complex control flow, use a full taint-tracking tool.

**Shallow clones for remote repos.** When scanning a remote URL, Gatekeeper clones shallowly for speed. Git history scanning (catching secrets that were committed and later deleted) only works on full local clones. If you need history scanning on a remote repo, clone it first and scan the local path.

**Phantom dependency false positives.** Dynamic plugin architectures that resolve package names at runtime (configuration-driven plugin loaders, extension systems) may appear to have phantom dependencies, the import never appears in source code, but it's intentional. These will produce false positives that you'll need to suppress.

**Basic Perl coverage.** Detection covers the common dangerous functions (`system`, `exec`, `eval`, backticks, open pipes) but Perl's flexibility means coverage is shallower than other languages. More patterns are planned.

**Foundational Lua and C# coverage.** Detection covers common dangerous patterns but is not comprehensive. More patterns are planned.

**Modular architecture.** The scanner spans the `gatekeeper_scanner` package: `core.py`, `ast_scanner.py`, `patterns.py`, `models.py`, `reporter.py`, plus the optional engine modules `taint.py`, `yara_engine.py` (with `yara_rules/`), and `osv.py`.

**`--timeout` cross-platform support.** A `threading.Timer` fallback is used on Windows when `SIGALRM` is unavailable. For CI on Windows, external timeout mechanisms (e.g., GitHub Actions `timeout-minutes`) also work.

**Private repo tokens.** When using `--token`, the PAT is scoped to the git subprocess environment and never exported globally. However, it is visible in the cloned repo's git config until the temp directory is cleaned up at scan completion.

---

## How It Compares

**vs. Semgrep / CodeQL**

Both are AST-based with full inter-procedural taint tracking and deep data flow analysis, significantly more powerful for complex control flow. Gatekeeper's taint analysis is intra-function only, a lighter pass aimed at pre-install triage rather than exhaustive review. The trade-off is setup: both require language-specific rules, language servers, and configuration to get value. Semgrep is faster to configure than CodeQL but still requires you to know what you're looking for. Gatekeeper requires nothing: run it against any repo in any language and get a grade in under 60 seconds. For pre-install triage of unknown code, Gatekeeper wins on speed and coverage breadth. For production security review of your own codebase, Semgrep/CodeQL are the right tools.

**vs. Snyk**

Snyk is primarily a dependency CVE scanner with IDE integration. It's excellent at what it does: tracking known vulnerabilities in your dependency tree, integrated into a development workflow. It does not scan code patterns, AI configuration files, MCP schemas, supply chain indicators in install hooks, or anything in the AI-specific attack surface. The use cases overlap only on the dependency scanning component, where Gatekeeper uses pip-audit and npm-audit under the hood to cover the same ground.

**Gatekeeper's unique coverage:** MCP and AI-specific attack surface. Prompt injection in tool descriptions and parameter schemas. CLAUDE.md poisoning designed to compromise Claude Code users. Config file attacks targeting Cursor, Copilot, and other AI coding assistants. Phantom dependencies that exist purely for malicious install hooks. String concatenation evasion specifically designed to defeat regex-based detection. No commercial scanner covers this attack surface because it didn't exist until recently. Gatekeeper was built specifically for it.

---

## What's Next

Development is ongoing. This is very early stage and I hope to continue improvements regularly as new bugs are discovered, or gaps are found that can be filled with new scan modules. When a detection gap is discovered, it gets patched and the update will push live to everyone.

Planned for v2:

- **Additional language coverage.** Expanding Perl patterns significantly. Adding R, Zig, and Move (Sui/Aptos smart contracts). Deepening C/C++ coverage beyond the current buffer overflow and command injection patterns.
- **Structured logging improvements.** Better machine-readable output for integration with SIEM systems and security dashboards.
- **More AI-specific patterns.** The AI agent attack surface is evolving quickly. New MCP poisoning vectors, agent prompt injection techniques, and model-specific attack patterns will be added as they're documented.
- **Full git history scanning for remote repos.** Currently limited to local clones. Remote history scanning is architecturally complex but the value is real, many credential leaks are in deleted commits.

If you want to help take this further and contribute to something meaningful in the AI/agentic space, improving detection patterns, adding new languages, or improving the architecture: I would love to see this become an open-source project that makes it to enterprise level doing something not yet on the market. Reach out on X: [@simchabrodsky](https://x.com/simchabrodsky).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

For bugs, feature requests, and everything else: [@simchabrodsky](https://x.com/simchabrodsky) on X/Twitter.

---

## License

MIT
