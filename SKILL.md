---
name: security-scanner
description: Gatekeeper security scanner. Scan a repo, skill, or agent for risks before installing or running it.
---

# Gatekeeper v1.4.0

| name | description |
| --- | --- |
| gatekeeper | Full-stack security analysis for GitHub repos, MCP servers, AI agent packages, and local projects: by Simcha Brodsky (@simchabrodsky) |

## When to use

Use this skill whenever the user wants to:
- Scan a GitHub repo before installing it
- Check if an MCP server or agent package is safe
- Audit a local project/tool for security issues
- Verify an agent, skill, or plugin before adding it to their system
- Run a security review on any codebase

## How to invoke

```bash
python3 ~/.claude/skills/security-scanner/gatekeeper.py <target>
```

**Targets can be:**
- GitHub URL: `https://github.com/user/repo`
- GitLab URL: `https://gitlab.com/user/repo`
- Local directory: `/path/to/project`
- Local file: `/path/to/file.py`

**Options:**
- `--no-osv`: Disable the OSV.dev network fallback for CVE lookups (used when pip-audit/npm are absent)
- `--no-yara`: Disable YARA signature scanning (webshells, miners, reverse shells, droppers)
- `--no-taint`: Disable intra-function taint analysis (Python source-to-sink data flow)
- `--json`: Output raw JSON report (for programmatic use)
- `--sarif`: Output SARIF v2.1.0 for CI/CD integration (GitHub Advanced Security, GitLab, VS Code)
- `--skip-deps`: Skip dependency audit (offline mode)
- `--exclude "pattern,pattern"`: Comma-separated glob patterns to skip (e.g. `"vendor/**,*.min.js"`)
- `--output /path/to/report.json`: Save report to specific path instead of default location
- `--quiet`: Minimal output: grade and exit code only (for CI pipelines)
- `--no-color`: Disable ANSI colors (auto-detected when piped)
- `--max-files N`: Cap file count for large repos (default: 50,000)
- `--verbose` / `-v`: Verbose output with file-by-file progress
- `--self-scan`: Scan Gatekeeper's own source code (quick verification)
- `--policy "critical=0,high<=5"`: Policy-based pass/fail for CI pipelines
- `--trust`: Trust target code (enables inline suppression comments for remote repos)
- `--baseline /path/to/baseline.json`: Only report findings not present in baseline
- `--save-baseline /path/to/baseline.json`: Save current scan findings as baseline
- `--disable-rules "GK-EXE-eval,..."`: Comma-separated rule IDs to disable
- `--token <git-token>`: Git auth token for private repos (scoped to subprocess)
- `--diff <base-ref>`: Only scan files changed since base-ref (e.g. `'main'`)
- `--timeout <seconds>`: Set overall scan timeout (threading.Timer fallback on Windows)

## What it scans

Every scan runs every check. No tiers, no "deep" mode. One scan catches everything.

| Category | What it catches |
|----------|----------------|
| SECRET | API keys, tokens, passwords, private keys, database strings, JWT tokens (AWS, GitHub, Anthropic, OpenAI, Stripe, Slack, GCP, Azure, Twilio, SendGrid, Telegram) |
| EXECUTION | Shell execution, eval, dynamic code loading, dangerous deserialization, install hooks (Python, JS, Go, Rust, Java, Ruby, Shell) |
| NETWORK | Outbound HTTP calls, WebSocket connections, suspicious URLs, data exfiltration endpoints, tunneling services |
| FILESYSTEM | Sensitive path access, directory traversal, recursive deletion, symlink attacks, permission modification |
| INJECTION | Prompt injection in tool descriptions, CLAUDE.md poisoning, .cursorrules attacks, SQL injection, XSS patterns, GitHub Actions command injection |
| DEPENDENCY | Known CVEs (pip audit/npm audit, with OSV.dev network fallback when those tools are absent), typosquatting, phantom dependencies (declared but never imported), lockfile drift, suspicious install scripts |
| PERMISSION | Root containers, privilege escalation, Docker socket mounts, SYS_ADMIN caps, setuid bits |
| OBFUSCATION | Base64 payloads, string concatenation evasion, dynamic imports, invisible Unicode characters, high-entropy strings, minified code, pre-compiled binaries |
| LICENSE | Missing or restrictive licenses (AGPL, GPL) |
| MCP | Tool shadowing, schema poisoning (beyond descriptions: parameters, defaults, required fields), rug pull indicators, config injection |
| CI/CD | GitHub Actions untrusted input injection, pull_request_target escalation, outdated actions |
| DOCKER | Running as root, secrets in build args, curl-pipe-bash, privileged containers, socket mounts, host network mode |
| KUBERNETES | Privileged pods, hostPath mounts, excessive RBAC permissions, missing security contexts |
| SIGNATURE | YARA signature matches for known-bad content: PHP webshells, reverse shells (bash/nc/python), cryptominers, PowerShell download-and-execute, Python remote droppers, base64-embedded PE executables. Runs over text AND binary files. Optional (requires yara-python) |
| TAINT | Intra-function data flow: untrusted input (request data, sys.argv, input(), os.environ, decorated handler params) reaching a dangerous sink (eval/exec, subprocess, os.system, pickle/yaml deserialization, SQL execute, open, dynamic import, file deletion, SSRF). Python. Sanitizers (int(), shlex.quote, html.escape) clear taint |

## Three-phase analysis protocol

The scanner produces raw findings. Your job is to apply context intelligence on top. Every scan follows this exact protocol, no shortcuts, no skipping phases.

### Phase 1: Run the scan

Run the scanner and let the full output complete. Do NOT show the grade early or give your own pre-judgment. Let the scanner's output speak first.

```bash
python3 ~/.claude/skills/security-scanner/gatekeeper.py <target>
```

For JSON analysis (when you need to inspect findings programmatically):
```bash
python3 ~/.claude/skills/security-scanner/gatekeeper.py <target> --json
```

### Phase 2: Context analysis (MANDATORY: never skip)

After the scan completes, perform deep context analysis on EVERY finding, not just CRITICAL and HIGH. MEDIUM and LOW findings can hide real problems that the scanner underweighted. A MEDIUM that got downgraded from HIGH by the verification pass might still be dangerous in context. A LOW in a file that shouldn't exist at all could be the most important signal in the scan. Miss nothing.

Start with CRITICAL and HIGH, then work through MEDIUM and LOW. This is where the real value is, the scanner finds patterns, you determine intent.

**Your job is NOT to justify findings away. Your job is to determine the truth.** If a finding looks dangerous, say so: even if the repo is popular. If a finding is clearly architectural, say that too. But never assume "well-known repo = safe" or "lots of findings = must be false positives." The scanner caught them for a reason. Verify each one independently.

**For each finding, answer:**

1. **What is this repo?** Read the README, package.json/pyproject.toml description, and directory structure. Understand the tool's stated purpose before evaluating any finding.

2. **Is this pattern expected for this type of tool?**
   - A web framework (Django, Flask, FastAPI) will have SQL patterns, subprocess calls, and serialization: these are architectural necessities, not vulnerabilities
   - A security scanner will contain the very attack patterns it detects, eval, exec, pickle, prompt injection strings
   - A CLI tool may legitimately use subprocess with shell=True to invoke system commands
   - A terminal library may use os.dup2() for console redirection, not a reverse shell
   - An HTTP client library will have outbound network calls, that's its entire purpose
   - A data validation library (pydantic) may have pickle support for model serialization
   - A build script (build-docs.sh, deploy.sh) at the repo root may use curl|bash for toolchain setup

3. **Does this finding represent actual risk to someone installing this tool?**
   - pickle.loads() in Django's session framework ≠ pickle.loads() in a random npm package
   - subprocess.run(cmd, shell=True) in click's pager ≠ subprocess.run(user_input, shell=True) in a web handler
   - SQL f-strings in an ORM's query builder ≠ SQL f-strings in application code
   - eval() in a template engine's sandboxed evaluator ≠ eval() on user input

4. **Are there signals of intentional malice vs. legitimate architecture?**
   - Malicious: data exfiltration URLs, prompt injection strings, obfuscated payloads, suspicious packages, credential theft patterns
   - Architectural: patterns that exist because the tool's purpose requires them
   - Sloppy: real vulnerabilities from careless coding, not malicious intent

5. **Did the scanner miss anything?** Look at the dismissed findings count. If hundreds were dismissed, spot-check whether the verification pass was too aggressive. Check if MEDIUM/LOW findings were downgraded from CRITICAL/HIGH, read the `original_severity` field. A downgraded finding is still a finding. If something was downgraded and you disagree with the downgrade, flag it.

6. **Are there patterns the scanner can't see?** The scanner uses regex, AST, YARA signatures, and intra-function taint tracking. The taint engine follows untrusted input to a dangerous sink WITHIN a single function, but it does NOT follow data flow ACROSS functions or files, and it does not evaluate runtime behavior. If you see a function that takes user input in file A and passes it to eval() in file B, the scanner won't connect those dots. You can. Flag cross-function and cross-file risks the scanner missed.

7. **Read the MCP CAPABILITY MANIFEST as disclosure, not as a verdict.** When the report prints a manifest ("This package's MCP tools grant the connected model: process execution, raw network access, ..."), the target defines MCP tools and those are the host capabilities its handlers reach. Granted capabilities are not automatically malicious: a shell-runner MCP server grants exec BY DESIGN. Your job is to answer two questions for the user in plain language. First, does the granted power match the tool's stated purpose? A note-taking MCP server granting raw TCP is a red flag; a deployment tool granting exec is expected. Second, does the user understand that installing this hands those capabilities to whatever model connects to it, including a model processing attacker-controlled content? Always restate the manifest in the verdict for any MCP server, even at grade A.

### Phase 3: Second verification pass (MANDATORY for ALL scans)

Run a second pass on every scan, not just C and below. An A-grade repo could still have a finding worth mentioning. A B-grade repo might have one HIGH that deserves deeper explanation. The second pass is where you catch what the first pass might have normalized away.

**Second pass checklist: challenge your own assumptions:**
- [ ] Re-read every finding at every severity level. For CRITICAL/HIGH: could this pattern exist ONLY because the tool needs it to function? For MEDIUM/LOW: was this correctly downgraded, or was the verification pass too lenient?
- [ ] Count how many findings are architectural vs. genuinely concerning vs. uncertain. Report all three categories. "Uncertain" is a valid answer: don't force every finding into clean/dirty.
- [ ] Check if the repo has security infrastructure (SECURITY.md, security tests, input validation, parameterized queries). This is a signal, not an excuse: a repo with SECURITY.md can still have real vulnerabilities.
- [ ] Check if dangerous patterns are wrapped in safety mechanisms (sandboxing, input validation, parameterization) that the regex scanner can't see.
- [ ] Look for what ISN'T in the scan results. Does the repo handle user input? Does it make network calls? Does it write to disk? If yes, are there protections the scanner didn't check for? Absence of findings in a complex repo can be as concerning as their presence.
- [ ] Check the dismissed count. If the scanner dismissed 300+ findings, pull the JSON report and spot-check the `suppressed_findings` list. The verification pass is good but not perfect.

**After the second pass, deliver an honest verdict:**
- If CRITICALs are mostly architectural → say so explicitly, but name the specific architectural reason for each: "pickle.loads() in django/contrib/sessions: session serialization framework. subprocess shell=True in management commands: CLI tooling." Generic "these are expected" is not enough.
- If CRITICALs are genuine concerns → say so plainly: "These findings represent real vulnerabilities: [list]. Do not install without understanding [specific risks]."
- If it's mixed → separate them clearly. Never hide the genuine concerns behind the architectural ones.
- If you're uncertain about a finding → say so. "I cannot determine from static analysis whether this pickle.loads() receives untrusted input. Treat it as a risk until verified." Honesty about uncertainty is more useful than false confidence.

## Delivering the verdict

### For grade A or B
State the scanner's verdict. Note any minor findings if relevant. Done.

### For grade C
Summarize every CRITICAL and HIGH finding in plain English. For each one, explain what it does and whether it's justified by the tool's purpose. Include your second-pass analysis. Let the user decide with full context.

### For grade D or F
Explain exactly what's wrong. Be specific about the risks. Separate architectural patterns from genuine vulnerabilities. If the scanner says POTENTIALLY MALICIOUS, lead with that: tell the user what malicious patterns were found. If it says VULNERABLE, explain what holes exist and how they could be exploited. Include your second-pass analysis showing which findings you verified as genuinely dangerous.

## Critical rules

- **NEVER show the grade or give your own verdict before the scanner finishes.** The scanner handles grading at the bottom of its output. Let it complete.
- **NEVER skip the context analysis phase.** The scanner's grade is a starting point, not a final answer. Your context analysis is what makes this useful.
- **NEVER skip the second verification pass.** It runs on every scan, every grade. This is where both false positives AND false negatives get caught.
- **NEVER over-justify.** Your job is to find the truth, not to make repos look safe. If you catch yourself writing "this is probably fine" without a specific reason, stop. Either verify it's fine and explain why, or flag it as uncertain. A security tool that rubber-stamps everything is worse than no tool at all.
- **Use maximum compute for analysis.** This is a security decision, thoroughness beats speed. Read the findings carefully, cross-reference with the repo structure, and think through each one. If the scan has 50+ findings, take the time to categorize all of them. Do not summarize or skip.
- **Analyze ALL severity levels.** CRITICAL and HIGH get the deepest analysis, but MEDIUM and LOW findings still get reviewed. A MEDIUM finding that was downgraded from CRITICAL by the verification pass may still warrant the user's attention.
- **Be specific, not generic.** "Some findings were detected" is useless. "pickle.loads() in django/contrib/sessions/backends/db.py is Django's session serialization, expected for a web framework, not a vulnerability in your application" is useful.
- **Flag what the scanner can't see.** If you notice cross-file data flow risks, missing input validation, or architectural concerns that regex can't detect, say so. The scanner covers patterns. You cover logic.

## What this catches that other scanners miss

- **CLAUDE.md / AI config poisoning**: prompt injection in repos targeting Claude Code, Cursor, Copilot users
- **Phantom dependencies**: packages declared but never imported (exist only for install hooks)
- **String concatenation evasion**: `'ev' + 'al'` defeats every regex scanner; this one reconstructs and catches it
- **Full MCP schema poisoning**: checks parameter schemas, defaults, and required fields, not just descriptions
- **GitHub Actions injection**: untrusted event data interpolated in run blocks
- **Lockfile drift**: declared versions vs actually resolved versions
- **Unicode/invisible character injection**: zero-width chars, RTL overrides in source and AI configs
- **Entropy scoring**: flags high-entropy strings likely to be encoded payloads
- **Source-to-sink taint flow**: tracks untrusted input to a dangerous call within a function; catches injection a single-line regex can't see (e.g. `c = request.args['x']` three lines before `os.system(c)`)
- **YARA signatures**: fingerprints known webshells, reverse shells, cryptominers, and droppers across both text and binary files
- **OSV.dev fallback**: keeps CVE detection working on bare hosts where pip-audit/npm aren't installed, instead of silently skipping
