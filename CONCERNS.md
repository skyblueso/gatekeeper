# Post-P0 concerns tracker (for next session)

Consolidated from Claude, Codex, and Grok at end of the P0 session (2026-07-13).
Confidence that we are closer to enterprise-grade than before: Claude 92, Codex 98, Grok 88.
Next session: mark each **CLOSED** (cite commit + test), **OPEN (P#)**, or **WONTFIX (reason)**.
Dedup key in brackets shows who raised it.

## FROZEN EXECUTION ORDER (agreed Claude/Codex/Grok, do not re-litigate)
0. Rule every concern below CLOSED/OPEN/WONTFIX against the merge commit (or `6ece8d9`).
   Every CLOSED must cite `git show <hash>` hunk + the test name. No CLOSED on chat narrative.
1. **P2-strip (first, cheap, no dependencies):** delete the three unimplemented MCP capability
   claims (tool-shadowing, rug-pull, namespace-collision) from README/SKILL.md and reconcile docs
   to P0 semantics. An overclaiming security tool is worse than a soft-grading one.
2. **P1 grade integrity:** kill the grade-softening heuristics (frequency downgrade, path-class,
   B-floor, per-file cap, density factor).
3. **E2E validation pack:** benign pinned-commit repo + in-repo malicious fixture + self-scan, with
   saved outputs. Runs AFTER P1 so it validates the corrected verdict model, not grades we know are distorted.
4. **P2-implement / P3 detectors → P4 ecosystem → P5 toxic-flow + live-MCP → enterprise
   provenance / policy-as-code / architecture separation.**
Rationale for the split: stripping false claims has zero dependency on the verdict model (do it
first); implementing those detectors is P3-scale (defer); e2e before P1 would certify grades we are
about to change (defer past P1).

## Ranked by how much it can still fake a safe install

### 1. Grade integrity — P1, the biggest verdict-quality gap [Claude, Codex, Grok]
A non-INCOMPLETE letter grade can still be softened for findings we DID surface. Fail-closed
only protects coverage gaps, not downgrades. Still live in `core.py`:
- Five-file frequency downgrade (same message across ≥5 files → MEDIUM, except INJECTION/SECRET).
- Path-class downgrades (tests/vendor/docs/build treated as lower risk by path).
- B-floor: ≤3 HIGHs with no CRITICAL floored at install-friendly B.
- Per-file cap of 2 (understates prevalence in score and report surface).
- LOC density factor softens large repos.
Verify: plant the same CRITICAL in 6 files and under `tests/`; confirm the grade stays honest.

### 2. Documentation honesty — P2 [Claude, Codex, Grok]
README/SKILL.md advertise tool-shadowing, rug-pull, and namespace-collision detection with NO
implementation and no tests. False assurance in a security product. Implement-or-strip each claim.
Also confirm docs match P0 semantics at HEAD (INCOMPLETE, SCOPED, `--accept-scoped`, explicit
`--trust`, yara-python required, `audit_status`) — check against HEAD, not memory.

### 3. End-to-end validation — not done tonight [Claude, Codex, Grok]
Everything is unit tests. The real CLI has never been run against a genuinely malicious repo and
verdict-checked. Required reproducible runs: (a) known-benign pinned-commit repo, (b) malicious
fixture exercising target-config hide + broken manifest + missing auditor, (c) gatekeeper self-scan.
Eyeball each verdict; keep the malicious fixture in the repo for future gates.

### 4. Detector false negatives — P3 [Claude, Codex, Grok]
- Taint only checks `args[0]` (misses kwargs, later positionals, cross-function, cross-file flow).
- Reverse-shell socket detector is IP-literal only (hostname C2 evades).
- No `importlib` in AST `DANGEROUS_MODULES`.
- OSV `_cvss_to_severity` can't read CVSS base score from vector-only fields (weak banding).
Write an evasion sample per item; confirm caught or documented out-of-scope.

### 5. Self-scan completeness [Claude, Codex, Grok]
Self-scan needs `--skip-deps --accept-scoped` for a clean path because gatekeeper's own
pyproject-declared deps have no CVE auditor input. Either add pyproject-aware auditing (P4) or
make STATE explicit that a whole-product self-scan is always SCOPED.

### 6. Breaking release / install story — v2.0.0.dev0 [Claude]
Turned a zero-dependency stdlib tool into one needing native build deps (yara-python compiler/wheels;
tomli <3.11). Every unadorned scan now grades INCOMPLETE without them. Correct security behavior,
real migration cliff. Confirm the install story and breaking change are documented where upgraders see them.

## Residual fail-open / partial-coverage [Grok, Codex]
7. YARA 2MB truncation → INCOMPLETE on any large binary. Correct fail-closed but blocks monorepo
   install grades; decide a policy (risk-class gating vs always-incomplete). P4.
8. Line/regex parsers for requirements.txt / go.mod / Cargo.toml can't truthfully emit `unparseable`
   the way JSON/TOML manifests can; malformed content may best-effort parse. P4.
9. OSV stops at 400 packages (returns `partial`); full coverage needs request batching. P4.

## Enterprise governance — roadmap bucket [Grok, Codex]
10. No signed scan provenance / coverage digest.
11. No rule-pack + engine-version capture in machine-readable reports.
12. No policy-as-code (required engines, permitted scope, ban on auto-trust).
13. `core.py` (~3,900 lines) couples walk → detect → suppress → score → verdict; scoring can rewrite
    severity before the verdict with no separate policy stage. Regression risk grows as P3 adds detectors.
    Decide whether to separate stages before P3.
14. Operational usability: large repos may frequently get INCOMPLETE; needs clear per-gap remediation
    guidance so teams reach a complete verdict without weakening policy. [Codex]

## MCP / architecture — P5 [Codex, Grok]
15. Static inspection can't see live schema drift, remote tool poisoning, or post-install behavior change.
16. Toxic flow: individually benign agents/skills/MCP tools can compose into a dangerous path that
    file-level analysis misses. Largest remaining FN reducer after fail-closed.

## Process / evidence [Grok]
17. Mid-session completion claims were wrong more than once; reviewers found blockers still open.
    Binding next session: every "closed" claim cites hash + diff hunk + failing-then-passing test.
    Trust `git show`, not chat narrative. (Saved to Claude memory: feedback-evidence-protocol-for-completion-claims.)

## Competitive-gap decisions — keep explicit, do not evaporate [all]
- P1: grade integrity. P2: doc honesty + MCP claim implement-or-strip. P3: detector breadth.
- P4: pyproject audit path, OSV batching, stronger manifest parsers, remaining ecosystem edges.
- P5: cross-file toxic flow, live MCP schema retrieval behind consent.
- Complementary (document only, do not copy into static core): Google Model Armor, Google ADK tool callbacks.
- Taxonomy only: OWASP LLM Top 10 as a coverage matrix for P2/P3 rule inventory.

## Merge status [Codex]
18. PR #3 (skyblueso/gatekeeper) is green on all 9 CI jobs but UNMERGED. The published branch
    `p0-fail-closed` is the current source of P0 until a maintainer merges.
