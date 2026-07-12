# Gatekeeper hardening — session state (cold-resume note)

Last updated: 2026-07-13 (Israel time), end of the P0 session.
Repo: `~/.claude/skills/security-scanner/` (its own git repo; branch `p0-fail-closed`, also on `main`). **No git remote is configured** — see "Push status" below.

## What this effort is
A multi-model review (Claude implementing with write access, Codex adversarial review, Grok three competitive-research check-ins) hardening the Gatekeeper security scanner to genuine enterprise grade. Agreed plan, in priority order:

- **P0 — fail closed (DONE this session).** When the scanner could not inspect something, it must never issue a clean grade over the gap.
- **P1 — grade integrity (NOT STARTED).** Remove/neutralize grade-distorting heuristics.
- **P2 — documentation honesty (NOT STARTED).** Every README/SKILL.md capability claim must have a tested implementation, or the claim is removed.
- **P3 — detector breadth. P4 — dependency/ecosystem normalization. P5 — architecture (toxic-flow, live MCP).**

## P0 — COMPLETE (commits on branch `p0-fail-closed`)
Baseline `08cfa48`, then:
- `9f62012` — INCOMPLETE fails CI (exit 1, policy cannot override); analyzer crashes/import failures fail closed.
- `61a6635` — YARA absence/rule-compile failure fail closed; ImportError tests; yara-python in venv + dev extra.
- `8fe0e29` — YARA runtime fail-closed (scan_bytes engine errors, unreadable targets, 2 MB truncation); yara-python promoted to main dependency.
- `60288e1` — SCOPED verdict semantics + `--accept-scoped`.
- `e6da31f` — scoped-semantics hardening (suppression allowlist, reporter SCOPED output, diff/baseline fail-closed, state reset).
- `88d0d54` — baseline schema validation; empty-diff asserts zero files scanned.
- `d69c57d` — dependency-audit fail-closed accounting (first pass).
- `71eb3dd` — removed local auto-trust (explicit `--trust` only, scopes verdict); split audit states; `--no-osv` accounting documented.
- `47f00cc` — dependency-audit REBUILD: audit every ecosystem independently; per-ecosystem finding deltas (no cross-contamination); Go/Rust integrated via govulncheck/cargo-audit (unavailable when binary absent); OSV pinned-only → partial; native auditor JSON schema-validated; malformed package.json → unparseable.
- `7bab823` — OSV 400-cap and short-batch responses → partial (3-tuple `audit_packages` API); corrected trust regression test (suppressible MEDIUM, asserts default-retains/trust-suppresses/trust-scopes).
- `e01ec88` — CHANGELOG, version bump to `2.0.0.dev0`, STATE.md.
- `8b` (this commit) — nested auditor schema validation (pip vulns list-of-objects, npm vulnerabilities-must-be-object, cargo vulnerabilities.list-must-be-list, go malformed-line → unparseable); tool-specific acceptable return codes; pyproject-declared deps beyond requirements.txt → partial; real `tomllib` TOML parse failure and malformed `package-lock.json` → unparseable.

- `8c`/`8d` — direct `audit_packages` internal-cap test; pip nested-schema now rejects non-list `vulns` and non-object entries as `unparseable`; pip completeness check (a declared requirement absent from the audit result → `partial`, the native analogue of the OSV short-batch bug); npm/cargo nested entries guarded with isinstance before `.get`.

Test suite: **424 tests, all passing** (yara-python 4.5.4 installed in `.venv`; 0 skips).

### P0 behavior now
- Coverage ledger (`report.coverage_gaps`) + `incomplete`/`scoped`/`scoped_grade`/`incomplete_reasons`/`scope_reasons`/`trust_target` on the report and JSON.
- `INCOMPLETE` replaces the grade on any lost coverage; exits 1; policy can't override.
- `SCOPED` for explicit opt-outs; keeps letter as diagnostic; exits 1 without `--accept-scoped`.
- Local targets untrusted by default; `--trust` opt-in, scopes verdict.
- Per-ecosystem `audit_status`; `clean` only after a completed, schema-validated auditor run.

## Deferred / NOT done
- **P1 (next session):** kill as grade inputs — five-file frequency downgrade (`_apply_frequency_downgrade`), path-class downgrades (tests/vendor/docs), B-floor at `score=max(score,65)`, per-file cap of 2, LOC density floor. Order: P1 before P2.
- **P2:** README/SKILL.md advertise MCP tool-shadowing, rug-pull, namespace-collision with NO detector (Codex finding 17). Implement or strip. Docs also need INCOMPLETE/SCOPED/`--accept-scoped`/`--trust`/yara-python-required sections.
- **P3 detector breadth:** taint sinks only check `args[0]` (miss kwargs/later args); reverse-shell socket detector is IP-literal only (misses hostname C2); no `importlib` in AST `DANGEROUS_MODULES`; OSV `_cvss_to_severity` can't read CVSS base score from vector-only fields.
- **P4:** OSV `audit_packages` still caps at 400 packages internally (now correctly flagged `partial`, but true full coverage needs request batching); pyproject-declared deps have no direct CVE auditor input path (now flagged `partial`/`unaudited`, so self-scan still needs `--skip-deps`); line-based manifest parsers for `requirements.txt` and `go.mod`/`Cargo.toml` counts don't detect malformed content as `unparseable` (only `pyproject.toml` via tomllib and JSON manifests do).
- **Enterprise-controls roadmap bucket (Grok):** signed scan provenance + coverage digest; rule-pack/engine-version capture; policy-as-code (required engines, permitted scope, trust); explicit detector/policy/scoring/verdict separation.

## Validation still required (moved to next session by owner)
- End-to-end CLI runs against 3 live targets (benign pinned-commit repo, crafted-malicious fixture, gatekeeper self-scan), preserving full output.
- Self-scan line-by-line finding classification.

## Competitive research (Grok verified, this session)
- Google Model Armor = runtime prompt/response screen, NOT a pre-install scanner → document as complementary, do not copy into core.
- Google ADK before_tool/after_tool callbacks = runtime tool boundary → maps to P5 live-MCP, not P0.
- OWASP LLM Top 10 = taxonomy → use as a P2/P3 coverage matrix, not a detector design.
- garak probe/detector split, Agent Scan toxic-flow + live MCP → P5 architecture; toxic-flow + live MCP are the largest remaining false-negative reducers after fail-closed.

## Push status
No git remote is configured on this repo (`git remote -v` empty). Nothing was pushed. To push: add a remote (pyproject references `github.com/skyblueso/gatekeeper`) and `git push -u <remote> p0-fail-closed`. Branch `p0-fail-closed` holds all P0 work.
