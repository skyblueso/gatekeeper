"""
Gatekeeper YARA signature engine

Signature-based detection of known-bad content (webshells, reverse shells,
cryptominers, droppers, embedded PE blobs) that regex/AST pattern matching
misses because it matches byte signatures and multi-string conditions rather
than language constructs. Runs over source, text, config, AND binary files.

yara-python is an OPTIONAL dependency. When it is not installed, available()
returns False and the engine is skipped with a single warning (parity with the
pip-audit / OSV fallback behavior). The scanner never hard-depends on it.

Rules live in gatekeeper_scanner/yara_rules/*.yar and are authored from
scratch for this project (no third-party rules), so there is no licensing
entanglement with Gatekeeper's MIT license.
"""

import os

try:
    import yara  # yara-python
    _YARA_IMPORT_ERROR = None
except ImportError as e:  # pragma: no cover - depends on host
    yara = None
    _YARA_IMPORT_ERROR = str(e)

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yara_rules")

# Cap how much of any single file we hand to YARA. Signatures we care about sit
# near the top of droppers/webshells; this keeps huge vendored blobs cheap.
MAX_SCAN_BYTES = 2_000_000


def available() -> bool:
    """True if yara-python is importable and at least one rule file exists."""
    if yara is None:
        return False
    try:
        return any(f.endswith((".yar", ".yara")) for f in os.listdir(RULES_DIR))
    except OSError:
        return False


def compile_rules(rules_dir: str = RULES_DIR):
    """Compile every .yar/.yara file in rules_dir into one ruleset.
    Returns (rules, error). On any compile/IO error returns (None, message)."""
    if yara is None:
        return None, "yara-python not installed"
    try:
        filepaths = {
            fname: os.path.join(rules_dir, fname)
            for fname in os.listdir(rules_dir)
            if fname.endswith((".yar", ".yara"))
        }
    except OSError as e:
        return None, f"YARA rules directory unreadable: {e}"
    if not filepaths:
        return None, "no YARA rule files found"
    try:
        return yara.compile(filepaths=filepaths), None
    except yara.Error as e:  # syntax error in a rule file
        return None, f"YARA rule compilation failed: {e}"


def scan_bytes(rules, data: bytes):
    """Match compiled rules against a byte buffer. Returns a list of dicts
    {rule, severity, description}. Never raises."""
    if rules is None or not data:
        return []
    try:
        matches = rules.match(data=data[:MAX_SCAN_BYTES])
    except Exception:
        return []
    out = []
    for m in matches:
        meta = getattr(m, "meta", {}) or {}
        out.append({
            "rule": getattr(m, "rule", "unknown"),
            "severity": str(meta.get("severity", "HIGH")).upper(),
            "description": meta.get("description", getattr(m, "rule", "signature match")),
        })
    return out
