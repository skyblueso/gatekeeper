"""
Gatekeeper OSV.dev client

Offline-safe fallback CVE lookups against the public OSV.dev API
(https://osv.dev). Used when the native audit binaries (pip-audit, npm)
are not installed, so dependency CVE detection still works on a bare host.

Pure standard library (urllib). Every network path is wrapped: on any
failure (no network, timeout, bad JSON, HTTP error) the functions return
empty results plus a human-readable warning. They never raise to the caller
and never block the scan for more than the supplied timeout budget.

Detection strategy (minimizes HTTP calls):
  1. One POST to /v1/querybatch with all (name, version) pairs. The batch
     response says WHICH packages have vulnerabilities and lists vuln IDs,
     but not summaries.
  2. For each vulnerable package only, one GET to /v1/vulns/{id} to fetch the
     summary, severity, and CVE alias. Vulnerable packages are usually few,
     so this stays cheap. Detail fetches are capped (MAX_DETAIL_FETCHES).
"""

import json
import urllib.request
import urllib.error

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

# Bound the work so a repo with hundreds of deps can't stall the scan.
MAX_QUERIES = 400          # packages sent in one batch
MAX_DETAIL_FETCHES = 60    # per-vuln detail GETs (only for vulnerable packages)


def _post_json(url, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "gatekeeper-scanner"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "gatekeeper-scanner"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _cvss_to_severity(vuln):
    """Map an OSV vuln's CVSS score to Gatekeeper severity. Defaults to HIGH
    (parity with the pip-audit path, which flags every CVE as HIGH)."""
    try:
        for sev in vuln.get("severity", []) or []:
            score = sev.get("score", "")
            # CVSS_V3 score field is the vector string; database_specific may
            # carry a numeric base score. We only escalate on an obvious 9.x/10.
            for token in str(score).replace("/", " ").split():
                try:
                    val = float(token)
                except ValueError:
                    continue
                if val >= 9.0:
                    return "CRITICAL"
    except (AttributeError, TypeError):
        pass
    return "HIGH"


def audit_packages(packages, ecosystem, timeout=15):
    """Look up CVEs for a list of pinned packages via OSV.dev.

    packages: list of {"name": str, "version": str}
    ecosystem: OSV ecosystem string ("PyPI", "npm", "Go", "crates.io")

    Returns (results, warning):
      results: list of dicts {package, version, id, cve, summary, severity}
      warning: None on success, else a short string explaining what failed.
    Network/parse failures yield ([], warning), never an exception.
    """
    pinned = [p for p in packages if p.get("name") and p.get("version")]
    if not pinned:
        return [], None
    pinned = pinned[:MAX_QUERIES]

    batch_payload = {
        "queries": [
            {"version": p["version"], "package": {"name": p["name"], "ecosystem": ecosystem}}
            for p in pinned
        ]
    }

    try:
        batch = _post_json(OSV_BATCH_URL, batch_payload, timeout)
    except urllib.error.URLError as e:
        return [], f"OSV.dev lookup skipped: network error ({getattr(e, 'reason', e)})"
    except (TimeoutError, OSError) as e:
        return [], f"OSV.dev lookup skipped: connection failed ({e})"
    except (json.JSONDecodeError, ValueError):
        return [], "OSV.dev lookup skipped: unexpected response"

    osv_results = batch.get("results", []) if isinstance(batch, dict) else []
    results = []
    detail_cache = {}
    fetches = 0

    for pkg, res in zip(pinned, osv_results):
        if not isinstance(res, dict):
            continue
        for vuln in res.get("vulns", []) or []:
            vid = vuln.get("id", "")
            if not vid:
                continue
            detail = detail_cache.get(vid)
            if detail is None and fetches < MAX_DETAIL_FETCHES:
                try:
                    detail = _get_json(OSV_VULN_URL + vid, timeout)
                    fetches += 1
                except (urllib.error.URLError, TimeoutError, OSError,
                        json.JSONDecodeError, ValueError):
                    detail = {}
                detail_cache[vid] = detail
            detail = detail or {}
            aliases = detail.get("aliases", []) or []
            cve = next((a for a in aliases if str(a).startswith("CVE-")), "")
            summary = detail.get("summary") or detail.get("details", "") or ""
            results.append({
                "package": pkg["name"],
                "version": pkg["version"],
                "id": vid,
                "cve": cve,
                "summary": summary[:200],
                "severity": _cvss_to_severity(detail),
            })

    return results, None
