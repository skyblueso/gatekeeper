"""
Gatekeeper Report Output

Terminal-formatted reports and SARIF generation for CI/CD integration.
"""

import hashlib
import json
import re
from typing import Dict, List

from gatekeeper_scanner.models import Finding, ScanReport


class ReportPrinter:
    """Terminal report formatter with ANSI color support."""

    def __init__(self, use_color=True, version: str = "1.0.0"):
        self._version = version
        if use_color:
            self.RESET = "\033[0m"
            self.BOLD = "\033[1m"
            self.DIM = "\033[2m"
            self.RED = "\033[91m"
            self.GREEN = "\033[92m"
            self.YELLOW = "\033[93m"
            self.ORANGE = "\033[38;5;208m"
            self.BLUE = "\033[94m"
            self.CYAN = "\033[96m"
            self.SEVERITY_COLORS = {
                "CRITICAL": "\033[91m\033[1m", "HIGH": "\033[91m",
                "MEDIUM": "\033[93m", "LOW": "\033[96m", "INFO": "\033[2m",
            }
            self.GRADE_COLORS = {
                "A": "\033[92m", "B": "\033[93m",
                "C": "\033[38;5;208m", "D": "\033[38;5;208m", "F": "\033[91m",
            }
        else:
            self.RESET = self.BOLD = self.DIM = ""
            self.RED = self.GREEN = self.YELLOW = self.ORANGE = self.BLUE = self.CYAN = ""
            self.SEVERITY_COLORS = {k: "" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
            self.GRADE_COLORS = {k: "" for k in ("A", "B", "C", "D", "F")}

    SEVERITY_ICONS = {
        "CRITICAL": "!!!",  "HIGH": " !! ",
        "MEDIUM": " !  ", "LOW": " .  ", "INFO": " -  ",
    }
    GRADE_LABELS = {
        "A": "SAFE",
        "B": "LOW RISK",
        "C": "CAUTION",
        "D": "DANGER",
        "F": "FAIL",
    }

    def print_banner(self):
        C = f"{self.BOLD}{self.CYAN}"
        R = self.RESET
        D = self.DIM
        print(f"  {C}\u2554\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2566\u2550\u2550\u2550\u2557{R}")
        print(f"  {C}\u2551   \u2551   \u2551   \u2551      G A T E K E E P E R   \u2551   \u2551   \u2551   \u2551{R}")
        print(f"  {C}\u2568   \u2568   \u2568   \u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d   \u2568   \u2568   \u2568{R}")
        print(f"  {D}v{self._version} By @simchabrodsky \u2014 Exposes what other scanners can't see.{R}")
        print(f"  {D}The brutally honest repo, skill & agent scanner.{R}")

    def print_warnings(self, warnings: List[str]):
        if not warnings:
            return
        print(f"\n  {self.BOLD}WARNINGS{self.RESET}")
        for w in warnings:
            print(f"  {self.YELLOW}[!]{self.RESET} {w}")

    def print_report(self, report: ScanReport, warnings: List[str] = None):
        self._print_header(report)
        self._print_structure(report.structure)
        self._print_findings(report.findings, report.dismissed_count)
        self._print_deps(report.dependency_report)
        self.print_warnings(warnings or [])
        # Everything above = Discovery + Investigation (no grade shown)
        # Everything below = Final judgment (context + grade + verdict)
        self._print_context(report)
        self.print_banner()
        self._print_score(report)
        self._print_recommendation(report)
        self._print_verdict(report)
        if report.mcp_scan_available:
            print(f"\n  {self.DIM}mcp-scan detected. Run 'mcp-scan' for additional cloud-based analysis.{self.RESET}")
        print()

    def _print_header(self, report: ScanReport):
        w = 60
        print()
        print(f"  {self.BOLD}{'=' * w}{self.RESET}")
        print(f"  {self.BOLD}  SECURITY SCAN REPORT{self.RESET}")
        print(f"  {self.BOLD}{'=' * w}{self.RESET}")
        print(f"  {self.DIM}Target:{self.RESET}  {report.target}")
        print(f"  {self.DIM}Type:{self.RESET}    {report.scan_type}")
        print(f"  {self.DIM}Time:{self.RESET}    {report.timestamp[:19]}")
        print(f"  {self.DIM}Scan:{self.RESET}    {report.duration_seconds:.1f}s")
        disabled = getattr(report, "disabled_checks", None)
        if disabled:
            print(f"  {self.YELLOW}Disabled:{self.RESET} {', '.join(disabled)}")
            print(f"  {self.DIM}         Grade reflects a reduced scan. Disabled checks can hide risk.{self.RESET}")
        print(f"  {self.BOLD}{'-' * w}{self.RESET}")

    def _print_structure(self, s: Dict):
        if not s:
            return
        print(f"\n  {self.BOLD}STRUCTURE{self.RESET}")
        if s.get("languages"):
            total = sum(s["languages"].values())
            langs = sorted(s["languages"].items(), key=lambda x: -x[1])
            print(f"  Languages:    {', '.join(f'{n} ({c*100//total}%)' for n, c in langs[:4])}")
        print(f"  Files:        {s.get('source_files', 0)} source, {s.get('config_files', 0)} config, {s.get('total_files', 0)} total")
        print(f"  Lines:        {s.get('total_lines', 0):,}")
        size = s.get("total_size_bytes", 0)
        print(f"  Size:         {size / 1_000_000:.1f} MB" if size > 1_000_000 else f"  Size:         {size / 1_000:.1f} KB")
        if s.get("entry_points"):
            print(f"  Entry points: {', '.join(s['entry_points'][:5])}")
        flags = []
        for key, label in [("has_mcp_config", "MCP config"), ("has_skill_md", "SKILL.md"),
                           ("has_dockerfile", "Dockerfile"), ("has_compose", "Compose"), ("has_ci", "CI/CD"), ("has_ai_config", "AI config")]:
            if s.get(key):
                flags.append(label)
        if s.get("binary_count"):
            flags.append(f"{s['binary_count']} binaries")
        if s.get("symlink_count"):
            flags.append(f"{s['symlink_count']} symlinks")
        if flags:
            print(f"  Detected:     {', '.join(flags)}")

    def _print_findings(self, findings: List[Finding], dismissed: int):
        if not findings:
            print(f"\n  {self.BOLD}DISCOVERY{self.RESET}")
            print(f"  No security issues detected.")
            if dismissed:
                print(f"  {self.DIM}{dismissed} detections dismissed as false positives.{self.RESET}")
            return

        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [f"{counts.get(s, 0)} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if s in counts]
        print(f"\n  {self.BOLD}DISCOVERY ({len(findings)} potential vulnerabilities: {', '.join(parts)}){self.RESET}")
        if dismissed:
            print(f"  {self.DIM}{dismissed} detections dismissed as false positives.{self.RESET}")
        print()

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_f = sorted(findings, key=lambda f: sev_order.get(f.severity, 5))
        for i, f in enumerate(sorted_f):
            if i >= 40:
                print(f"  {self.DIM}  ... and {len(sorted_f) - i} more findings{self.RESET}")
                break
            color = self.SEVERITY_COLORS.get(f.severity, "")
            icon = self.SEVERITY_ICONS.get(f.severity, "  ")
            loc = f.file + (f":{f.line}" if f.line else "") if f.file else ""
            downgraded = f" (was {f.original_severity})" if f.original_severity else ""
            print(f"  {color}{icon} [{f.category}] {f.message}{downgraded}{self.RESET}")
            if loc:
                print(f"       {self.DIM}{loc}{self.RESET}")
            if f.snippet:
                print(f"       {self.DIM}{f.snippet}{self.RESET}")
            print()

    def _print_deps(self, d: Dict):
        if not d or not d.get("package_manager"):
            return
        print(f"  {self.BOLD}DEPENDENCIES ({d['package_manager']}){self.RESET}")
        print(f"  Total:        {d.get('total_deps', 0)}")
        audit = d.get("audit_findings", [])
        print(f"  {self.RED}Vulnerabilities: {len(audit)}{self.RESET}" if audit else f"  Vulnerabilities: 0")
        unpinned = d.get("unpinned", [])
        if unpinned:
            print(f"  {self.YELLOW}Unpinned:       {len(unpinned)}{self.RESET}")
        sus = d.get("suspicious_packages", [])
        if sus:
            for s in sus:
                print(f"  {self.RED}  {s['name']}: {s['reason']}{self.RESET}")
        phantom = d.get("phantom_deps", [])
        if phantom:
            print(f"  {self.YELLOW}Phantom deps:   {len(phantom)} (declared but never imported){self.RESET}")

    def _print_context(self, report: ScanReport):
        """Print context section \u2014 what the tool is and why it got the grade it got."""
        if not report.tool_description and not report.grade_drivers:
            return
        print(f"\n  {self.BOLD}CONTEXT{self.RESET}")
        if report.tool_description:
            print(f"  {self.DIM}This tool:{self.RESET} {report.tool_description}")
        if report.grade_drivers:
            print(f"  {self.DIM}Grade driven by:{self.RESET}")
            for driver in report.grade_drivers:
                print(f"    {self.DIM}- {driver}{self.RESET}")

    def _print_score(self, report: ScanReport):
        grade = report.grade
        color = self.GRADE_COLORS.get(grade, self.RED)
        label = self.GRADE_LABELS.get(grade, "")
        # Visual bar: A=20 filled, B=16, C=12, D=6, F=2
        fill_map = {"A": 20, "B": 16, "C": 12, "D": 6, "F": 2}
        filled = fill_map.get(grade, 2)
        bar = "\u2588" * filled + "\u2591" * (20 - filled)
        print(f"\n  {self.BOLD}RAW SCAN{self.RESET}")
        print(f"  {color}{self.BOLD}{bar}  {grade}{self.RESET}  {color}{label}{self.RESET}")
        print(f"  {self.DIM}Pattern-only score \u2014 context analysis required for final verdict.{self.RESET}")

    def _print_recommendation(self, report: ScanReport):
        grade = report.grade
        color = self.GRADE_COLORS.get(grade, self.RED)
        print(f"\n  {self.BOLD}NEXT STEP{self.RESET}")
        print(f"  {color}{self.BOLD}[{grade}]{self.RESET} {report.recommendation}")

    # Findings that suggest INTENTIONAL malice, not just sloppy code
    _MALICIOUS_SIGNALS = {
        "Prompt injection",
        "Data exfiltration",
        "credential theft",
        "API redirect instruction",
        "API base URL override",
        "API base URL set to non-official",
        "traffic hijacking",
        "Hidden instruction",
        "behavior override",
        "information suppression",
        "Schema poisoning",
        "Suspicious package",
        "Typosquat",
        "String concat assembles dangerous function",
        "Invisible Unicode char",
        "curl piped to shell",
        "wget piped to shell",
        "Suspicious URL: data exfiltration or tunneling",
    }

    def _has_malicious_intent(self, findings: List[Finding]) -> bool:
        """Check if findings suggest intentional malice vs just bad security.
        Requires 3+ distinct FINDINGS with malicious signals to avoid
        false positives from educational repos that reference attack patterns."""
        malicious_finding_count = 0
        for f in findings:
            if f.severity not in ("CRITICAL", "HIGH") or f.original_severity:
                continue
            for signal in self._MALICIOUS_SIGNALS:
                if signal.lower() in f.message.lower():
                    malicious_finding_count += 1
                    break  # Count each finding only once
        return malicious_finding_count >= 3

    def _print_verdict(self, report: ScanReport):
        grade = report.grade
        is_malicious = self._has_malicious_intent(report.findings)
        print()
        if grade in ("A", "B"):
            print(f"  {self.GREEN}{self.BOLD}LOW RISK{self.RESET}")
            print(f"  {self.DIM}Minimal patterns detected. Context analysis likely to confirm safe.{self.RESET}")
        elif grade == "C":
            print(f"  {self.ORANGE}{self.BOLD}REVIEW RECOMMENDED{self.RESET}")
            print(f"  {self.DIM}Patterns detected that need context analysis to determine risk.{self.RESET}")
        elif is_malicious:
            print(f"  {self.RED}{self.BOLD}HIGH RISK \u2014 MALICIOUS PATTERNS{self.RESET}")
            print(f"  {self.DIM}Contains patterns consistent with intentional harm.{self.RESET}")
            print(f"  {self.DIM}Context analysis required \u2014 run /gatekeeper for full verdict.{self.RESET}")
        else:
            print(f"  {self.RED}{self.BOLD}NEEDS CONTEXT ANALYSIS{self.RESET}")
            print(f"  {self.DIM}Multiple security patterns detected. These may be justified{self.RESET}")
            print(f"  {self.DIM}by the tool's purpose \u2014 run /gatekeeper for context-aware verdict.{self.RESET}")


def generate_sarif(report: ScanReport, version: str = "1.0.0") -> Dict:
    """Generate SARIF v2.1.0 output for CI/CD integration."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Gatekeeper",
                    "version": version,
                    "rules": [],
                }
            },
            "results": [],
        }],
    }
    run = sarif["runs"][0]
    rule_ids = {}
    severity_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

    for f in report.findings:
        rule_id = f.rule_id
        if rule_id not in rule_ids:
            rule_ids[rule_id] = len(run["tool"]["driver"]["rules"])
            rule_def = {
                "id": rule_id,
                "name": f.message.split("\u2014")[0].strip()[:60],
                "shortDescription": {"text": f.message},
                "defaultConfiguration": {"level": severity_map.get(f.severity, "warning")},
            }
            if f.cwe:
                rule_def["properties"] = {
                    "tags": [f.cwe],
                    "security-severity": "9.0" if f.severity == "CRITICAL" else "7.0" if f.severity == "HIGH" else "4.0",
                }
                if '-' in f.cwe:
                    rule_def["helpUri"] = f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"
            run["tool"]["driver"]["rules"].append(rule_def)
        # Fingerprint for baseline tracking \u2014 stable across runs for same file+rule
        fp_input = f"{f.file}:{f.rule_id}:{f.message}"
        fingerprint = hashlib.sha256(fp_input.encode()).hexdigest()[:16]
        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_ids[rule_id],
            "level": severity_map.get(f.severity, "warning"),
            "message": {"text": f.message + (f" | {f.snippet}" if f.snippet else "")},
            "fingerprints": {"gatekeeper/v1": fingerprint},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1)},
                }
            }] if f.file else [],
        }
        run["results"].append(result)

    # Coverage gaps and other scan warnings surface here as execution notifications,
    # not as results, so CI sees the disclosure without it affecting any gate or grade.
    notifications = [
        {"level": "warning", "message": {"text": w}}
        for w in getattr(report, "warnings", [])
    ]
    run["invocations"] = [{
        "executionSuccessful": True,
        "toolExecutionNotifications": notifications,
    }]
    return sarif
