"""
Gatekeeper Data Models v1.0

Dataclasses for findings, categorized files, and scan reports.
"""

import re
import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple

# CWE mapping — stable rule ID → CWE identifier
# Reference: https://cwe.mitre.org/
CWE_MAP = {
    # Execution
    "GK-EXE-eval": "CWE-95",
    "GK-EXE-exec": "CWE-95",
    "GK-EXE-compile": "CWE-95",
    "GK-EXE-__import__": "CWE-502",
    "GK-EXE-subprocess-with-shell-true": "CWE-78",
    "GK-EXE-os-system": "CWE-78",
    "GK-EXE-os-popen": "CWE-78",
    "GK-EXE-commands-getoutput": "CWE-78",
    "GK-EXE-pickle-deserialization": "CWE-502",
    "GK-EXE-yaml-load-without-safe-loader": "CWE-502",
    "GK-EXE-marshal-deserialization": "CWE-502",
    "GK-EXE-shelve-open": "CWE-502",
    "GK-EXE-os-dup2": "CWE-78",
    "GK-EXE-getattr-on-sensitive-module": "CWE-470",
    "GK-EXE-__builtins__-access": "CWE-470",
    "GK-EXE-dynamic-function-lookup-via-glo": "CWE-470",
    "GK-EXE-dangerous-module-imported-under": "CWE-470",
    "GK-EXE-new-function": "CWE-95",
    "GK-EXE-synchronous-shell-execution": "CWE-78",
    "GK-EXE-shell-exec-with-user-input": "CWE-78",
    "GK-EXE-child-process-exec": "CWE-78",
    "GK-EXE-vm-code-execution": "CWE-94",
    "GK-EXE-deserialization": "CWE-502",
    "GK-EXE-runtime-exec": "CWE-78",
    "GK-EXE-processbuilder": "CWE-78",
    "GK-EXE-objectinputstream": "CWE-502",
    "GK-EXE-xmldecoder": "CWE-502",
    "GK-EXE-xstream-deserialization": "CWE-502",
    "GK-EXE-php-eval": "CWE-95",
    "GK-EXE-php-shell-execution-function": "CWE-78",
    "GK-EXE-php-unserialize": "CWE-502",
    "GK-EXE-curl-piped-to-shell": "CWE-829",
    "GK-EXE-system": "CWE-78",
    "GK-EXE-exec-family": "CWE-78",
    # Injection
    "GK-INJ-sql-string-formatting": "CWE-89",
    "GK-INJ-sql-string-concatenation": "CWE-89",
    "GK-INJ-sql-f-string": "CWE-89",
    "GK-INJ-sql-f-string-in-cursor-execute": "CWE-89",
    "GK-INJ-sql--format": "CWE-89",
    "GK-INJ-sql-template-literal": "CWE-89",
    "GK-INJ-sql-concatenation-with-user-inp": "CWE-89",
    "GK-INJ-ssrf": "CWE-918",
    "GK-INJ-ssti": "CWE-94",
    "GK-INJ-mongodb--where-with-user-input": "CWE-943",
    "GK-INJ-react-dangerouslysetinnerhtml": "CWE-79",
    "GK-INJ-innerhtml-assignment": "CWE-79",
    "GK-INJ-document-write": "CWE-79",
    "GK-INJ-nosql-query-directly-from-reque": "CWE-943",
    "GK-INJ-xxe": "CWE-611",
    "GK-INJ-open-redirect": "CWE-601",
    "GK-INJ-prototype-pollution": "CWE-1321",
    "GK-INJ-jwt": "CWE-345",
    "GK-INJ-prompt-injection": "CWE-77",
    "GK-INJ-xml-tag-injection": "CWE-77",
    "GK-INJ-data-exfiltration-instruction": "CWE-200",
    "GK-INJ-credential/file-access-instruct": "CWE-200",
    "GK-INJ-api-redirect-instruction": "CWE-200",
    "GK-INJ-api-base-url-override": "CWE-200",
    "GK-INJ-gets": "CWE-120",
    "GK-INJ-sprintf": "CWE-120",
    "GK-INJ-strcpy": "CWE-120",
    "GK-INJ-strcat": "CWE-120",
    "GK-INJ-scanf-with-%s": "CWE-120",
    "GK-INJ-php-dynamic-include/require": "CWE-98",
    "GK-INJ-string-concatenation-in-logger": "CWE-117",
    "GK-INJ-github-actions": "CWE-78",
    # Secret
    "GK-SEC-hardcoded-secret/token": "CWE-798",
    "GK-SEC-hardcoded-password": "CWE-798",
    "GK-SEC-sensitive-data-in-sharedprefere": "CWE-312",
    "GK-SEC-sensitive-data-in-userdefaults": "CWE-312",
    "GK-SEC-secret-in-dockerfile-arg/env": "CWE-798",
    # Filesystem
    "GK-FIL-access-to-sensitive-credential": "CWE-552",
    "GK-FIL-shutil-rmtree": "CWE-459",
    "GK-FIL-symlink-points-outside-project": "CWE-59",
    "GK-FIL-mktemp": "CWE-377",
    # Network
    "GK-NET-socket-connect-to-ip-address": "CWE-918",
    "GK-NET-raw-socket-operation": "CWE-918",
    "GK-NET-ats-disabled": "CWE-319",
    "GK-NET-ssl-certificate-validation-disa": "CWE-295",
    # Permission
    "GK-PER-k8s": "CWE-250",
    "GK-PER-container-running-as-root-user": "CWE-250",
    "GK-PER-privileged-container": "CWE-250",
    "GK-PER-docker-socket-mount": "CWE-250",
    "GK-PER-chmod-777": "CWE-732",
    "GK-PER-setuid-bit": "CWE-250",
    # Obfuscation
    "GK-OBF-base64-decoding": "CWE-506",
    "GK-OBF-rot-encoding": "CWE-506",
    "GK-OBF-string-concat-assembles-dangero": "CWE-506",
    "GK-OBF-chr-chain": "CWE-506",
    "GK-OBF-invisible-unicode-char": "CWE-506",
    # Dependency
    "GK-DEP-suspicious-package": "CWE-829",
    "GK-DEP-phantom-dependency": "CWE-829",
    "GK-DEP-lockfile-drift": "CWE-829",
    # MCP
    "GK-MCP-schema-poisoning": "CWE-77",
    "GK-MCP-mcp-server": "CWE-77",
    # C#
    "GK-EXE-process-start": "CWE-78",
    "GK-INJ-sqlcommand-with-string-concat": "CWE-89",
    "GK-EXE-binaryformatter-deserializatio": "CWE-502",
    "GK-EXE-javascriptserializer-deseriali": "CWE-502",
    "GK-EXE-xmlserializer-with-dynamic-typ": "CWE-502",
    "GK-EXE-dynamic-assembly-loading": "CWE-470",
    "GK-INJ-regex-with-user-input": "CWE-1333",
    "GK-EXE-p/invoke": "CWE-111",
    "GK-EXE-unsafe-block": "CWE-787",
    # ML-specific
    "GK-EXE-torch-load---without-weights-on": "CWE-502",
}


@dataclass
class Finding:
    severity: str
    category: str
    file: str
    line: int
    message: str
    snippet: str = ""
    verified: bool = True    # False = dismissed by verification pass
    original_severity: str = ""  # Set if severity was downgraded
    rule_id: str = ""
    cwe: str = ""  # CWE-xxx identifier
    suppression_source: str = ""
    suppression_reason: str = ""

    def __post_init__(self):
        if not self.rule_id:
            slug = re.sub(r'[^a-z0-9]', '-', self.message.split('\u2014')[0].strip().lower())[:60].rstrip('-')
            hash4 = hashlib.sha256(self.message.encode()).hexdigest()[:4]
            self.rule_id = f"GK-{self.category[:3].upper()}-{slug}-{hash4}"
        if not self.cwe:
            self.cwe = CWE_MAP.get(self.rule_id, "")
            if not self.cwe:
                base_id = re.sub(r'-[0-9a-f]{4}$', '', self.rule_id)
                self.cwe = CWE_MAP.get(base_id, "")

    def to_dict(self):
        d = asdict(self)
        if not d["original_severity"]:
            del d["original_severity"]
        return d


@dataclass
class CategorizedFiles:
    source_files: List[Tuple[str, str, str]] = field(default_factory=list)
    config_files: List[Tuple[str, str, str]] = field(default_factory=list)
    ai_config_files: List[Tuple[str, str]] = field(default_factory=list)
    dockerfiles: List[Tuple[str, str]] = field(default_factory=list)
    compose_files: List[Tuple[str, str]] = field(default_factory=list)
    ci_files: List[Tuple[str, str]] = field(default_factory=list)
    makefiles: List[Tuple[str, str]] = field(default_factory=list)
    binary_files: List[Tuple[str, str]] = field(default_factory=list)
    env_files: List[Tuple[str, str]] = field(default_factory=list)
    mcp_configs: List[Tuple[str, str]] = field(default_factory=list)
    skill_files: List[Tuple[str, str]] = field(default_factory=list)
    setup_files: List[Tuple[str, str]] = field(default_factory=list)
    symlinks: List[Tuple[str, str]] = field(default_factory=list)
    all_text_files: List[Tuple[str, str, str]] = field(default_factory=list)
    structure: Dict = field(default_factory=dict)


@dataclass
class ScanReport:
    target: str
    scan_type: str
    timestamp: str = ""
    duration_seconds: float = 0.0
    structure: Dict = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    dependency_report: Dict = field(default_factory=dict)
    score: int = 100
    grade: str = ""
    recommendation: str = ""
    verdict: str = ""
    mcp_scan_available: bool = False
    verified_count: int = 0
    dismissed_count: int = 0
    tool_description: str = ""
    tool_type: str = "unknown"
    grade_drivers: List[str] = field(default_factory=list)
    git_history_skipped: bool = False
    severity_summary: Dict = field(default_factory=dict)
    category_summary: Dict = field(default_factory=dict)

    _all_findings: List[Finding] = field(default_factory=list, repr=False)

    def to_dict(self):
        d = {
            "target": self.target, "scan_type": self.scan_type,
            "timestamp": self.timestamp, "duration_seconds": self.duration_seconds,
            "structure": self.structure,
            "findings": [f.to_dict() for f in self.findings],
            "dependency_report": self.dependency_report,
            "score": self.score, "grade": self.grade,
            "recommendation": self.recommendation,
            "verdict": self.verdict,
            "mcp_scan_available": self.mcp_scan_available,
            "verified_count": self.verified_count,
            "dismissed_count": self.dismissed_count,
            "tool_description": self.tool_description,
            "tool_type": self.tool_type,
            "grade_drivers": self.grade_drivers,
            "git_history_skipped": self.git_history_skipped,
            "severity_summary": self.severity_summary,
            "category_summary": self.category_summary,
        }
        d["suppressed_findings"] = [
            {"rule_id": f.rule_id, "file": f.file, "line": f.line,
             "message": f.message, "suppression_source": f.suppression_source,
             "suppression_reason": f.suppression_reason}
            for f in self._all_findings if not f.verified and f.suppression_source
        ]
        return d
