"""
Gatekeeper Security Scanner — proper package namespace.

Public API re-exports for backward compatibility.
"""

from gatekeeper_scanner.core import SecurityScanner, VERSION, SECRET_PLACEHOLDERS  # noqa: F401

__version__ = VERSION
from gatekeeper_scanner.models import Finding, CategorizedFiles, ScanReport  # noqa: F401
from gatekeeper_scanner.reporter import ReportPrinter, generate_sarif  # noqa: F401
from gatekeeper_scanner.patterns import (  # noqa: F401
    DANGER_WORDS_CORE, DANGER_WORDS_EXTENDED,
    SECRET_PATTERNS,
    DANGEROUS_PYTHON, DANGEROUS_JS, DANGEROUS_SHELL, DANGEROUS_GO,
    DANGEROUS_RUST, DANGEROUS_JAVA, DANGEROUS_RUBY, DANGEROUS_PHP,
    DANGEROUS_SWIFT, DANGEROUS_C_CPP, DANGEROUS_LUA, DANGEROUS_PERL,
    DANGEROUS_CSHARP,
    K8S_PATTERNS, MCP_INJECTION_PATTERNS, AI_CONFIG_INJECTION_PATTERNS,
    MCP_TOOL_MARKERS, MCP_CAPABILITY_SINKS,
    DOCKERFILE_PATTERNS, DOCKER_COMPOSE_PATTERNS,
    GITHUB_ACTIONS_PATTERNS, MAKEFILE_PATTERNS,
    SUSPICIOUS_URLS, SUSPICIOUS_PACKAGES_PY, SUSPICIOUS_PACKAGES_JS,
    UNICODE_SUSPICIOUS,
)
