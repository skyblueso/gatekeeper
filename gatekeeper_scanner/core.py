#!/usr/bin/env python3
"""
Gatekeeper Security Scanner v1.2.0

Full-stack security analysis for GitHub repos, MCP servers, AI agent packages,
and local projects. One command. Every check. Every time.

Architecture: Detect → Verify → Score
  Phase 1: Walk the file tree once, categorize everything
  Phase 2: Run all detection modules — produce raw findings
  Phase 3: Verification pass — contextually validate each finding
  Phase 4: Score from verified findings only
"""

import argparse
import fnmatch
import hashlib
import importlib.util
import json
import logging
import math
import os
import re
import subprocess
import sys
import tempfile
import shutil
import threading
from pathlib import Path
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

logger = logging.getLogger("gatekeeper")

try:
    import tomllib
except ImportError:
    tomllib = None

# Canonical imports from extracted modules
from gatekeeper_scanner.patterns import (  # noqa: F401 — re-exports for test compatibility
    DANGER_WORDS_CORE, DANGER_WORDS_EXTENDED,
    SECRET_PATTERNS,
    DANGEROUS_PYTHON, DANGEROUS_JS, DANGEROUS_SHELL, DANGEROUS_GO,
    DANGEROUS_RUST, DANGEROUS_JAVA, DANGEROUS_RUBY, DANGEROUS_PHP,
    DANGEROUS_SWIFT, DANGEROUS_C_CPP, DANGEROUS_LUA, DANGEROUS_PERL,
    DANGEROUS_CSHARP,
    K8S_PATTERNS, MCP_INJECTION_PATTERNS, AI_CONFIG_INJECTION_PATTERNS,
    DOCKERFILE_PATTERNS, DOCKER_COMPOSE_PATTERNS,
    GITHUB_ACTIONS_PATTERNS, MAKEFILE_PATTERNS,
    SUSPICIOUS_URLS, SUSPICIOUS_PACKAGES_PY, SUSPICIOUS_PACKAGES_JS,
    UNICODE_SUSPICIOUS,
)
from gatekeeper_scanner.models import Finding, CategorizedFiles, ScanReport  # noqa: F401
from gatekeeper_scanner.reporter import ReportPrinter, generate_sarif  # noqa: F401

# ============================================================================
# CONFIGURATION
# ============================================================================

VERSION = "1.2.0"

SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh",
    ".rb", ".go", ".rs", ".java", ".kt", ".swift",
    ".c", ".cpp", ".h", ".hpp",
    ".php", ".pl", ".lua", ".cs",
}

CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".xml", ".plist",
}

AI_CONFIG_FILES = {
    "claude.md", ".claude.md", "claude_md", ".cursorrules", ".cursorignore",
    "copilot-instructions.md", ".github/copilot-instructions.md",
    ".aider.conf.yml", ".continue/config.json", ".codeium/config.json",
    "rules.md", ".rules", "system-prompt.md", "system_prompt.txt",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".a", ".o", ".obj",
    ".wasm", ".pyc", ".pyo", ".class",
    ".bin", ".dat",
}

# Files that should be excluded from secret detection (translations, generated content)
SECRET_SKIP_EXTENSIONS = {
    ".po", ".pot", ".mo",  # Gettext translation files — UI strings like "Enter your password" are not secrets
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "coverage", ".coverage", ".eggs",
    "vendor", "target", "out", "bin", ".idea", ".vscode",
}

MAX_FILE_SIZE = 500_000
MAX_LINE_LENGTH = 2000
MAX_TOTAL_FILES = 50_000

SUPPRESSION_COMMENT = re.compile(r"(?:#|//|--)\s*gatekeeper:\s*ignore", re.IGNORECASE)

# Default config — set via constructor or CLI flags (operator-controlled, never from scan target)
DEFAULT_CONFIG = {
    "exclude": [],                # glob patterns to skip
    "fail_on": ["D", "F"],        # grades that produce exit code 1
    "max_files": MAX_TOTAL_FILES,
    "severity_weights": {"CRITICAL": 15, "HIGH": 7, "MEDIUM": 3, "LOW": 1, "INFO": 0},
    "grade_bands": [[80, "A"], [65, "B"], [50, "C"], [30, "D"], [0, "F"]],
    "skip_dirs": list(SKIP_DIRS),
    "custom_patterns": [],        # [{"pattern": "...", "category": "...", "severity": "...", "message": "...", "languages": [".py"]}]
}

LANG_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".jsx": "React JSX", ".tsx": "React TSX",
    ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
    ".java": "Java", ".kt": "Kotlin", ".swift": "Swift",
    ".sh": "Shell", ".bash": "Bash",
    ".c": "C", ".cpp": "C++", ".php": "PHP", ".lua": "Lua",
    ".pl": "Perl", ".cs": "C#",
}

ENTRY_POINT_NAMES = {
    "main.py", "server.py", "index.js", "index.ts", "app.py",
    "app.js", "app.ts", "cli.py", "cli.js", "run.py", "run.js",
    "main.js", "main.ts", "mod.rs", "main.go", "main.rs",
}

# Placeholders — if a "secret" matches these, it's a template, not a leak
SECRET_PLACEHOLDERS = re.compile(
    r"(?i)("
    r"your[_\-]?\w*[_\-]?(?:key|token|secret|password|here)|"
    r"replace[_\-]?me|"
    r"insert[_\-]?\w*here|"
    r"xxx+|"
    r"TODO|"
    r"CHANGE[_\-]?ME|"
    r"sk-ant-xxx|"
    r"example|"
    r"placeholder|"
    r"dummy|"
    r"test[_\-]?(?:key|token|secret)|"
    r"fake[_\-]?\w*|"
    r"sample[_\-]?\w*|"
    r"user:pass(?:word)?|"
    r"username:password|"
    r"admin:admin|"
    r"root:root|"
    r"(?:my|your|the)[_\-]?(?:user|password|secret)|"
    r"<[^>]+>"  # <your-key-here>
    r")"
)

# Private/localhost IPs — not suspicious
PRIVATE_IP = re.compile(
    r"^(?:"
    r"127\.\d+\.\d+\.\d+|"
    r"0\.0\.0\.0|"
    r"10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"169\.254\.\d+\.\d+|"
    r"::1|localhost"
    r")"
)

# ============================================================================
# CORE SCANNER
# ============================================================================

class SecurityScanner:
    def __init__(self, skip_deps=False, max_files=MAX_TOTAL_FILES, exclude_patterns=None, config=None, trust_target=False, git_env=None, verbose=False, no_osv=False, no_taint=False, no_yara=False):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.config["severity_weights"] = dict(self.config["severity_weights"])
        self.skip_deps = skip_deps
        self.no_osv = no_osv
        self.no_taint = no_taint
        self.no_yara = no_yara
        self.verbose = verbose
        self.max_files = self.config.get("max_files", max_files)
        self.exclude_patterns = exclude_patterns or self.config.get("exclude", [])
        self._original_exclude = list(self.exclude_patterns)
        self._trust_explicit = trust_target  # Operator explicitly set trust
        self.trust_target = trust_target
        self._git_env = git_env or {}
        self._findings_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self.findings: List[Finding] = []
        self.warnings: List[str] = []
        self.temp_dirs: List[str] = []
        self._file_cache: Dict[str, str] = {}
        self._cache_total_bytes: int = 0
        self._diff_files: Optional[Set[str]] = None
        self._project_suppress: List[Dict] = []
        self._custom_patterns: Dict[str, List] = {}
        self._load_custom_patterns()

    def _load_custom_patterns(self):
        """Build _custom_patterns dict from config. Called on init and scan reset."""
        self._custom_patterns = {}
        for cp in self.config.get("custom_patterns", []):
            for lang in cp.get("languages", []):
                self._custom_patterns.setdefault(lang, []).append(
                    (cp["pattern"], cp.get("category", "CUSTOM"), cp.get("severity", "MEDIUM"), cp.get("message", "Custom pattern match"))
                )

    def _add_finding(self, finding: 'Finding'):
        with self._findings_lock:
            self.findings.append(finding)

    def _add_findings(self, findings_list: List['Finding']):
        with self._findings_lock:
            self.findings.extend(findings_list)

    def _add_warning(self, message: str):
        with self._findings_lock:
            self.warnings.append(message)

    def _add_warnings(self, messages: List[str]):
        with self._findings_lock:
            self.warnings.extend(messages)

    def _read_file(self, fpath: str, max_size: int = MAX_FILE_SIZE) -> Optional[str]:
        """Read file with caching. Returns None if too large or unreadable."""
        if fpath in self._file_cache:
            return self._file_cache[fpath]
        try:
            if os.path.getsize(fpath) > max_size:
                return None
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            with self._cache_lock:
                if self._cache_total_bytes + len(content) <= 500_000_000:  # 500MB limit
                    self._file_cache[fpath] = content
                    self._cache_total_bytes += len(content)
            return content
        except (OSError, IOError):
            return None

    def _resolve_binary(self, name: str) -> Optional[str]:
        """Resolve full path to a binary, or None if not found."""
        return shutil.which(name)

    def _load_project_config(self, scan_path: str) -> Dict:
        """Load project-level config from .gatekeeper.yml or .gatekeeper.json.
        Only called when trust_target is True — never loads config from untrusted repos."""
        for name in (".gatekeeper.yml", ".gatekeeper.yaml", ".gatekeeper.json"):
            cfg_path = os.path.join(scan_path, name)
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r") as f:
                        if name.endswith(".json"):
                            return json.load(f)
                        else:
                            try:
                                import yaml
                                return yaml.safe_load(f) or {}
                            except ImportError:
                                self._add_warning("PyYAML not installed — .gatekeeper.yml ignored. Use .gatekeeper.json instead.")
                                return {}
                except Exception as e:
                    self._add_warning(f"Could not parse {name}: {e}")
        return {}

    def scan(self, target: str) -> ScanReport:
        self.findings = []
        self.warnings = []
        self._project_suppress = []
        self._load_custom_patterns()
        self.exclude_patterns = list(self._original_exclude)
        start = datetime.now()
        scan_type, scan_path = self._resolve_target(target)
        # Auto-set trust: local dirs are trusted (user's own code), remote repos are not
        # Only auto-detect if the operator didn't explicitly set --trust
        if not self._trust_explicit:
            self.trust_target = scan_type in ("local_dir", "local_file")

        report = ScanReport(
            target=target,
            scan_type=scan_type,
            timestamp=datetime.now().isoformat(),
        )

        if scan_path is None:
            report.score = 0
            report.grade = "ERROR"
            report.recommendation = "Could not access target."
            return report

        try:
            # Load project config (only from trusted targets)
            if self.trust_target:
                project_cfg = self._load_project_config(scan_path)
                if project_cfg:
                    if "exclude" in project_cfg:
                        self.exclude_patterns = list(set(self.exclude_patterns + project_cfg["exclude"]))
                    if "severity_weights" in project_cfg:
                        self.config["severity_weights"].update(project_cfg["severity_weights"])
                    if "custom_patterns" in project_cfg:
                        for cp in project_cfg["custom_patterns"]:
                            for lang in cp.get("languages", []):
                                self._custom_patterns.setdefault(lang, []).append(
                                    (cp["pattern"], cp.get("category", "CUSTOM"), cp.get("severity", "MEDIUM"), cp.get("message", "Custom pattern match"))
                                )
                    self._project_suppress = project_cfg.get("suppress", [])
                    for i, sup in enumerate(self._project_suppress):
                        if "rule" not in sup:
                            self._add_warning(f"Suppression #{i+1} missing 'rule' key — ignored")
                        if "files" not in sup:
                            self._add_warning(f"Suppression for {sup.get('rule', '?')} missing 'files' key — will not match anything")

            # Phase 1: Single walk — categorize everything
            cats = self._walk_and_categorize(scan_path)
            report.structure = cats.structure

            # Phase 2: Run ALL detection modules (raw findings)
            self._scan_code_patterns(cats)
            self._scan_ast(cats)
            self._scan_taint(cats)
            self._scan_multiline_patterns(cats)
            self._detect_secrets(cats, scan_path)
            self._analyze_network(cats, scan_path)
            self._check_mcp_specific(cats)
            self._scan_ai_configs(cats)
            self._scan_dockerfiles(cats)
            self._scan_compose_files(cats)
            self._scan_ci_pipelines(cats)
            self._scan_makefiles(cats)
            self._scan_setup_files(cats)
            self._detect_binaries(cats)
            self._scan_yara(cats)
            self._detect_symlinks(cats)
            self._detect_obfuscation(cats)
            self._detect_aliased_imports(cats)
            self._scan_prompt_injection_in_code(cats)
            self._scan_k8s_manifests(cats)
            self._check_no_user_in_dockerfile(cats)
            self._scan_git_history(scan_path)

            if not self.skip_deps:
                report.dependency_report = self._scan_dependencies(scan_path)

            self._check_licenses(scan_path)

            report.mcp_scan_available = self._check_mcp_scan()

            # Phase 3: VERIFICATION PASS — validate every finding
            self._verify_findings()

            # Phase 4: Score from verified findings only
            report._all_findings = list(self.findings)  # Keep all for audit trail
            verified = [f for f in self.findings if f.verified]
            dismissed = [f for f in self.findings if not f.verified]
            report.findings = verified
            report.verified_count = len(verified)
            report.dismissed_count = len(dismissed)
            for f in verified:
                report.severity_summary[f.severity] = report.severity_summary.get(f.severity, 0) + 1
                report.category_summary[f.category] = report.category_summary.get(f.category, 0) + 1
            total_lines = cats.structure.get("total_lines", 0)
            report.score, report.grade = self._calculate_score(verified, total_lines)
            report.recommendation = self._generate_recommendation(report)
            report.verdict = {"A": "INSTALL", "B": "INSTALL", "C": "REVIEW BEFORE INSTALLING",
                              "D": "DO NOT INSTALL — VULNERABLE", "F": "DO NOT INSTALL"}.get(report.grade, "ERROR")
            report.tool_description = self._extract_description(scan_path)
            report.tool_type = self._detect_tool_type(cats.structure, scan_path)
            report.structure["tool_type"] = report.tool_type
            report.grade_drivers = self._build_grade_drivers(verified)
            report.git_history_skipped = any("shallow clone" in w for w in self.warnings)
            report.duration_seconds = (datetime.now() - start).total_seconds()

        finally:
            self._file_cache.clear()
            self._cache_total_bytes = 0
            for td in self.temp_dirs:
                if os.path.exists(td):
                    shutil.rmtree(td, ignore_errors=True)
            self.temp_dirs.clear()

        return report

    # ------------------------------------------------------------------
    # Target resolution
    # ------------------------------------------------------------------

    def _resolve_target(self, target: str) -> Tuple[str, Optional[str]]:
        parsed = urlparse(target) if target.startswith("http") else None
        if (parsed and parsed.hostname in ("github.com", "gitlab.com", "www.github.com", "www.gitlab.com")) or target.endswith(".git"):
            return "github", self._clone_repo(target)
        path = Path(target).expanduser().resolve()
        if path.is_dir():
            return "local_dir", str(path)
        if path.is_file():
            return "local_file", str(path.parent)
        if target.startswith("http"):
            return "github", self._clone_repo(target)
        logger.warning("Cannot resolve target: %s", target)
        return "unknown", None

    _BLOCKED_PROTOCOLS = re.compile(r"^(?:file|ext|gopher|ftp)(?:://|::)", re.IGNORECASE)

    def _clone_repo(self, url: str) -> Optional[str]:
        temp_dir = tempfile.mkdtemp(prefix="agent-scan-")
        self.temp_dirs.append(temp_dir)
        url = url.strip().rstrip("/")
        # Parse #branch suffix for branch-specific scanning
        branch = ""
        if "#" in url:
            url, branch = url.rsplit("#", 1)
            # Validate branch name to prevent git flag injection
            if branch and not re.match(r'^[A-Za-z0-9._/\-]+$', branch):
                logger.warning("Invalid branch name rejected: %s", branch)
                branch = ""
        # Block dangerous git protocols
        if self._BLOCKED_PROTOCOLS.match(url):
            logger.warning("Blocked unsafe protocol in URL: %s", url)
            return None
        # Extract subdirectory path from /tree/ or /blob/ URLs before stripping
        subdir = ""
        tree_match = re.search(r"/(tree|blob)/[^/]+/(.+)", url)
        if tree_match:
            subdir = tree_match.group(2).rstrip("/")
        # Strip to repo root for cloning
        url = re.sub(r"/(blob|tree|raw|blame|commits|edit)/[^?#]+", "", url)
        if not url.endswith(".git"):
            url = url + ".git"
        try:
            clone_env = {**os.environ, **self._git_env} if self._git_env else None
            clone_cmd = ["git", "clone", "--depth", "1", "--single-branch"]
            if branch:
                clone_cmd.extend(["--branch", branch])
            clone_cmd.extend(["--", url, temp_dir + "/repo"])
            result = subprocess.run(
                clone_cmd,
                capture_output=True, text=True, timeout=300, env=clone_env
            )
            if result.returncode != 0:
                logger.warning("Clone failed: %s", result.stderr.strip())
                return None
            # If user pointed to a subdirectory, scope scan to it
            scan_path = temp_dir + "/repo"
            if subdir:
                scoped = os.path.join(scan_path, subdir)
                if not os.path.abspath(scoped).startswith(os.path.abspath(scan_path)):
                    logger.warning("Path traversal blocked: %s", subdir)
                    return scan_path
                if os.path.isdir(scoped):
                    return scoped
                elif os.path.isfile(scoped):
                    return os.path.dirname(scoped)
                # Subdir doesn't exist — fall back to full repo
            return scan_path
        except subprocess.TimeoutExpired:
            logger.warning("Clone timed out after 300s")
            return None
        except FileNotFoundError:
            logger.error("git not found — install git first")
            return None

    # ------------------------------------------------------------------
    # Single walk — categorize all files
    # ------------------------------------------------------------------

    def _walk_and_categorize(self, path: str) -> CategorizedFiles:
        # Load .gatekeeper-ignore from trusted targets
        if self.trust_target:
            ignore_path = os.path.join(path, ".gatekeeper-ignore")
            if os.path.exists(ignore_path):
                try:
                    with open(ignore_path) as igf:
                        for line in igf:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                self.exclude_patterns.append(line)
                except OSError:
                    pass

        cats = CategorizedFiles()
        structure = {
            "total_files": 0, "source_files": 0, "config_files": 0,
            "total_lines": 0, "total_size_bytes": 0,
            "languages": {}, "entry_points": [],
            "has_mcp_config": False, "has_skill_md": False,
            "has_dockerfile": False, "has_compose": False, "has_ci": False,
            "has_ai_config": False, "binary_count": 0, "symlink_count": 0,
        }

        # Track paths already added to all_text_files to prevent duplication
        text_file_paths = set()

        def _add_text_file(fpath, rel_path, ext):
            if fpath not in text_file_paths:
                cats.all_text_files.append((fpath, rel_path, ext))
                text_file_paths.add(fpath)

        file_limit_reached = False
        for root, dirs, files in os.walk(path):
            if file_limit_reached:
                break
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            rel_root = os.path.relpath(root, path)

            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.join(rel_root, fname) if rel_root != "." else fname

                # Exclude patterns
                if self.exclude_patterns and any(fnmatch.fnmatch(rel_path, p) for p in self.exclude_patterns):
                    continue

                # Diff mode: only scan changed files
                if self._diff_files is not None and rel_path not in self._diff_files:
                    continue

                if os.path.islink(fpath):
                    link_target = os.readlink(fpath)
                    cats.symlinks.append((fpath, rel_path))
                    structure["symlink_count"] += 1
                    if link_target.startswith("/") or ".." in link_target:
                        continue

                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    continue

                structure["total_files"] += 1
                if structure["total_files"] >= self.max_files:
                    self._add_warning(f"File limit reached ({self.max_files}). Use --max-files to increase.")
                    file_limit_reached = True
                    break
                structure["total_size_bytes"] += fsize

                ext = Path(fname).suffix.lower()
                lname = fname.lower()

                # Source files
                if ext in SOURCE_EXTENSIONS:
                    structure["source_files"] += 1
                    lang = LANG_MAP.get(ext, ext)
                    structure["languages"][lang] = structure["languages"].get(lang, 0) + 1
                    cats.source_files.append((fpath, rel_path, ext))
                    _add_text_file(fpath, rel_path, ext)
                    cached = self._read_file(fpath)
                    if cached is not None:
                        structure["total_lines"] += cached.count("\n") + (1 if cached and not cached.endswith("\n") else 0)

                # Config files
                if ext in CONFIG_EXTENSIONS:
                    structure["config_files"] += 1
                    cats.config_files.append((fpath, rel_path, ext))
                    _add_text_file(fpath, rel_path, ext)

                # AI config files
                if lname in AI_CONFIG_FILES or rel_path.lower() in AI_CONFIG_FILES:
                    cats.ai_config_files.append((fpath, rel_path))
                    structure["has_ai_config"] = True

                # Dockerfiles
                if lname in ("dockerfile", "dockerfile.dev", "dockerfile.prod", "dockerfile.test") or lname.startswith("dockerfile."):
                    cats.dockerfiles.append((fpath, rel_path))
                    structure["has_dockerfile"] = True

                # Docker compose
                if lname in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml") or lname.startswith("docker-compose."):
                    cats.compose_files.append((fpath, rel_path))
                    structure["has_compose"] = True

                # CI/CD
                if (rel_root.startswith(".github") and ext in (".yml", ".yaml")) or \
                   lname in (".gitlab-ci.yml", "jenkinsfile", ".circleci/config.yml", "bitbucket-pipelines.yml"):
                    cats.ci_files.append((fpath, rel_path))
                    structure["has_ci"] = True

                # Makefiles
                if lname in ("makefile", "gnumakefile") or lname.startswith("makefile."):
                    cats.makefiles.append((fpath, rel_path))

                # Binary files
                if ext in BINARY_EXTENSIONS:
                    cats.binary_files.append((fpath, rel_path))
                    structure["binary_count"] += 1

                # Env files
                if lname.startswith(".env"):
                    cats.env_files.append((fpath, rel_path))
                    _add_text_file(fpath, rel_path, ext)

                # MCP configs
                if lname in ("mcp.json", "claude_desktop_config.json"):
                    cats.mcp_configs.append((fpath, rel_path))
                    structure["has_mcp_config"] = True

                # Skill files
                if lname == "skill.md":
                    cats.skill_files.append((fpath, rel_path))
                    structure["has_skill_md"] = True

                # Setup files
                if lname in ("setup.py", "setup.cfg"):
                    cats.setup_files.append((fpath, rel_path))

                # Entry points
                if lname in ENTRY_POINT_NAMES:
                    structure["entry_points"].append(rel_path)

                # Markdown/text for secrets scan
                if ext in (".md", ".txt", ".rst"):
                    _add_text_file(fpath, rel_path, ext)

                # Catch-all: any non-binary file under size limit gets secret-scanned.
                # Without this, files with unusual extensions (.pem, .key, no ext, etc.)
                # are invisible to secret detection.
                if ext not in BINARY_EXTENSIONS and fsize <= MAX_FILE_SIZE:
                    _add_text_file(fpath, rel_path, ext)

        cats.structure = structure
        return cats

    # ------------------------------------------------------------------
    # Code pattern scanning
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Comment tracking (multi-line aware)
    # ------------------------------------------------------------------

    class _CommentTracker:
        """Tracks multi-line comment state across lines within a file."""
        C_FAMILY = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".go", ".rs",
                    ".java", ".kt", ".swift", ".c", ".cpp", ".h", ".hpp", ".php"}
        PYTHON_FAMILY = {".py"}
        RUBY_FAMILY = {".rb"}

        def __init__(self, ext: str):
            self.ext = ext
            self.in_block = False
            self._py_quote = None

        def is_comment(self, line: str) -> bool:
            stripped = line.strip()
            if self.in_block:
                if self.ext in self.C_FAMILY:
                    if "*/" in stripped:
                        self.in_block = False
                    return True
                elif self.ext in self.PYTHON_FAMILY:
                    if self._py_quote and self._py_quote in stripped:
                        self.in_block = False
                    return True
                elif self.ext in self.RUBY_FAMILY:
                    if stripped == "=end":
                        self.in_block = False
                    return True
                return True
            # Single-line comments
            if self.ext in (".py", ".rb", ".sh", ".bash", ".zsh"):
                if stripped.startswith("#"):
                    return True
            if self.ext in self.C_FAMILY or self.ext == ".php":
                if stripped.startswith("//"):
                    return True
                if stripped.startswith("/*"):
                    if "*/" in stripped[2:]:
                        return True  # Single-line block comment
                    self.in_block = True
                    return True
            if self.ext == ".php" and stripped.startswith("#"):
                return True
            # Python docstrings at statement level
            if self.ext in self.PYTHON_FAMILY:
                for q in ('"""', "'''"):
                    if stripped.startswith(q):
                        if q in stripped[3:]:
                            return True
                        self.in_block = True
                        self._py_quote = q
                        return True
            # Ruby =begin/=end
            if self.ext in self.RUBY_FAMILY and stripped == "=begin":
                self.in_block = True
                return True
            return False

    def _get_patterns_for_ext(self, ext: str):
        patterns_map = {
            ".py": DANGEROUS_PYTHON, ".js": DANGEROUS_JS, ".ts": DANGEROUS_JS,
            ".jsx": DANGEROUS_JS, ".tsx": DANGEROUS_JS, ".mjs": DANGEROUS_JS,
            ".cjs": DANGEROUS_JS, ".sh": DANGEROUS_SHELL, ".bash": DANGEROUS_SHELL,
            ".zsh": DANGEROUS_SHELL, ".go": DANGEROUS_GO, ".rs": DANGEROUS_RUST,
            ".java": DANGEROUS_JAVA, ".kt": DANGEROUS_JAVA, ".rb": DANGEROUS_RUBY,
            ".php": DANGEROUS_PHP, ".swift": DANGEROUS_SWIFT,
            ".c": DANGEROUS_C_CPP, ".cpp": DANGEROUS_C_CPP,
            ".h": DANGEROUS_C_CPP, ".hpp": DANGEROUS_C_CPP,
            ".lua": DANGEROUS_LUA, ".pl": DANGEROUS_PERL,
            ".cs": DANGEROUS_CSHARP,
        }
        base = patterns_map.get(ext, [])
        custom = self._custom_patterns.get(ext, [])
        return base + custom if custom else base

    def _scan_code_patterns(self, cats: CategorizedFiles):
        def _scan_file(fpath, rel_path, ext):
            results = []
            patterns = self._get_patterns_for_ext(ext)
            if not patterns:
                return results
            content = self._read_file(fpath)
            if content is None:
                return results
            lines = content.split("\n")

            ct = self._CommentTracker(ext)
            for i, line in enumerate(lines, 1):
                if len(line) > MAX_LINE_LENGTH or ct.is_comment(line):
                    continue
                if self.trust_target and SUPPRESSION_COMMENT.search(line):
                    continue
                for pattern, category, severity, message in patterns:
                    if re.search(pattern, line):
                        results.append(Finding(
                            severity=severity, category=category,
                            file=rel_path, line=i,
                            message=message, snippet=line.strip()[:120],
                        ))
            return results

        workers = min(8, (os.cpu_count() or 4))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_scan_file, fp, rp, ext) for fp, rp, ext in cats.source_files]
            for future in as_completed(futures):
                try:
                    file_findings = future.result()
                except Exception as e:
                    self._add_warning(f"File scan error: {e}")
                    continue
                self._add_findings(file_findings)

    # ------------------------------------------------------------------
    # Multi-line pattern detection
    # ------------------------------------------------------------------

    MULTILINE_PATTERNS = [
        (r"subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*?shell\s*=\s*True",
         "EXECUTION", "CRITICAL", "subprocess with shell=True — command injection risk", {".py"}),
        (r"cursor\.execute\s*\(\s*f['\"]",
         "INJECTION", "CRITICAL", "SQL f-string in cursor.execute — injection risk", {".py"}),
        (r"child_process.*?\.exec\s*\([^)]*?(?:req\.|input|user|param)",
         "EXECUTION", "CRITICAL", "Shell exec with user input — command injection", {".js", ".ts"}),
    ]

    def _scan_ast(self, cats: CategorizedFiles):
        """Run AST-based analysis on Python files (supplements regex detection)."""
        try:
            from gatekeeper_scanner.ast_scanner import ASTScanner
        except ImportError:
            return  # Graceful degradation if module is missing
        ast_scanner = ASTScanner()
        workers = min(8, (os.cpu_count() or 4))

        def _scan_one(fpath, rel_path, ext):
            if ext != ".py":
                return []
            content = self._read_file(fpath)
            if content is None:
                return []
            return ast_scanner.scan_file(fpath, rel_path, content,
                                            trust_target=self.trust_target)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_scan_one, fp, rp, ext)
                for fp, rp, ext in cats.source_files
            ]
            for future in as_completed(futures):
                try:
                    self._add_findings(future.result())
                except Exception:
                    pass  # AST parse failures already return [] inside scan_file

    def _scan_multiline_patterns(self, cats: CategorizedFiles):
        """Scan for patterns that span multiple lines."""
        for fpath, rel_path, ext in cats.source_files:
            content = self._read_file(fpath)
            if content is None:
                continue
            for pattern, category, severity, message, langs in self.MULTILINE_PATTERNS:
                if ext not in langs:
                    continue
                for m in re.finditer(pattern, content, re.DOTALL):
                    line_num = content[:m.start()].count("\n") + 1
                    snippet = m.group(0).replace("\n", " ")[:120]
                    self._add_finding(Finding(
                        severity=severity, category=category,
                        file=rel_path, line=line_num,
                        message=f"(multi-line) {message}",
                        snippet=snippet,
                    ))

    # ------------------------------------------------------------------
    # Secret detection
    # ------------------------------------------------------------------

    def _detect_secrets(self, cats: CategorizedFiles, scan_path: str):
        for fpath, rel_path in cats.env_files:
            self._add_finding(Finding(
                severity="HIGH", category="SECRET", file=rel_path, line=0,
                message=f"Environment file found: {os.path.basename(rel_path)} — may contain secrets",
            ))

        for fpath, rel_path, ext in cats.all_text_files:
            # Skip translation files — UI strings like "Enter your password" are not secrets
            if ext in SECRET_SKIP_EXTENSIONS:
                continue
            content = self._read_file(fpath)
            if content is None:
                continue

            for pattern, label in SECRET_PATTERNS:
                for m in re.finditer(pattern, content):
                    matched = m.group(0)
                    # Extract value portion (between quotes) for placeholder check —
                    # checking the full match would dismiss real secrets assigned to
                    # variables named "your_api_key" because "your" is a placeholder word
                    value_match = re.search(r"""['\"]([^'"]+)['\"]""", matched)
                    check_str = value_match.group(1) if value_match else matched
                    if SECRET_PLACEHOLDERS.search(check_str):
                        continue
                    line_num = content[:m.start()].count("\n") + 1
                    if len(matched) > 12:
                        redacted = matched[:6] + "..." + matched[-4:]
                    else:
                        redacted = matched[:4] + "..."
                    self._add_finding(Finding(
                        severity="CRITICAL", category="SECRET",
                        file=rel_path, line=line_num,
                        message=f"{label} detected",
                        snippet=f"[REDACTED: {redacted}]",
                    ))

    # ------------------------------------------------------------------
    # Network analysis
    # ------------------------------------------------------------------

    def _analyze_network(self, cats: CategorizedFiles, scan_path: str):
        url_pattern = re.compile(r'https?://[^\s\'"<>,\)]{1,2000}')

        for fpath, rel_path, ext in cats.source_files + cats.config_files:
            content = self._read_file(fpath)
            if content is None:
                continue

            # FIX: Use finditer for correct line numbers per occurrence
            for url_match in url_pattern.finditer(content):
                url = url_match.group(0)
                for sus_pattern in SUSPICIOUS_URLS:
                    if re.search(sus_pattern, url, re.IGNORECASE):
                        line_num = content[:url_match.start()].count("\n") + 1
                        self._add_finding(Finding(
                            severity="HIGH", category="NETWORK",
                            file=rel_path, line=line_num,
                            message="Suspicious URL: data exfiltration or tunneling endpoint",
                            snippet=url[:100],
                        ))
                        break

    # ------------------------------------------------------------------
    # MCP-specific checks
    # ------------------------------------------------------------------

    def _check_mcp_specific(self, cats: CategorizedFiles):
        for fpath, rel_path in cats.skill_files:
            self._scan_file_for_injection(fpath, rel_path, MCP_INJECTION_PATTERNS)
        for fpath, rel_path in cats.mcp_configs:
            self._scan_mcp_config(fpath, rel_path)
        for fpath, rel_path, ext in cats.source_files:
            self._scan_tool_descriptions(fpath, rel_path)

    def _scan_file_for_injection(self, fpath: str, rel_path: str, patterns):
        content = self._read_file(fpath)
        if content is None:
            return
        for pattern, category, severity, message in patterns:
            for m in re.finditer(pattern, content):
                line_num = content[:m.start()].count("\n") + 1
                self._add_finding(Finding(
                    severity=severity, category=category,
                    file=rel_path, line=line_num,
                    message=message, snippet=m.group(0)[:100],
                ))

    def _scan_mcp_config(self, fpath: str, rel_path: str):
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            self._add_warning(f"Could not parse MCP config: {e}")
            return

        servers = config.get("mcpServers", config.get("servers", {}))
        if not isinstance(servers, dict):
            return

        for name, server in servers.items():
            if not isinstance(server, dict):
                continue
            cmd = server.get("command", "")
            args = server.get("args", [])

            dangerous_cmds = ["rm", "curl", "wget", "bash", "sh", "powershell", "cmd"]
            if any(cmd.endswith(dc) or cmd == dc for dc in dangerous_cmds):
                self._add_finding(Finding(
                    severity="CRITICAL", category="MCP",
                    file=rel_path, line=0,
                    message=f"MCP server '{name}' uses dangerous command: {cmd}",
                    snippet=f"{cmd} {' '.join(str(a) for a in args[:3])}",
                ))

            env = server.get("env", {})
            for key, val in env.items():
                if isinstance(val, str) and len(val) > 10 and not val.startswith("${"):
                    if any(s in key.lower() for s in ("key", "secret", "token", "password", "auth")):
                        self._add_finding(Finding(
                            severity="CRITICAL", category="SECRET",
                            file=rel_path, line=0,
                            message=f"Hardcoded secret in MCP config env: {key}",
                            snippet=f"{key}=[REDACTED]",
                        ))

            raw_content = self._read_file(fpath)
            self._check_mcp_schema_poisoning(server, name, rel_path, raw_content)

    def _check_mcp_schema_poisoning(self, server_config: Dict, server_name: str, rel_path: str, raw_content: str = None):
        candidates = []  # (Finding, is_description_field)
        def _find_line(text: str) -> int:
            if raw_content and text:
                pos = raw_content.find(text[:60])
                if pos >= 0:
                    return raw_content[:pos].count("\n") + 1
            return 0
        def _deep_scan(obj, path=""):
            if isinstance(obj, str) and len(obj) > 30:
                is_desc = "description" in path.lower()
                for pattern, category, severity, message in MCP_INJECTION_PATTERNS + AI_CONFIG_INJECTION_PATTERNS:
                    if re.search(pattern, obj):
                        candidates.append((Finding(
                            severity=severity, category="MCP",
                            file=rel_path, line=_find_line(obj),
                            message=f"Schema poisoning in '{server_name}' at {path}: {message}",
                            snippet=obj[:100],
                        ), is_desc))
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _deep_scan(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    _deep_scan(v, f"{path}[{i}]")
        _deep_scan(server_config, server_name)
        # Only emit if 2+ matches found, or any match is in a description field
        if len(candidates) >= 2 or any(is_desc for _, is_desc in candidates):
            for finding, _ in candidates:
                self._add_finding(finding)

    def _scan_tool_descriptions(self, fpath: str, rel_path: str):
        content = self._read_file(fpath)
        if content is None:
            return

        desc_patterns = [
            r'description\s*=\s*["\']([^"\']{50,})["\']',
            r'"description"\s*:\s*"([^"]{50,})"',
            r"'description'\s*:\s*'([^']{50,})'",
            r'description\s*=\s*"""(.*?)"""',
        ]
        for dp in desc_patterns:
            for m in re.finditer(dp, content, re.DOTALL):
                desc_text = m.group(1)
                line_num = content[:m.start()].count("\n") + 1
                for inj_pattern, category, severity, message in MCP_INJECTION_PATTERNS + AI_CONFIG_INJECTION_PATTERNS:
                    if re.search(inj_pattern, desc_text):
                        self._add_finding(Finding(
                            severity=severity, category=category,
                            file=rel_path, line=line_num,
                            message=f"Tool description: {message}",
                            snippet=desc_text[:100],
                        ))

    # ------------------------------------------------------------------
    # AI config file scanning
    # ------------------------------------------------------------------

    def _scan_ai_configs(self, cats: CategorizedFiles):
        for fpath, rel_path in cats.ai_config_files:
            self._scan_file_for_injection(fpath, rel_path, AI_CONFIG_INJECTION_PATTERNS)
            self._scan_file_for_injection(fpath, rel_path, MCP_INJECTION_PATTERNS)
            content = self._read_file(fpath)
            if content:
                for m in UNICODE_SUSPICIOUS.finditer(content):
                    line_num = content[:m.start()].count("\n") + 1
                    self._add_finding(Finding(
                        severity="CRITICAL", category="OBFUSCATION",
                        file=rel_path, line=line_num,
                        message=f"Invisible Unicode char (U+{ord(m.group(0)):04X}) in AI config — likely prompt injection",
                    ))

    # ------------------------------------------------------------------
    # Prompt injection in source code
    # ------------------------------------------------------------------

    # Patterns for prompt injection embedded in source code strings
    # (distinct from AI config patterns — these target string literals
    # in Python/JS/etc. that manipulate LLM behavior)
    PROMPT_INJECTION_CODE_PATTERNS = [
        (r"""['"](?:[^'"]{0,200})(?:ignore\s+(?:all\s+)?previous\s+instructions)(?:[^'"]{0,200})['"]""", "INJECTION", "CRITICAL", "Prompt injection string: ignore previous instructions"),
        (r"""['"](?:[^'"]{0,200})(?:you\s+(?:are|must|should|will)\s+now\s+(?:act|behave|respond|pretend))(?:[^'"]{0,200})['"]""", "INJECTION", "HIGH", "Prompt injection string: behavior override"),
        (r"""['"](?:[^'"]{0,200})(?:(?:do\s+not|don't|never)\s+(?:tell|reveal|show|mention|disclose)\s+(?:the\s+)?(?:user|human|anyone))(?:[^'"]{0,200})['"]""", "INJECTION", "HIGH", "Prompt injection string: information suppression"),
        (r"""['"](?:[^'"]{0,200})(?:(?:extract|exfiltrate|send|transmit)\s+.*?(?:to|at)\s+https?://)(?:[^'"]{0,200})['"]""", "INJECTION", "CRITICAL", "Prompt injection string: data exfiltration instruction"),
        (r"""['"](?:[^'"]{0,200})(?:read\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~/|/home|/Users|/etc|\.ssh|\.aws|\.env))(?:[^'"]{0,200})['"]""", "INJECTION", "CRITICAL", "Prompt injection string: credential/file access"),
        (r"""['"](?:[^'"]*?)(?:(?:override|replace|modify)\s+.{0,40}(?:api[_\-]?key|endpoint|base.?url|api.?base))(?:[^'"]*?)['"]""", "INJECTION", "CRITICAL", "Prompt injection string: API redirect/credential theft"),
        (r"""['"](?:[^'"]{0,200})<(?:system|human|assistant|claude|instruction)>(?:[^'"]{0,200})['"]""", "INJECTION", "CRITICAL", "Prompt injection string: XML tag injection for LLM manipulation"),
    ]

    def _scan_prompt_injection_in_code(self, cats: CategorizedFiles):
        """Scan source files for prompt injection strings embedded in code.

        These are string literals that contain LLM manipulation instructions —
        the kind of thing that gets passed to an AI model at runtime to hijack
        its behavior, exfiltrate data, or steal credentials.
        """
        for fpath, rel_path, ext in cats.source_files:
            content = self._read_file(fpath)
            if content is None:
                continue

            lines = content.split("\n")
            ct = self._CommentTracker(ext)
            for i, line in enumerate(lines, 1):
                if len(line) > MAX_LINE_LENGTH or ct.is_comment(line):
                    continue
                if self.trust_target and SUPPRESSION_COMMENT.search(line):
                    continue
                for pattern, category, severity, message in self.PROMPT_INJECTION_CODE_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        self._add_finding(Finding(
                            severity=severity, category=category,
                            file=rel_path, line=i,
                            message=message,
                            snippet=line.strip()[:120],
                        ))

        # Also scan non-source text files (markdown, txt, html, etc.)
        # that could contain injection payloads passed to LLMs
        for fpath, rel_path, ext in cats.all_text_files:
            if ext in SOURCE_EXTENSIONS:
                continue  # Already scanned above
            content = self._read_file(fpath)
            if content is None:
                continue

            # For non-source files, only flag the most dangerous patterns
            for pattern, category, severity, message in MCP_INJECTION_PATTERNS:
                if severity != "CRITICAL":
                    continue
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:m.start()].count("\n") + 1
                    self._add_finding(Finding(
                        severity=severity, category=category,
                        file=rel_path, line=line_num,
                        message=f"In text file: {message}",
                        snippet=m.group(0)[:120],
                    ))

    # ------------------------------------------------------------------
    # Kubernetes manifest scanning
    # ------------------------------------------------------------------

    def _scan_k8s_manifests(self, cats: CategorizedFiles):
        """Scan YAML config files for Kubernetes security misconfigurations."""
        for fpath, rel_path, ext in cats.config_files:
            if ext not in (".yaml", ".yml"):
                continue
            content = self._read_file(fpath)
            if content is None:
                continue
            # Only scan files that look like K8s manifests
            if not re.search(r"(?:kind:\s*(?:Deployment|Pod|DaemonSet|StatefulSet|Job|CronJob|ReplicaSet)|apiVersion:)", content):
                continue
            for pattern, category, severity, message in K8S_PATTERNS:
                for m in re.finditer(pattern, content):
                    line_num = content[:m.start()].count("\n") + 1
                    self._add_finding(Finding(
                        severity=severity, category=category,
                        file=rel_path, line=line_num,
                        message=message,
                        snippet=m.group(0).strip()[:120],
                    ))

    # ------------------------------------------------------------------
    # Dockerfile / compose / CI / Makefile / setup.py scanning
    # ------------------------------------------------------------------

    def _scan_file_patterns(self, files: List[Tuple[str, str]], patterns, skip_comments=False):
        for fpath, rel_path in files:
            content = self._read_file(fpath)
            if content is None:
                continue
            for line_num, line in enumerate(content.split("\n"), 1):
                if skip_comments and line.strip().startswith("#"):
                    continue
                for pattern, category, severity, message in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        self._add_finding(Finding(
                            severity=severity, category=category,
                            file=rel_path, line=line_num,
                            message=message, snippet=line.strip()[:120],
                        ))

    def _scan_dockerfiles(self, cats: CategorizedFiles):
        self._scan_file_patterns(cats.dockerfiles, DOCKERFILE_PATTERNS)

    def _scan_compose_files(self, cats: CategorizedFiles):
        self._scan_file_patterns(cats.compose_files, DOCKER_COMPOSE_PATTERNS)

    # Pattern handled separately by _check_actions_run_blocks (which tracks YAML context).
    # Matched by message prefix to survive reordering of GITHUB_ACTIONS_PATTERNS.
    _CI_RUN_BLOCK_MSG_PREFIX = "GitHub Actions: attacker-controlled input in run block"

    def _scan_ci_pipelines(self, cats: CategorizedFiles):
        non_run_patterns = [p for p in GITHUB_ACTIONS_PATTERNS if not p[3].startswith(self._CI_RUN_BLOCK_MSG_PREFIX)]
        self._scan_file_patterns(cats.ci_files, non_run_patterns, skip_comments=True)
        for fpath, rel_path in cats.ci_files:
            content = self._read_file(fpath)
            if content:
                self._check_actions_run_blocks(content, rel_path)
                self._check_actions_workflow_patterns(content, rel_path)

    def _scan_makefiles(self, cats: CategorizedFiles):
        self._scan_file_patterns(cats.makefiles, MAKEFILE_PATTERNS, skip_comments=True)

    # Expressions in run blocks that are attacker-controllable
    _DANGEROUS_RUN_EXPRESSIONS = re.compile(
        r"\$\{\{\s*(?:"
        r"github\.event\.(?:pull_request\.(?:title|body|head\.ref|head\.label)|"
        r"issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body|"
        r"discussion\.(?:title|body)|commits\[\d+\]\.message|head_commit\.message|"
        r"pages\[\d+\]\.page_name))"
    )

    def _check_actions_run_blocks(self, content: str, rel_path: str):
        lines = content.split("\n")
        in_run_block = False
        indent_level = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Handle both "run:" and "- run:" (YAML list item) forms
            run_stripped = stripped[2:].strip() if stripped.startswith("- ") else stripped
            if run_stripped.startswith("run:"):
                in_run_block = True
                indent_level = len(line) - len(line.lstrip())
                if "${{" in stripped and self._DANGEROUS_RUN_EXPRESSIONS.search(stripped):
                    self._add_finding(Finding(
                        severity="CRITICAL", category="INJECTION",
                        file=rel_path, line=i,
                        message="GitHub Actions: attacker-controlled input in run block — command injection",
                        snippet=stripped[:120],
                    ))
            elif in_run_block:
                current_indent = len(line) - len(line.lstrip())
                if stripped and current_indent <= indent_level and not stripped.startswith(("|", ">")):
                    in_run_block = False
                elif "${{" in line and self._DANGEROUS_RUN_EXPRESSIONS.search(line):
                    self._add_finding(Finding(
                        severity="CRITICAL", category="INJECTION",
                        file=rel_path, line=i,
                        message="GitHub Actions: attacker-controlled input in run block — command injection",
                        snippet=stripped[:120],
                    ))

    def _check_actions_workflow_patterns(self, content: str, rel_path: str):
        """Check for workflow-level vulnerabilities that span multiple lines."""
        lines = content.split("\n")

        # Pattern 1: pull_request_target + checkout without SHA pinning (pwn request)
        has_pr_target = bool(re.search(r"pull_request_target", content))
        if has_pr_target:
            has_checkout = bool(re.search(r"uses:\s*actions/checkout", content))
            has_dangerous_ref = bool(re.search(
                r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:ref|label)\s*\}\}", content))
            if has_checkout and has_dangerous_ref:
                # Find the checkout line for accurate reporting
                for i, line in enumerate(lines, 1):
                    if re.search(r"uses:\s*actions/checkout", line):
                        self._add_finding(Finding(
                            severity="CRITICAL", category="INJECTION",
                            file=rel_path, line=i,
                            message="GitHub Actions: pull_request_target + checkout without SHA pin — attacker code runs with write access",
                            snippet=line.strip()[:120],
                        ))
                        break

        # Pattern 2: gh pr checkout with PR number (TOCTOU race)
        for i, line in enumerate(lines, 1):
            if re.search(r"gh\s+pr\s+checkout\s+\$\{\{", line):
                self._add_finding(Finding(
                    severity="CRITICAL", category="INJECTION",
                    file=rel_path, line=i,
                    message="GitHub Actions: gh pr checkout with expression — TOCTOU race condition",
                    snippet=line.strip()[:120],
                ))

        # Pattern 3: Secret echoed to build log
        for i, line in enumerate(lines, 1):
            if re.search(r"echo\s+.*\$(?:PRIVATE_KEY|SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL|AUTH)", line, re.IGNORECASE):
                self._add_finding(Finding(
                    severity="HIGH", category="SECRET",
                    file=rel_path, line=i,
                    message="GitHub Actions: secret variable echoed to build log",
                    snippet=line.strip()[:120],
                ))

    def _scan_setup_files(self, cats: CategorizedFiles):
        for fpath, rel_path in cats.setup_files:
            if not fpath.endswith(".py"):
                content = self._read_file(fpath)
                if content and re.search(r"entry_points|console_scripts", content):
                    self._add_finding(Finding(
                        severity="LOW", category="EXECUTION",
                        file=rel_path, line=0,
                        message="setup.cfg defines entry_points — custom code runs on pip install",
                    ))
                continue
            content = self._read_file(fpath)
            if content is None:
                continue
            lines = content.split("\n")
            if re.search(r"cmdclass\s*=\s*\{", content):
                self._add_finding(Finding(
                    severity="HIGH", category="EXECUTION",
                    file=rel_path, line=0,
                    message="setup.py has cmdclass overrides — custom code runs on pip install",
                ))

            for i, line in enumerate(lines, 1):
                if line.strip().startswith("#"):
                    continue
                for pattern, category, severity, message in DANGEROUS_PYTHON:
                    if severity in ("CRITICAL", "HIGH") and re.search(pattern, line):
                        self._add_finding(Finding(
                            severity="HIGH", category="EXECUTION",
                            file=rel_path, line=i,
                            message=f"In setup.py: {message}",
                            snippet=line.strip()[:100],
                        ))

    # ------------------------------------------------------------------
    # Git history scanning — secrets removed from working tree
    # ------------------------------------------------------------------

    _GIT_HISTORY_PATTERNS = [
        "AKIA[0-9A-Z]{16}",                          # AWS Access Key
        "-----BEGIN.*PRIVATE KEY-----",                # Private keys
        "sk-ant-[A-Za-z0-9\\-]{20,}",                 # Anthropic key
        "sk-[A-Za-z0-9]{48,}",                        # OpenAI key
        "ghp_[A-Za-z0-9]{36}",                        # GitHub PAT
        "xoxb-[0-9]{10,}",                            # Slack bot token
        "sk_live_[A-Za-z0-9]{24,}",                   # Stripe secret
    ]

    def _scan_git_history(self, scan_path: str):
        """Scan git history for secrets that were committed then 'deleted.'"""
        git_dir = os.path.join(scan_path, ".git")
        if not os.path.isdir(git_dir):
            return
        # Shallow clones have no meaningful history to scan
        if os.path.exists(os.path.join(git_dir, "shallow")):
            self._add_warning("Git history scan skipped — shallow clone (remote repos). Use local full clone for history scanning.")
            return
        combined_pattern = "|".join(self._GIT_HISTORY_PATTERNS)
        try:
            result = subprocess.run(
                ["git", "log", "--all", "-G", combined_pattern, "--oneline"],
                capture_output=True, text=True, timeout=30, cwd=scan_path
            )
            if result.stdout.strip():
                commits = result.stdout.strip().split("\n")
                self._add_finding(Finding(
                    severity="CRITICAL", category="SECRET",
                    file=".git/history", line=0,
                    message=f"Secret pattern found in git history ({len(commits)} commit(s)) — secrets were committed then removed",
                    snippet="; ".join(c[:60] for c in commits[:3]),
                ))
        except subprocess.TimeoutExpired:
            self._add_warning("Git history scan timed out")
        except FileNotFoundError:
            pass

    def _check_no_user_in_dockerfile(self, cats: CategorizedFiles):
        for fpath, rel_path in cats.dockerfiles:
            content = self._read_file(fpath)
            if content is not None:
                if not re.search(r"^\s*USER\s+", content, re.MULTILINE):
                    self._add_finding(Finding(
                        severity="MEDIUM", category="PERMISSION",
                        file=rel_path, line=0,
                        message="Dockerfile has no USER directive — container runs as root by default",
                    ))

    # ------------------------------------------------------------------
    # Binary / symlink detection
    # ------------------------------------------------------------------

    def _detect_binaries(self, cats: CategorizedFiles):
        for fpath, rel_path in cats.binary_files:
            ext = Path(fpath).suffix.lower()
            if ext in (".pyc", ".pyo"):
                sev, msg = "LOW", f"Compiled Python file ({ext}) — may contain different code than source"
            elif ext == ".wasm":
                sev, msg = "MEDIUM", "WebAssembly binary — cannot be audited by source review"
            elif ext in (".exe", ".dll", ".so", ".dylib"):
                sev, msg = "HIGH", f"Pre-compiled binary ({ext}) — cannot audit"
            else:
                sev, msg = "MEDIUM", f"Binary file ({ext}) — cannot be audited by source review"
            self._add_finding(Finding(severity=sev, category="OBFUSCATION", file=rel_path, line=0, message=msg))

    def _detect_symlinks(self, cats: CategorizedFiles):
        for fpath, rel_path in cats.symlinks:
            try:
                link_target = os.readlink(fpath)
            except OSError:
                link_target = "unknown"
            if link_target.startswith("/") or ".." in link_target:
                self._add_finding(Finding(
                    severity="HIGH", category="FILESYSTEM", file=rel_path, line=0,
                    message="Symlink points outside project — path traversal risk",
                    snippet=f"-> {link_target[:100]}",
                ))
            else:
                self._add_finding(Finding(
                    severity="LOW", category="FILESYSTEM", file=rel_path, line=0,
                    message="Symlink detected", snippet=f"-> {link_target[:100]}",
                ))

    # ------------------------------------------------------------------
    # Obfuscation detection
    # ------------------------------------------------------------------

    def _detect_obfuscation(self, cats: CategorizedFiles):
        for fpath, rel_path, ext in cats.source_files:
            content = self._read_file(fpath)
            if content is None:
                continue
            lines = content.split("\n")

            ct = self._CommentTracker(ext)
            for i, line in enumerate(lines, 1):
                if len(line) > MAX_LINE_LENGTH:
                    ct.is_comment(line)  # Keep tracker state consistent for subsequent lines
                    self._add_finding(Finding(
                        severity="MEDIUM", category="OBFUSCATION", file=rel_path, line=i,
                        message=f"Extremely long line ({len(line)} chars) — likely minified/obfuscated",
                    ))
                    continue
                if ct.is_comment(line):
                    continue
                if self.trust_target and SUPPRESSION_COMMENT.search(line):
                    continue

                # String concatenation evasion
                for cm in re.findall(r"""['"]\w{1,6}['"]\s*\+\s*['"]\w{1,6}['"]""", line):
                    reconstructed = re.sub(r"""['"]\s*\+\s*['"]""", "", cm).strip("'\"")
                    if reconstructed.lower() in DANGER_WORDS_EXTENDED:
                        self._add_finding(Finding(
                            severity="CRITICAL", category="OBFUSCATION", file=rel_path, line=i,
                            message=f"String concat assembles dangerous function: '{reconstructed}'",
                            snippet=line.strip()[:120],
                        ))

                # chr() payload assembly — common in Python malware
                if re.search(r'(?:chr\s*\(\s*\d+\s*\)\s*\+?\s*){4,}', line):
                    self._add_finding(Finding(
                        severity="CRITICAL", category="OBFUSCATION", file=rel_path, line=i,
                        message="chr() chain — assembles string from character codes to evade detection",
                        snippet=line.strip()[:120],
                    ))

                # Unicode invisible characters
                if UNICODE_SUSPICIOUS.search(line):
                    m = UNICODE_SUSPICIOUS.search(line)
                    self._add_finding(Finding(
                        severity="HIGH", category="OBFUSCATION", file=rel_path, line=i,
                        message=f"Invisible Unicode char (U+{ord(m.group(0)):04X}) — may hide malicious content",
                        snippet=line.strip()[:120],
                    ))

                # High-entropy strings
                for s in re.findall(r"""['"]([A-Za-z0-9+/=]{40,})['"]""", line):
                    # Skip pure hex strings (SHA hashes, checksums)
                    if re.fullmatch(r'[0-9a-fA-F]+', s):
                        continue
                    # Skip standard base64 with padding under 200 chars (certs, config values)
                    if len(s) < 200 and re.fullmatch(r'[A-Za-z0-9+/]+={1,2}', s):
                        continue
                    entropy = self._shannon_entropy(s)
                    if entropy > 4.5 and len(s) > 50:
                        self._add_finding(Finding(
                            severity="MEDIUM", category="OBFUSCATION", file=rel_path, line=i,
                            message=f"High-entropy string (entropy={entropy:.1f}) — possible encoded payload",
                            snippet=s[:60] + "...",
                        ))

            # Variable-based assembly: a = "ev"; b = "al"; func = a + b
            if ext == ".py":
                short_assigns = {}
                ct2 = self._CommentTracker(ext)
                for i, line in enumerate(lines, 1):
                    if ct2.is_comment(line):
                        continue
                    m = re.match(r"""(\w+)\s*=\s*['"](\w{1,8})['"]""", line.strip())
                    if m:
                        short_assigns[m.group(1)] = (m.group(2), i)
                # Pre-compute dangerous pairs to avoid O(n^2) per line
                danger_pairs = []
                for var1, (val1, _) in short_assigns.items():
                    for var2, (val2, _) in short_assigns.items():
                        if var1 != var2 and (val1 + val2).lower() in DANGER_WORDS_CORE:
                            danger_pairs.append((var1, var2, val1 + val2))
                if danger_pairs:
                    for i, line in enumerate(lines, 1):
                        for var1, var2, combined in danger_pairs:
                            if re.search(rf"\b{re.escape(var1)}\s*\+\s*{re.escape(var2)}\b", line):
                                self._add_finding(Finding(
                                    severity="CRITICAL", category="OBFUSCATION",
                                    file=rel_path, line=i,
                                    message=f"Variable concat assembles dangerous function: '{combined}' ({var1}+{var2})",
                                    snippet=line.strip()[:120],
                                ))

    # ------------------------------------------------------------------
    # Aliased import detection
    # ------------------------------------------------------------------

    _DANGEROUS_ALIASES = {
        "pickle": [(r"\.loads?\s*\(", "CRITICAL", "pickle deserialization — arbitrary code execution")],
        "marshal": [(r"\.loads?\s*\(", "HIGH", "marshal deserialization — code execution")],
        "subprocess": [(r"\.(?:call|run|Popen|check_output|check_call)\s*\(", "HIGH", "subprocess execution via alias")],
        "os": [(r"\.(?:system|popen|exec\w*)\s*\(", "HIGH", "OS command execution via alias")],
        "shutil": [(r"\.rmtree\s*\(", "MEDIUM", "recursive directory deletion via alias")],
    }

    # JS/TS: dangerous Node.js modules — dotted usage patterns (alias.method())
    _DANGEROUS_JS_MODULES = {
        "child_process": [
            (r"\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(", "CRITICAL", "shell execution via aliased child_process"),
        ],
        "fs": [
            (r"\.(?:writeFile|appendFile|unlink|rmdir|rm)(?:Sync)?\s*\(", "MEDIUM", "filesystem write/delete via aliased fs"),
        ],
        "vm": [
            (r"\.(?:runInNewContext|runInThisContext|createContext|compileFunction)\s*\(", "HIGH", "VM code execution via aliased vm"),
        ],
    }

    # JS/TS: dangerous methods per module — for destructured import matching
    _DANGEROUS_JS_METHODS = {
        "child_process": {
            "exec": ("CRITICAL", "shell execution"), "execSync": ("CRITICAL", "shell execution"),
            "spawn": ("CRITICAL", "process spawning"), "spawnSync": ("CRITICAL", "process spawning"),
            "execFile": ("CRITICAL", "shell execution"), "execFileSync": ("CRITICAL", "shell execution"),
        },
        "fs": {
            "writeFile": ("MEDIUM", "filesystem write"), "writeFileSync": ("MEDIUM", "filesystem write"),
            "appendFile": ("MEDIUM", "filesystem write"), "appendFileSync": ("MEDIUM", "filesystem write"),
            "unlink": ("MEDIUM", "file deletion"), "unlinkSync": ("MEDIUM", "file deletion"),
            "rmdir": ("MEDIUM", "directory deletion"), "rmdirSync": ("MEDIUM", "directory deletion"),
            "rm": ("MEDIUM", "file/dir deletion"), "rmSync": ("MEDIUM", "file/dir deletion"),
        },
        "vm": {
            "runInNewContext": ("HIGH", "VM code execution"), "runInThisContext": ("HIGH", "VM code execution"),
            "createContext": ("HIGH", "VM context creation"), "compileFunction": ("HIGH", "VM code compilation"),
        },
    }

    # JS/TS: bare dangerous function aliases (const danger = eval; danger(code))
    _DANGEROUS_JS_BARE = {
        "eval": ("CRITICAL", "EXECUTION", "eval() called via alias"),
        "Function": ("CRITICAL", "EXECUTION", "Function constructor called via alias"),
    }

    # Regexes for extracting JS/TS require/import bindings
    _RE_REQUIRE_ALIAS = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
    _RE_REQUIRE_DESTRUCTURE = re.compile(r"""(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
    _RE_IMPORT_DEFAULT = re.compile(r"""import\s+(\w+)\s+from\s+['"]([^'"]+)['"]""")
    _RE_IMPORT_NAMED = re.compile(r"""import\s*\{([^}]+)\}\s*from\s+['"]([^'"]+)['"]""")
    _RE_BARE_ALIAS = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*(eval|Function)\s*(?:;|\s*//|$)""")

    _JS_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

    def _detect_aliased_imports(self, cats: CategorizedFiles):
        """Detect dangerous module usage via import aliases (Python and JS/TS)."""
        for fpath, rel_path, ext in cats.source_files:
            if ext == ".py":
                self._detect_aliased_imports_python(fpath, rel_path, ext)
            elif ext in self._JS_EXTS:
                self._detect_aliased_imports_js(fpath, rel_path, ext)

    def _detect_aliased_imports_python(self, fpath: str, rel_path: str, ext: str):
        """Python: detect import X as Y aliasing of dangerous modules."""
        content = self._read_file(fpath)
        if content is None:
            return

        lines = content.split("\n")
        ct = self._CommentTracker(ext)
        aliases = {}
        for line in lines:
            if ct.is_comment(line):
                continue
            m = re.search(r"import\s+(\w+)\s+as\s+(\w+)", line)
            if m:
                mod, alias = m.group(1), m.group(2)
                if mod in self._DANGEROUS_ALIASES:
                    aliases[alias] = mod

        if not aliases:
            return

        ct2 = self._CommentTracker(ext)
        for i, line in enumerate(lines, 1):
            if ct2.is_comment(line):
                continue
            for alias, mod in aliases.items():
                for pattern, severity, message in self._DANGEROUS_ALIASES[mod]:
                    if re.search(rf"\b{re.escape(alias)}{pattern}", line):
                        self._add_finding(Finding(
                            severity=severity, category="EXECUTION",
                            file=rel_path, line=i,
                            message=f"Aliased {mod} as '{alias}': {message}",
                            snippet=line.strip()[:120],
                        ))

    def _detect_aliased_imports_js(self, fpath: str, rel_path: str, ext: str):
        """JS/TS: detect require/import aliasing of dangerous modules."""
        content = self._read_file(fpath)
        if content is None:
            return

        lines = content.split("\n")

        # Pass 1: extract module aliases from require/import statements
        # alias_map: varName -> moduleName (for dotted usage: alias.method())
        # bare_map: varName -> (moduleName, methodName) (for bare calls: alias())
        alias_map = {}   # var -> module
        bare_map = {}    # var -> (module, method_name_for_message)
        bare_fn_map = {} # var -> (severity, category, message) for eval/Function aliases

        ct = self._CommentTracker(ext)
        for line in lines:
            if ct.is_comment(line):
                continue
            stripped = line.strip()

            # const cp = require('child_process')
            m = self._RE_REQUIRE_ALIAS.search(stripped)
            if m:
                var_name, mod_name = m.group(1), m.group(2)
                if mod_name in self._DANGEROUS_JS_MODULES:
                    alias_map[var_name] = mod_name

            # const { exec, spawn } = require('child_process')
            # JS destructuring uses ':' for renaming: { exec: run }
            m = self._RE_REQUIRE_DESTRUCTURE.search(stripped)
            if m:
                names_str, mod_name = m.group(1), m.group(2)
                if mod_name in self._DANGEROUS_JS_MODULES:
                    for part in names_str.split(","):
                        part = part.strip()
                        if ":" in part:
                            orig, alias = part.split(":", 1)
                            bare_map[alias.strip()] = (mod_name, orig.strip())
                        elif " as " in part:
                            orig, alias = part.split(" as ", 1)
                            bare_map[alias.strip()] = (mod_name, orig.strip())
                        elif part:
                            bare_map[part] = (mod_name, part)

            # import cp from 'child_process'
            m = self._RE_IMPORT_DEFAULT.search(stripped)
            if m:
                var_name, mod_name = m.group(1), m.group(2)
                if mod_name in self._DANGEROUS_JS_MODULES:
                    alias_map[var_name] = mod_name

            # import { exec, spawn as run } from 'child_process'
            m = self._RE_IMPORT_NAMED.search(stripped)
            if m:
                names_str, mod_name = m.group(1), m.group(2)
                if mod_name in self._DANGEROUS_JS_MODULES:
                    for part in names_str.split(","):
                        part = part.strip()
                        if " as " in part:
                            orig, alias = part.split(" as ", 1)
                            bare_map[alias.strip()] = (mod_name, orig.strip())
                        elif part:
                            bare_map[part] = (mod_name, part)

            # const danger = eval; const F = Function;
            m = self._RE_BARE_ALIAS.search(stripped)
            if m:
                var_name, builtin = m.group(1), m.group(2)
                if builtin in self._DANGEROUS_JS_BARE:
                    bare_fn_map[var_name] = self._DANGEROUS_JS_BARE[builtin]

        if not alias_map and not bare_map and not bare_fn_map:
            return

        # Pass 2: scan for aliased usage
        ct2 = self._CommentTracker(ext)
        for i, line in enumerate(lines, 1):
            if ct2.is_comment(line):
                continue

            # Dotted usage: cp.exec(...), myFs.writeFile(...)
            for alias, mod in alias_map.items():
                for pattern, severity, message in self._DANGEROUS_JS_MODULES[mod]:
                    if re.search(rf"\b{re.escape(alias)}{pattern}", line):
                        self._add_finding(Finding(
                            severity=severity, category="EXECUTION",
                            file=rel_path, line=i,
                            message=f"Aliased {mod} as '{alias}': {message}",
                            snippet=line.strip()[:120],
                        ))

            # Bare usage from destructured imports: exec(cmd), run(cmd)
            for alias, (mod, orig_name) in bare_map.items():
                if re.search(rf"\b{re.escape(alias)}\s*\(", line):
                    methods = self._DANGEROUS_JS_METHODS.get(mod, {})
                    if orig_name in methods:
                        severity, desc = methods[orig_name]
                        self._add_finding(Finding(
                            severity=severity, category="EXECUTION",
                            file=rel_path, line=i,
                            message=f"Destructured {orig_name} from '{mod}': {desc}",
                            snippet=line.strip()[:120],
                        ))

            # Bare function aliases: const danger = eval; danger(code)
            for alias, (severity, category, message) in bare_fn_map.items():
                if re.search(rf"\b{re.escape(alias)}\s*\(", line):
                    self._add_finding(Finding(
                        severity=severity, category=category,
                        file=rel_path, line=i,
                        message=f"{message} — '{alias}' is an alias",
                        snippet=line.strip()[:120],
                    ))

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    # ------------------------------------------------------------------
    # Dependency scanning
    # ------------------------------------------------------------------

    def _scan_dependencies(self, path: str) -> Dict:
        report = {
            "package_manager": None, "total_deps": 0,
            "audit_findings": [], "suspicious_packages": [],
            "unpinned": [], "phantom_deps": [], "lockfile_issues": [],
        }

        req_file = os.path.join(path, "requirements.txt")
        pyproject = os.path.join(path, "pyproject.toml")

        py_declared: Set[str] = set()
        py_optional: Set[str] = set()
        if os.path.exists(req_file):
            report["package_manager"] = "pip"
            py_declared |= self._scan_python_deps(req_file, report, path)
        if os.path.exists(pyproject):
            report["package_manager"] = "pip"
            proj_declared, proj_optional = self._scan_pyproject_deps(pyproject, report)
            py_declared |= proj_declared
            py_optional |= proj_optional

        # Unified phantom dep check — run once after both sources have contributed
        if py_declared:
            self._check_phantom_deps_python(py_declared, path, report, py_optional)

        pkg_json = os.path.join(path, "package.json")
        if os.path.exists(pkg_json):
            report["package_manager"] = "npm"
            self._scan_js_deps(pkg_json, path, report)
            self._check_lockfile_integrity(path, report)

        go_mod = os.path.join(path, "go.mod")
        if os.path.exists(go_mod):
            if not report["package_manager"]:
                report["package_manager"] = "go"
            self._scan_go_deps(go_mod, report)

        cargo_toml = os.path.join(path, "Cargo.toml")
        if os.path.exists(cargo_toml):
            if not report["package_manager"]:
                report["package_manager"] = "cargo"
            self._scan_cargo_deps(cargo_toml, report)

        if report["package_manager"] == "pip":
            self._run_pip_audit(path, report)
        elif report["package_manager"] == "npm":
            self._run_npm_audit(path, report)

        return report

    def _check_suspicious_package(self, pkg: str, file: str, report: Dict):
        """Check a package name against known suspicious/typosquat packages."""
        for sus, reason in SUSPICIOUS_PACKAGES_PY.items():
            if pkg.lower() == sus.lower():
                report["suspicious_packages"].append({"name": pkg, "reason": reason})
                self._add_finding(Finding(
                    severity="CRITICAL", category="DEPENDENCY",
                    file=file, line=0,
                    message=f"Suspicious package: {pkg} — {reason}",
                ))

    def _scan_python_deps(self, req_file: str, report: Dict, scan_path: str):
        declared = set()
        try:
            with open(req_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    report["total_deps"] += 1
                    pkg = re.split(r"[>=<!\[]", line)[0].strip()
                    declared.add(pkg.lower())
                    if not re.search(r"[><=!~]=|[><]", line):
                        report["unpinned"].append(pkg)
                    self._check_suspicious_package(pkg, "requirements.txt", report)
        except (OSError, IOError) as e:
            self._add_warning(f"Could not read requirements.txt: {e}")
        return declared

    def _check_phantom_deps_python(self, declared: Set[str], scan_path: str, report: Dict, optional_declared: Optional[Set[str]] = None):
        imported = set()
        for fpath, content in self._file_cache.items():
            if not fpath.endswith(".py") or os.path.basename(fpath) in ("setup.py", "conftest.py"):
                continue
            for line in content.split("\n"):
                m = re.match(r"^\s*(?:import|from)\s+(\w+)", line)
                if m:
                    imported.add(m.group(1).lower())
                m2 = re.search(r"importlib\.import_module\s*\(\s*['\"](\w+)", line)
                if m2:
                    imported.add(m2.group(1).lower())
                m3 = re.search(r"__import__\s*\(\s*['\"](\w+)", line)
                if m3:
                    imported.add(m3.group(1).lower())

        pkg_to_import = {
            "pillow": "pil", "scikit-learn": "sklearn", "python-dateutil": "dateutil",
            "pyyaml": "yaml", "beautifulsoup4": "bs4", "opencv-python": "cv2",
            "opencv-python-headless": "cv2", "python-dotenv": "dotenv",
            "pymysql": "pymysql", "python-multipart": "multipart",
            "python-jose": "jose", "python-decouple": "decouple",
            "python-magic": "magic", "python-slugify": "slugify",
            "msgpack-python": "msgpack", "ruamel.yaml": "ruamel",
            "attrs": "attr", "cattrs": "cattr",
            "google-cloud-storage": "google", "google-cloud-bigquery": "google",
            "google-auth": "google", "google-api-python-client": "googleapiclient",
            "tensorflow-gpu": "tensorflow", "tensorflow-cpu": "tensorflow",
        }
        dev_tools = {"setuptools", "wheel", "pip", "build", "twine", "pytest",
                     "black", "flake8", "mypy", "isort", "pylint", "pre-commit",
                     "coverage", "tox", "sphinx", "nox", "ruff",
                     "setuptools-scm", "flit", "flit-core", "hatch", "hatchling",
                     "maturin", "cython", "poetry", "poetry-core", "pdm", "pdm-backend"}
        dev_tools |= optional_declared or set()

        for pkg in declared:
            import_name = pkg_to_import.get(pkg, pkg.replace("-", "_").replace(".", "_"))
            if import_name not in imported and pkg not in imported and pkg not in dev_tools:
                report["phantom_deps"].append(pkg)

        for pkg in report["phantom_deps"][:10]:
            self._add_finding(Finding(
                severity="MEDIUM", category="DEPENDENCY",
                file="requirements.txt", line=0,
                message=f"Phantom dependency: '{pkg}' declared but never imported",
            ))

    def _scan_pyproject_deps(self, pyproject: str, report: Dict):
        declared = set()
        optional = set()
        scan_path = os.path.dirname(pyproject)

        parsed = False
        if tomllib:
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                # PEP 621: [project] dependencies
                for dep in data.get("project", {}).get("dependencies", []):
                    pkg = re.split(r"[>=<!\[;\s]", dep)[0].strip()
                    if pkg:
                        declared.add(pkg.lower())
                        report["total_deps"] += 1
                        self._check_suspicious_package(pkg, "pyproject.toml", report)
                # PEP 621: [project.optional-dependencies] (e.g. dev = ["pip-audit"])
                # Track separately — CLI-only optional tools are never imported
                for group_deps in data.get("project", {}).get("optional-dependencies", {}).values():
                    if isinstance(group_deps, list):
                        for dep in group_deps:
                            pkg = re.split(r"[>=<!\[;\s]", dep)[0].strip()
                            if pkg:
                                optional.add(pkg.lower())
                                report["total_deps"] += 1
                                self._check_suspicious_package(pkg, "pyproject.toml", report)
                # Poetry: [tool.poetry.dependencies]
                for pkg in data.get("tool", {}).get("poetry", {}).get("dependencies", {}):
                    if pkg.lower() != "python":
                        declared.add(pkg.lower())
                        report["total_deps"] += 1
                        self._check_suspicious_package(pkg, "pyproject.toml", report)
                parsed = True
            except (OSError, ValueError, KeyError) as e:
                self._add_warning(f"Could not parse pyproject.toml: {e}")

        if not parsed:
            # Fallback: regex parsing for Python 3.9-3.10 or malformed TOML
            try:
                with open(pyproject, "r") as f:
                    content = f.read()
                in_deps = False
                in_optional = False
                for line in content.split("\n"):
                    # [project.optional-dependencies] contains group names, not packages
                    if re.match(r"\[project\.optional-dependencies\]", line, re.IGNORECASE):
                        in_optional = True
                        in_deps = False
                        continue
                    if re.match(r"\[.*dependencies.*\]", line, re.IGNORECASE):
                        in_deps = True
                        in_optional = False
                        continue
                    if (in_deps or in_optional) and line.startswith("["):
                        in_deps = False
                        in_optional = False
                        continue
                    # In optional-deps, parse the list values (e.g. dev = ["pip-audit"])
                    if in_optional and "=" in line:
                        for m in re.finditer(r'"([^"]+)"', line):
                            pkg = re.split(r"[>=<!\[;\s]", m.group(1))[0].strip()
                            if pkg:
                                optional.add(pkg.lower())
                                report["total_deps"] += 1
                                self._check_suspicious_package(pkg, "pyproject.toml", report)
                        continue
                    if in_deps and ("=" in line or line.strip().startswith('"')):
                        report["total_deps"] += 1
                        pkg = re.split(r"[>=<!\[]", line.strip().strip('"').strip(","))[0].strip()
                        if pkg:
                            declared.add(pkg.lower())
                            self._check_suspicious_package(pkg, "pyproject.toml", report)
            except (OSError, IOError) as e:
                self._add_warning(f"Could not read pyproject.toml: {e}")

        return declared, optional

    def _scan_js_deps(self, pkg_json: str, path: str, report: Dict):
        try:
            with open(pkg_json, "r") as f:
                pkg = json.load(f)

            all_deps = {}
            all_deps.update(pkg.get("dependencies", {}))
            all_deps.update(pkg.get("devDependencies", {}))
            report["total_deps"] = len(all_deps)

            for name, version in all_deps.items():
                if version.startswith(("^", "~")) or version in ("*", "latest"):
                    report["unpinned"].append(name)
                for sus, reason in SUSPICIOUS_PACKAGES_JS.items():
                    if name.lower() == sus.lower():
                        report["suspicious_packages"].append({"name": name, "reason": reason})
                        self._add_finding(Finding(
                            severity="CRITICAL", category="DEPENDENCY",
                            file="package.json", line=0,
                            message=f"Suspicious package: {name} — {reason}",
                        ))

            scripts = pkg.get("scripts", {})
            for sname, scmd in scripts.items():
                if sname in ("preinstall", "postinstall", "preuninstall", "install", "prepare", "prepack"):
                    danger = ["curl", "wget", "eval", "base64", "nc ", "/dev/tcp",
                              "python", "node -e", "powershell", "cmd /c"]
                    if any(d in scmd for d in danger):
                        self._add_finding(Finding(
                            severity="CRITICAL", category="EXECUTION",
                            file="package.json", line=0,
                            message=f"Dangerous {sname} script — may execute malicious code on install",
                            snippet=scmd[:120],
                        ))
                    else:
                        self._add_finding(Finding(
                            severity="MEDIUM", category="EXECUTION",
                            file="package.json", line=0,
                            message=f"Package has {sname} script — runs automatically on npm install",
                            snippet=scmd[:120],
                        ))

            self._check_phantom_deps_js(pkg, path, report)
        except (OSError, json.JSONDecodeError) as e:
            self._add_warning(f"Could not parse package.json: {e}")

    def _check_phantom_deps_js(self, pkg: Dict, path: str, report: Dict):
        deps = set(pkg.get("dependencies", {}).keys())
        if not deps:
            return
        js_exts = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
        imported = set()
        for fpath, content in self._file_cache.items():
            if not any(fpath.endswith(ext) for ext in js_exts):
                continue
            for line in content.split("\n"):
                m = re.search(r"""(?:require\s*\(\s*['"]|from\s+['"])(@?[a-z0-9][\w\-.]*(?:/[a-z0-9][\w\-.]*)?)""", line)
                if m:
                    imported.add(m.group(1).split("/")[0])
                m2 = re.search(r"""import\s*\(\s*['"]([@\w\-./]+)""", line)
                if m2:
                    imported.add(m2.group(1).split("/")[0])

        build_deps = {"typescript", "webpack", "vite", "rollup", "esbuild", "parcel",
                      "eslint", "prettier", "jest", "mocha", "vitest", "tsx", "ts-node",
                      "@types", "tailwindcss", "postcss", "autoprefixer", "nodemon",
                      "husky", "lint-staged", "commitlint", "@commitlint",
                      "semantic-release", "release-it", "turbo", "lerna", "nx"}
        for dep in deps:
            base = dep.split("/")[0]
            if base not in imported and dep not in imported and base not in build_deps and not base.startswith("@types"):
                report["phantom_deps"].append(dep)

        for dep in report["phantom_deps"][:10]:
            self._add_finding(Finding(
                severity="MEDIUM", category="DEPENDENCY",
                file="package.json", line=0,
                message=f"Phantom dependency: '{dep}' declared but never imported",
            ))

    def _check_lockfile_integrity(self, path: str, report: Dict):
        lock_file = os.path.join(path, "package-lock.json")
        if not os.path.exists(lock_file):
            return
        try:
            with open(os.path.join(path, "package.json")) as f:
                pkg = json.load(f)
            with open(lock_file) as f:
                lock = json.load(f)
            lock_pkgs = lock.get("packages", lock.get("dependencies", {}))
            for name, spec in pkg.get("dependencies", {}).items():
                entry = lock_pkgs.get(f"node_modules/{name}", lock_pkgs.get(name, {}))
                if isinstance(entry, dict):
                    locked = entry.get("version", "")
                    if locked:
                        drift = False
                        if spec.startswith("^"):
                            # Caret: when major is 0, minor must also match
                            # (^0.x.y means >=0.x.y <0.(x+1).0, not <1.0.0)
                            spec_parts = spec.lstrip("^").split(".")
                            locked_parts = locked.split(".")
                            if spec_parts[0] == "0":
                                drift = len(spec_parts) >= 2 and len(locked_parts) >= 2 and spec_parts[:2] != locked_parts[:2]
                            else:
                                drift = spec_parts[0] != locked_parts[0]
                        elif spec.startswith("~"):
                            # Tilde: major.minor must match
                            sp = spec[1:].split(".")
                            lp = locked.split(".")
                            drift = sp[:2] != lp[:2]
                        if drift:
                            report["lockfile_issues"].append({"package": name, "declared": spec, "locked": locked})
                            self._add_finding(Finding(
                                severity="HIGH", category="DEPENDENCY",
                                file="package-lock.json", line=0,
                                message=f"Lockfile drift: {name} declared {spec} but locked at {locked}",
                            ))
        except (OSError, json.JSONDecodeError) as e:
            self._add_warning(f"Could not check lockfile integrity: {e}")

    def _scan_go_deps(self, go_mod: str, report: Dict):
        """Parse go.mod for dependency info and run govulncheck if available."""
        try:
            with open(go_mod, "r") as f:
                content = f.read()
            in_require = False
            for line in content.split("\n"):
                stripped = line.strip()
                if stripped.startswith("require ("):
                    in_require = True
                    continue
                if in_require and stripped == ")":
                    in_require = False
                    continue
                if in_require and stripped:
                    parts = stripped.split()
                    if len(parts) >= 2:
                        report["total_deps"] += 1
                elif stripped.startswith("require "):
                    report["total_deps"] += 1
        except (OSError, IOError) as e:
            self._add_warning(f"Could not read go.mod: {e}")
        # Try govulncheck if available
        scan_path = os.path.dirname(go_mod)
        govulncheck_bin = self._resolve_binary("govulncheck")
        if not govulncheck_bin:
            return
        try:
            result = subprocess.run(
                [govulncheck_bin, "-json", "./..."],
                capture_output=True, text=True, timeout=60, cwd=scan_path
            )
            if result.stdout:
                try:
                    for line in result.stdout.strip().split("\n"):
                        entry = json.loads(line)
                        vuln = entry.get("vulnerability")
                        if vuln:
                            report["audit_findings"].append({"package": vuln.get("module", "?"), "severity": "high", "description": vuln.get("id", "")})
                            self._add_finding(Finding(
                                severity="HIGH", category="DEPENDENCY",
                                file="go.mod", line=0,
                                message=f"Go vulnerability: {vuln.get('id', '?')} in {vuln.get('module', '?')}",
                            ))
                except (json.JSONDecodeError, KeyError):
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _scan_cargo_deps(self, cargo_toml: str, report: Dict):
        """Parse Cargo.toml for dependency info and run cargo audit if available."""
        try:
            with open(cargo_toml, "r") as f:
                content = f.read()
            in_deps = False
            for line in content.split("\n"):
                stripped = line.strip()
                if re.match(r"\[(?:dev-)?dependencies", stripped):
                    in_deps = True
                    continue
                if in_deps and stripped.startswith("["):
                    in_deps = False
                    continue
                if in_deps and "=" in stripped and not stripped.startswith("#"):
                    report["total_deps"] += 1
        except (OSError, IOError) as e:
            self._add_warning(f"Could not read Cargo.toml: {e}")
        # Try cargo audit if available
        scan_path = os.path.dirname(cargo_toml)
        cargo_bin = self._resolve_binary("cargo")
        if not cargo_bin:
            return
        try:
            result = subprocess.run(
                [cargo_bin, "audit", "--json"],
                capture_output=True, text=True, timeout=60, cwd=scan_path
            )
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for vuln in data.get("vulnerabilities", {}).get("list", []):
                        advisory = vuln.get("advisory", {})
                        report["audit_findings"].append({"package": advisory.get("package", "?"), "severity": "high", "description": advisory.get("title", "")})
                        self._add_finding(Finding(
                            severity="HIGH", category="DEPENDENCY",
                            file="Cargo.toml", line=0,
                            message=f"Rust vulnerability: {advisory.get('id', '?')} in {advisory.get('package', '?')}",
                        ))
                except (json.JSONDecodeError, KeyError):
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _run_pip_audit(self, path: str, report: Dict):
        req = os.path.join(path, "requirements.txt")
        if not os.path.exists(req):
            return
        pip_audit_bin = self._resolve_binary("pip-audit")
        if not pip_audit_bin:
            if self._osv_python(path, report):
                return
            self._add_warning("pip-audit not installed — CVE scanning skipped. Install with: pip install pip-audit")
            return
        try:
            result = subprocess.run([pip_audit_bin, "--format", "json", "-r", req],
                                    capture_output=True, text=True, timeout=30)
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for dep in data.get("dependencies", []):
                        for vuln in dep.get("vulns", []):
                            pkg = dep.get("name", "?")
                            vid = vuln.get("id", "?")
                            desc = vuln.get("description", "")[:200]
                            report["audit_findings"].append({
                                "package": pkg, "severity": "high",
                                "description": f"{vid}: {desc}",
                            })
                            self._add_finding(Finding(
                                severity="HIGH", category="DEPENDENCY",
                                file="requirements.txt", line=0,
                                message=f"CVE in {pkg}: {vid} — {desc[:100]}",
                            ))
                except (json.JSONDecodeError, KeyError):
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _run_npm_audit(self, path: str, report: Dict):
        if not os.path.exists(os.path.join(path, "package-lock.json")):
            return
        npm_bin = self._resolve_binary("npm")
        if not npm_bin:
            if self._osv_npm(path, report):
                return
            self._add_warning("npm not found — CVE scanning skipped")
            return
        try:
            result = subprocess.run([npm_bin, "audit", "--json", "--omit=dev"], capture_output=True, text=True, timeout=30, cwd=path)
            if result.stdout:
                for name, info in json.loads(result.stdout).get("vulnerabilities", {}).items():
                    sev = info.get("severity", "low")
                    report["audit_findings"].append({"package": name, "severity": sev, "description": info.get("title", "")})
                    if sev in ("critical", "high"):
                        self._add_finding(Finding(
                            severity="HIGH", category="DEPENDENCY",
                            file="package.json", line=0,
                            message=f"npm audit: {name} — {info.get('title', sev)}",
                        ))
        except FileNotFoundError:
            if self._osv_npm(path, report):
                return
            self._add_warning("WARNING: npm not available — CVE scanning skipped. Install Node.js")
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass

    # ------------------------------------------------------------------
    # Intra-function taint analysis (Python)
    # ------------------------------------------------------------------

    def _scan_taint(self, cats: CategorizedFiles):
        """Follow untrusted input from source to dangerous sink within a single
        Python function. Catches data-flow risks regex/AST cannot see."""
        if self.no_taint:
            return
        try:
            from gatekeeper_scanner import taint
        except ImportError:
            return
        for fpath, rel_path, ext in cats.source_files:
            if ext != ".py":
                continue
            content = self._read_file(fpath)
            if content is None:
                continue
            for t in taint.analyze(rel_path, content):
                self._add_finding(Finding(
                    severity=t["severity"], category="TAINT",
                    file=rel_path, line=t["line"], message=t["message"],
                    snippet="", cwe=t["cwe"],
                ))

    # ------------------------------------------------------------------
    # YARA signature engine (optional — requires yara-python)
    # ------------------------------------------------------------------

    def _scan_yara(self, cats: CategorizedFiles):
        """Match authored YARA signatures over text + binary files. Catches
        known-bad content (webshells, reverse shells, miners, droppers) that
        pattern/AST matching misses. Optional: skipped if yara-python absent."""
        if self.no_yara:
            return
        try:
            from gatekeeper_scanner import yara_engine
        except ImportError:
            return
        if not yara_engine.available():
            self._add_warning(
                "YARA signature scan skipped — yara-python not installed "
                "(pip install yara-python enables webshell/miner/dropper signatures).")
            return
        rules, err = yara_engine.compile_rules()
        if rules is None:
            if err:
                self._add_warning(f"YARA signature scan skipped — {err}")
            return

        seen_paths = set()
        targets = []
        for fp, rp, _ext in cats.all_text_files:
            if fp not in seen_paths:
                seen_paths.add(fp)
                targets.append((fp, rp))
        for fp, rp in cats.binary_files:
            if fp not in seen_paths:
                seen_paths.add(fp)
                targets.append((fp, rp))

        valid_sev = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for fp, rp in targets:
            # Signature/rule files self-match by design — never scan them.
            if rp.lower().endswith((".yar", ".yara", ".sigma")):
                continue
            try:
                with open(fp, "rb") as fh:
                    data = fh.read(yara_engine.MAX_SCAN_BYTES)
            except (OSError, IOError):
                continue
            for m in yara_engine.scan_bytes(rules, data):
                sev = m["severity"] if m["severity"] in valid_sev else "HIGH"
                self._add_finding(Finding(
                    severity=sev, category="SIGNATURE", file=rp, line=0,
                    message=f"YARA signature: {m['description']} [{m['rule']}]",
                    snippet="", cwe="CWE-506",
                ))

    # ------------------------------------------------------------------
    # OSV.dev fallback — network CVE lookups when audit binaries are absent
    # ------------------------------------------------------------------

    def _osv_enabled(self) -> bool:
        """OSV is a network fallback; disabled by --no-osv and by offline mode."""
        return not self.no_osv and not self.skip_deps

    def _emit_osv_findings(self, results, file_label: str, report: Dict) -> bool:
        """Turn osv.audit_packages results into Findings. Returns True if OSV
        ran (regardless of whether vulns were found), so callers can suppress
        the 'binary not installed' warning."""
        for r in results:
            ident = r["cve"] or r["id"]
            desc = r["summary"] or "no description"
            report["audit_findings"].append({
                "package": r["package"], "severity": r["severity"].lower(),
                "description": f"{ident}: {desc}",
            })
            self._add_finding(Finding(
                severity=r["severity"], category="DEPENDENCY",
                file=file_label, line=0,
                message=f"CVE in {r['package']} {r['version']}: {ident} — {desc[:100]} (via OSV.dev)",
            ))
        return True

    def _osv_python(self, path: str, report: Dict) -> bool:
        if not self._osv_enabled():
            return False
        req = os.path.join(path, "requirements.txt")
        if not os.path.exists(req):
            return False
        packages = []
        try:
            with open(req, "r") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if not line or line.startswith("-"):
                        continue
                    m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!-]+)", line)
                    if m:
                        packages.append({"name": m.group(1), "version": m.group(2)})
        except (OSError, IOError):
            return False
        if not packages:
            return False
        try:
            from gatekeeper_scanner.osv import audit_packages
        except ImportError:
            return False
        results, warning = audit_packages(packages, "PyPI")
        if warning:
            self._add_warning(warning)
            return False
        self._add_warning("pip-audit not installed — used OSV.dev for CVE lookup (pinned packages only)")
        return self._emit_osv_findings(results, "requirements.txt", report)

    def _osv_npm(self, path: str, report: Dict) -> bool:
        if not self._osv_enabled():
            return False
        lock = os.path.join(path, "package-lock.json")
        if not os.path.exists(lock):
            return False
        packages = []
        try:
            with open(lock, "r") as f:
                data = json.load(f)
        except (OSError, IOError, json.JSONDecodeError):
            return False
        # lockfileVersion 2/3: "packages" keyed by "node_modules/<name>"
        for key, meta in (data.get("packages") or {}).items():
            if not key or not isinstance(meta, dict):
                continue
            name = key.split("node_modules/")[-1]
            ver = meta.get("version")
            if name and ver:
                packages.append({"name": name, "version": ver})
        # lockfileVersion 1: "dependencies" keyed by name
        if not packages:
            for name, meta in (data.get("dependencies") or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    packages.append({"name": name, "version": meta["version"]})
        if not packages:
            return False
        try:
            from gatekeeper_scanner.osv import audit_packages
        except ImportError:
            return False
        results, warning = audit_packages(packages, "npm")
        if warning:
            self._add_warning(warning)
            return False
        self._add_warning("npm not available — used OSV.dev for CVE lookup")
        return self._emit_osv_findings(results, "package.json", report)

    # ------------------------------------------------------------------
    # License checking
    # ------------------------------------------------------------------

    def _check_licenses(self, path: str):
        license_files = []
        try:
            for fname in os.listdir(path):
                if fname.upper().startswith(("LICENSE", "LICENCE")) or fname.upper() == "COPYING":
                    license_files.append(fname)
        except OSError:
            return

        if not license_files:
            has_field = False
            for check_file, key in [("package.json", "license"), ("pyproject.toml", None)]:
                fp = os.path.join(path, check_file)
                if os.path.exists(fp):
                    try:
                        with open(fp) as f:
                            content = f.read()
                        if key:
                            has_field = bool(json.loads(content).get(key))
                        else:
                            has_field = "license" in content.lower()
                    except Exception:
                        pass
            if not has_field:
                self._add_finding(Finding(severity="MEDIUM", category="LICENSE", file="", line=0, message="No license file found — usage rights unclear"))

        for lf in license_files:
            try:
                with open(os.path.join(path, lf), "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(2000).upper()
                if "AGPL" in content or "AFFERO" in content:
                    self._add_finding(Finding(severity="MEDIUM", category="LICENSE", file=lf, line=0, message="AGPL license — requires source disclosure for network use"))
                elif "GPL" in content and "LGPL" not in content:
                    self._add_finding(Finding(severity="LOW", category="LICENSE", file=lf, line=0, message="GPL license — copyleft, check compatibility"))
            except Exception:
                pass

    def _check_mcp_scan(self) -> bool:
        mcp_bin = self._resolve_binary("mcp-scan")
        if not mcp_bin:
            return False
        try:
            return subprocess.run([mcp_bin, "--version"], capture_output=True, text=True, timeout=5).returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    # ==================================================================
    # PHASE 3: VERIFICATION PASS
    # ==================================================================

    def _dismiss(self, f: 'Finding', source: str, reason: str = ""):
        f.verified = False
        f.suppression_source = source
        f.suppression_reason = reason or source

    def _verify_findings(self):
        """Second pass: contextually validate each raw finding.

        This is what separates this scanner from pattern-matchers.
        We flag everything, then verify whether it's actually dangerous.
        """
        seen = set()  # (file, line, category) for deduplication

        for f in self.findings:
            self._verify_scanner_self_detection(f)
            if not f.verified:
                continue
            self._verify_git_history_self_detection(f)
            if not f.verified:
                continue
            self._verify_globals_false_positives(f)
            if not f.verified:
                continue
            self._verify_eval_false_positives(f)
            if not f.verified:
                continue
            self._verify_makefile_eval(f)
            if not f.verified:
                continue
            self._verify_getattr_false_positives(f)
            if not f.verified:
                continue
            self._verify_compile_false_positives(f)
            if not f.verified:
                continue
            self._apply_project_suppressions(f)
            if not f.verified:
                continue
            ctx = self._classify_file_context(f)
            self._apply_context_downgrade(f, ctx)
            if not f.verified:
                continue
            self._deduplicate(f, seen)
            if not f.verified:
                continue
            # INFO findings: dismiss unless verbose mode
            if f.severity == "INFO" and not self.verbose:
                self._dismiss(f, "info_severity", "INFO findings dismissed as noise")
                continue

        self._apply_frequency_downgrade()
        self._apply_per_file_cap()
        self._apply_cross_detector_dedup()

    def _verify_scanner_self_detection(self, f):
        """Suppress findings in scanner source files (rule definitions, not vulnerabilities)."""
        if f.file.endswith(("gatekeeper.py", "scanner.py", "rules.py", "patterns.py", "ast_scanner.py", "reporter.py", "core.py", "models.py", "yara_engine.py", "taint.py", "osv.py")):
            if f.category == "SIGNATURE":
                self._dismiss(f, "pattern_definition", "Signature string in scanner's own rule/pattern definitions, not a real payload")
                return
            # Detector logic: a dangerous-API name appearing INSIDE a string
            # literal (sink label or name comparison, e.g. "yaml.load()",
            # chain == "__import__") is a definition, not a call. Real calls have
            # no leading quote before the token, so they are not dismissed here.
            if f.snippet and re.search(
                    r"""['"][^'"]*(?:eval|exec|__import__|yaml\.load|pickle|marshal|subprocess|os\.system|os\.popen|compile|importlib|import_module)\b""",
                    f.snippet):
                self._dismiss(f, "detector_logic", "Dangerous API name inside a string literal in scanner detector code, not a call")
                return
            if f.snippet and re.search(r'"(?:EXECUTION|INJECTION|FILESYSTEM|NETWORK|PERMISSION|OBFUSCATION|SECRET|MCP|DEPENDENCY|LICENSE)"', f.snippet):
                self._dismiss(f, "pattern_definition", "Rule definition line, not actual vulnerability")
                return
            if f.snippet and f.snippet.lstrip().startswith(('"', "'")):
                self._dismiss(f, "pattern_definition", "Scanner message string, not actual vulnerability")
                return
            if f.snippet and ("self._dismiss" in f.snippet or "self._add" in f.snippet):
                self._dismiss(f, "suppression_logic", "Scanner internal logic referencing pattern names")
                return

    def _verify_git_history_self_detection(self, f):
        """Dismiss git history findings when scanning a repo that contains scanner pattern files.
        The scanner's own secret detection patterns (regex strings like 'sk_live_...')
        appear in core.py and patterns.py — git -G matches them as 'secrets in history'
        but they're pattern definitions, not leaked credentials."""
        if f.file == ".git/history" and f.category == "SECRET":
            # Check if any scanner source files exist in the current findings set
            scanner_files = {"patterns.py", "core.py", "ast_scanner.py", "reporter.py", "models.py"}
            if any(any(sf.endswith(name) for name in scanner_files) for sf in
                   {ff.file for ff in self.findings if ff.file}):
                self._dismiss(f, "scanner_self_detection",
                             "Git history contains scanner pattern definitions (regex strings), not leaked credentials")

    def _verify_globals_false_positives(self, f):
        """Dismiss globals()/locals() in __init__.py, import aliasing, dispatch tables."""
        if "globals()" in f.message or "locals()" in f.message:
            if f.file.endswith("__init__.py") or (f.snippet and "__getattr__" in f.snippet):
                self._dismiss(f, "lazy_import", "globals()/locals() in __init__.py is a Python lazy-import convention")
                return
            if f.snippet and re.search(r"(?:locals|globals)\s*\(\s*\)\s*\[.*\]\s*=\s*__import__", f.snippet):
                self._dismiss(f, "import_alias", "Import aliasing via locals/globals — package compatibility pattern")
                return
            if f.snippet and re.search(r"(?:locals|globals)\s*\(\s*\)\s*(?:\[|\.get\s*\()", f.snippet):
                if any(kw in f.file.lower() for kw in ("parser", "dispatch", "registry", "router", "handler", "command", "cli")):
                    self._dismiss(f, "dispatch_table", "globals()/locals() lookup in parser/dispatch code — standard pattern")
                    return

    def _verify_eval_false_positives(self, f):
        """Dismiss eval() string comparisons, method definitions, constant evals, method calls."""
        if f.message == "eval() — executes arbitrary code" and f.snippet:
            if re.search(r"""(?:==|!=|in)\s*['"].*eval\s*\(""", f.snippet):
                self._dismiss(f, "string_comparison", "String comparison containing 'eval()', not a call to eval()")
                return
            if re.search(r'\bdef\s+eval\s*\(', f.snippet):
                self._dismiss(f, "method_definition", "Method definition named eval(), not a call to eval()")
                return
            if re.search(r"""eval\s*\(\s*['"][A-Za-z_][A-Za-z0-9_]*['"]\s*\)""", f.snippet):
                self._dismiss(f, "constant_eval", "eval() with constant identifier string — introspection, not injection risk")
                return
            if re.search(r"\.\s*eval\s*\(", f.snippet):
                self._dismiss(f, "method_call", "Method .eval() call (e.g. model.eval()), not Python eval()")
                return

    def _verify_makefile_eval(self, f):
        """Dismiss $(eval) in Makefiles — Make syntax, not shell eval."""
        if "Makefile: eval" in f.message and f.snippet and re.search(r'\$\(\s*eval\b', f.snippet):
            self._dismiss(f, "make_eval", "$(eval) is Make syntax for variable assignment, not shell eval")

    def _verify_getattr_false_positives(self, f):
        """Dismiss getattr(os/sys, "constant", default) — platform compatibility, not evasion."""
        if "getattr()" in f.message and f.snippet:
            # getattr(os, "O_BINARY", 0) or getattr(sys, "frozen", False) with a default value
            # = reading a platform constant with fallback. Not dynamic dispatch evasion.
            if re.search(r"""getattr\s*\(\s*(?:os|sys)\s*,\s*['"][A-Za-z_]+['"]\s*,""", f.snippet):
                self._dismiss(f, "platform_compat", "getattr() reading a platform constant with default — compatibility pattern, not evasion")

    def _verify_compile_false_positives(self, f):
        """Dismiss compile() called on safe modules or as a method call."""
        if "compile()" in f.message and f.snippet:
            if re.search(r"(?:re|ast|template|sass|less|babel|webpack|typescript|coffee)\.", f.snippet, re.IGNORECASE):
                self._dismiss(f, "safe_caller", "compile() called on safe module")
                return
            if re.search(r"\w+\.compile\s*\(", f.snippet):
                self._dismiss(f, "safe_caller", "Method compile() on object, not builtin")
                return

    def _apply_project_suppressions(self, f):
        """Apply project config (.gatekeeper.json) suppressions."""
        if self._project_suppress:
            for sup in self._project_suppress:
                if f.rule_id == sup.get("rule") and any(fnmatch.fnmatch(f.file, fp) for fp in sup.get("files", [])):
                    expires = sup.get("expires", "")
                    if expires:
                        try:
                            if datetime.strptime(expires, "%Y-%m-%d").date() < datetime.now().date():
                                continue  # Suppression expired
                        except ValueError:
                            pass  # Malformed date — treat as no expiry
                    self._dismiss(f, "config_suppress", sup.get("reason", "Project config suppression"))
                    break

    def _classify_file_context(self, f):
        """Classify file by path context: test, example, docs, vendor, devtool, etc."""
        fl = f.file.lower().replace("\\", "/")
        _parts = fl.split("/")
        _dirs = set(_parts[:-1]) if len(_parts) > 1 else set()
        _fname = _parts[-1] if _parts else ""

        _TEST_DIRS = {"test", "tests", "t", "spec", "specs", "fixture", "fixtures",
                      "mock", "mocks", "__tests__", "__test__", "testdata", "test_data"}
        is_test = (
            bool(_dirs & _TEST_DIRS)
            or _fname.startswith("test_")
            or bool(re.search(r'[._](?:test|spec)\.', _fname))
            or _fname == "conftest.py"
        )

        _EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos",
                         "tutorial", "tutorials", "cookbook", "cookbooks", "evaluation",
                         "evaluations", "capabilities", "recipes", "notebooks", "snippets",
                         "playground", "playgrounds", "sandbox", "sandboxes", "workshop",
                         "workshops", "template", "templates", "scaffold", "scaffolds",
                         "starter", "starters", "boilerplate", "boilerplates"}
        is_example = (
            bool(_dirs & _EXAMPLE_DIRS)
            or any(d.startswith(("example", "sample", "demo", "tutorial"))
                   for d in _dirs)
        )

        _DOCS_DIRS = {"docs", "doc", "guide", "guides", "how-to", "howto"}
        _DOCS_FILES = {"readme.md", "readme.rst", "readme", "readme.txt",
                       "changelog.md", "changelog.rst", "changelog",
                       "contributing.md", "contributing.rst", "contributing",
                       "history.md", "history.rst", "changes.md", "changes.rst",
                       "news.md", "news.rst"}
        is_docs = bool(_dirs & _DOCS_DIRS) or _fname in _DOCS_FILES

        is_template = any(x in fl for x in (".example", ".template", ".sample", ".dist"))
        is_vendor = (fl.startswith(("vendor/", "third_party/", "third-party/", "extern/", "external/"))
                     or "/_vendor/" in fl or "/vendor/" in fl
                     or "/extern/" in fl or "/external/" in fl)
        _DEVTOOL_DIRS = {"scripts", "script", "tools", "build", "dev", "hack", "contrib"}
        is_devtool = (
            bool(_dirs & _DEVTOOL_DIRS)
            or any(x in fl for x in ("makefile", "gruntfile", "gulpfile", "rakefile",
                                      "playgrounds/", "benchmarks/", "bench/"))
        )
        is_infra = bool(_dirs & {".devcontainer", ".github", ".circleci", ".gitlab"})
        is_reference = bool(_dirs & {"references", "reference", "hooks"})
        _RULE_DEF_DIRS = {"rules", "detectors", "signatures", "patterns", "checks",
                           "yara", "sigma", "indicators", "ruleset", "rulesets"}
        _RULE_DEF_FNAMES = {"gitleaks.toml", ".gitleaks.toml"}
        is_rule_definition = (
            bool(_dirs & _RULE_DEF_DIRS)
            or _fname in _RULE_DEF_FNAMES
            or _fname.endswith((".yar", ".yara", ".sigma"))
        )
        is_skill_file = fl.endswith("skill.md")

        return {
            "is_test": is_test, "is_example": is_example, "is_docs": is_docs,
            "is_vendor": is_vendor, "is_devtool": is_devtool, "is_infra": is_infra,
            "is_reference": is_reference, "is_rule_definition": is_rule_definition,
            "is_template": is_template, "is_skill_file": is_skill_file,
            "_fname": _fname,
        }

    def _apply_context_downgrade(self, f, ctx):
        """Apply context-aware severity downgrades and dismissals."""
        is_test = ctx["is_test"]
        is_example = ctx["is_example"]
        is_docs = ctx["is_docs"]
        is_vendor = ctx["is_vendor"]
        is_devtool = ctx["is_devtool"]
        is_infra = ctx["is_infra"]
        is_reference = ctx["is_reference"]
        is_rule_definition = ctx["is_rule_definition"]
        is_template = ctx["is_template"]
        is_skill_file = ctx["is_skill_file"]
        _fname = ctx["_fname"]

        # --- Docs/text files: INJECTION findings in non-source files are references to attack patterns ---
        if f.category == "INJECTION" and "In text file:" in f.message:
            ext_lower = Path(f.file).suffix.lower() if f.file else ""
            if ext_lower not in SOURCE_EXTENSIONS:
                if is_docs or is_example or is_reference:
                    self._dismiss(f, "docs_reference", "Documentation describing attack patterns, not actual injection")
                    return
                # Non-source text files (markdown, notebooks, XML, etc.) get downgraded, not dismissed
                if ext_lower in (".md", ".mdx", ".txt", ".rst", ".html", ".htm", ".ipynb", ".xml"):
                    f.original_severity = f.severity
                    f.severity = "LOW"

        # --- SKILL.md: XML tags are expected syntax, not injection ---
        if is_skill_file and f.category == "INJECTION":
            if f.snippet and re.search(r"</?(?:prompt|system|user|assistant|instruction|human|claude)[\s>]", f.snippet, re.IGNORECASE):
                self._dismiss(f, "skill_syntax", "XML tags are legitimate SKILL.md syntax")
                return
            if "suppression" in f.message.lower():
                self._dismiss(f, "skill_syntax", "Instructional directive in SKILL.md, not injection")
                return

        # --- SECRET verification ---
        if f.category == "SECRET":
            if f.snippet and SECRET_PLACEHOLDERS.search(f.snippet):
                self._dismiss(f, "placeholder", "Value matches placeholder pattern")
                return
            if f.snippet and re.search(r'\$\{\{?\s*secrets\.', f.snippet):
                self._dismiss(f, "ci_secret_ref", "CI/CD secret reference (${{ secrets.* }}), not a hardcoded credential")
                return
            if is_infra and f.snippet and "}}" in f.snippet and "REDACTED" in f.snippet:
                self._dismiss(f, "ci_secret_ref", "CI/CD workflow secret reference (redacted), not a hardcoded credential")
                return
            _url_parser_names = {"url", "urls", "_url", "_urls", "uri", "urlparse", "urllib", "href"}
            if any(_fname.startswith(n + ".") or _fname == n for n in _url_parser_names):
                if "password" in f.message.lower() or "credentials" in f.message.lower() or "auth" in f.message.lower():
                    self._dismiss(f, "url_parser", "URL parser code referencing password/auth as URL spec component, not hardcoded credential")
                    return
            if is_template:
                f.original_severity = f.severity
                f.severity = "LOW"
            if is_test or is_docs:
                f.original_severity = f.severity
                f.severity = "INFO"
            if is_rule_definition:
                f.original_severity = f.severity
                f.severity = "INFO"

        # --- NETWORK: dismiss private/localhost IPs (but NOT socket connections) ---
        if f.category == "NETWORK" and f.snippet and "connect" not in f.message.lower():
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", f.snippet)
            if ip_match and PRIVATE_IP.match(ip_match.group(1)):
                self._dismiss(f, "private_ip", "Private/localhost IP address")
                return

        # --- Test/example file downgrade for non-secret findings ---
        if is_test and f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            f.original_severity = f.severity
            f.severity = "LOW"
        elif is_rule_definition and f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            f.original_severity = f.severity
            f.severity = "LOW"
        elif is_example and f.severity in ("CRITICAL", "HIGH"):
            f.original_severity = f.severity
            f.severity = "MEDIUM"
        elif is_docs and f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
            f.original_severity = f.severity
            f.severity = "LOW"

        # --- Vendor: findings are informational ---
        if is_vendor:
            f.original_severity = f.severity
            f.severity = "LOW"

        # --- Dev/build scripts ---
        if is_devtool and f.severity in ("CRITICAL", "HIGH") and f.category not in ("SECRET",):
            f.original_severity = f.severity
            f.severity = "LOW"
        elif is_devtool and f.severity == "MEDIUM":
            f.original_severity = f.severity
            f.severity = "LOW"

        # --- Infrastructure files ---
        if is_infra and f.severity in ("CRITICAL", "HIGH") and f.category not in ("INJECTION", "SECRET"):
            f.original_severity = f.severity
            f.severity = "MEDIUM"

        # --- Reference/hook files ---
        if is_reference and f.severity in ("CRITICAL", "HIGH"):
            f.original_severity = f.severity
            f.severity = "LOW"

    def _deduplicate(self, f, seen):
        """Deduplicate by file+line+message."""
        key = (f.file, f.line, f.message)
        if key in seen:
            self._dismiss(f, "deduplication")
        else:
            seen.add(key)

    def _apply_frequency_downgrade(self):
        """Downgrade CRITICAL/HIGH findings that appear in 5+ files (architectural patterns).
        Exception: INJECTION and SECRET are never downgraded by frequency."""
        _FREQ_EXEMPT = {"INJECTION", "SECRET"}
        msg_file_count = {}
        for f in self.findings:
            if not f.verified or f.severity not in ("CRITICAL", "HIGH"):
                continue
            if f.category in _FREQ_EXEMPT:
                continue
            msg_file_count.setdefault(f.message, set()).add(f.file)
        for f in self.findings:
            if not f.verified or f.severity not in ("CRITICAL", "HIGH"):
                continue
            if f.category in _FREQ_EXEMPT:
                continue
            if len(msg_file_count.get(f.message, set())) >= 5:
                f.original_severity = f.severity
                f.severity = "MEDIUM"

    def _apply_per_file_cap(self):
        """Cap same (file, message) at 2 occurrences — dismiss the rest."""
        file_msg_count = {}
        for f in self.findings:
            if not f.verified:
                continue
            key = (f.file, f.message)
            file_msg_count[key] = file_msg_count.get(key, 0) + 1
            if file_msg_count[key] > 2:
                self._dismiss(f, "per_file_cap", "Same finding type capped at 2 per file")

    def _apply_cross_detector_dedup(self):
        """When regex + alias detection both flag the same (file, line) in EXECUTION,
        keep only the highest severity."""
        _SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        line_best = {}
        for idx, f in enumerate(self.findings):
            if not f.verified or f.line == 0 or f.category != "EXECUTION":
                continue
            key = (f.file, f.line)
            rank = _SEV_RANK.get(f.severity, 5)
            if key in line_best:
                existing_rank, existing_idx = line_best[key]
                if rank < existing_rank:
                    if self.findings[existing_idx].verified:
                        self._dismiss(self.findings[existing_idx], "cross_detector_dedup",
                                     "Same line flagged by multiple EXECUTION detectors")
                    line_best[key] = (rank, idx)
                else:
                    if f.verified:
                        self._dismiss(f, "cross_detector_dedup",
                                     "Same line flagged by multiple EXECUTION detectors")
            else:
                line_best[key] = (rank, idx)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    # Grade bands: internal score → letter grade
    # A = clean/safe, B = minor concerns, C = review needed, D = serious, F = fail
    GRADE_BANDS = [
        (80, "A"), (65, "B"), (50, "C"), (30, "D"), (0, "F"),
    ]

    def _calculate_score(self, findings: List[Finding], total_lines: int = 0) -> Tuple[int, str]:
        score = 100.0
        severity_weights = self.config.get("severity_weights", {"CRITICAL": 15, "HIGH": 7, "MEDIUM": 3, "LOW": 1, "INFO": 0})

        # Density adjustment: large codebases (50K+ LOC) get reduced weight per finding
        # Small repos (< 1K LOC) get amplified weight — every finding matters more
        density_factor = 1.0
        if total_lines > 50000:
            # Large repo: reduce impact — 100K LOC → 0.7x, 500K LOC → 0.5x
            density_factor = max(0.4, 1.0 - (total_lines - 50000) / 500000)
        elif total_lines > 0 and total_lines < 1000:
            # Tiny repo: amplify impact — dense vulns in small code = worse
            density_factor = min(1.5, 1.0 + (1000 - total_lines) / 2000)

        for f in findings:
            weight = severity_weights.get(f.severity, 0)

            # If verification downgraded this finding, reduce its score impact.
            if f.original_severity:
                if f.severity == "LOW":
                    weight = 0
                elif f.severity == "MEDIUM":
                    weight = max(1, weight // 2)

            # Apply density factor
            weight = weight * density_factor

            # Diminishing returns: each subsequent point costs more
            # This prevents a single category from dominating but doesn't cap it
            effective = weight * (score / 100.0)
            score -= effective

        score = max(0, min(100, int(score)))

        # Hard ceiling based on CRITICAL/HIGH counts (density-adjusted thresholds)
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL" and not f.original_severity)
        high_count = sum(1 for f in findings if f.severity == "HIGH" and not f.original_severity)

        # For large repos (50K+ LOC), raise the ceiling thresholds — more findings expected
        crit_scale = 1
        high_scale = 1
        if total_lines > 50000:
            crit_scale = min(3, max(1, total_lines // 50000))  # 100K LOC → 2x, cap at 3x
            high_scale = crit_scale

        if critical_count >= 10 * crit_scale:
            score = min(score, 10)
        elif critical_count >= 5 * crit_scale:
            score = min(score, 20)
        elif critical_count >= 3 * crit_scale:
            score = min(score, 35)
        elif critical_count >= 2 * crit_scale:
            score = min(score, 45)
        elif critical_count >= 1 * crit_scale:
            score = min(score, 49)

        if high_count >= 15 * high_scale:
            score = min(score, 25)
        elif high_count >= 10 * high_scale:
            score = min(score, 35)
        elif high_count >= 5 * high_scale:
            score = min(score, 50)

        # Score floors — context-aware grading
        # F means "dangerous," not "large codebase with expected patterns."
        #
        # 1. Zero CRITICALs → minimum C. MEDIUM findings alone can't produce F or D.
        # 2. Low critical DENSITY → floor based on proportionality.
        #    A 500K LOC framework with 15 CRITICALs (0.3/10K lines) is fundamentally
        #    different from a 500-line package with 1 CRITICAL (20/10K lines).
        if critical_count == 0:
            if high_count <= 3:
                score = max(score, 65)  # B floor
            elif high_count <= 10:
                score = max(score, 50)  # C floor
            else:
                score = max(score, 40)  # D floor — extreme volume of HIGHs with no CRITICALs
        elif critical_count <= 10 * crit_scale and total_lines > 0:
            # Density floor applies when CRITICAL count is moderate relative to repo size.
            # crit_scale grows with LOC (100K→2x, 150K+→3x), so large repos get proportional allowance.
            crit_density = (critical_count / total_lines) * 10000  # per 10K lines
            if crit_density < 0.5:
                score = max(score, 50)  # C floor — very low density, but still has CRITICALs
            elif crit_density < 1.0:
                score = max(score, 40)  # D floor — low density

        # Absolute rule: any undowngraded CRITICAL → never above C (score < 65 = B threshold)
        # This runs AFTER floors to prevent density floors from overriding CRITICAL ceilings
        if critical_count >= 1:
            score = min(score, 64)

        # Convert to letter grade
        grade = "F"
        bands = self.config.get("grade_bands", self.GRADE_BANDS)
        for threshold, letter in bands:
            if score >= threshold:
                grade = letter
                break

        return score, grade

    def _generate_recommendation(self, report: ScanReport) -> str:
        critical = sum(1 for f in report.findings if f.severity == "CRITICAL")
        high = sum(1 for f in report.findings if f.severity == "HIGH")
        grade = report.grade

        if grade == "A":
            msg = "Clean. Safe to install."
            if high > 0:
                msg += f" Review {high} HIGH finding(s) for awareness."
            return msg
        elif grade == "B":
            return f"Low risk. {critical + high} finding(s) worth reviewing before installing."
        elif grade == "C":
            return f"Review required. {critical} CRITICAL and {high} HIGH finding(s). Check before installing."
        elif grade == "D":
            return f"Significant risks. {critical} CRITICAL and {high} HIGH finding(s). Do NOT install without review."
        return f"FAIL. {critical} CRITICAL and {high} HIGH finding(s). Do NOT install."

    def _detect_tool_type(self, structure: Dict, scan_path: str) -> str:
        """Classify project type based on structure, metadata, and entry points."""
        # MCP server
        if structure.get("has_mcp_config"):
            return "mcp-server"
        # Check package metadata for keywords
        desc = self._extract_description(scan_path).lower()
        keywords = set()
        # Read package.json keywords/bin
        pkg = os.path.join(scan_path, "package.json")
        has_bin = False
        if os.path.exists(pkg):
            try:
                with open(pkg) as f:
                    data = json.load(f)
                keywords.update(k.lower() for k in data.get("keywords", []))
                has_bin = bool(data.get("bin"))
            except Exception:
                pass
        # Read pyproject.toml scripts
        pyp = os.path.join(scan_path, "pyproject.toml")
        if os.path.exists(pyp):
            try:
                content = self._read_file(pyp) or ""
                if "[project.scripts]" in content or "[tool.poetry.scripts]" in content:
                    has_bin = True
            except Exception:
                pass
        # Read setup.py/setup.cfg for console_scripts
        for sf in ("setup.py", "setup.cfg"):
            sp = os.path.join(scan_path, sf)
            if os.path.exists(sp):
                content = self._read_file(sp) or ""
                if "console_scripts" in content:
                    has_bin = True
        # Read Cargo.toml [[bin]]
        cargo = os.path.join(scan_path, "Cargo.toml")
        if os.path.exists(cargo):
            content = self._read_file(cargo) or ""
            if "[[bin]]" in content:
                has_bin = True
        # Security tool detection
        sec_keywords = {"security", "scanner", "vulnerability", "exploit", "pentest",
                        "audit", "scan", "detection", "malware", "forensic", "osint",
                        "reconnaissance", "injection", "fuzzer", "fuzzing", "secret"}
        if keywords & sec_keywords or any(k in desc for k in sec_keywords):
            return "security-tool"
        # Web app / API
        langs = structure.get("languages", {})
        has_web_framework = any(k in desc for k in ("web framework", "web application", "http server",
                                                     "api framework", "rest api", "graphql"))
        if structure.get("has_dockerfile") or has_web_framework:
            if has_web_framework or "web" in desc or "server" in desc:
                if "framework" in desc or "library" in desc:
                    return "framework"
                return "web-app"
        # Framework / library detection
        if "framework" in desc:
            return "framework"
        if any(k in desc for k in ("library", "utility", "helper", "toolkit", "sdk", "client")):
            return "library"
        # CLI tool
        if has_bin or any(k in desc for k in ("cli", "command-line", "command line", "terminal")):
            return "cli-tool"
        # Browser extension
        manifest = os.path.join(scan_path, "manifest.json")
        if os.path.exists(manifest):
            content = self._read_file(manifest) or ""
            if "manifest_version" in content:
                return "browser-extension"
        # Build tool
        if any(k in desc for k in ("build", "bundler", "compiler", "transpiler", "minifier")):
            return "build-tool"
        # Skill/agent
        if structure.get("has_skill_md"):
            return "cli-tool"
        # Fallback: library if it has source, unknown otherwise
        if structure.get("source_files", 0) > 0:
            return "library"
        return "unknown"

    def _extract_description(self, scan_path: str) -> str:
        """Extract tool description from package.json, pyproject.toml, or README."""
        # Try package.json first
        pkg = os.path.join(scan_path, "package.json")
        if os.path.exists(pkg):
            try:
                with open(pkg) as f:
                    data = json.load(f)
                desc = data.get("description", "")
                if desc:
                    return desc[:200]
            except Exception:
                pass
        # Try pyproject.toml
        pyp = os.path.join(scan_path, "pyproject.toml")
        if os.path.exists(pyp):
            try:
                with open(pyp) as f:
                    for line in f:
                        if line.strip().startswith("description"):
                            val = line.split("=", 1)[1].strip().strip('"\'')
                            if val:
                                return val[:200]
            except Exception:
                pass
        # Try first meaningful line of README (skip badges, links, blank lines)
        for readme in ("README.md", "readme.md", "README.rst", "README"):
            rp = os.path.join(scan_path, readme)
            if os.path.exists(rp):
                try:
                    with open(rp, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip().lstrip("#").strip()
                            # Skip empty, badges, images, links-only, HTML tags
                            if not line or len(line) < 15:
                                continue
                            if line.startswith(("![", "[![", "<", ">", "[!", "---", "***", "```")):
                                continue
                            if re.match(r"^\[.*\]\(.*\)$", line):
                                continue
                            return line[:200]
                except Exception:
                    pass
        return ""

    def _build_grade_drivers(self, findings: List[Finding]) -> List[str]:
        """Build human-readable list of what drove the grade."""
        drivers = []
        by_cat = {}
        for f in findings:
            if f.severity in ("CRITICAL", "HIGH"):
                by_cat.setdefault(f.category, []).append(f)
        for cat, items in sorted(by_cat.items(), key=lambda x: -len(x[1])):
            crit = sum(1 for f in items if f.severity == "CRITICAL")
            high = sum(1 for f in items if f.severity == "HIGH")
            parts = []
            if crit:
                parts.append(f"{crit} CRITICAL")
            if high:
                parts.append(f"{high} HIGH")
            # Get unique message types
            types = list(dict.fromkeys(f.message.split("—")[0].strip()[:50] for f in items))[:2]
            drivers.append(f"{cat}: {', '.join(parts)} ({', '.join(types)})")
        return drivers


# ============================================================================
# CLI
# ============================================================================


def _evaluate_policy(findings: List[Finding], policy_str: str) -> bool:
    """Evaluate a policy string against findings. Returns True if policy passes."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if not f.original_severity:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    for rule in policy_str.split(","):
        rule = rule.strip()
        m = re.match(r"(critical|high|medium|low)\s*(<=?|>=?|==?)\s*(\d+)", rule, re.IGNORECASE)
        if not m:
            continue
        sev, op, threshold = m.group(1).upper(), m.group(2), int(m.group(3))
        if op == "==":
            op = "="
        actual = counts.get(sev, 0)
        if op == "=" and actual != threshold: return False
        elif op == "<=" and actual > threshold: return False
        elif op == "<" and actual >= threshold: return False
        elif op == ">=" and actual < threshold: return False
        elif op == ">" and actual <= threshold: return False
    return True


# Optional add-ons that unlock extra checks. Gatekeeper runs fully without them.
# import: the importable module name. pkg: the pip package to install.
OPTIONAL_DEPS = [
    {
        "pkg": "yara-python",
        "import": "yara",
        "reason": "signature scanning that catches known webshells, crypto miners, "
                  "reverse shells, and malware droppers by their fingerprint",
    },
]


def _missing_optional_deps():
    """Return the OPTIONAL_DEPS entries whose module is not importable."""
    return [d for d in OPTIONAL_DEPS if importlib.util.find_spec(d["import"]) is None]


def _prompt_optional_deps(args):
    """First-run, terminal-only offer to install optional add-ons.

    Stays silent unless a human is at a real TTY and output is human-facing
    (not --json/--sarif/--quiet). Never blocks piped/automated runs. Asks once
    per package: the choice is remembered in ~/.gatekeeper/deps-prompted.json,
    so a newly added optional dep prompts once and prior answers are kept."""
    if args.json or args.sarif or args.quiet:
        return
    if os.environ.get("GATEKEEPER_NO_PROMPT"):
        return
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return
    except (ValueError, AttributeError):
        return

    missing = _missing_optional_deps()
    if not missing:
        return

    marker_dir = os.path.expanduser("~/.gatekeeper")
    marker = os.path.join(marker_dir, "deps-prompted.json")
    prompted = set()
    try:
        with open(marker) as f:
            prompted = set(json.load(f))
    except (OSError, json.JSONDecodeError, ValueError):
        pass

    fresh = [d for d in missing if d["pkg"] not in prompted]
    if not fresh:
        return

    print()
    if len(fresh) == 1:
        d = fresh[0]
        print("  Gatekeeper works with zero dependencies. There is one optional add-on we recommend:")
        print(f"    {d['pkg']} — {d['reason']}.")
        print("  Without it, every other check still runs.")
    else:
        print("  Gatekeeper works with zero dependencies. A few optional add-ons would extend it:")
        for d in fresh:
            print(f"    {d['pkg']} — {d['reason']}.")
        print("  Without them, every other check still runs.")

    pkgs = [d["pkg"] for d in fresh]
    try:
        answer = input("  Install now with pip? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"

    if answer in ("y", "yes"):
        print(f"  Installing: {' '.join(pkgs)} ...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", *pkgs], check=False)
        except Exception as e:
            print(f"  Install did not complete ({e}). Install manually: pip install {' '.join(pkgs)}")
    else:
        print(f"  Skipped. Install anytime: pip install {' '.join(pkgs)}")

    try:
        os.makedirs(marker_dir, exist_ok=True)
        with open(marker, "w") as f:
            json.dump(sorted(prompted | set(pkgs)), f)
    except OSError:
        pass
    print()


def main():
    # Ensure UTF-8 output on Windows (cp1252 can't render Unicode box-drawing/block chars)
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass  # Python 3.6 or non-reconfigurable stream

    parser = argparse.ArgumentParser(
        description="Gatekeeper Security Scanner v1.2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 gatekeeper.py https://github.com/user/repo\n"
               "  python3 gatekeeper.py /path/to/local/project\n"
               "  python3 gatekeeper.py https://github.com/user/repo --json\n"
               "  python3 gatekeeper.py https://github.com/user/repo --sarif\n",
    )
    parser.add_argument("target", nargs="?", default="", help="GitHub URL or local path to scan")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--sarif", action="store_true", help="Output SARIF v2.1.0 for CI/CD integration")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency audit (offline mode)")
    parser.add_argument("--no-osv", action="store_true", help="Disable OSV.dev network fallback for CVE lookups")
    parser.add_argument("--no-taint", action="store_true", help="Disable intra-function taint analysis (Python)")
    parser.add_argument("--no-yara", action="store_true", help="Disable YARA signature scanning")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--max-files", type=int, default=MAX_TOTAL_FILES, help=f"Maximum files to scan (default: {MAX_TOTAL_FILES})")
    parser.add_argument("--exclude", type=str, default="", help="Comma-separated glob patterns to exclude (e.g. 'vendor/**,*.min.js')")
    parser.add_argument("--output", type=str, default="", help="Save report to specific path instead of default location")
    parser.add_argument("--quiet", action="store_true", help="Minimal output — grade and exit code only")
    parser.add_argument("--trust", action="store_true", help="Trust target code (enables inline suppression for remote repos)")
    parser.add_argument("--timeout", type=int, default=0, help="Maximum scan time in seconds (0 = no limit)")
    parser.add_argument("--baseline", type=str, default="", help="Baseline file — only report new findings not in baseline")
    parser.add_argument("--save-baseline", type=str, default="", help="Save current findings as baseline to file")
    parser.add_argument("--disable-rules", type=str, default="", help="Comma-separated rule IDs to disable (e.g. 'GK-EXE-eval,GK-NET-raw-socket')")
    parser.add_argument("--token", type=str, default="", help="Git auth token for private repos (sets GIT_ASKPASS)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output — show file-by-file progress and timing")
    parser.add_argument("--self-scan", action="store_true", help="Scan Gatekeeper's own source code (quick verification)")
    parser.add_argument("--policy", type=str, default="", help="Policy-based pass/fail (e.g. 'critical=0,high<=5')")
    parser.add_argument("--diff", type=str, default="", help="Only scan files changed since <base-ref> (e.g. 'main')")
    parser.add_argument("--version", action="version", version=f"Gatekeeper {VERSION}")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    use_color = not args.no_color and sys.stdout.isatty()
    printer = ReportPrinter(use_color=use_color, version=VERSION)
    exclude_patterns = [p.strip() for p in args.exclude.split(",") if p.strip()] if args.exclude else []

    # --self-scan overrides target
    if args.self_scan:
        args.target = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    elif not args.target:
        parser.error("target is required (or use --self-scan)")

    # Git auth token for private repos — scoped to subprocess env, not global
    git_env = {}
    if args.token:
        git_env = {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "url.https://x-access-token:" + args.token + "@github.com/.insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/",
        }

    # First-run, terminal-only offer to install optional add-ons (e.g. yara-python).
    _prompt_optional_deps(args)

    if not args.json and not args.sarif and not args.quiet:
        print(f"\n  Scanning: {args.target}...")
        print()

    # Set up overall scan timeout — Unix uses SIGALRM (raises TimeoutError),
    # Windows uses threading.Timer (started after scanner creation for cleanup access)
    _timeout_timer = None
    _use_signal_timeout = False
    if args.timeout > 0:
        import signal
        def _timeout_handler(signum, frame):
            raise TimeoutError(f"Scan exceeded {args.timeout}s timeout")
        try:
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(args.timeout)
            _use_signal_timeout = True
        except (AttributeError, OSError):
            pass  # Windows: timer started below after scanner creation

    disabled_rules = set(r.strip() for r in args.disable_rules.split(",") if r.strip()) if args.disable_rules else set()
    scanner = SecurityScanner(skip_deps=args.skip_deps, max_files=args.max_files, exclude_patterns=exclude_patterns, trust_target=args.trust, git_env=git_env, verbose=args.verbose, no_osv=args.no_osv, no_taint=args.no_taint, no_yara=args.no_yara)

    # Windows timeout fallback — started after scanner creation so cleanup can access temp_dirs
    if args.timeout > 0 and not _use_signal_timeout:
        def _timer_expire():
            for td in scanner.temp_dirs:
                shutil.rmtree(td, ignore_errors=True)
            scanner._file_cache.clear()
            print(f"\nERROR: Scan exceeded {args.timeout}s timeout", file=sys.stderr)
            os._exit(2)
        _timeout_timer = threading.Timer(args.timeout, _timer_expire)
        _timeout_timer.daemon = True
        _timeout_timer.start()

    # Diff mode: only scan files changed since base ref
    if args.diff:
        diff_target = args.target if not args.self_scan else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if os.path.isdir(diff_target):
            diff_result = subprocess.run(
                ["git", "diff", "--name-only", args.diff, "HEAD"],
                capture_output=True, text=True, cwd=diff_target
            )
            if diff_result.returncode == 0 and diff_result.stdout.strip():
                scanner._diff_files = set(diff_result.stdout.strip().split("\n"))
        else:
            logger.warning("--diff requires a local directory target; ignored for remote URLs")

    fail_on = scanner.config.get("fail_on", ["D", "F"])
    try:
        report = scanner.scan(args.target)
    except TimeoutError as e:
        logger.error("%s", e)
        sys.exit(2)
    finally:
        if args.timeout > 0:
            try:
                signal.alarm(0)
            except (AttributeError, NameError):
                pass
            if _timeout_timer:
                _timeout_timer.cancel()

    # Apply --disable-rules
    if disabled_rules:
        report.findings = [f for f in report.findings if f.rule_id not in disabled_rules]

    # Apply --baseline (filter out known findings)
    if args.baseline and os.path.exists(args.baseline):
        try:
            with open(args.baseline, "r") as bf:
                baseline = set(json.load(bf))
            report.findings = [
                f for f in report.findings
                if hashlib.sha256(f"{f.file}:{f.rule_id}:{f.message}".encode()).hexdigest()[:16] not in baseline
            ]
        except (json.JSONDecodeError, OSError):
            pass

    # Save baseline if requested
    if args.save_baseline:
        fingerprints = [
            hashlib.sha256(f"{f.file}:{f.rule_id}:{f.message}".encode()).hexdigest()[:16]
            for f in report.findings
        ]
        with open(args.save_baseline, "w") as bf:
            json.dump(fingerprints, bf, indent=2)
        if not args.quiet:
            print(f"  Baseline saved: {args.save_baseline} ({len(fingerprints)} findings)")

    # Recalculate score and recommendation after filtering
    if disabled_rules or (args.baseline and os.path.exists(args.baseline)):
        report.score, report.grade = scanner._calculate_score(
            report.findings, report.structure.get("total_lines", 0))
        report.recommendation = scanner._generate_recommendation(report)
        # Recalculate summaries to match filtered findings
        report.severity_summary = {}
        report.category_summary = {}
        report.verified_count = len(report.findings)
        for f in report.findings:
            report.severity_summary[f.severity] = report.severity_summary.get(f.severity, 0) + 1
            report.category_summary[f.category] = report.category_summary.get(f.category, 0) + 1
        report.verdict = {"A": "INSTALL", "B": "INSTALL", "C": "REVIEW BEFORE INSTALLING",
                          "D": "DO NOT INSTALL — VULNERABLE", "F": "DO NOT INSTALL"}.get(report.grade, "ERROR")
        report.grade_drivers = scanner._build_grade_drivers(report.findings)

    # Determine save path — only create report dir for modes that actually save files
    save_path = ""
    if args.output:
        save_path = args.output
        os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
    elif not args.json and not args.sarif and not args.quiet:
        report_dir = os.environ.get("GATEKEEPER_REPORT_DIR", os.path.expanduser("~/.gatekeeper/reports"))
        os.makedirs(report_dir, exist_ok=True)
        # Auto-cleanup: keep last 50 reports
        try:
            existing = sorted([
                os.path.join(report_dir, f) for f in os.listdir(report_dir)
                if f.startswith("scan-") and f.endswith(".json")
            ])
            for old in existing[:-50]:
                os.remove(old)
        except OSError:
            pass
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        slug = re.sub(r"[^a-zA-Z0-9]", "-", args.target)[:50]
        save_path = os.path.join(report_dir, f"scan-{slug}-{ts}.json")

    if args.quiet:
        print(f"GRADE: {report.grade} (score: {report.score})")
        if args.output:
            with open(save_path, "w") as f:
                json.dump(report.to_dict(), indent=2, fp=f, default=str)
    elif args.sarif:
        sarif_output = json.dumps(generate_sarif(report, version=VERSION), indent=2)
        if args.output:
            with open(save_path, "w") as f:
                f.write(sarif_output)
        else:
            print(sarif_output)
    elif args.json:
        json_output = json.dumps(report.to_dict(), indent=2, default=str)
        if args.output:
            with open(save_path, "w") as f:
                f.write(json_output)
        else:
            print(json_output)
    else:
        # Neutral discovery summary — no grade or color yet
        total = len(report.findings)
        if total == 0:
            print(f"  No potential vulnerabilities discovered.")
        else:
            print(f"  Discovered {total} potential vulnerabilit{'y' if total == 1 else 'ies'}. Investigating...")
        print()
        printer.print_report(report, warnings=scanner.warnings)
        with open(save_path, "w") as f:
            json.dump(report.to_dict(), indent=2, fp=f, default=str)
        print(f"  {printer.DIM}Report saved: {save_path}{printer.RESET}")
        print()

    # Exit code: policy overrides grade-based exit when set
    if args.policy:
        sys.exit(0 if _evaluate_policy(report.findings, args.policy) else 1)
    sys.exit(1 if report.grade in fail_on or report.grade == "ERROR" else 0)


if __name__ == "__main__":
    main()
