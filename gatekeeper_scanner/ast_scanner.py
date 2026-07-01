"""
Gatekeeper AST Scanner v1.0

Structure-aware security analysis for Python files using the stdlib ast module.
Supplements regex-based detection with precise call analysis, import tracking,
keyword argument inspection, and string concatenation folding.

Zero external dependencies — uses only Python's built-in ast module.
"""

import ast
import re
from typing import List, Dict, Tuple, Optional

from gatekeeper_scanner.models import Finding
from gatekeeper_scanner.patterns import DANGER_WORDS_EXTENDED


class ASTScanner:
    """AST-based security scanner for Python files.

    Stateless — safe to share across threads. Each scan_file call is independent.
    """

    def scan_file(self, fpath: str, rel_path: str, content: str,
                  trust_target: bool = False) -> List[Finding]:
        """Scan a Python file using AST analysis.

        Args:
            fpath: Absolute file path (for error context).
            rel_path: Relative path (used in Finding.file).
            content: File content (pre-loaded from scanner's cache).
            trust_target: If True, honor inline # gatekeeper: ignore comments.

        Returns:
            List of Finding objects. Empty list if parsing fails.
        """
        try:
            tree = ast.parse(content, filename=fpath)
        except (SyntaxError, ValueError, RecursionError):
            return []  # Fall back to regex for this file

        visitor = _SecurityVisitor(rel_path, content.split("\n"), trust_target)
        visitor.visit(tree)
        return visitor.findings


class _ImportTracker:
    """Tracks import statements and resolves aliases to original module/function names."""

    # Modules where method calls are security-relevant
    DANGEROUS_MODULES = frozenset({
        "pickle", "marshal", "shelve", "subprocess", "os", "shutil",
        "yaml", "torch", "commands", "socket",
    })

    def __init__(self):
        # import X as Y  →  aliases[Y] = X
        self.module_aliases: Dict[str, str] = {}
        # from X import Y as Z  →  from_imports[Z] = (X, Y)
        self.from_imports: Dict[str, Tuple[str, str]] = {}

    def track_import(self, node: ast.Import):
        """Track `import X` and `import X as Y` statements."""
        for alias in node.names:
            name = alias.asname or alias.name
            if alias.name in self.DANGEROUS_MODULES:
                self.module_aliases[name] = alias.name

    def track_from_import(self, node: ast.ImportFrom):
        """Track `from X import Y` and `from X import Y as Z` statements."""
        if not node.module:
            return
        # Track direct module imports (e.g., from os import system)
        mod = node.module.split(".")[0]  # Handle from os.path import ...
        if mod in self.DANGEROUS_MODULES:
            for alias in node.names:
                name = alias.asname or alias.name
                self.from_imports[name] = (mod, alias.name)

    def resolve_call(self, node: ast.Call) -> Optional[Tuple[str, str]]:
        """Resolve a Call node to (module, function_name). Returns None if unknown.

        Handles:
          - subprocess.run(...)  →  ("subprocess", "run")
          - p.loads(...)  where import pickle as p  →  ("pickle", "loads")
          - loads(...)  where from pickle import loads  →  ("pickle", "loads")
          - ld(...)  where from pickle import loads as ld  →  ("pickle", "loads")
        """
        func = node.func

        # Case 1: obj.method(...)
        if isinstance(func, ast.Attribute):
            receiver = self._resolve_name(func.value)
            if receiver:
                mod = self.module_aliases.get(receiver, receiver)
                if mod in self.DANGEROUS_MODULES:
                    return (mod, func.attr)

        # Case 2: func(...)
        elif isinstance(func, ast.Name):
            if func.id in self.from_imports:
                return self.from_imports[func.id]

        return None

    def _resolve_name(self, node: ast.expr) -> Optional[str]:
        """Resolve an AST expression to a simple name string."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value)
            if base:
                return f"{base}.{node.attr}"
        return None


# Dangerous module.method → (severity, category, message)
_DANGEROUS_ATTRS: Dict[Tuple[str, str], Tuple[str, str, str]] = {
    ("pickle", "load"): ("CRITICAL", "EXECUTION", "pickle.load() — arbitrary code execution"),
    ("pickle", "loads"): ("CRITICAL", "EXECUTION", "pickle.loads() — arbitrary code execution"),
    ("marshal", "load"): ("HIGH", "EXECUTION", "marshal.load() — code execution"),
    ("marshal", "loads"): ("HIGH", "EXECUTION", "marshal.loads() — code execution"),
    ("os", "system"): ("HIGH", "EXECUTION", "os.system() — shell command execution"),
    ("os", "popen"): ("HIGH", "EXECUTION", "os.popen() — shell command execution"),
    ("os", "dup2"): ("CRITICAL", "EXECUTION", "os.dup2() — file descriptor redirection, likely reverse shell setup"),
    ("shutil", "rmtree"): ("MEDIUM", "FILESYSTEM", "shutil.rmtree() — recursive directory deletion"),
    ("shelve", "open"): ("MEDIUM", "EXECUTION", "shelve.open() — uses pickle internally"),
    ("commands", "getoutput"): ("HIGH", "EXECUTION", "commands.getoutput() — shell execution"),
}

# subprocess methods that need shell=True checking
_SUBPROCESS_METHODS = frozenset({"run", "call", "Popen", "check_output", "check_call"})


_SUPPRESSION_RE = re.compile(r"(?:#|//|--)\s*gatekeeper:\s*ignore", re.IGNORECASE)


class _SecurityVisitor(ast.NodeVisitor):
    """Single-pass AST visitor that collects security findings."""

    def __init__(self, rel_path: str, lines: List[str], trust_target: bool = False):
        self.rel_path = rel_path
        self.lines = lines
        self._trust_target = trust_target
        self.findings: List[Finding] = []
        self.imports = _ImportTracker()

    def _snippet(self, node: ast.AST) -> str:
        """Extract source line as snippet."""
        lineno = getattr(node, "lineno", 0)
        if 0 < lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()[:120]
        return ""

    def _add(self, node: ast.AST, severity: str, category: str, message: str):
        lineno = getattr(node, "lineno", 0)
        # Honor inline suppression comments on trusted targets, but only for LOW/MEDIUM
        # non-secret noise. A target's comment can never hide a CRITICAL, HIGH, or SECRET.
        if self._trust_target and 0 < lineno <= len(self.lines):
            if _SUPPRESSION_RE.search(self.lines[lineno - 1]) and severity in ("LOW", "MEDIUM") and category != "SECRET":
                return
        self.findings.append(Finding(
            severity=severity,
            category=category,
            file=self.rel_path,
            line=getattr(node, "lineno", 0),
            message=message,
            snippet=self._snippet(node),
        ))

    # ---- Import tracking ----

    def visit_Import(self, node: ast.Import):
        self.imports.track_import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        self.imports.track_from_import(node)
        self.generic_visit(node)

    # ---- Call analysis ----

    def visit_Call(self, node: ast.Call):
        self._check_bare_dangerous_calls(node)
        self._check_module_method_calls(node)
        self._check_sql_injection(node)
        self.generic_visit(node)

    def _check_bare_dangerous_calls(self, node: ast.Call):
        """Detect eval(), exec(), compile(), __import__() — bare name calls only."""
        func = node.func
        if not isinstance(func, ast.Name):
            return

        name = func.id

        if name in ("eval", "exec"):
            # Skip eval/exec with a simple identifier constant — introspection like eval('__doc__')
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', node.args[0].value):
                    return
            self._add(node, "HIGH", "EXECUTION", f"{name}() — executes arbitrary code")

        elif name == "compile":
            # Only flag builtin compile(), not method calls (those are ast.Attribute)
            self._add(node, "MEDIUM", "EXECUTION", "compile() — compiles code for execution")

        elif name == "__import__":
            self._add(node, "HIGH", "EXECUTION", "__import__() — dynamic module import")

        # from-import aliased calls (e.g., from pickle import loads; loads(data))
        elif name in self.imports.from_imports:
            mod, orig_name = self.imports.from_imports[name]
            key = (mod, orig_name)
            if key in _DANGEROUS_ATTRS:
                sev, cat, msg = _DANGEROUS_ATTRS[key]
                self._add(node, sev, cat, msg)
            elif mod == "subprocess" and orig_name in _SUBPROCESS_METHODS:
                self._check_shell_true(node, f"subprocess.{orig_name}")
            elif mod == "yaml" and orig_name in ("load", "unsafe_load"):
                self._check_yaml_load(node)
            elif mod == "torch" and orig_name == "load":
                self._check_torch_load(node)

    def _check_module_method_calls(self, node: ast.Call):
        """Detect dangerous module.method() calls with import alias resolution."""
        resolved = self.imports.resolve_call(node)
        if not resolved:
            return

        mod, method = resolved

        key = (mod, method)
        if key in _DANGEROUS_ATTRS:
            sev, cat, msg = _DANGEROUS_ATTRS[key]
            self._add(node, sev, cat, msg)
        elif mod == "subprocess" and method in _SUBPROCESS_METHODS:
            self._check_shell_true(node, f"subprocess.{method}")
        elif mod == "yaml" and method in ("load", "unsafe_load"):
            self._check_yaml_load(node)
        elif mod == "torch" and method == "load":
            self._check_torch_load(node)
        elif mod == "socket" and method == "connect":
            self._check_socket_connect(node)

    def _check_shell_true(self, node: ast.Call, call_name: str):
        """Flag subprocess calls only when shell=True is explicitly set."""
        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(node, "CRITICAL", "EXECUTION",
                              "subprocess with shell=True — command injection risk")
                return  # shell= is present but not True — safe

    def _check_yaml_load(self, node: ast.Call):
        """yaml.load() is dangerous only without a safe Loader argument."""
        for kw in node.keywords:
            if kw.arg == "Loader":
                return  # Has Loader kwarg
        if len(node.args) >= 2:
            return  # Has positional Loader arg
        self._add(node, "HIGH", "EXECUTION", "yaml.load() without safe Loader")

    def _check_torch_load(self, node: ast.Call):
        """torch.load() is dangerous without weights_only=True."""
        for kw in node.keywords:
            if kw.arg == "weights_only":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return  # Safe
        self._add(node, "CRITICAL", "EXECUTION",
                  "torch.load() without weights_only=True — arbitrary code execution via malicious model weights")

    def _check_socket_connect(self, node: ast.Call):
        """socket.connect() to a raw IP address — potential reverse shell."""
        if not node.args:
            return
        arg = node.args[0]
        # Check for tuple literal like ("1.2.3.4", 4444)
        if isinstance(arg, ast.Tuple) and arg.elts:
            first = arg.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", first.value):
                    self._add(node, "CRITICAL", "NETWORK",
                              "Socket connect to IP address — potential reverse shell")

    def _check_sql_injection(self, node: ast.Call):
        """Detect SQL injection via f-strings, concat, or .format() in execute() calls."""
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "execute":
            return
        if not node.args:
            return

        first_arg = node.args[0]

        # f-string in execute()
        if isinstance(first_arg, ast.JoinedStr):
            self._add(node, "CRITICAL", "INJECTION",
                      "SQL f-string in cursor.execute — injection risk")

        # String concatenation in execute()
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
            self._add(node, "HIGH", "INJECTION",
                      "SQL string concatenation — injection risk")

        # .format() in execute()
        elif isinstance(first_arg, ast.Call):
            inner_func = first_arg.func
            if isinstance(inner_func, ast.Attribute) and inner_func.attr == "format":
                self._add(node, "HIGH", "INJECTION",
                          "SQL .format() — injection risk")

        # %-formatting in execute()
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
            self._add(node, "HIGH", "INJECTION",
                      "SQL string formatting — injection risk")

    # ---- Subscript analysis ----

    def visit_Subscript(self, node: ast.Subscript):
        """Detect globals()[...] / locals()[...] — dynamic function lookup evasion."""
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id in ("globals", "locals"):
                self._add(node, "CRITICAL", "EXECUTION",
                          f"Dynamic function lookup via {func.id}() — evasion technique")
        self.generic_visit(node)

    # ---- String concat obfuscation ----

    def visit_BinOp(self, node: ast.BinOp):
        """Detect string concatenation that assembles dangerous function names."""
        if isinstance(node.op, ast.Add):
            folded = _try_fold_concat(node)
            if folded is not None and len(folded) >= 3:
                if folded.lower() in DANGER_WORDS_EXTENDED:
                    self._add(node, "CRITICAL", "OBFUSCATION",
                              f"String concat assembles dangerous function name: '{folded}'")
        self.generic_visit(node)

    # ---- Standalone f-string SQL detection ----

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Detect standalone SQL f-strings (not inside execute() — that's caught above)."""
        if not node.values:
            self.generic_visit(node)
            return
        # Check if the first part is a string starting with a SQL keyword
        first = node.values[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            stripped = first.value.strip().upper()
            if stripped.startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ")):
                # Only flag if it has interpolated values (not a pure constant)
                if any(isinstance(v, ast.FormattedValue) for v in node.values):
                    self._add(node, "CRITICAL", "INJECTION",
                              "SQL f-string — injection risk")
        self.generic_visit(node)


def _try_fold_concat(node: ast.expr) -> Optional[str]:
    """Recursively fold string concatenation chains into a single string.

    Returns the concatenated string if all parts are string constants,
    or None if any part is non-constant.

    Handles chains of any length: "e" + "v" + "a" + "l" → "eval"
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _try_fold_concat(node.left)
        right = _try_fold_concat(node.right)
        if left is not None and right is not None:
            return left + right
    return None
