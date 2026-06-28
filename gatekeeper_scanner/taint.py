"""
Gatekeeper intra-function taint analysis (Python)

Closes the gap the scanner's own docs admit: regex/AST pattern matching cannot
follow data flow. This module tracks untrusted input from a SOURCE to a
dangerous SINK *within a single function scope* and flags the flow.

Scope is deliberately intra-procedural (one function body, or module top level)
for v1: high signal, bounded complexity. Cross-function / cross-file taint is a
later iteration. Analysis is flow-insensitive within a scope (a fixpoint over
assignments), which errs toward flagging, appropriate for a security tool, and
the human review phase filters the rare false positive.

------------------------------------------------------------------------------
DECISION TREE
------------------------------------------------------------------------------
For each SCOPE (Module body; every FunctionDef/AsyncFunctionDef body, excluding
nested function bodies which are their own scopes):

  1. SEED taint:
       - If the function has a request/route/tool decorator (web handler or MCP
         tool handler), every parameter name is a source (caller-controlled).
  2. FIXPOINT over assignments in the scope until no change:
       - Assign / AnnAssign:  target := value.  If is_tainted(value) → taint
         every Name target. (Flow-insensitive: never untainted later.)
       - AugAssign (x += v):  taint x if is_tainted(v) or x already tainted.
       - For (for x in it):   if is_tainted(it) → taint loop target names.
  3. SINKS: for each dangerous Call in the scope, if its payload argument
     is_tainted → emit a finding (sink label, severity, CWE).

is_tainted(node):
   - SANITIZER call wrapping (int()/float()/bool()/len()/shlex.quote()/
     html.escape()/...quote()/...escape()) → NOT tainted, regardless of args.
   - SOURCE expression (see below) → tainted.
   - Name in the scope's tainted set → tainted.
   - else recurse into children; tainted if ANY child is tainted.
     (So f-strings, concatenation, .strip()/.format()/str(), dict/list access,
      os.path.join(base, taint), etc. all propagate.)

SOURCES (untrusted input):
   request.{args,form,values,json,data,cookies,files,headers}  (Flask/like)
   request.get_json(...)        flask.request.*
   sys.argv                     os.environ / os.environ.get(...) / os.getenv(...)
   input(...)                   + decorated-handler parameters

SINKS (payload = first positional arg unless noted):
   eval(), exec()                         CRITICAL  CWE-95   (bare-name calls)
   os.system(), os.popen()                CRITICAL  CWE-78
   subprocess.run/call/Popen/check_*      CWE-78: CRITICAL if shell=True else HIGH
   pickle.loads/cPickle.loads/marshal.loads  HIGH   CWE-502
   yaml.load()                            HIGH      CWE-502
   <obj>.execute()/.executemany()         HIGH      CWE-89   (SQL)
   open()                                 MEDIUM    CWE-22   (path traversal)
   __import__()/importlib.import_module() HIGH      CWE-470
   shutil.rmtree/os.remove/os.unlink      MEDIUM    CWE-73
   requests.{get,post,put,delete,patch,head}/urlopen  MEDIUM CWE-918 (SSRF)
------------------------------------------------------------------------------
"""

import ast

SOURCE_REQUEST_ATTRS = {
    "args", "form", "values", "json", "data", "cookies", "files",
    "headers", "get_json", "query_params", "path_params",
}
DECORATOR_HINTS = ("route", "get", "post", "put", "delete", "patch",
                   "tool", "command", "endpoint", "websocket", "api")
SANITIZER_LAST = {"int", "float", "bool", "len", "quote", "escape", "quote_plus"}


def _chain(node):
    """Reconstruct a dotted name from an Attribute/Name/Call/Subscript node.
    request.args['x'] -> 'request.args';  os.path.join -> 'os.path.join'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _chain(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _chain(node.func)
    if isinstance(node, ast.Subscript):
        return _chain(node.value)
    return ""


def _target_names(target):
    """Names bound by an assignment/for target (handles tuple/list unpacking)."""
    out = []
    if isinstance(target, ast.Name):
        out.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            out.extend(_target_names(elt))
    return out


# Taint levels: 0 = clean, 1 = weak (operator-controlled, e.g. env vars),
# 2 = strong (remote/attacker-controlled, e.g. request data, argv, input()).
# Weak taint only reaches high-impact sinks (code exec, deserialization, SQL);
# it does NOT trip the MEDIUM file-path / SSRF sinks, where an env-controlled
# value is almost always intended configuration rather than an attack.
STRONG, WEAK, CLEAN = 2, 1, 0


def _source_level(node):
    """Level for THIS node treated as a source expression (not its children)."""
    chain = _chain(node)
    if chain == "sys.argv":
        return STRONG
    parts = chain.split(".")
    if "request" in parts:
        idx = parts.index("request")
        if idx + 1 < len(parts) and parts[idx + 1] in SOURCE_REQUEST_ATTRS:
            return STRONG
    if isinstance(node, ast.Call):
        fchain = _chain(node.func)
        if fchain == "input":
            return STRONG
        if fchain.split(".")[-1] == "get_json":
            return STRONG
        if fchain == "os.getenv" or fchain.startswith("os.environ"):
            return WEAK
    if chain == "os.environ" or chain.startswith("os.environ"):
        return WEAK
    return CLEAN


def _is_sanitizer(node):
    if not isinstance(node, ast.Call):
        return False
    last = _chain(node.func).split(".")[-1]
    full = _chain(node.func)
    return last in SANITIZER_LAST or full in ("shlex.quote", "html.escape")


class _ScopeTaint:
    """Taint state and analysis for one function/module scope."""

    def __init__(self, rel_path, seed_params=None):
        self.rel = rel_path
        # Seeded params (handler args) are strong (caller-controlled).
        self.strong = set(seed_params or [])
        self.weak = set()
        self.findings = []

    # -- taint test -------------------------------------------------------
    def taint_level(self, node):
        """Highest taint level reaching this expression (0/1/2)."""
        if node is None:
            return CLEAN
        if _is_sanitizer(node):
            return CLEAN
        lvl = _source_level(node)
        if isinstance(node, ast.Name):
            if node.id in self.strong:
                lvl = max(lvl, STRONG)
            elif node.id in self.weak:
                lvl = max(lvl, WEAK)
        for child in ast.iter_child_nodes(node):
            lvl = max(lvl, self.taint_level(child))
            if lvl == STRONG:
                break
        return lvl

    def source_label(self, node):
        """Short human label for what made an argument tainted."""
        if _source_level(node):
            return _chain(node) or "untrusted input"
        if isinstance(node, ast.Name) and (node.id in self.strong or node.id in self.weak):
            return f"variable '{node.id}'"
        for child in ast.iter_child_nodes(node):
            if self.taint_level(child):
                return self.source_label(child)
        return "untrusted input"

    # -- propagation ------------------------------------------------------
    def _mark(self, name, level):
        """Raise a variable's taint level monotonically. Returns True if changed."""
        if level == STRONG and name not in self.strong:
            self.strong.add(name)
            self.weak.discard(name)
            return True
        if level == WEAK and name not in self.strong and name not in self.weak:
            self.weak.add(name)
            return True
        return False

    def seed_fixpoint(self, assignments, fors):
        changed = True
        while changed:
            changed = False
            for targets, value in assignments:
                lvl = self.taint_level(value)
                if lvl:
                    for name in targets:
                        changed |= self._mark(name, lvl)
            for targets, it in fors:
                lvl = self.taint_level(it)
                if lvl:
                    for name in targets:
                        changed |= self._mark(name, lvl)

    # -- sinks ------------------------------------------------------------
    def check_sink(self, call):
        func = call.func
        chain = _chain(func)
        last = chain.split(".")[-1]
        arg0 = call.args[0] if call.args else None

        # spec = (label, severity, cwe, min_level). MEDIUM file-path / SSRF
        # sinks require STRONG taint; code-exec / deser / SQL accept WEAK too.
        spec = None
        if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
            spec = (f"{func.id}()", "CRITICAL", "CWE-95", WEAK)
        elif chain in ("os.system", "os.popen"):
            spec = (f"{chain}()", "CRITICAL", "CWE-78", WEAK)
        elif chain.startswith("subprocess.") and last in (
                "run", "call", "Popen", "check_output", "check_call"):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in call.keywords)
            sev = "CRITICAL" if shell_true else "HIGH"
            spec = (f"subprocess.{last}({'shell=True' if shell_true else 'argv'})", sev, "CWE-78", WEAK)
        elif last == "loads" and chain.split(".")[0] in ("pickle", "cPickle", "marshal"):
            spec = (f"{chain}()", "HIGH", "CWE-502", WEAK)
        elif chain == "yaml.load":
            spec = ("yaml.load()", "HIGH", "CWE-502", WEAK)
        elif isinstance(func, ast.Attribute) and last in ("execute", "executemany"):
            spec = (f".{last}() (SQL)", "HIGH", "CWE-89", WEAK)
        elif isinstance(func, ast.Name) and func.id == "__import__":
            spec = ("__import__()", "HIGH", "CWE-470", WEAK)
        elif chain == "importlib.import_module":
            spec = ("importlib.import_module()", "HIGH", "CWE-470", WEAK)
        elif isinstance(func, ast.Name) and func.id == "open":
            spec = ("open()", "MEDIUM", "CWE-22", STRONG)
        elif chain == "shutil.rmtree" or chain in ("os.remove", "os.unlink"):
            spec = (f"{chain}()", "MEDIUM", "CWE-73", STRONG)
        elif (chain.startswith("requests.") and last in (
                "get", "post", "put", "delete", "patch", "head")) or last == "urlopen":
            spec = (f"{chain}()", "MEDIUM", "CWE-918", STRONG)

        if spec is None or arg0 is None:
            return
        label, severity, cwe, min_level = spec
        if self.taint_level(arg0) < min_level:
            return
        self.findings.append({
            "line": getattr(call, "lineno", 0),
            "severity": severity,
            "cwe": cwe,
            "message": (f"Tainted data from {self.source_label(arg0)} reaches "
                        f"{label} (intra-function taint flow)"),
        })


def _scope_statements(body):
    """Yield nodes in a scope's body, NOT descending into nested function/lambda
    scopes (they are analyzed separately)."""
    stack = list(body)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue  # separate scope
        for child in ast.iter_child_nodes(node):
            stack.append(child)


def _decorator_taints_params(func):
    for dec in func.decorator_list:
        chain = _chain(dec)
        last = chain.split(".")[-1].lower()
        if any(h in last for h in DECORATOR_HINTS) or any(h in chain.lower() for h in DECORATOR_HINTS):
            return True
    return False


def _analyze_scope(rel, body, seed_params=None):
    scope = _ScopeTaint(rel, seed_params)
    assignments, fors, calls = [], [], []
    for node in _scope_statements(body):
        if isinstance(node, ast.Assign):
            names = []
            for t in node.targets:
                names.extend(_target_names(t))
            assignments.append((names, node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            assignments.append((_target_names(node.target), node.value))
        elif isinstance(node, ast.AugAssign):
            assignments.append((_target_names(node.target), node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            fors.append((_target_names(node.target), node.iter))
        elif isinstance(node, ast.Call):
            calls.append(node)
    scope.seed_fixpoint(assignments, fors)
    for call in calls:
        scope.check_sink(call)
    return scope.findings


def analyze(rel_path, source_code):
    """Parse Python source and return a list of taint findings:
    [{line, severity, cwe, message}]. Returns [] on syntax error."""
    try:
        tree = ast.parse(source_code)
    except (SyntaxError, ValueError):
        return []

    findings = []
    # Module top-level scope (no seeded params).
    findings.extend(_analyze_scope(rel_path, tree.body))
    # Every function scope.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            seed = []
            if _decorator_taints_params(node):
                args = node.args
                for a in (args.posonlyargs + args.args + args.kwonlyargs):
                    seed.append(a.arg)
                if args.vararg:
                    seed.append(args.vararg.arg)
                if args.kwarg:
                    seed.append(args.kwarg.arg)
            findings.extend(_analyze_scope(rel_path, node.body, seed))
    return findings
