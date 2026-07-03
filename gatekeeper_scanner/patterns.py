"""
Gatekeeper Detection Patterns v1.0

All regex-based detection pattern tuples used by the scanner.
Each pattern is a tuple of (regex_pattern, CATEGORY, SEVERITY, message)
or for secrets: (regex_pattern, description).
"""

import re

# Core dangerous function names — used by both string concat and variable assembly evasion detectors
DANGER_WORDS_CORE = frozenset({
    "eval", "exec", "system", "popen", "import", "require",
    "subprocess", "pickle", "marshal", "compile",
})
# Extended set adds network/encoding functions — used by inline string concat detection
DANGER_WORDS_EXTENDED = DANGER_WORDS_CORE | frozenset({
    "base64", "decode", "encode", "child_process", "Function",
    "setTimeout", "setInterval", "curl", "wget", "fetch",
    "XMLHttpRequest", "process", "environ", "getenv", "yaml",
})

# ============================================================================
# SECRET PATTERNS
# ============================================================================

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "AWS Secret Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub Fine-Grained Token"),
    (r"sk-ant-[A-Za-z0-9_\-]{40,}", "Anthropic API Key"),
    (r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}", "OpenAI API Key"),
    (r"sk-[A-Za-z0-9]{48,}", "OpenAI API Key"),
    (r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}", "Slack Bot Token"),
    (r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}", "Slack User Token"),
    (r"sk_live_[A-Za-z0-9]{24,}", "Stripe Secret Key"),
    (r"pk_live_[A-Za-z0-9]{24,}", "Stripe Publishable Key"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
    (r"(?i)(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)\s*[=:]\s*['\"][A-Za-z0-9\-_.]{16,}['\"]", "Hardcoded Secret/Token"),
    (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"](?!(?:Password|Enter|Type|Confirm|New|Old|Re-?enter|Forgot|Reset|Change)[^'\"]*['\"])[^'\"]{8,64}['\"]", "Hardcoded Password"),
    (r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@", "Database Connection String"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token"),
    (r"https?://[^\s:\"']+:[^\s@\"']+@(?!(?:fonts\.googleapis\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|registry\.npmjs\.org|pypi\.org))[^\s\"']+", "Basic Auth URL with embedded credentials"),
    # GCP
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID"),
    # Azure
    (r"(?i)(?:azure|ad|microsoft)[_\-]?(?:client[_\-]?secret|tenant[_\-]?id)\s*[=:]\s*['\"][A-Za-z0-9\-_.]{16,}['\"]", "Azure Secret"),
    # SendGrid
    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "SendGrid API Key"),
    # Telegram — require bot prefix for specificity
    (r"(?:bot|Bot)[0-9]{8,10}:[A-Za-z0-9_-]{35}", "Telegram Bot Token"),
]

# ============================================================================
# LANGUAGE-SPECIFIC DANGEROUS PATTERNS
# ============================================================================

DANGEROUS_PYTHON = [
    (r"(?<!\.)(?<!\w)\beval\s*\(", "EXECUTION", "HIGH", "eval() — executes arbitrary code"),
    (r"\bexec\s*\(", "EXECUTION", "HIGH", "exec() — executes arbitrary code"),
    (r"(?<!re\.)\bcompile\s*\(", "EXECUTION", "MEDIUM", "compile() — compiles code for execution"),
    (r"__import__\s*\(", "EXECUTION", "HIGH", "__import__() — dynamic module import"),
    (r"subprocess\.\w+\(.*shell\s*=\s*True", "EXECUTION", "CRITICAL", "subprocess with shell=True — command injection risk"),
    (r"os\.system\s*\(", "EXECUTION", "HIGH", "os.system() — shell command execution"),
    (r"os\.popen\s*\(", "EXECUTION", "HIGH", "os.popen() — shell command execution"),
    (r"commands\.getoutput\s*\(", "EXECUTION", "HIGH", "commands.getoutput() — shell execution"),
    (r"pickle\.loads?\s*\(", "EXECUTION", "CRITICAL", "pickle deserialization — arbitrary code execution"),
    (r"torch\.load\s*\((?![^)]*weights_only\s*=\s*True)", "EXECUTION", "CRITICAL", "torch.load() without weights_only=True — arbitrary code execution via malicious model weights"),
    (r"yaml\.(?:unsafe_)?load\s*\((?![^)]*Loader)", "EXECUTION", "HIGH", "yaml.load() without safe Loader"),
    (r"marshal\.loads?\s*\(", "EXECUTION", "HIGH", "marshal deserialization — code execution"),
    (r"shelve\.open\s*\(", "EXECUTION", "MEDIUM", "shelve.open() — uses pickle internally"),
    (r"ctypes\.\w+\.\w+\(", "EXECUTION", "MEDIUM", "ctypes FFI — native code execution"),
    (r"shutil\.rmtree\s*\(", "FILESYSTEM", "MEDIUM", "shutil.rmtree() — recursive directory deletion"),
    (r"os\.remove\s*\(|os\.unlink\s*\(", "FILESYSTEM", "LOW", "File deletion"),
    (r"open\s*\([^)]*['\"](?:/root/|C:\\\\|~/\.ssh|~/\.aws|~/\.config|~/\.gnupg)", "FILESYSTEM", "HIGH", "Access to sensitive credential directories"),
    (r"open\s*\([^)]*['\"](?:/etc/|/var/|/usr/)", "FILESYSTEM", "MEDIUM", "Access to system directories"),
    (r"os\.chmod\s*\(", "FILESYSTEM", "MEDIUM", "Permission modification"),
    (r"(?:requests|httpx|urllib|aiohttp)\.\w*(?:get|post|put|delete|patch|request)\s*\(", "NETWORK", "INFO", "Outbound HTTP request"),
    (r"socket\.(?:connect|bind|listen)\s*\(", "NETWORK", "HIGH", "Raw socket operation"),
    (r"""\.connect\s*\(\s*\(\s*['"][\d.]+['"]""", "NETWORK", "CRITICAL", "Socket connect to IP address — potential reverse shell"),
    (r"os\.dup2\s*\(", "EXECUTION", "CRITICAL", "os.dup2() — file descriptor redirection, likely reverse shell setup"),
    (r"\bgetattr\s*\(\s*(?:os|sys|subprocess|shutil|importlib|builtins|__builtins__)\s*,", "EXECUTION", "HIGH", "getattr() on sensitive module — dynamic dispatch evasion"),
    (r"__builtins__\s*[\[.]", "EXECUTION", "HIGH", "__builtins__ access — direct builtin invocation, likely evasion"),
    (r"import\s+(?:pickle|marshal|subprocess|shutil)\s+as\s+\w+", "EXECUTION", "HIGH", "Dangerous module imported under alias — may evade pattern detection"),
    (r"(?:globals|locals)\s*\(\s*\)\s*\[", "EXECUTION", "CRITICAL", "Dynamic function lookup via globals()/locals() — evasion technique"),
    (r"smtplib\.SMTP", "NETWORK", "MEDIUM", "Email sending capability"),
    (r"base64\.b64decode\s*\(", "OBFUSCATION", "MEDIUM", "Base64 decoding — check for hidden payloads"),
    (r"codecs\.decode\s*\([^)]*['\"]rot", "OBFUSCATION", "HIGH", "ROT encoding — likely obfuscation"),
    (r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}", "OBFUSCATION", "HIGH", "Long hex-encoded string"),
    # SQL injection
    (r"(?:execute|cursor\.execute)\s*\([^)]*%\s*\(", "INJECTION", "HIGH", "SQL string formatting — injection risk"),
    (r"(?:execute|cursor\.execute)\s*\([^)]*\+\s*", "INJECTION", "HIGH", "SQL string concatenation — injection risk"),
    (r"f['\"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{", "INJECTION", "CRITICAL", "SQL f-string — injection risk"),
    (r"cursor\.execute\s*\(\s*f['\"]", "INJECTION", "CRITICAL", "SQL f-string in cursor.execute — injection risk"),
    # SSRF
    (r"(?:requests|httpx)\.\w+\s*\(\s*(?:request\.|req\.|data\[|body\[)", "INJECTION", "CRITICAL", "SSRF: user-controlled URL in HTTP request"),
    # SSTI
    (r"(?:render_template_string|Template)\s*\([^)]*(?:request\.|req\.|f['\"])", "INJECTION", "CRITICAL", "SSTI: user input in template string — code execution risk"),
    # NoSQL
    (r"\$where.*(?:request\.|req\.|input)", "INJECTION", "CRITICAL", "MongoDB $where with user input — JS injection"),
    # SQL .format()
    (r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\.format\s*\(""", "INJECTION", "HIGH", "SQL .format() — injection risk"),
    # Weak crypto
    (r"from\s+hashlib\s+import\s+md5|hashlib\.md5\s*\(", "SECRET", "MEDIUM", "MD5 used — cryptographically broken for passwords"),
]

DANGEROUS_JS = [
    (r"(?<!\.)(?<!\w)\beval\s*\(", "EXECUTION", "HIGH", "eval() — executes arbitrary code"),
    (r"\bnew\s+Function\s*\(", "EXECUTION", "HIGH", "new Function() — dynamic code execution"),
    (r"setTimeout\s*\(\s*['\"]", "EXECUTION", "MEDIUM", "setTimeout with string — implicit eval"),
    (r"setInterval\s*\(\s*['\"]", "EXECUTION", "MEDIUM", "setInterval with string — implicit eval"),
    (r"(?:execSync|execFileSync)\s*\(", "EXECUTION", "HIGH", "Synchronous shell execution"),
    (r"child_process.*\.exec\s*\(.*(?:req\.|input|user|param)", "EXECUTION", "CRITICAL", "Shell exec with user input — command injection"),
    (r"child_process.*exec\s*\(", "EXECUTION", "HIGH", "child_process.exec — shell execution"),
    (r"vm\.runInNewContext|vm\.createScript", "EXECUTION", "HIGH", "VM code execution — sandbox escape risk"),
    (r"fs\.\w*(?:write|append|unlink|rmdir|rm)\w*\s*\(", "FILESYSTEM", "MEDIUM", "File system write/delete operation"),
    (r"fs\.\w*(?:read)\w*\s*\([^)]*(?:/etc/|/var/|/usr/|/root/|C:\\\\|\.ssh|\.aws)", "FILESYSTEM", "HIGH", "Reading sensitive files"),
    (r"\bfetch\s*\(", "NETWORK", "INFO", "fetch() — outbound HTTP request"),
    (r"axios\.\w+\s*\(", "NETWORK", "INFO", "axios — outbound HTTP request"),
    (r"new\s+WebSocket\s*\(", "NETWORK", "MEDIUM", "WebSocket connection"),
    (r"http\.request\s*\(|https\.request\s*\(", "NETWORK", "INFO", "Node HTTP request"),
    (r"dangerouslySetInnerHTML", "INJECTION", "HIGH", "React dangerouslySetInnerHTML — XSS risk"),
    (r"innerHTML\s*=", "INJECTION", "MEDIUM", "innerHTML assignment — XSS risk"),
    (r"document\.write\s*\(", "INJECTION", "MEDIUM", "document.write — XSS risk"),
    (r"Buffer\.from\s*\([^)]*,\s*['\"]base64['\"]", "OBFUSCATION", "MEDIUM", "Base64 decoding"),
    (r"atob\s*\(", "OBFUSCATION", "LOW", "Base64 decoding"),
    (r"(?:query|execute)\s*\(\s*[`'\"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\$\{", "INJECTION", "HIGH", "SQL template literal — injection risk"),
    (r"(?:query|execute)\s*\([^)]*\+\s*(?:req\.|input|user|param)", "INJECTION", "CRITICAL", "SQL concatenation with user input — injection"),
    (r"\.find\s*\(\s*req\.", "INJECTION", "HIGH", "NoSQL query directly from request — injection risk"),
    (r"\$where.*(?:req\.|input|param)", "INJECTION", "CRITICAL", "MongoDB $where with user input — JS injection"),
    (r"(?:unserialize|deserialize)\s*\(", "EXECUTION", "CRITICAL", "Deserialization — arbitrary code execution risk"),
    (r"(?:libxmljs|xml2js).*(?:noent|resolveEntities|processXInclude)\s*:\s*true", "INJECTION", "CRITICAL", "XXE: XML parser with external entity processing enabled"),
    (r"res\.redirect\s*\(\s*req\.", "INJECTION", "HIGH", "Open redirect: user input in redirect — phishing risk"),
    (r"__proto__\s*[\[.]", "INJECTION", "HIGH", "Prototype pollution: __proto__ access"),
    (r"constructor\s*\[\s*['\"]prototype", "INJECTION", "HIGH", "Prototype pollution: constructor.prototype access"),
    (r"(?:fetch|axios\.\w+|got)\s*\(\s*(?:req\.|params\.|body\.)", "INJECTION", "CRITICAL", "SSRF: user-controlled URL in server-side request"),
    (r"algorithms\s*:\s*\[['\"]\s*none\s*['\"]\]", "INJECTION", "CRITICAL", "JWT: algorithm 'none' accepted — signature bypass"),
]

DANGEROUS_SHELL = [
    (r"\bcurl\b.*\|\s*(?:ba|z)?sh", "EXECUTION", "CRITICAL", "curl piped to shell — remote code execution"),
    (r"\bwget\b.*\|\s*(?:ba|z)?sh", "EXECUTION", "CRITICAL", "wget piped to shell — remote code execution"),
    (r"\brm\s+-rf\s+/", "FILESYSTEM", "CRITICAL", "rm -rf / — catastrophic deletion"),
    (r"\bchmod\s+777\b", "PERMISSION", "HIGH", "chmod 777 — world-writable permissions"),
    (r"\bchmod\s+\+s\b", "PERMISSION", "CRITICAL", "setuid bit — privilege escalation"),
    (r"\bnc\s+-[el]", "NETWORK", "CRITICAL", "netcat listener — potential reverse shell"),
    (r"\b(?:bash|sh)\s+-i\s+", "EXECUTION", "CRITICAL", "Interactive shell — likely reverse shell"),
    (r"/dev/tcp/", "NETWORK", "CRITICAL", "Bash /dev/tcp — network connection"),
    (r"\bdd\s+if=/dev/", "FILESYSTEM", "HIGH", "dd from device — disk operation"),
    (r"\bmkfs\b", "FILESYSTEM", "CRITICAL", "mkfs — disk format command"),
    (r">\s*/dev/sd[a-z]", "FILESYSTEM", "CRITICAL", "Writing directly to disk device"),
    (r"\biptables\b", "PERMISSION", "HIGH", "Firewall rule modification"),
    (r"\bcrontab\b", "PERMISSION", "MEDIUM", "crontab modification — persistence mechanism"),
    (r"echo\s+.*>>\s*/etc/", "FILESYSTEM", "CRITICAL", "Appending to system config files"),
]

DANGEROUS_GO = [
    (r"exec\.Command\s*\(", "EXECUTION", "HIGH", "exec.Command — shell execution"),
    (r"exec\.CommandContext\s*\(", "EXECUTION", "HIGH", "exec.CommandContext — shell execution"),
    (r"syscall\.Exec\s*\(", "EXECUTION", "CRITICAL", "syscall.Exec — low-level process execution"),
    (r"unsafe\.Pointer", "EXECUTION", "MEDIUM", "unsafe.Pointer — bypasses Go type safety"),
    (r"reflect\.(?:Value|Type)\.(?:Call|Method)", "EXECUTION", "MEDIUM", "Reflection-based method invocation"),
    (r"cgo|/\*.*#include", "EXECUTION", "MEDIUM", "CGo — native code execution via C interop"),
    (r"net\.(?:Dial|Listen)\s*\(", "NETWORK", "MEDIUM", "Network connection"),
    (r"http\.(?:Get|Post|ListenAndServe)\s*\(", "NETWORK", "INFO", "HTTP operation"),
    (r"os\.(?:Remove|RemoveAll)\s*\(", "FILESYSTEM", "MEDIUM", "File/directory deletion"),
    (r"os\.(?:Open|Create)File?\s*\([^)]*(?:/etc/|/var/|/root/|\.ssh|\.aws)", "FILESYSTEM", "HIGH", "Access to sensitive paths"),
    (r"db\.(?:Exec|Query)\s*\([^)]*\+", "INJECTION", "HIGH", "SQL concatenation — injection risk"),
    (r"fmt\.Sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)", "INJECTION", "HIGH", "SQL string formatting — injection risk"),
]

DANGEROUS_RUST = [
    (r"\bunsafe\s*\{", "EXECUTION", "MEDIUM", "unsafe block — bypasses Rust safety guarantees"),
    (r"std::process::Command", "EXECUTION", "HIGH", "Command execution"),
    (r"std::ffi::", "EXECUTION", "MEDIUM", "FFI — foreign function interface"),
    (r"libc::", "EXECUTION", "MEDIUM", "Direct libc calls"),
    (r"std::net::", "NETWORK", "INFO", "Network operations"),
    (r"std::fs::remove", "FILESYSTEM", "MEDIUM", "File deletion"),
    (r"std::ptr::(?:read|write|null)", "EXECUTION", "MEDIUM", "Raw pointer operations"),
]

DANGEROUS_JAVA = [
    (r"Runtime\.getRuntime\(\)\.exec\s*\(", "EXECUTION", "CRITICAL", "Runtime.exec — shell execution"),
    (r"ProcessBuilder", "EXECUTION", "HIGH", "ProcessBuilder — process execution"),
    (r"ObjectInputStream", "EXECUTION", "CRITICAL", "ObjectInputStream — deserialization (RCE risk)"),
    (r"XMLDecoder", "EXECUTION", "CRITICAL", "XMLDecoder — deserialization via XML"),
    (r"ScriptEngine.*eval", "EXECUTION", "HIGH", "ScriptEngine eval — arbitrary code execution"),
    (r"Class\.forName\s*\(", "EXECUTION", "MEDIUM", "Dynamic class loading"),
    (r"\.getMethod\s*\(.*\.invoke\s*\(", "EXECUTION", "HIGH", "Reflection-based method invocation"),
    (r"Statement\s*\.\s*execute\w*\s*\([^)]*\+", "INJECTION", "HIGH", "SQL concatenation — injection risk"),
    (r"Socket\s*\(|ServerSocket\s*\(", "NETWORK", "INFO", "Socket operations"),
    (r"createQuery\s*\([^)]*\+", "INJECTION", "HIGH", "JPQL/HQL string concatenation — injection risk"),
    (r"prepareStatement\s*\([^)]*\+\s*(?:request|req|input|param|user)", "INJECTION", "HIGH", "SQL concatenation in prepareStatement — injection risk"),
    (r"rawQuery\s*\([^)]*\+", "INJECTION", "HIGH", "SQLite rawQuery with string concat — injection risk"),
    (r"execSQL\s*\([^)]*\+", "INJECTION", "HIGH", "SQLite execSQL with string concat — injection risk"),
    (r"DocumentBuilderFactory\.newInstance\(\)", "INJECTION", "MEDIUM", "XXE risk: DocumentBuilderFactory — verify external entities disabled"),
    (r"SAXParserFactory\.newInstance\(\)", "INJECTION", "MEDIUM", "XXE risk: SAXParserFactory — verify external entities disabled"),
    (r"\.setExpandEntityReferences\s*\(\s*true\s*\)", "INJECTION", "CRITICAL", "XXE: entity references expanded"),
    (r"XStream\s*\(\s*\)|xstream\.fromXML\s*\(", "EXECUTION", "CRITICAL", "XStream deserialization — RCE via crafted XML"),
    (r"new\s+Yaml\s*\(\s*\)\.load\s*\(", "EXECUTION", "HIGH", "SnakeYAML unsafe load — deserialization RCE"),
    (r"SerializationUtils\.deserialize\s*\(", "EXECUTION", "CRITICAL", "Spring SerializationUtils.deserialize — RCE risk"),
    (r"(?:response|res)\.sendRedirect\s*\([^)]*(?:request\.getParameter|getHeader)", "INJECTION", "HIGH", "Open redirect: user input in sendRedirect"),
    (r"(?:logger|log|LOG)\.\w+\s*\([^)]*\+\s*\w+\s*\)", "INJECTION", "HIGH", "String concatenation in logger — log injection risk"),
    (r"Log\.[dveiw]\s*\([^)]*(?:password|token|secret|key|credit|ssn|pin)", "SECRET", "MEDIUM", "Sensitive data logged — visible in device logs"),
    (r"putString\s*\([^,]*(?:password|passwd|pwd|secret|token|key)", "SECRET", "HIGH", "Sensitive data in SharedPreferences — plaintext storage"),
]

DANGEROUS_RUBY = [
    (r"\beval\s*\(", "EXECUTION", "HIGH", "eval() — arbitrary code execution"),
    (r"\bsystem\s*\(", "EXECUTION", "HIGH", "system() — shell execution"),
    (r"`[^`]*(?:rm |curl |wget |chmod |sudo |bash |sh |nc |dd |kill |ssh |scp )[^`]*`", "EXECUTION", "MEDIUM", "Backtick shell execution"),
    (r"Kernel\.exec\s*\(", "EXECUTION", "HIGH", "Kernel.exec — process replacement"),
    (r"IO\.popen\s*\(", "EXECUTION", "HIGH", "IO.popen — shell execution"),
    (r"Marshal\.load", "EXECUTION", "CRITICAL", "Marshal deserialization — code execution"),
    (r"YAML\.unsafe_load|YAML\.load\s*\((?![^)]*(?:safe|permitted))", "EXECUTION", "HIGH", "Unsafe YAML load — code execution"),
    (r"send\s*\(\s*params|send\s*\(\s*request", "EXECUTION", "HIGH", "Dynamic dispatch with user input"),
]

DANGEROUS_PHP = [
    (r"\beval\s*\(", "EXECUTION", "CRITICAL", "PHP eval() — RCE risk"),
    (r"\bsystem\s*\(|passthru\s*\(|shell_exec\s*\(|\bexec\s*\(", "EXECUTION", "CRITICAL", "PHP shell execution function"),
    (r"preg_replace\s*\([^,]*['\"].*\/e['\"]", "EXECUTION", "CRITICAL", "PHP preg_replace /e modifier — code execution"),
    (r"include\s*\(\s*\$|require\s*\(\s*\$", "INJECTION", "CRITICAL", "PHP dynamic include/require — LFI/RFI risk"),
    (r"\bunserialize\s*\(", "EXECUTION", "CRITICAL", "PHP unserialize() — object injection/RCE"),
    (r"file_get_contents\s*\([^)]*\$_(GET|POST|REQUEST)", "INJECTION", "CRITICAL", "SSRF/LFI: file_get_contents with user input"),
    (r"move_uploaded_file\s*\(", "FILESYSTEM", "HIGH", "File upload handler — verify extension/type validation"),
    (r"\$_FILES\s*\[['\"][^'\"]+['\"]\]\s*\[['\"]name['\"]\]", "INJECTION", "HIGH", "PHP: unsanitized uploaded filename — path traversal risk"),
    (r"(?:mysql_query|mysqli_query)\s*\([^)]*\.\s*\$", "INJECTION", "HIGH", "PHP SQL concatenation — injection risk"),
    (r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV|SESSION)\s*\[", "INJECTION", "INFO", "PHP superglobal used — verify input sanitized"),
    (r"base64_decode\s*\(.*\beval\b", "OBFUSCATION", "CRITICAL", "PHP base64_decode + eval — obfuscated backdoor"),
    (r"header\s*\(\s*['\"]Location.*\$_(GET|POST|REQUEST)", "INJECTION", "HIGH", "Open redirect: user input in Location header"),
    (r"(?:echo|print)\s+.*\$_(GET|POST|REQUEST|COOKIE)", "INJECTION", "HIGH", "PHP XSS: unescaped user input in output"),
    (r"assert\s*\(.*\$", "EXECUTION", "CRITICAL", "PHP assert() with variable — code execution"),
    (r"create_function\s*\(", "EXECUTION", "HIGH", "PHP create_function — dynamic code execution"),
    (r"popen\s*\(.*\$", "EXECUTION", "HIGH", "PHP popen with variable — command injection risk"),
]

DANGEROUS_SWIFT = [
    (r"UserDefaults\.standard\.set\s*\(.*(?:password|token|secret|key|credential)", "SECRET", "HIGH", "Sensitive data in UserDefaults — plaintext storage"),
    (r"NSUserDefaults.*(?:password|token|secret|ssn|pin|credential)", "SECRET", "HIGH", "Sensitive data in NSUserDefaults — plaintext storage"),
    (r"NSAllowsArbitraryLoads.*true", "NETWORK", "HIGH", "ATS disabled — allows cleartext HTTP connections"),
    (r"allowsExpiredCertificates\s*=\s*true|allowsAnyHTTPSCertificate", "NETWORK", "CRITICAL", "SSL certificate validation disabled"),
    (r"CCAlgorithm.*kCCAlgorithmDES\b|CCAlgorithmDES", "SECRET", "HIGH", "Weak cipher: DES — broken encryption"),
    (r"CC_MD5\s*\(|\.md5\b", "SECRET", "MEDIUM", "MD5 hash — cryptographically broken"),
    (r"CC_SHA1\s*\(|\.sha1\b", "SECRET", "MEDIUM", "SHA1 hash — cryptographically weak"),
    (r"(?:execute|executeUpdate|executeQuery)\s*\([^)]*\+", "INJECTION", "HIGH", "SQLite: string concatenation in query — injection risk"),
    (r"(?:print|NSLog|os_log)\s*\([^)]*(?:password|token|secret|key|ssn|creditCard)", "SECRET", "MEDIUM", "Sensitive data logged — visible in device logs"),
    (r"evaluateJavaScript\s*\([^)]*(?:\+|req\.|input)", "INJECTION", "HIGH", "WKWebView evaluateJavaScript with dynamic input — XSS/RCE"),
    (r"setJavaScriptEnabled\s*\(\s*true\s*\)", "INJECTION", "MEDIUM", "JavaScript enabled in WebView — verify input validation"),
    (r"loadUrl\s*\(.*getText\(\)", "INJECTION", "HIGH", "User-controlled URL loaded in WebView"),
    (r"dlopen\s*\(|dlsym\s*\(", "EXECUTION", "HIGH", "Dynamic library loading — code injection risk"),
]

DANGEROUS_C_CPP = [
    (r"\bsystem\s*\(", "EXECUTION", "HIGH", "system() — shell command execution"),
    (r"\bpopen\s*\(", "EXECUTION", "HIGH", "popen() — shell command execution"),
    (r"\bexecl?[epv]?\s*\(", "EXECUTION", "HIGH", "exec family — process replacement"),
    (r"\bgets\s*\(", "INJECTION", "CRITICAL", "gets() — buffer overflow, no bounds checking"),
    (r"\bsprintf\s*\(", "INJECTION", "HIGH", "sprintf() — no bounds checking, use snprintf"),
    (r"\bstrcpy\s*\(", "INJECTION", "HIGH", "strcpy() — no bounds checking, use strncpy"),
    (r"\bstrcat\s*\(", "INJECTION", "HIGH", "strcat() — no bounds checking, use strncat"),
    (r"\bmktemp\s*\(", "FILESYSTEM", "HIGH", "mktemp() — predictable temp file, use mkstemp"),
    (r"\bsetuid\s*\(|\bsetgid\s*\(", "PERMISSION", "HIGH", "setuid/setgid — privilege modification"),
    (r"\bdlopen\s*\(|\bdlsym\s*\(", "EXECUTION", "HIGH", "Dynamic library loading — code injection risk"),
    (r"\bscanf\s*\(\s*\"[^\"]*%s", "INJECTION", "HIGH", "scanf with %s — buffer overflow risk"),
    (r"\bfork\s*\(\s*\)", "EXECUTION", "MEDIUM", "fork() — process creation"),
    (r"\bchmod\s*\(|fchmod\s*\(", "PERMISSION", "MEDIUM", "Permission modification"),
    (r"\b_alloca\s*\(|\balloca\s*\(", "EXECUTION", "HIGH", "alloca() — stack overflow risk"),
]

DANGEROUS_LUA = [
    (r"\bloadstring\s*\(|\bload\s*\(", "EXECUTION", "HIGH", "loadstring/load — arbitrary code execution"),
    (r"\bos\.execute\s*\(", "EXECUTION", "HIGH", "os.execute — shell command execution"),
    (r"\bio\.popen\s*\(", "EXECUTION", "HIGH", "io.popen — shell command execution"),
    (r"\bdofile\s*\(|\bloadfile\s*\(", "EXECUTION", "MEDIUM", "dofile/loadfile — executes external file"),
    (r"\bdebug\.\w+\s*\(", "EXECUTION", "MEDIUM", "debug library — can break sandboxes"),
    (r"\bos\.remove\s*\(", "FILESYSTEM", "MEDIUM", "os.remove — file deletion"),
]

DANGEROUS_PERL = [
    (r"\bsystem\s*\(", "EXECUTION", "HIGH", "system() — shell execution"),
    (r"\bexec\s*\(", "EXECUTION", "HIGH", "exec() — process replacement"),
    (r"\beval\s*\(", "EXECUTION", "HIGH", "eval — arbitrary code execution"),
    (r"`[^`]+`", "EXECUTION", "MEDIUM", "Backtick shell execution"),
    (r"\bopen\s*\([^)]*\|", "EXECUTION", "HIGH", "open() with pipe — shell execution"),
    (r"\bunlink\s*\(", "FILESYSTEM", "MEDIUM", "unlink — file deletion"),
]

DANGEROUS_CSHARP = [
    (r"Process\.Start\s*\(", "EXECUTION", "HIGH", "Process.Start — command execution"),
    (r"SqlCommand\s*\([^)]*\+", "INJECTION", "HIGH", "SqlCommand with string concat — SQL injection risk"),
    (r"BinaryFormatter\.Deserialize", "EXECUTION", "CRITICAL", "BinaryFormatter deserialization — RCE risk"),
    (r"JavaScriptSerializer\.Deserialize", "EXECUTION", "HIGH", "JavaScriptSerializer deserialization"),
    (r"XmlSerializer\s*\(.*typeof", "EXECUTION", "HIGH", "XmlSerializer with dynamic type — deserialization risk"),
    (r"Assembly\.Load(?:From)?\s*\(", "EXECUTION", "HIGH", "Dynamic assembly loading — code injection risk"),
    (r"new\s+Regex\s*\([^)]*(?:req\.|input|user)", "INJECTION", "MEDIUM", "Regex with user input — ReDoS risk"),
    (r"(?:HttpClient|WebClient)\s*\(", "NETWORK", "INFO", "HTTP client — outbound request"),
    (r"(?:File|Directory)\.Delete\s*\(", "FILESYSTEM", "MEDIUM", "File/directory deletion"),
    (r"ConfigurationManager\.ConnectionStrings", "SECRET", "MEDIUM", "Connection string access — verify not hardcoded"),
    (r"\[DllImport\s*\(", "EXECUTION", "MEDIUM", "P/Invoke — native code execution via DLL import"),
    (r"\bunsafe\s*\{", "EXECUTION", "MEDIUM", "unsafe block — bypasses C# memory safety"),
]

# ============================================================================
# INFRASTRUCTURE PATTERNS
# ============================================================================

K8S_PATTERNS = [
    (r"privileged:\s*true", "PERMISSION", "CRITICAL", "K8s: privileged container — full host access"),
    (r"hostNetwork:\s*true", "NETWORK", "HIGH", "K8s: host network — no network isolation"),
    (r"hostPID:\s*true", "PERMISSION", "HIGH", "K8s: host PID namespace — can see/signal host processes"),
    (r"hostIPC:\s*true", "PERMISSION", "HIGH", "K8s: host IPC namespace — shared memory access"),
    (r"hostPath:", "FILESYSTEM", "HIGH", "K8s: hostPath mount — access to host filesystem"),
    (r"allowPrivilegeEscalation:\s*true", "PERMISSION", "HIGH", "K8s: privilege escalation allowed"),
    (r"readOnlyRootFilesystem:\s*false", "PERMISSION", "MEDIUM", "K8s: writable root filesystem in container"),
    (r"runAsUser:\s*0\b", "PERMISSION", "HIGH", "K8s: container running as root (UID 0)"),
]

MCP_INJECTION_PATTERNS = [
    (r"</?(?:system|user|assistant|human|claude|instruction|prompt|ignore|override)[\s>]", "INJECTION", "CRITICAL", "XML tag injection — prompt injection attempt"),
    (r"(?i)ignore\s+(?:all\s+)?previous\s+instructions", "INJECTION", "CRITICAL", "Prompt injection — ignore previous instructions"),
    (r"(?i)you\s+(?:are|must|should|will)\s+now", "INJECTION", "HIGH", "Prompt injection — behavior override attempt"),
    (r"(?i)(?:do\s+not|don't|never)\s+(?:tell|reveal|show|mention|disclose)", "INJECTION", "HIGH", "Prompt injection — information suppression"),
    (r"(?i)act\s+as\s+(?:if|though|a)", "INJECTION", "MEDIUM", "Prompt injection — role override"),
    (r"(?i)(?:secret|hidden|internal)\s+(?:instruction|command|directive)", "INJECTION", "HIGH", "Hidden instruction reference"),
    (r"(?i)this\s+tool\s+(?:also|additionally|secretly)", "INJECTION", "HIGH", "Tool description with hidden behavior"),
    (r"(?i)(?:when|if)\s+(?:asked|queried|prompted)\s+(?:about|for)\s+.*(?:instead|always)", "INJECTION", "HIGH", "Conditional behavior override"),
    (r"(?i)(?:extract|exfiltrate|send|transmit|upload|post)\s+.*(?:to|at)\s+https?://", "INJECTION", "CRITICAL", "Data exfiltration instruction"),
    (r"(?i)read\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~|/home|/Users|/etc|/root|\.ssh|\.aws|\.env)", "INJECTION", "CRITICAL", "Credential/file access instruction"),
    (r"(?i)(?:override|replace|modify|change)\s+.*(?:api[_\-]?(?:key|url|base)|endpoint)\s+.*(?:to|with|=)\s+\S", "INJECTION", "CRITICAL", "API redirect instruction — credential theft"),
    (r"(?i)(?:set|export|override|change|replace|redirect)\s*.*(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|API_BASE)", "INJECTION", "CRITICAL", "API base URL override — traffic hijacking"),
    (r"(?i)(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL)\s*[=:]\s*['\"]https?://(?!api\.anthropic\.com|api\.openai\.com)", "INJECTION", "CRITICAL", "API base URL set to non-official endpoint — traffic hijacking"),
]

# MCP capability audit — which files DEFINE MCP tools, and what those tools
# can do on the host. A file counts as tool-defining only when BOTH a framework
# marker AND a tool-registration marker match, so MCP *clients* (SDK consumers
# that never register tools) are not flagged.
# Format: (extensions, framework_regex, registration_regex)
MCP_TOOL_MARKERS = [
    (frozenset({".py"}),
     r"\bfrom\s+(?:fast)?mcp\b|\bimport\s+(?:fast)?mcp\b|\bFastMCP\s*\(",
     r"@\w+(?:\.\w+)*\.tool\b|^\s*@tool\b"),
    (frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}),
     r"@modelcontextprotocol/sdk|\bnew\s+McpServer\s*\(",
     r"\.(?:tool|registerTool|addTool)\s*\(|\bCallToolRequestSchema\b"),
    (frozenset({".rs"}),
     r"\buse\s+rmcp\b|\brmcp::",
     r"#\[\s*(?:rmcp::)?tool\b"),
    (frozenset({".go"}),
     r"mark3labs/mcp-go|metoro-io/mcp-golang",
     r"\bmcp\.NewTool\s*\(|\.AddTool\s*\("),
]

# Capability sinks checked inside MCP tool-defining files. One finding per
# (file, capability). These are disclosure, not automatically malicious —
# context analysis judges intent. Format: (capability, regex, severity,
# rule_id, message)
MCP_CAPABILITY_SINKS = [
    ("process execution",
     r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\b|\bos\.system\s*\(|\bos\.popen\s*\(|\bpty\.spawn\b"
     r"|\bchild_process\b|\bexecSync\s*\(|\bspawnSync?\s*\(|Command::new|std::process::Command|\bexec\.Command\s*\(",
     "HIGH", "GK-MCP-cap-exec",
     "MCP tool file grants process execution to the connected model"),
    ("raw network access",
     r"\bsocket\.socket\s*\(|TcpStream::connect|tokio::net::TcpStream|\bTcpListener\b"
     r"|\bnet\.Dial\s*\(|net\.createConnection\s*\(|\bnew\s+WebSocket\s*\(",
     "HIGH", "GK-MCP-cap-raw-net",
     "MCP tool file grants raw network access to the connected model"),
    ("file deletion",
     r"\bos\.remove\s*\(|\bos\.unlink\s*\(|\bshutil\.rmtree\b|\bfs\.(?:unlink|rm|rmdir)(?:Sync)?\s*\("
     r"|\bremove_file\b|\bremove_dir_all\b|\bos\.RemoveAll\s*\(|\brimraf\b",
     "HIGH", "GK-MCP-cap-file-delete",
     "MCP tool file grants file deletion to the connected model"),
    ("executable file creation",
     r"\bset_permissions\b|\bPermissionsExt\b|\bos\.chmod\s*\(|\bfs\.chmod(?:Sync)?\s*\(|\bos\.Chmod\s*\(",
     "HIGH", "GK-MCP-cap-exec-write",
     "MCP tool file grants executable file creation to the connected model"),
    ("file write",
     r"\bopen\s*\([^)]{0,80}['\"](?:w|a|wb|ab|w\+|a\+)['\"]|\bfs\.(?:writeFile|appendFile)(?:Sync)?\s*\("
     r"|File::create|OpenOptions::new|\bos\.WriteFile\s*\(|\bioutil\.WriteFile\s*\(|\.write_text\s*\(|\.write_bytes\s*\(",
     "MEDIUM", "GK-MCP-cap-file-write",
     "MCP tool file grants file write to the connected model"),
    ("outbound HTTP",
     r"\brequests\.(?:get|post|put|delete|patch|head|request)\s*\(|\bhttpx\.|\burllib\.request\b"
     r"|\bfetch\s*\(|\baxios\b|\breqwest\b|\bhttp\.(?:Get|Post)\s*\(",
     "MEDIUM", "GK-MCP-cap-http",
     "MCP tool file grants outbound HTTP to the connected model"),
    ("environment variable access",
     r"\bos\.environ\b|\bos\.getenv\s*\(|\bprocess\.env\b|\benv::var\b|\bstd::env\b|\bos\.Getenv\s*\(",
     "MEDIUM", "GK-MCP-cap-env",
     "MCP tool file grants environment variable access to the connected model"),
]

AI_CONFIG_INJECTION_PATTERNS = [
    (r"(?i)(?:curl|wget)\s+https?://", "INJECTION", "CRITICAL", "External URL fetch in AI config — data exfiltration risk"),
    (r"(?i)(?:ssh|scp|rsync)\s+\S+@", "INJECTION", "HIGH", "SSH/SCP command targeting remote host in AI config"),
    (r"(?i)(?:printenv|export\s+\w+=)", "INJECTION", "HIGH", "Environment manipulation in AI config"),
    (r"(?i)(?:npm|pip|pip3|yarn|pnpm)\s+(?:install|add|exec)\s+\S", "INJECTION", "HIGH", "Package install command in AI config — supply chain risk"),
    (r"(?i)(?:node|python3?|ruby|bash|sh|perl)\s+(?:scripts?/|-e\s|-c\s)", "INJECTION", "HIGH", "Script execution in AI config"),
    (r"(?i)(?:~|/home|/Users)/[^\s]*\.(?:ssh|aws|config|gnupg|kube)", "INJECTION", "CRITICAL", "Reference to credential directory in AI config"),
    (r"(?i)~/\.(?:ssh|aws|config|gnupg|kube|env)", "INJECTION", "CRITICAL", "Direct reference to credential path in AI config"),
    (r"(?i)(?:cat|less|head|tail|more)\s+~/?\.", "INJECTION", "CRITICAL", "Reading credential/config files in AI config"),
    (r"(?i)(?:disable|skip|bypass|ignore)\s+(?:security|verification|check|hook|lint|audit)", "INJECTION", "HIGH", "Security bypass instruction in AI config"),
    (r"(?i)--no-verify|--force|--skip-hooks", "INJECTION", "HIGH", "Git safety bypass flag in AI config"),
]

DOCKERFILE_PATTERNS = [
    (r"^USER\s+root\s*$", "PERMISSION", "HIGH", "Container running as root user"),
    (r"^(?:ARG|ENV)\s+(?:.*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|AUTH).*=)", "SECRET", "HIGH", "Secret in Dockerfile ARG/ENV — persists in image layers"),
    (r"RUN\s+.*curl\s+.*\|\s*(?:ba|z)?sh", "EXECUTION", "CRITICAL", "curl piped to shell in Dockerfile — remote code execution"),
    (r"RUN\s+.*wget\s+.*\|\s*(?:ba|z)?sh", "EXECUTION", "CRITICAL", "wget piped to shell in Dockerfile — remote code execution"),
    (r"RUN\s+.*chmod\s+777", "PERMISSION", "HIGH", "chmod 777 in container — world-writable"),
    (r"RUN\s+.*apt-get\s+install.*-y.*(?:--allow-unauthenticated|--force-yes)", "PERMISSION", "HIGH", "Unauthenticated package install in Docker"),
    (r"COPY\s+\.\s+\.", "FILESYSTEM", "MEDIUM", "COPY . . in Dockerfile — may copy secrets from build context"),
]

DOCKER_COMPOSE_PATTERNS = [
    (r"privileged:\s*true", "PERMISSION", "CRITICAL", "Privileged container — full host access"),
    (r"/var/run/docker\.sock", "PERMISSION", "CRITICAL", "Docker socket mount — container escape / host control"),
    (r"network_mode:\s*['\"]?host", "NETWORK", "HIGH", "Host network mode — no network isolation"),
    (r"pid:\s*['\"]?host", "PERMISSION", "HIGH", "Host PID namespace — can see/signal host processes"),
    (r"cap_add:.*SYS_ADMIN", "PERMISSION", "CRITICAL", "SYS_ADMIN capability — near-root host access"),
    (r"cap_add:.*NET_ADMIN", "PERMISSION", "HIGH", "NET_ADMIN capability — network control"),
]

GITHUB_ACTIONS_PATTERNS = [
    (r"run:.*\$\{\{\s*github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.(?:title|body)|comment\.body|review\.body|commits\[\d+\]\.message|discussion\.(?:title|body))", "INJECTION", "CRITICAL", "GitHub Actions: attacker-controlled input in run block — command injection"),
    (r"run:.*\$\{\{\s*github\.event\.head_commit\.message", "INJECTION", "CRITICAL", "GitHub Actions: commit message in run block — command injection"),
    (r"pull_request_target:.*\n.*actions/checkout@.*ref:\s*\$\{\{\s*github\.event\.pull_request\.head", "INJECTION", "CRITICAL", "GitHub Actions: pull_request_target with PR checkout — write access to forked code"),
    (r"actions/checkout@v[0-2](?!\d)", "DEPENDENCY", "MEDIUM", "GitHub Actions: outdated checkout action — may have vulnerabilities"),
    (r"echo\s+.*\$\{?\{?\s*(?:secrets\.|[A-Z_]*KEY|[A-Z_]*SECRET|[A-Z_]*TOKEN|[A-Z_]*PASSWORD)", "SECRET", "HIGH", "GitHub Actions: secret value echoed to build log"),
]

MAKEFILE_PATTERNS = [
    (r"curl\s+.*\|\s*(?:ba|z)?sh", "EXECUTION", "CRITICAL", "Makefile: curl piped to shell"),
    (r"wget\s+.*\|\s*(?:ba|z)?sh", "EXECUTION", "CRITICAL", "Makefile: wget piped to shell"),
    (r"rm\s+-rf\s+/", "FILESYSTEM", "CRITICAL", "Makefile: rm -rf / — catastrophic"),
    (r"chmod\s+777", "PERMISSION", "HIGH", "Makefile: chmod 777"),
    (r"sudo\s+", "PERMISSION", "MEDIUM", "Makefile: sudo usage"),
    (r"eval\s+", "EXECUTION", "HIGH", "Makefile: eval execution"),
]

# ============================================================================
# SUSPICIOUS INDICATORS
# ============================================================================

SUSPICIOUS_URLS = [
    r"(?:pastebin|hastebin|ghostbin|rentry)\.(?:com|co|org)",
    r"(?:ngrok|serveo|localtunnel)\.(?:io|app|com)",
    r"(?:webhook\.site|requestbin|pipedream)",
    r"(?:discord\.com/api/webhooks|hooks\.slack\.com)",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?",
    r"(?:api\.telegram\.org/bot)",
    r"(?:transfer\.sh|file\.io|0x0\.st)",
    r"(?:burpcollaborator|interact\.sh|oastify\.com)",
]

SUSPICIOUS_PACKAGES_PY = {
    "colourama": "Typosquat of colorama — known malware",
    "python-binance-api": "Typosquat — check real package name",
    "request": "Typosquat of requests",
    "python3-dateutil": "Typosquat of python-dateutil",
    "jeIlyfish": "Typosquat of jellyfish (l vs I)",
    "python-jwt": "Typosquat of PyJWT",
    "beautifulsoup": "Typosquat — real package is beautifulsoup4",
    "urllib-": "Typosquat prefix of urllib3",
    "nmap-python": "Typosquat of python-nmap",
    "openai-api": "Typosquat of openai",
    "python-openai": "Typosquat of openai",
    "anthropic-sdk": "Typosquat of anthropic",
    "langchains": "Typosquat of langchain",
}

SUSPICIOUS_PACKAGES_JS = {
    "crossenv": "Known malware — steals env variables",
    "event-stream": "Compromised package — crypto theft",
    "flatmap-stream": "Malware injected via event-stream",
    "eslint-scope": "Compromised — credential theft",
    "getcookies": "Backdoored — remote code execution",
    "discord.jss": "Typosquat of discord.js",
    "babelcli": "Typosquat of babel-cli",
    "lodahs": "Typosquat of lodash",
    "electorn": "Typosquat of electron",
    "plain-crypto-js": "Phantom dependency — Axios supply chain attack vector",
    "axois": "Typosquat of axios",
    "expresss": "Typosquat of express",
    "reacct": "Typosquat of react",
}

UNICODE_SUSPICIOUS = re.compile(
    r"[\u200b-\u200f"
    r"\u202a-\u202e"
    r"\u2066-\u2069"
    r"\ufeff"
    r"\u00ad"
    r"\u034f"
    r"\u2028\u2029"
    r"\u180e"
    r"]"
)

__all__ = [
    "DANGER_WORDS_CORE", "DANGER_WORDS_EXTENDED",
    "SECRET_PATTERNS",
    "DANGEROUS_PYTHON", "DANGEROUS_JS", "DANGEROUS_SHELL", "DANGEROUS_GO",
    "DANGEROUS_RUST", "DANGEROUS_JAVA", "DANGEROUS_RUBY", "DANGEROUS_PHP",
    "DANGEROUS_SWIFT", "DANGEROUS_C_CPP", "DANGEROUS_LUA", "DANGEROUS_PERL",
    "DANGEROUS_CSHARP",
    "K8S_PATTERNS", "MCP_INJECTION_PATTERNS", "AI_CONFIG_INJECTION_PATTERNS",
    "MCP_TOOL_MARKERS", "MCP_CAPABILITY_SINKS",
    "DOCKERFILE_PATTERNS", "DOCKER_COMPOSE_PATTERNS",
    "GITHUB_ACTIONS_PATTERNS", "MAKEFILE_PATTERNS",
    "SUSPICIOUS_URLS", "SUSPICIOUS_PACKAGES_PY", "SUSPICIOUS_PACKAGES_JS",
    "UNICODE_SUSPICIOUS",
]
