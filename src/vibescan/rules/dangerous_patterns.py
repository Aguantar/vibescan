"""DangerousPatternRule - detects dangerous code patterns.

Uses: text_files
Covers: Python, JavaScript/TypeScript, SQL injection patterns.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule


# ---------------------------------------------------------------------------
# Pattern definition: (regex, severity, message, why, fix)
# ---------------------------------------------------------------------------

_PY = "py"
_JS = "js"
_SQL = "sql"

PatternDef = tuple[re.Pattern[str], Severity, str, str, str]

# ---- Python patterns ----
PYTHON_PATTERNS: list[PatternDef] = [
    (
        re.compile(r'\beval\s*\('),
        Severity.HIGH,
        "Use of eval() detected",
        "eval() executes arbitrary Python code. If user input reaches eval(), "
        "an attacker can run any code on your server (Remote Code Execution).",
        "Use ast.literal_eval() for safe literal parsing, or redesign to "
        "avoid dynamic code execution entirely.",
    ),
    (
        re.compile(r'\bexec\s*\('),
        Severity.HIGH,
        "Use of exec() detected",
        "exec() executes arbitrary Python statements. It poses the same "
        "Remote Code Execution risk as eval().",
        "Avoid exec(). Use structured data, dispatch tables, or a safe "
        "DSL instead of executing dynamic code.",
    ),
    (
        re.compile(r'subprocess\.\w+\(.*shell\s*=\s*True', re.DOTALL),
        Severity.HIGH,
        "subprocess with shell=True detected",
        "shell=True passes the command through the system shell, enabling "
        "command injection if any part comes from user input.",
        "Use shell=False (the default) and pass arguments as a list: "
        "subprocess.run(['cmd', 'arg1', 'arg2']).",
    ),
    (
        re.compile(r'\bos\.system\s*\('),
        Severity.HIGH,
        "Use of os.system() detected",
        "os.system() runs commands through the shell, vulnerable to "
        "command injection attacks.",
        "Use subprocess.run() with shell=False instead.",
    ),
    (
        re.compile(r'\bpickle\.loads?\s*\('),
        Severity.HIGH,
        "Use of pickle.load(s)() detected",
        "Deserializing untrusted pickle data can execute arbitrary code. "
        "This is a known Remote Code Execution vector.",
        "Use JSON or other safe serialization formats for untrusted data. "
        "If pickle is required, only load data from trusted sources.",
    ),
    (
        re.compile(r'yaml\.load\s*\([^)]*\)(?!.*Loader)'),
        Severity.MEDIUM,
        "yaml.load() without explicit Loader",
        "yaml.load() without a safe Loader can execute arbitrary Python "
        "objects embedded in YAML, leading to code execution.",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
    ),
    (
        re.compile(r'\bDEBUG\s*=\s*True\b'),
        Severity.MEDIUM,
        "DEBUG = True in code",
        "Debug mode in production exposes detailed error pages, stack "
        "traces, and internal state to attackers.",
        "Set DEBUG via environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'. "
        "Ensure it's False in production.",
    ),
    (
        re.compile(r"""ALLOWED_HOSTS\s*=\s*\[['"]?\*['"]?\]"""),
        Severity.MEDIUM,
        "ALLOWED_HOSTS = ['*'] detected",
        "Allowing all hosts disables Django's host header validation, "
        "enabling HTTP Host header attacks.",
        "Set ALLOWED_HOSTS to your actual domain names: "
        "ALLOWED_HOSTS = ['example.com', 'www.example.com'].",
    ),
    (
        re.compile(r'CORS_ALLOW_ALL_ORIGINS\s*=\s*True'),
        Severity.MEDIUM,
        "CORS_ALLOW_ALL_ORIGINS = True",
        "Allowing all CORS origins lets any website make authenticated "
        "requests to your API, potentially stealing user data.",
        "Set CORS_ALLOWED_ORIGINS to specific trusted domains.",
    ),
    (
        re.compile(r'verify\s*=\s*False'),
        Severity.MEDIUM,
        "SSL verification disabled (verify=False)",
        "Disabling SSL certificate verification makes the connection "
        "vulnerable to man-in-the-middle attacks.",
        "Remove verify=False. Fix the underlying certificate issue instead. "
        "Use certifi package if CA bundle is missing.",
    ),
    (
        re.compile(r'hashlib\.(?:md5|sha1)\s*\('),
        Severity.LOW,
        "Weak hash algorithm (MD5/SHA1) used",
        "MD5 and SHA1 are cryptographically broken. If used for password "
        "hashing or security-sensitive operations, they can be attacked.",
        "Use hashlib.sha256() or bcrypt/argon2 for password hashing.",
    ),
]

# ---- JavaScript / TypeScript patterns ----
JS_PATTERNS: list[PatternDef] = [
    (
        re.compile(r'[^.]\beval\s*\('),
        Severity.HIGH,
        "Use of eval() detected",
        "eval() executes arbitrary JavaScript code. If user input reaches "
        "eval(), attackers can steal data or hijack sessions (XSS).",
        "Use JSON.parse() for data, or structured alternatives. "
        "Never eval() user-controlled input.",
    ),
    (
        re.compile(r'\.innerHTML\s*='),
        Severity.HIGH,
        "Direct innerHTML assignment detected",
        "Setting innerHTML with unsanitized data is a primary XSS vector. "
        "Attackers can inject scripts that steal cookies and credentials.",
        "Use textContent for plain text, or DOMPurify.sanitize() for HTML. "
        "In React, avoid dangerouslySetInnerHTML.",
    ),
    (
        re.compile(r'dangerouslySetInnerHTML'),
        Severity.HIGH,
        "dangerouslySetInnerHTML used in React",
        "This bypasses React's XSS protection. If the HTML comes from "
        "user input or an external source, it enables XSS attacks.",
        "Use sanitization libraries like DOMPurify before passing HTML, "
        "or restructure to avoid raw HTML injection.",
    ),
    (
        re.compile(r'child_process\.exec\s*\('),
        Severity.HIGH,
        "child_process.exec() detected",
        "exec() runs commands through the shell, enabling command injection "
        "if arguments include user input.",
        "Use child_process.execFile() or spawn() with arguments as an array.",
    ),
    (
        re.compile(r'document\.write\s*\('),
        Severity.MEDIUM,
        "document.write() detected",
        "document.write() can inject arbitrary HTML/scripts into the page, "
        "creating XSS vulnerabilities.",
        "Use DOM manipulation methods: createElement(), appendChild(), "
        "or textContent.",
    ),
    (
        re.compile(r"""cors\s*\(\s*\{[^}]*origin\s*:\s*['"]?\*['"]?"""),
        Severity.MEDIUM,
        "CORS with wildcard origin: '*'",
        "Allowing all CORS origins lets any website make requests to your "
        "API, potentially accessing sensitive data.",
        "Set origin to specific trusted domains: "
        "cors({ origin: ['https://myapp.com'] }).",
    ),
    (
        re.compile(r'jwt\.decode\s*\('),
        Severity.MEDIUM,
        "jwt.decode() without verification",
        "jwt.decode() does not verify the token signature. Attackers can "
        "forge tokens with arbitrary claims.",
        "Use jwt.verify() instead, which validates the signature.",
    ),
    (
        re.compile(r'eslint-disable.*(?:no-eval|security)'),
        Severity.MEDIUM,
        "Security-related ESLint rule disabled",
        "Disabling security ESLint rules removes automated detection of "
        "dangerous patterns in this code section.",
        "Fix the underlying issue instead of disabling the rule. "
        "If intentional, add a comment explaining why.",
    ),
]

# ---- SQL injection patterns ----
SQL_PATTERNS: list[PatternDef] = [
    (
        re.compile(r'''f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{''', re.IGNORECASE),
        Severity.CRITICAL,
        "SQL query built with f-string interpolation",
        "Embedding variables directly in SQL via f-strings enables SQL "
        "injection. Attackers can read, modify, or delete all database data.",
        "Use parameterized queries: cursor.execute('SELECT * FROM users "
        "WHERE id = %s', (user_id,)).",
    ),
    (
        re.compile(r'''`(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\$\{''', re.IGNORECASE),
        Severity.CRITICAL,
        "SQL query built with template literal interpolation",
        "Embedding variables in SQL via template literals enables SQL "
        "injection attacks.",
        "Use parameterized queries with your ORM or query builder: "
        "db.query('SELECT * FROM users WHERE id = $1', [userId]).",
    ),
    (
        re.compile(
            r'''["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*["']\s*\+''',
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "SQL query built with string concatenation",
        "Concatenating user input into SQL strings is the classic SQL "
        "injection vulnerability.",
        "Use parameterized queries or an ORM. Never build SQL from "
        "string concatenation.",
    ),
    (
        re.compile(
            r'''\+\s*["'](?:\s*(?:WHERE|AND|OR|SET|VALUES)\b)''',
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "SQL clause built with string concatenation",
        "Appending SQL clauses via string concatenation suggests "
        "dynamic query building vulnerable to injection.",
        "Use parameterized queries or a query builder library.",
    ),
]

# Map file extensions to applicable pattern sets
EXTENSION_MAP: dict[str, list[list[PatternDef]]] = {
    ".py": [PYTHON_PATTERNS, SQL_PATTERNS],
    ".js": [JS_PATTERNS, SQL_PATTERNS],
    ".jsx": [JS_PATTERNS, SQL_PATTERNS],
    ".ts": [JS_PATTERNS, SQL_PATTERNS],
    ".tsx": [JS_PATTERNS, SQL_PATTERNS],
    ".mjs": [JS_PATTERNS, SQL_PATTERNS],
    ".cjs": [JS_PATTERNS, SQL_PATTERNS],
    ".vue": [JS_PATTERNS, SQL_PATTERNS],
    ".svelte": [JS_PATTERNS, SQL_PATTERNS],
    # SQL-only files
    ".sql": [SQL_PATTERNS],
    ".rb": [SQL_PATTERNS],
    ".php": [SQL_PATTERNS],
    ".java": [SQL_PATTERNS],
    ".go": [SQL_PATTERNS],
    ".rs": [SQL_PATTERNS],
}


class DangerousPatternRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for tf in ctx.text_files:
            ext = PurePosixPath(tf.path).suffix.lower()
            pattern_sets = EXTENSION_MAP.get(ext)
            if not pattern_sets:
                continue

            lines = tf.content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue

                for pset in pattern_sets:
                    for regex, severity, message, why, fix in pset:
                        if regex.search(line):
                            issues.append(Issue(
                                rule_id="DANGER-CODE",
                                severity=severity,
                                file=tf.path,
                                line=line_no,
                                message=message,
                                why=why,
                                fix=fix,
                            ))

        return issues
