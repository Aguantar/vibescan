"""Rule 3-H: Hardcoded secrets in code (regex + variable name patterns)."""

from __future__ import annotations

import re

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule
from vibescan.rules.secret._filters import is_false_positive_value

# API key prefixes that strongly indicate real secrets
API_KEY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), "OpenAI-style API key"),
    (re.compile(r'sk-ant-[a-zA-Z0-9\-]{20,}'), "Anthropic API key"),
    (re.compile(r'pk_live_[a-zA-Z0-9]{20,}'), "Stripe live publishable key"),
    (re.compile(r'pk_test_[a-zA-Z0-9]{20,}'), "Stripe test publishable key"),
    (re.compile(r'rk_live_[a-zA-Z0-9]{20,}'), "Stripe restricted key"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub personal access token"),
    (re.compile(r'glpat-[a-zA-Z0-9\-]{20,}'), "GitLab personal access token"),
    (re.compile(r'xox[bp]-[a-zA-Z0-9\-]{20,}'), "Slack token"),
]

# Variable assignment patterns: password = "...", API_KEY: "..."
VARIABLE_PATTERN = re.compile(
    r'''(?:password|passwd|secret|token|api_key|apikey|auth_token|'''
    r'''access_key|private_key|client_secret)'''
    r'''\s*[:=]\s*["']([^"']{8,})["']''',
    re.IGNORECASE,
)


# Connection strings with credentials
CONN_STRING_PATTERN = re.compile(
    r'(?:mongodb|postgres|postgresql|mysql|redis|amqp)://\S+:\S+@',
    re.IGNORECASE,
)

# Webhook URLs
WEBHOOK_PATTERN = re.compile(
    r'https?://(?:hooks\.slack\.com/services/|discord\.com/api/webhooks/)\S+',
)


class HardcodedPatternsRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for tf in ctx.text_files:
            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                # API key prefixes
                for pattern, desc in API_KEY_PATTERNS:
                    if pattern.search(line):
                        issues.append(Issue(
                            rule_id="SECRET-HARDCODED",
                            severity=Severity.CRITICAL,
                            file=tf.path,
                            line=line_no,
                            message=f"Possible {desc} detected",
                            why="Hardcoded API keys in source code can be "
                                "extracted by anyone with repository access and "
                                "used to compromise your services.",
                            fix="Move the key to an environment variable or a "
                                "secrets manager. Rotate the exposed key immediately.",
                        ))
                        break  # one issue per line

                # Variable assignments
                var_match = VARIABLE_PATTERN.search(line)
                if var_match:
                    value = var_match.group(1)
                    if not is_false_positive_value(value):
                        issues.append(Issue(
                            rule_id="SECRET-HARDCODED",
                            severity=Severity.HIGH,
                            file=tf.path,
                            line=line_no,
                            message="Possible hardcoded secret in variable assignment",
                            why="Secrets stored directly in code are visible to "
                                "anyone with access to the repository.",
                            fix="Use environment variables or a secrets manager "
                                "instead of hardcoding values.",
                        ))

                # Connection strings
                if CONN_STRING_PATTERN.search(line):
                    issues.append(Issue(
                        rule_id="SECRET-HARDCODED",
                        severity=Severity.HIGH,
                        file=tf.path,
                        line=line_no,
                        message="Database connection string with credentials detected",
                        why="Connection strings containing passwords expose "
                            "database access to anyone who can read the code.",
                        fix="Use environment variables for connection strings: "
                            "DATABASE_URL=postgres://...",
                    ))

                # Webhooks
                if WEBHOOK_PATTERN.search(line):
                    issues.append(Issue(
                        rule_id="SECRET-HARDCODED",
                        severity=Severity.MEDIUM,
                        file=tf.path,
                        line=line_no,
                        message="Webhook URL detected in source code",
                        why="Exposed webhook URLs can be abused to send "
                            "unauthorized messages.",
                        fix="Store webhook URLs in environment variables.",
                    ))

        return issues
