"""Rule 3-B: Configuration files with potential hardcoded secrets."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule
from vibescan.rules.secret._filters import is_false_positive_value

# Files that commonly contain hardcoded credentials
SENSITIVE_CONFIG_NAMES: set[str] = {
    "config.py", "settings.py", "config.js", "config.ts",
    "config.yaml", "config.yml", "config.toml",
    "application.properties", "application.yml",
    "appsettings.json", "appsettings.Development.json",
    "wp-config.php", "alembic.ini",
    "knexfile.js", "ormconfig.json",
    "database.yml", "secrets.yml",
}

# Patterns inside prisma/.env are also sensitive
SENSITIVE_PATH_PATTERNS: list[str] = [
    "prisma/.env",
]

SECRET_VALUE_RE = re.compile(
    r'''(?:password|passwd|secret|token|api_key|apikey|auth_token|'''
    r'''access_key|private_key|client_secret|database_url|db_pass)'''
    r'''\s*[:=]\s*["']([^"']{4,})["']''',
    re.IGNORECASE,
)


class ConfigHardcodeRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        # Check text files whose name matches sensitive configs
        for tf in ctx.text_files:
            name = PurePosixPath(tf.path).name
            is_sensitive = (
                name in SENSITIVE_CONFIG_NAMES
                or any(tf.path.endswith(p) for p in SENSITIVE_PATH_PATTERNS)
            )
            if not is_sensitive:
                continue

            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                m = SECRET_VALUE_RE.search(line)
                if m and not is_false_positive_value(m.group(1)):
                    issues.append(Issue(
                        rule_id="SECRET-CONFIG",
                        severity=Severity.HIGH,
                        file=tf.path,
                        line=line_no,
                        message=f"Hardcoded secret in config file '{name}'",
                        why="Configuration files with hardcoded credentials "
                            "are often committed to version control, exposing "
                            "secrets to anyone with repository access.",
                        fix="Use environment variables or a secrets manager. "
                            "Reference them in config: os.environ['DB_PASSWORD'].",
                    ))

        return issues
