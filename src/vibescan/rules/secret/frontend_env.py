"""Rule 3-I: Frontend environment variable exposure."""

from __future__ import annotations

import re

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

# Frontend env prefixes that get bundled into client-side code
FRONTEND_PREFIXES = (
    "NEXT_PUBLIC_", "VITE_", "REACT_APP_",
    "NUXT_PUBLIC_", "EXPO_PUBLIC_",
)

# Dangerous suffixes when combined with public prefixes
DANGEROUS_SUFFIXES_RE = re.compile(
    r'(?:SECRET|PASSWORD|PRIVATE|PRIVATE_KEY|DB_|DATABASE_)',
    re.IGNORECASE,
)

# Exclude false positives
SAFE_SUFFIXES_RE = re.compile(
    r'(?:PUBLIC_KEY|PUBLIC_URL|PUBLIC_API_URL)',
    re.IGNORECASE,
)

ASSIGNMENT_RE = re.compile(
    r'^([A-Z_]+)\s*=\s*(.+)$',
)


class FrontendEnvRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for tf in ctx.text_files:
            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                match = ASSIGNMENT_RE.match(stripped)
                if not match:
                    continue

                var_name = match.group(1)

                # Must start with a frontend prefix
                if not any(var_name.startswith(p) for p in FRONTEND_PREFIXES):
                    continue

                # Skip safe patterns
                if SAFE_SUFFIXES_RE.search(var_name):
                    continue

                # Check for dangerous suffix
                if DANGEROUS_SUFFIXES_RE.search(var_name):
                    issues.append(Issue(
                        rule_id="SECRET-FRONTEND-ENV",
                        severity=Severity.HIGH,
                        file=tf.path,
                        line=line_no,
                        message=f"Sensitive value in public frontend env var '{var_name}'",
                        why=f"Variables with prefix like NEXT_PUBLIC_ or VITE_ "
                            f"are embedded in the client-side JavaScript bundle "
                            f"and visible to all users. '{var_name}' suggests "
                            f"a secret value.",
                        fix="Move the secret to a server-side-only env var "
                            "(without the public prefix) and access it via "
                            "an API route instead.",
                    ))

        return issues
