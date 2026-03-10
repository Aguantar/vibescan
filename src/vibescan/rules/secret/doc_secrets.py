"""Rule 3-K: Secrets accidentally left in documentation."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule
from vibescan.rules.secret._filters import is_false_positive_value

DOC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'README\.md$', re.IGNORECASE),
    re.compile(r'CONTRIBUTING\.md$', re.IGNORECASE),
    re.compile(r'docs/.*\.md$', re.IGNORECASE),
]

# Patterns that suggest real secrets pasted in docs
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), "API key"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub token"),
    (re.compile(r'glpat-[a-zA-Z0-9\-]{20,}'), "GitLab token"),
    (re.compile(r'xox[bp]-[a-zA-Z0-9\-]{20,}'), "Slack token"),
    (re.compile(
        r'(?:password|secret|token|api_key)\s*[:=]\s*["\'`]([^"\'`]{8,})["\'`]',
        re.IGNORECASE,
    ), "hardcoded secret"),
    (re.compile(
        r'(?:mongodb|postgres|mysql|redis)://\S+:\S+@',
        re.IGNORECASE,
    ), "connection string"),
]


def _is_doc_file(path: str) -> bool:
    for pat in DOC_PATTERNS:
        if pat.search(path):
            return True
    return False


class DocSecretsRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for tf in ctx.text_files:
            if not _is_doc_file(tf.path):
                continue

            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                for pattern, desc in SECRET_PATTERNS:
                    m = pattern.search(line)
                    if m:
                        # For patterns with capture groups, check false positives
                        if m.lastindex and is_false_positive_value(m.group(1)):
                            continue
                        issues.append(Issue(
                            rule_id="SECRET-DOC",
                            severity=Severity.HIGH,
                            file=tf.path,
                            line=line_no,
                            message=f"Possible {desc} in documentation",
                            why="Developers sometimes paste real credentials "
                                "in documentation as examples. These are "
                                "visible to anyone reading the docs.",
                            fix="Replace with placeholder values like "
                                "'sk-your-api-key-here' or "
                                "'<YOUR_TOKEN>'.",
                        ))
                        break

        return issues
