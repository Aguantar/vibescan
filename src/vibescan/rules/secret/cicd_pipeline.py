"""Rule 3-E: CI/CD pipeline files with potential secrets."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

CICD_NAMES: set[str] = {
    ".gitlab-ci.yml",
    "Jenkinsfile",
    "bitbucket-pipelines.yml",
    "vercel.json", "netlify.toml",
    ".travis.yml",
    "Procfile",
}

CICD_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\.github/workflows/.*\.ya?ml$'),
    re.compile(r'\.circleci/config\.yml$'),
]

SECRET_IN_CICD_RE = re.compile(
    r'''(?:password|passwd|secret|token|api_key|apikey|'''
    r'''credentials|auth_token|access_key)'''
    r'''\s*[:=]\s*["'][^"'${\s]{4,}["']''',
    re.IGNORECASE,
)


def _is_cicd_file(file_path: str) -> bool:
    name = PurePosixPath(file_path).name
    if name in CICD_NAMES:
        return True
    for pat in CICD_PATH_PATTERNS:
        if pat.search(file_path):
            return True
    return False


class CICDPipelineRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        for tf in ctx.text_files:
            if not _is_cicd_file(tf.path):
                continue
            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if SECRET_IN_CICD_RE.search(line):
                    issues.append(Issue(
                        rule_id="SECRET-CICD",
                        severity=Severity.CRITICAL,
                        file=tf.path,
                        line=line_no,
                        message="Hardcoded secret in CI/CD pipeline config",
                        why="CI/CD configs are almost always committed to "
                            "version control. Hardcoded secrets here are "
                            "visible to all contributors.",
                        fix="Use your CI/CD platform's secret management: "
                            "GitHub Actions secrets, GitLab CI variables, etc.",
                    ))
        return issues
