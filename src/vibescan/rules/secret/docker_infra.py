"""Rule 3-D: Docker and infrastructure configuration secrets."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule
from vibescan.rules.secret._filters import contains_env_var_ref

INFRA_NAMES: set[str] = {
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile",
    "nginx.conf", "values.yaml",
    "Caddyfile",
}

INFRA_NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'^docker-compose\..+\.ya?ml$'),
]

INFRA_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'k8s/.*\.ya?ml$'),
    re.compile(r'ansible/inventory'),
    re.compile(r'ansible/vars/.*\.ya?ml$'),
]

SECRET_IN_INFRA_RE = re.compile(
    r'''(?:password|passwd|secret|token|api_key|apikey|'''
    r'''MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|'''
    r'''AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)'''
    r'''\s*[:=]\s*["']?[^\s"'#]{4,}''',
    re.IGNORECASE,
)


def _is_infra_file(file_path: str) -> bool:
    name = PurePosixPath(file_path).name
    if name in INFRA_NAMES:
        return True
    for pat in INFRA_NAME_PATTERNS:
        if pat.match(name):
            return True
    for pat in INFRA_PATH_PATTERNS:
        if pat.search(file_path):
            return True
    return False


class DockerInfraRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        for tf in ctx.text_files:
            if not _is_infra_file(tf.path):
                continue
            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if SECRET_IN_INFRA_RE.search(line) and not contains_env_var_ref(line):
                    issues.append(Issue(
                        rule_id="SECRET-INFRA",
                        severity=Severity.HIGH,
                        file=tf.path,
                        line=line_no,
                        message="Hardcoded secret in infrastructure config",
                        why="Docker and infrastructure configs with hardcoded "
                            "secrets expose credentials when committed to "
                            "version control.",
                        fix="Use environment variable substitution: "
                            "${DB_PASSWORD} in docker-compose, or "
                            "Kubernetes Secrets for k8s manifests.",
                    ))
        return issues
