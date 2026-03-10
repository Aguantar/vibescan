"""Rule 3-M: Database client and system configuration files."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

# Files that should never be in a repo
CRITICAL_SYSTEM_FILES: dict[str, str] = {
    ".pgpass": "PostgreSQL password file",
    ".my.cnf": "MySQL client config (may contain password)",
    "kubeconfig": "Kubernetes cluster config",
}

CRITICAL_PATH_PATTERNS: list[tuple[str, str]] = [
    (".kube/config", "Kubernetes cluster config"),
]

# Files worth warning about
MEDIUM_SYSTEM_FILES: dict[str, str] = {
    "build.gradle": "Gradle build file (may contain repository credentials)",
    "build.gradle.kts": "Gradle build file (may contain repository credentials)",
    "Makefile": "Makefile (may contain embedded secrets)",
    "composer.json": "PHP Composer config (may reference private registry)",
    "Gemfile": "Ruby Gemfile (may reference private gem source)",
}


class SystemConfigsRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for file_path in ctx.all_files:
            name = PurePosixPath(file_path).name

            # Critical system files
            if name in CRITICAL_SYSTEM_FILES:
                desc = CRITICAL_SYSTEM_FILES[name]
                issues.append(Issue(
                    rule_id="SECRET-SYSTEM",
                    severity=Severity.CRITICAL,
                    file=file_path,
                    line=None,
                    message=f"System config file found: {desc}",
                    why="System configuration files like .pgpass and "
                        "kubeconfig contain plaintext credentials for "
                        "database and cluster access.",
                    fix="Remove from repository, add to .gitignore, "
                        "and rotate affected credentials.",
                ))
                continue

            # Path-based critical matches
            for pattern, desc in CRITICAL_PATH_PATTERNS:
                if file_path == pattern or file_path.endswith("/" + pattern):
                    issues.append(Issue(
                        rule_id="SECRET-SYSTEM",
                        severity=Severity.CRITICAL,
                        file=file_path,
                        line=None,
                        message=f"System config file found: {desc}",
                        why="This file contains authentication credentials "
                            "for infrastructure services.",
                        fix="Remove from repository and add to .gitignore.",
                    ))
                    break

        return issues
