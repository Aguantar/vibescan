"""Rule 3-A: Environment variable file exposure detection."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

ENV_FILE_PATTERNS: set[str] = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.vault",
}


def _is_env_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name in ENV_FILE_PATTERNS or name.startswith(".env.")


def _is_gitignored(path: str, patterns: list[str]) -> bool:
    name = PurePosixPath(path).name
    for pattern in patterns:
        cleaned = pattern.rstrip("/")
        if cleaned == name or cleaned == path:
            return True
        if cleaned == ".env*" or cleaned == ".env":
            if name.startswith(".env"):
                return True
    return False


class EnvExposureRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        for file_path in ctx.all_files:
            if not _is_env_file(file_path):
                continue

            ignored = _is_gitignored(file_path, ctx.gitignore_patterns)
            severity = Severity.MEDIUM if ignored else Severity.CRITICAL

            issues.append(Issue(
                rule_id="SECRET-ENV",
                severity=severity,
                file=file_path,
                line=None,
                message=f"Environment file '{file_path}' found"
                        + (" (gitignored)" if ignored else " (NOT gitignored)"),
                why="Environment files often contain database passwords, API keys, "
                    "and other secrets. If committed to git, they are exposed in "
                    "the repository history forever.",
                fix="Add the file to .gitignore. If already committed, rotate all "
                    "secrets and use `git filter-branch` or BFG to purge history.",
            ))
        return issues
