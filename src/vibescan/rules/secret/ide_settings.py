"""Rule 3-F: IDE and development tool settings."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

IDE_EXACT_FILES: set[str] = {
    ".npmrc", ".pypirc", ".netrc",
    "gradle.properties", "local.properties",
}

IDE_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'\.vscode/settings\.json$'),
    re.compile(r'\.vscode/launch\.json$'),
    re.compile(r'\.idea/'),
    re.compile(r'\.docker/config\.json$'),
]

AUTH_TOKEN_RE = re.compile(
    r'''(?:_auth|_authToken|token|password|registry)'''
    r'''\s*[:=]\s*["']?[^\s"'#]{8,}''',
    re.IGNORECASE,
)


def _is_ide_file(file_path: str) -> bool:
    name = PurePosixPath(file_path).name
    if name in IDE_EXACT_FILES:
        return True
    for pat in IDE_PATH_PATTERNS:
        if pat.search(file_path):
            return True
    return False


class IDESettingsRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for tf in ctx.text_files:
            if not _is_ide_file(tf.path):
                continue

            has_secret = False
            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                if AUTH_TOKEN_RE.search(line):
                    has_secret = True
                    issues.append(Issue(
                        rule_id="SECRET-IDE",
                        severity=Severity.HIGH,
                        file=tf.path,
                        line=line_no,
                        message="Possible credential in IDE/tool config",
                        why="IDE and tool configs like .npmrc, .pypirc, and "
                            ".netrc can contain registry auth tokens that "
                            "grant publish access to packages.",
                        fix="Use credential helpers or environment variables "
                            "instead. Add the file to .gitignore.",
                    ))

            if not has_secret:
                name = PurePosixPath(tf.path).name
                if name in {".npmrc", ".pypirc", ".netrc"} or \
                   ".docker/config.json" in tf.path:
                    issues.append(Issue(
                        rule_id="SECRET-IDE",
                        severity=Severity.MEDIUM,
                        file=tf.path,
                        line=None,
                        message=f"Sensitive tool config '{name}' in repository",
                        why="These files may contain authentication tokens "
                            "or registry credentials.",
                        fix="Add to .gitignore. Use per-machine config "
                            "or credential helpers instead.",
                    ))

        return issues
