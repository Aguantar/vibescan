"""Rule 3-L: Mobile app sensitive files."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

MOBILE_EXACT_NAMES: set[str] = {
    "Info.plist", "AndroidManifest.xml",
    "strings.xml", "Fastfile",
}

# Content patterns in mobile config files
MOBILE_SECRET_RE = re.compile(
    r'''(?:api_key|apikey|api-key|secret|password|'''
    r'''client_id|client_secret|google_maps_key)'''
    r'''\s*[:=<>]\s*["']?[a-zA-Z0-9_\-]{10,}''',
    re.IGNORECASE,
)


class MobileFilesRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for tf in ctx.text_files:
            name = PurePosixPath(tf.path).name
            if name not in MOBILE_EXACT_NAMES:
                continue

            for line_no, line in enumerate(tf.content.splitlines(), start=1):
                if MOBILE_SECRET_RE.search(line):
                    issues.append(Issue(
                        rule_id="SECRET-MOBILE",
                        severity=Severity.HIGH,
                        file=tf.path,
                        line=line_no,
                        message=f"Possible secret in mobile config '{name}'",
                        why="Mobile config files like AndroidManifest.xml and "
                            "Info.plist are bundled into app packages (APK/IPA) "
                            "that can be easily decompiled and inspected.",
                        fix="Use build-time secret injection (Gradle buildConfigField, "
                            "Xcode xcconfig) instead of hardcoding values.",
                    ))

        # Check for keystore files in all_files
        for file_path in ctx.all_files:
            ext = PurePosixPath(file_path).suffix.lower()
            if ext in {".keystore", ".jks"}:
                # Already handled by private_keys rule
                pass

        return issues
