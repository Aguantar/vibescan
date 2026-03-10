"""Rule 3-C: Cloud service credential files."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

EXACT_NAMES: set[str] = {
    "serviceAccountKey.json",
    "google-services.json", "GoogleService-Info.plist",
    "credentials.json", "application_default_credentials.json",
    "token.json",
    ".boto",
    "terraform.tfvars", "terraform.tfstate",
    "firebase.json", ".firebaserc",
    "wrangler.toml", "fly.toml",
    "sentry.properties",
}

NAME_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'.*-service-account\.json$'),
    re.compile(r'^client_secret.*\.json$'),
]

PATH_PATTERNS: list[str] = [
    "supabase/config.toml",
    "amplify/team-provider-info.json",
    ".aws/credentials",
    ".aws/config",
]


def _is_cloud_credential(file_path: str) -> bool:
    name = PurePosixPath(file_path).name
    if name in EXACT_NAMES:
        return True
    for pat in NAME_PATTERNS:
        if pat.match(name):
            return True
    for pp in PATH_PATTERNS:
        if file_path == pp or file_path.endswith("/" + pp):
            return True
    return False


class CloudCredentialsRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        for file_path in ctx.all_files:
            if not _is_cloud_credential(file_path):
                continue
            name = PurePosixPath(file_path).name
            issues.append(Issue(
                rule_id="SECRET-CLOUD",
                severity=Severity.CRITICAL,
                file=file_path,
                line=None,
                message=f"Cloud credential file '{name}' found in repository",
                why="Cloud service credential files contain authentication "
                    "keys that grant access to your cloud infrastructure. "
                    "Exposure can lead to unauthorized access and data breaches.",
                fix="Remove the file from version control, add it to "
                    ".gitignore, and rotate the credentials immediately.",
            ))
        return issues
