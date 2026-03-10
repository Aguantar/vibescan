"""Rule 3-G: SSH keys and certificate files."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

KEY_EXACT_NAMES: set[str] = {
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "known_hosts",
}

KEY_EXTENSIONS: set[str] = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
}

SEVERITY_MAP: dict[str, Severity] = {
    ".pem": Severity.CRITICAL,
    ".key": Severity.CRITICAL,
    ".p12": Severity.CRITICAL,
    ".pfx": Severity.CRITICAL,
    ".jks": Severity.HIGH,
    ".keystore": Severity.HIGH,
}


class PrivateKeysRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        for file_path in ctx.all_files:
            pp = PurePosixPath(file_path)
            name = pp.name
            ext = pp.suffix.lower()

            if name in KEY_EXACT_NAMES:
                sev = Severity.CRITICAL if name != "known_hosts" else Severity.MEDIUM
                issues.append(Issue(
                    rule_id="SECRET-KEY",
                    severity=sev,
                    file=file_path,
                    line=None,
                    message=f"SSH key file '{name}' found in repository",
                    why="Private SSH keys provide direct authentication to "
                        "servers and services. If exposed, attackers gain "
                        "unauthorized remote access.",
                    fix="Remove the file, add it to .gitignore, and rotate "
                        "the key pair immediately.",
                ))
            elif ext in KEY_EXTENSIONS:
                sev = SEVERITY_MAP.get(ext, Severity.HIGH)
                issues.append(Issue(
                    rule_id="SECRET-KEY",
                    severity=sev,
                    file=file_path,
                    line=None,
                    message=f"Certificate/key file '{name}' found in repository",
                    why="Private keys and certificates should never be stored "
                        "in version control. Exposure compromises TLS/SSL "
                        "security and service authentication.",
                    fix="Remove the file, add '*{ext}' to .gitignore, "
                        "and reissue the certificate.",
                ))

        return issues
