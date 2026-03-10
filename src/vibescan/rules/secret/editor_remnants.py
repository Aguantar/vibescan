"""Rule 3-N: Hidden files and editor remnants."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

# History files that may contain secrets typed in shell
HISTORY_FILES: set[str] = {
    ".bash_history", ".zsh_history",
    ".python_history", ".node_repl_history",
}

# Files that indicate poor gitignore hygiene
JUNK_FILES: set[str] = {
    ".DS_Store", "Thumbs.db",
}

# Config files that may contain credentials
SENSITIVE_DOTFILES: set[str] = {
    ".htaccess",
    ".ftpconfig", ".sftp-config.json",
    ".s3cfg",
}

# Editor swap files
SWAP_EXTENSIONS: set[str] = {
    ".swp", ".swo", ".swn",
}


class EditorRemnantsRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []

        for file_path in ctx.all_files:
            name = PurePosixPath(file_path).name
            ext = PurePosixPath(file_path).suffix.lower()

            if name in HISTORY_FILES:
                issues.append(Issue(
                    rule_id="SECRET-REMNANT",
                    severity=Severity.HIGH,
                    file=file_path,
                    line=None,
                    message=f"Shell history file '{name}' in repository",
                    why="Shell history files record commands typed in the "
                        "terminal, which often include passwords, tokens, "
                        "and connection strings passed as arguments.",
                    fix="Remove immediately, add to .gitignore, and rotate "
                        "any credentials visible in the history.",
                ))
            elif name in SENSITIVE_DOTFILES:
                issues.append(Issue(
                    rule_id="SECRET-REMNANT",
                    severity=Severity.MEDIUM,
                    file=file_path,
                    line=None,
                    message=f"Sensitive dotfile '{name}' in repository",
                    why="Files like .ftpconfig and .s3cfg often contain "
                        "server credentials and access keys.",
                    fix="Remove from repository and add to .gitignore.",
                ))
            elif name in JUNK_FILES:
                issues.append(Issue(
                    rule_id="SECRET-REMNANT",
                    severity=Severity.LOW,
                    file=file_path,
                    line=None,
                    message=f"OS junk file '{name}' in repository",
                    why="OS-generated files like .DS_Store can leak directory "
                        "structure information and indicate poor .gitignore "
                        "configuration.",
                    fix="Remove and add to .gitignore: echo '{name}' >> .gitignore",
                ))
            elif ext in SWAP_EXTENSIONS:
                issues.append(Issue(
                    rule_id="SECRET-REMNANT",
                    severity=Severity.LOW,
                    file=file_path,
                    line=None,
                    message=f"Editor swap file '{name}' in repository",
                    why="Vim swap files contain the contents of files being "
                        "edited, potentially including sensitive files.",
                    fix="Remove and add '*.swp' to .gitignore.",
                ))

        return issues
