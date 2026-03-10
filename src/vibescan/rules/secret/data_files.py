"""Rule 3-J: Data file exposure (databases, dumps, logs)."""

from __future__ import annotations

from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

DATA_FILE_RULES: list[tuple[set[str], Severity, str, str]] = [
    (
        {".sql", ".dump", ".bak"},
        Severity.HIGH,
        "Database dump/backup file",
        "Database dumps contain full table data including user records, "
        "passwords, and personal information.",
    ),
    (
        {".sqlite", ".db"},
        Severity.HIGH,
        "Database file",
        "Database files contain application data that may include "
        "user credentials and sensitive records.",
    ),
    (
        {".csv"},
        Severity.MEDIUM,
        "CSV data file",
        "CSV files may contain exported user data, financial records, "
        "or other sensitive information.",
    ),
    (
        {".log"},
        Severity.MEDIUM,
        "Log file",
        "Log files can inadvertently contain API keys, tokens, "
        "passwords, and stack traces with sensitive data.",
    ),
]

NOTEBOOK_EXT: set[str] = {".ipynb"}


class DataFilesRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        for file_path in ctx.all_files:
            ext = PurePosixPath(file_path).suffix.lower()

            for extensions, severity, desc, why in DATA_FILE_RULES:
                if ext in extensions:
                    issues.append(Issue(
                        rule_id="SECRET-DATA",
                        severity=severity,
                        file=file_path,
                        line=None,
                        message=f"{desc} found: '{file_path}'",
                        why=why,
                        fix="Add to .gitignore. If already committed, remove "
                            "from history with BFG or git filter-branch.",
                    ))
                    break

            if ext in NOTEBOOK_EXT:
                # Check if notebook has outputs (cell outputs may leak secrets)
                for tf in ctx.text_files:
                    if tf.path == file_path and '"outputs"' in tf.content:
                        if '"text"' in tf.content or '"data"' in tf.content:
                            issues.append(Issue(
                                rule_id="SECRET-DATA",
                                severity=Severity.MEDIUM,
                                file=file_path,
                                line=None,
                                message="Jupyter Notebook with cell outputs",
                                why="Notebook outputs can contain API responses, "
                                    "database query results, or error messages "
                                    "that leak secrets.",
                                fix="Clear all outputs before committing: "
                                    "jupyter nbconvert --clear-output notebook.ipynb",
                            ))
                        break

        return issues
