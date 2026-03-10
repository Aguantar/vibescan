"""Parse .gitignore files and extract patterns."""

from __future__ import annotations

from pathlib import Path


def parse_gitignore_files(root: Path) -> list[str]:
    patterns: list[str] = []

    for gitignore in root.rglob(".gitignore"):
        if gitignore.is_symlink():
            continue
        try:
            text = gitignore.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError, OSError):
            continue

        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                patterns.append(stripped)

    return patterns
