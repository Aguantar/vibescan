from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TextFile:
    path: str
    content: str


@dataclass
class ProjectContext:
    project_root: Path
    text_files: list[TextFile] = field(default_factory=list)
    all_files: list[str] = field(default_factory=list)
    gitignore_patterns: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
