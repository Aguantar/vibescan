"""Shared pytest fixtures for VibeScan tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibescan.collector.context import ProjectContext, TextFile


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal project directory and return its path."""
    return tmp_path


@pytest.fixture
def empty_ctx(tmp_path: Path) -> ProjectContext:
    """ProjectContext with no files."""
    return ProjectContext(project_root=tmp_path)


def make_ctx(
    tmp_path: Path,
    *,
    text_files: list[tuple[str, str]] | None = None,
    all_files: list[str] | None = None,
    gitignore_patterns: list[str] | None = None,
) -> ProjectContext:
    """Helper to build a ProjectContext from inline data.

    text_files: list of (path, content) tuples
    all_files: list of relative paths (defaults to text_files paths)
    gitignore_patterns: list of gitignore pattern strings
    """
    tfs = [TextFile(path=p, content=c) for p, c in (text_files or [])]
    af = all_files if all_files is not None else [tf.path for tf in tfs]
    return ProjectContext(
        project_root=tmp_path,
        text_files=tfs,
        all_files=af,
        gitignore_patterns=gitignore_patterns or [],
    )
