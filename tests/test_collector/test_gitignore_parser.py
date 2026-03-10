"""Tests for .gitignore parser (Track C)."""

from __future__ import annotations

from pathlib import Path

from vibescan.collector.gitignore_parser import parse_gitignore_files


class TestGitignoreParser:
    def test_parses_basic_patterns(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("node_modules\n.env\n*.pyc\n")
        patterns = parse_gitignore_files(tmp_path)
        assert patterns == ["node_modules", ".env", "*.pyc"]

    def test_ignores_comments(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("# comment\nnode_modules\n# another\n.env\n")
        patterns = parse_gitignore_files(tmp_path)
        assert patterns == ["node_modules", ".env"]

    def test_ignores_blank_lines(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("\n\nnode_modules\n\n.env\n\n")
        patterns = parse_gitignore_files(tmp_path)
        assert patterns == ["node_modules", ".env"]

    def test_strips_whitespace(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("  node_modules  \n  .env  \n")
        patterns = parse_gitignore_files(tmp_path)
        assert patterns == ["node_modules", ".env"]

    def test_nested_gitignore(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("*.log\n")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / ".gitignore").write_text("local.db\n")
        patterns = parse_gitignore_files(tmp_path)
        assert "*.log" in patterns
        assert "local.db" in patterns

    def test_no_gitignore_returns_empty(self, tmp_path: Path):
        patterns = parse_gitignore_files(tmp_path)
        assert patterns == []

    def test_skips_symlinked_gitignore(self, tmp_path: Path):
        real = tmp_path / "real_gitignore"
        real.write_text("secret\n")
        link = tmp_path / ".gitignore"
        link.symlink_to(real)
        patterns = parse_gitignore_files(tmp_path)
        assert patterns == []
