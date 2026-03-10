"""Tests for CLI entry point."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vibescan.cli import app

runner = CliRunner()


class TestCLI:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "vibescan" in result.output
        from vibescan import __version__
        assert __version__ in result.output

    def test_scan_clean_project(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "README.md").write_text("# Test")
        (tmp_path / ".gitignore").write_text("*.pyc")
        (tmp_path / "LICENSE").write_text("MIT")
        result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_leaky_project_exits_1(self, tmp_path: Path):
        (tmp_path / ".env").write_text("SECRET=abc")
        result = runner.invoke(app, [str(tmp_path)])
        assert result.exit_code == 1

    def test_min_severity_filter(self, tmp_path: Path):
        # .env without gitignore = CRITICAL
        (tmp_path / ".env").write_text("SECRET=abc")
        (tmp_path / "README.md").write_text("# Test")
        (tmp_path / ".gitignore").write_text("*.pyc")
        (tmp_path / "LICENSE").write_text("MIT")

        # With min-severity=critical, only CRITICAL issues reported
        result = runner.invoke(app, [str(tmp_path), "--min-severity", "critical"])
        assert result.exit_code == 1
        assert "CRITICAL" in result.output

    def test_min_severity_hides_lower(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Test")
        (tmp_path / ".gitignore").write_text("*.pyc")
        (tmp_path / "LICENSE").write_text("MIT")
        (tmp_path / "main.py").write_text("x = 1")
        # Only low/info issues should exist for this clean project
        result = runner.invoke(app, [str(tmp_path), "--min-severity", "high"])
        assert result.exit_code == 0

    def test_invalid_severity_exits_2(self, tmp_path: Path):
        result = runner.invoke(app, [str(tmp_path), "--min-severity", "invalid"])
        assert result.exit_code == 2
        assert "Invalid severity" in result.output

    def test_nonexistent_path(self):
        result = runner.invoke(app, ["/nonexistent/path"])
        assert result.exit_code != 0

    def test_default_path_current_dir(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "README.md").write_text("# Test")
        (tmp_path / ".gitignore").write_text("*.pyc")
        (tmp_path / "LICENSE").write_text("MIT")
        result = runner.invoke(app, [])
        assert result.exit_code == 0
