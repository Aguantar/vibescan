"""Tests for Console Reporter."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from vibescan.models.issue import Issue, Severity
from vibescan.models.scan_result import ScanResult
from vibescan.reporters.console import print_report


def _make_issue(severity: Severity, file: str = "test.py", line: int | None = 1) -> Issue:
    return Issue(
        rule_id="TEST",
        severity=severity,
        file=file,
        line=line,
        message=f"Test {severity.value} issue",
        why="Test why",
        fix="Test fix",
    )


def _capture_report(result: ScanResult) -> str:
    buf = StringIO()
    console = Console(file=buf, no_color=True, width=120)
    print_report(result, console=console)
    return buf.getvalue()


class TestConsoleReporter:
    def test_clean_project_output(self):
        result = ScanResult(files_scanned=10, project_root="/tmp/test")
        output = _capture_report(result)
        assert "No issues found" in output
        assert "10" in output

    def test_shows_summary_counts(self):
        result = ScanResult(
            issues=[_make_issue(Severity.CRITICAL), _make_issue(Severity.HIGH)],
            files_scanned=5,
            project_root="/tmp/test",
        )
        output = _capture_report(result)
        assert "CRITICAL" in output
        assert "HIGH" in output

    def test_shows_file_grouping(self):
        result = ScanResult(
            issues=[
                _make_issue(Severity.HIGH, file="a.py"),
                _make_issue(Severity.MEDIUM, file="b.py"),
            ],
            files_scanned=2,
            project_root="/tmp/test",
        )
        output = _capture_report(result)
        assert "a.py" in output
        assert "b.py" in output

    def test_shows_why_and_fix(self):
        result = ScanResult(
            issues=[_make_issue(Severity.HIGH)],
            files_scanned=1,
            project_root="/tmp/test",
        )
        output = _capture_report(result)
        assert "Why:" in output
        assert "Fix:" in output

    def test_shows_line_number(self):
        result = ScanResult(
            issues=[_make_issue(Severity.HIGH, line=42)],
            files_scanned=1,
            project_root="/tmp/test",
        )
        output = _capture_report(result)
        assert "42" in output

    def test_exit_code_message_for_critical(self):
        result = ScanResult(
            issues=[_make_issue(Severity.CRITICAL)],
            files_scanned=1,
            project_root="/tmp/test",
        )
        output = _capture_report(result)
        assert "Exit code 1" in output

    def test_exit_code_message_for_clean(self):
        result = ScanResult(
            issues=[_make_issue(Severity.LOW)],
            files_scanned=1,
            project_root="/tmp/test",
        )
        output = _capture_report(result)
        assert "Exit code 0" in output
