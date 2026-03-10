"""Tests for models (Issue, Severity, ScanResult)."""

from __future__ import annotations

from vibescan.models.issue import Issue, Severity
from vibescan.models.scan_result import ScanResult


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_equality(self):
        assert Severity.CRITICAL >= Severity.CRITICAL
        assert Severity.INFO <= Severity.INFO

    def test_rank_values(self):
        assert Severity.CRITICAL.rank == 4
        assert Severity.HIGH.rank == 3
        assert Severity.MEDIUM.rank == 2
        assert Severity.LOW.rank == 1
        assert Severity.INFO.rank == 0

    def test_string_value(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity("high") == Severity.HIGH


class TestIssue:
    def test_creation(self):
        issue = Issue(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            file="main.py",
            line=42,
            message="Test issue",
            why="Because testing",
            fix="Fix it",
        )
        assert issue.rule_id == "TEST-001"
        assert issue.severity == Severity.HIGH
        assert issue.line == 42

    def test_line_can_be_none(self):
        issue = Issue(
            rule_id="TEST-001",
            severity=Severity.LOW,
            file=".env",
            line=None,
            message="File-level issue",
            why="Why",
            fix="Fix",
        )
        assert issue.line is None


class TestScanResult:
    def _make_issue(self, severity: Severity) -> Issue:
        return Issue(
            rule_id="TEST",
            severity=severity,
            file="test.py",
            line=1,
            message="test",
            why="why",
            fix="fix",
        )

    def test_empty_result(self):
        result = ScanResult()
        assert result.exit_code == 0
        assert result.summary == {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }

    def test_exit_code_1_for_critical(self):
        result = ScanResult(issues=[self._make_issue(Severity.CRITICAL)])
        assert result.exit_code == 1

    def test_exit_code_1_for_high(self):
        result = ScanResult(issues=[self._make_issue(Severity.HIGH)])
        assert result.exit_code == 1

    def test_exit_code_0_for_medium(self):
        result = ScanResult(issues=[self._make_issue(Severity.MEDIUM)])
        assert result.exit_code == 0

    def test_exit_code_0_for_low(self):
        result = ScanResult(issues=[self._make_issue(Severity.LOW)])
        assert result.exit_code == 0

    def test_summary_counts(self):
        result = ScanResult(issues=[
            self._make_issue(Severity.CRITICAL),
            self._make_issue(Severity.CRITICAL),
            self._make_issue(Severity.HIGH),
            self._make_issue(Severity.MEDIUM),
            self._make_issue(Severity.LOW),
            self._make_issue(Severity.LOW),
            self._make_issue(Severity.LOW),
        ])
        s = result.summary
        assert s["critical"] == 2
        assert s["high"] == 1
        assert s["medium"] == 1
        assert s["low"] == 3
        assert s["info"] == 0
