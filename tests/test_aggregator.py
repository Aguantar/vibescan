"""Tests for end-to-end scan pipeline (integration)."""

from __future__ import annotations

from pathlib import Path

from vibescan.collector import collect
from vibescan.models.issue import Severity
from vibescan.rules import get_all_rules


class TestIntegrationScan:
    """Run all rules against real temporary project directories."""

    def _scan(self, root: Path):
        ctx = collect(root)
        issues = []
        for rule in get_all_rules():
            issues.extend(rule.run(ctx))
        return ctx, issues

    def test_clean_project_minimal_issues(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("import os\nprint(os.getcwd())")
        (tmp_path / "README.md").write_text("# My Project")
        (tmp_path / ".gitignore").write_text("*.pyc\n__pycache__/\n.env\n")
        (tmp_path / "LICENSE").write_text("MIT License")
        ctx, issues = self._scan(tmp_path)
        # Should have no CRITICAL or HIGH issues
        critical_high = [i for i in issues if i.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0

    def test_leaky_project_many_issues(self, tmp_path: Path):
        (tmp_path / ".env").write_text("DB_PASS=secret")
        (tmp_path / "config.py").write_text('password = "supersecretpw"')
        (tmp_path / "server.pem").write_bytes(b"fake pem")
        (tmp_path / "app.py").write_text("eval(user_input)")
        ctx, issues = self._scan(tmp_path)
        critical_high = [i for i in issues if i.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) >= 3

    def test_all_rules_registered(self):
        rules = get_all_rules()
        # 14 secret + 3 non-secret = 17 total
        assert len(rules) == 17

    def test_rules_return_list(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("pass")
        ctx = collect(tmp_path)
        for rule in get_all_rules():
            result = rule.run(ctx)
            assert isinstance(result, list)

    def test_issue_fields_populated(self, tmp_path: Path):
        (tmp_path / ".env").write_text("SECRET=x")
        ctx = collect(tmp_path)
        for rule in get_all_rules():
            for issue in rule.run(ctx):
                assert issue.rule_id
                assert issue.severity in Severity
                assert issue.file
                assert issue.message
                assert issue.why
                assert issue.fix
