"""Tests for GitHygieneRule."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import make_ctx
from vibescan.models.issue import Severity
from vibescan.rules.git_hygiene import GitHygieneRule


class TestNoGitignore:
    def test_flags_missing_gitignore(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py"])
        issues = GitHygieneRule().run(ctx)
        gi_issues = [i for i in issues if i.rule_id == "GIT-NO-GITIGNORE"]
        assert len(gi_issues) == 1
        assert gi_issues[0].severity == Severity.HIGH

    def test_no_flag_when_gitignore_exists(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".gitignore", "main.py"])
        issues = GitHygieneRule().run(ctx)
        gi_issues = [i for i in issues if i.rule_id == "GIT-NO-GITIGNORE"]
        assert len(gi_issues) == 0


class TestMissingPatterns:
    def test_suggests_node_modules_for_node_project(self, tmp_path: Path):
        ctx = make_ctx(
            tmp_path,
            all_files=["package.json", ".gitignore", "index.js"],
            gitignore_patterns=[],
        )
        issues = GitHygieneRule().run(ctx)
        nm_issues = [i for i in issues if "node_modules" in i.message]
        assert len(nm_issues) == 1

    def test_no_node_modules_suggestion_without_package_json(self, tmp_path: Path):
        ctx = make_ctx(
            tmp_path,
            all_files=[".gitignore", "main.py"],
            gitignore_patterns=[],
        )
        issues = GitHygieneRule().run(ctx)
        nm_issues = [i for i in issues if "node_modules" in i.message]
        assert len(nm_issues) == 0

    def test_no_suggestion_when_pattern_present(self, tmp_path: Path):
        ctx = make_ctx(
            tmp_path,
            all_files=["package.json", ".gitignore"],
            gitignore_patterns=["node_modules"],
        )
        issues = GitHygieneRule().run(ctx)
        nm_issues = [i for i in issues if "node_modules" in i.message]
        assert len(nm_issues) == 0


class TestDangerousTracked:
    def test_flags_pem_without_gitignore(self, tmp_path: Path):
        ctx = make_ctx(
            tmp_path,
            all_files=["server.pem", ".gitignore"],
            gitignore_patterns=[],
        )
        issues = GitHygieneRule().run(ctx)
        pem_issues = [i for i in issues if i.rule_id == "GIT-DANGEROUS-TRACKED"]
        assert len(pem_issues) == 1
        assert pem_issues[0].severity == Severity.CRITICAL

    def test_no_flag_when_extension_gitignored(self, tmp_path: Path):
        ctx = make_ctx(
            tmp_path,
            all_files=["server.pem", ".gitignore"],
            gitignore_patterns=["*.pem"],
        )
        issues = GitHygieneRule().run(ctx)
        pem_issues = [i for i in issues if i.rule_id == "GIT-DANGEROUS-TRACKED"
                      and "server.pem" in i.file]
        assert len(pem_issues) == 0

    def test_flags_sqlite_file(self, tmp_path: Path):
        ctx = make_ctx(
            tmp_path,
            all_files=["data.sqlite", ".gitignore"],
            gitignore_patterns=[],
        )
        issues = GitHygieneRule().run(ctx)
        db_issues = [i for i in issues if i.rule_id == "GIT-DANGEROUS-TRACKED"]
        assert len(db_issues) == 1
        assert db_issues[0].severity == Severity.MEDIUM


class TestBloat:
    def test_flags_large_node_modules(self, tmp_path: Path):
        files = [f"node_modules/pkg{i}/index.js" for i in range(150)]
        files.append(".gitignore")
        ctx = make_ctx(tmp_path, all_files=files, gitignore_patterns=[])
        issues = GitHygieneRule().run(ctx)
        bloat = [i for i in issues if i.rule_id == "GIT-BLOAT"]
        assert len(bloat) == 1

    def test_no_bloat_for_small_dir(self, tmp_path: Path):
        files = [f"src/file{i}.py" for i in range(10)]
        ctx = make_ctx(tmp_path, all_files=files)
        issues = GitHygieneRule().run(ctx)
        bloat = [i for i in issues if i.rule_id == "GIT-BLOAT"]
        assert len(bloat) == 0
