"""Tests for StructureRule."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import make_ctx
from vibescan.models.issue import Severity
from vibescan.rules.structure import StructureRule


rule = StructureRule()


class TestHealthFiles:
    def test_flags_missing_readme(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py", ".gitignore", "LICENSE"])
        issues = rule.run(ctx)
        health = [i for i in issues if i.rule_id == "STRUCTURE-HEALTH"]
        missing = {i.file for i in health}
        assert "README.md" in missing

    def test_flags_missing_gitignore(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py", "README.md", "LICENSE"])
        issues = rule.run(ctx)
        health = [i for i in issues if i.rule_id == "STRUCTURE-HEALTH"]
        missing = {i.file for i in health}
        assert ".gitignore" in missing

    def test_flags_missing_license(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py", "README.md", ".gitignore"])
        issues = rule.run(ctx)
        health = [i for i in issues if i.rule_id == "STRUCTURE-HEALTH"]
        missing = {i.file for i in health}
        assert "LICENSE" in missing

    def test_no_flag_when_all_present(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["README.md", ".gitignore", "LICENSE"])
        issues = rule.run(ctx)
        health = [i for i in issues if i.rule_id == "STRUCTURE-HEALTH"]
        assert len(health) == 0


class TestLockfile:
    def test_flags_missing_lockfile_for_package_json(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            "package.json", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        lock_issues = [i for i in issues if i.rule_id == "STRUCTURE-LOCKFILE"]
        assert len(lock_issues) == 1
        assert "npm" in lock_issues[0].message.lower() or "yarn" in lock_issues[0].message.lower()

    def test_no_flag_with_yarn_lock(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            "package.json", "yarn.lock", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        lock_issues = [i for i in issues if i.rule_id == "STRUCTURE-LOCKFILE"]
        assert len(lock_issues) == 0

    def test_no_flag_with_package_lock(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            "package.json", "package-lock.json", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        lock_issues = [i for i in issues if i.rule_id == "STRUCTURE-LOCKFILE"]
        assert len(lock_issues) == 0

    def test_flags_missing_lockfile_for_pipfile(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            "Pipfile", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        lock_issues = [i for i in issues if i.rule_id == "STRUCTURE-LOCKFILE"]
        assert len(lock_issues) == 1

    def test_no_flag_for_pipfile_with_lock(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            "Pipfile", "Pipfile.lock", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        lock_issues = [i for i in issues if i.rule_id == "STRUCTURE-LOCKFILE"]
        assert len(lock_issues) == 0

    def test_no_flag_without_manifest(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            "main.py", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        lock_issues = [i for i in issues if i.rule_id == "STRUCTURE-LOCKFILE"]
        assert len(lock_issues) == 0


class TestSuspiciousDirectories:
    def test_flags_ssh_directory(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            ".ssh/id_rsa", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        dir_issues = [i for i in issues if i.rule_id == "STRUCTURE-SUSPICIOUS-DIR"]
        assert len(dir_issues) == 1
        assert dir_issues[0].severity == Severity.CRITICAL

    def test_flags_aws_directory(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            ".aws/credentials", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        dir_issues = [i for i in issues if i.rule_id == "STRUCTURE-SUSPICIOUS-DIR"]
        assert len(dir_issues) == 1

    def test_flags_kube_directory(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            ".kube/config", "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        dir_issues = [i for i in issues if i.rule_id == "STRUCTURE-SUSPICIOUS-DIR"]
        assert len(dir_issues) == 1

    def test_no_flag_for_normal_dirs(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[
            "src/main.py", "tests/test_main.py",
            "README.md", ".gitignore", "LICENSE",
        ])
        issues = rule.run(ctx)
        dir_issues = [i for i in issues if i.rule_id == "STRUCTURE-SUSPICIOUS-DIR"]
        assert len(dir_issues) == 0


class TestFlatStructure:
    def test_flags_overly_flat_project(self, tmp_path: Path):
        files = [f"file{i}.py" for i in range(25)]
        files += ["README.md", ".gitignore", "LICENSE"]
        ctx = make_ctx(tmp_path, all_files=files)
        issues = rule.run(ctx)
        flat_issues = [i for i in issues if i.rule_id == "STRUCTURE-FLAT"]
        assert len(flat_issues) == 1
        assert flat_issues[0].severity == Severity.INFO

    def test_no_flag_for_organized_project(self, tmp_path: Path):
        files = [
            "src/main.py", "src/utils.py",
            "tests/test_main.py",
            "README.md", ".gitignore", "LICENSE",
        ]
        ctx = make_ctx(tmp_path, all_files=files)
        issues = rule.run(ctx)
        flat_issues = [i for i in issues if i.rule_id == "STRUCTURE-FLAT"]
        assert len(flat_issues) == 0
