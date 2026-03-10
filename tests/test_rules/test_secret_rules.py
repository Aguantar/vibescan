"""Tests for all Secret rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import make_ctx
from vibescan.models.issue import Severity
from vibescan.rules.secret.env_exposure import EnvExposureRule
from vibescan.rules.secret.hardcoded_patterns import HardcodedPatternsRule
from vibescan.rules.secret.config_hardcode import ConfigHardcodeRule
from vibescan.rules.secret.cloud_credentials import CloudCredentialsRule
from vibescan.rules.secret.docker_infra import DockerInfraRule
from vibescan.rules.secret.cicd_pipeline import CICDPipelineRule
from vibescan.rules.secret.ide_settings import IDESettingsRule
from vibescan.rules.secret.private_keys import PrivateKeysRule
from vibescan.rules.secret.frontend_env import FrontendEnvRule
from vibescan.rules.secret.data_files import DataFilesRule
from vibescan.rules.secret.doc_secrets import DocSecretsRule
from vibescan.rules.secret.mobile_files import MobileFilesRule
from vibescan.rules.secret.system_configs import SystemConfigsRule
from vibescan.rules.secret.editor_remnants import EditorRemnantsRule


# ── 3-A: EnvExposureRule ─────────────────────────────────────────────────

class TestEnvExposure:
    def test_detects_env_file(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".env"])
        issues = EnvExposureRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL
        assert issues[0].rule_id == "SECRET-ENV"

    def test_detects_env_variants(self, tmp_path: Path):
        files = [".env.local", ".env.production", ".env.staging"]
        ctx = make_ctx(tmp_path, all_files=files)
        issues = EnvExposureRule().run(ctx)
        assert len(issues) == 3

    def test_severity_medium_when_gitignored(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".env"], gitignore_patterns=[".env"])
        issues = EnvExposureRule().run(ctx)
        assert issues[0].severity == Severity.MEDIUM

    def test_severity_medium_with_wildcard_gitignore(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".env.local"], gitignore_patterns=[".env*"])
        issues = EnvExposureRule().run(ctx)
        assert issues[0].severity == Severity.MEDIUM

    def test_no_issue_for_non_env_file(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py", "README.md"])
        issues = EnvExposureRule().run(ctx)
        assert len(issues) == 0


# ── 3-B: ConfigHardcodeRule ──────────────────────────────────────────────

class TestConfigHardcode:
    def test_detects_password_in_config_py(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("config.py", 'DB_PASSWORD = "hunter2abc"'),
        ])
        issues = ConfigHardcodeRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].rule_id == "SECRET-CONFIG"

    def test_detects_secret_in_settings_yml(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("secrets.yml", 'api_key: "sk-very-long-secret-key"'),
        ])
        issues = ConfigHardcodeRule().run(ctx)
        assert len(issues) == 1

    def test_ignores_non_config_file(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("main.py", 'password = "hunter2abc"'),
        ])
        issues = ConfigHardcodeRule().run(ctx)
        assert len(issues) == 0

    def test_ignores_safe_config(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("config.py", 'DEBUG = True\nLOG_LEVEL = "info"'),
        ])
        issues = ConfigHardcodeRule().run(ctx)
        assert len(issues) == 0


# ── 3-C: CloudCredentialsRule ────────────────────────────────────────────

class TestCloudCredentials:
    @pytest.mark.parametrize("filename", [
        "serviceAccountKey.json",
        "terraform.tfvars",
        "terraform.tfstate",
        "credentials.json",
        "google-services.json",
        ".boto",
    ])
    def test_detects_known_cloud_files(self, tmp_path: Path, filename: str):
        ctx = make_ctx(tmp_path, all_files=[filename])
        issues = CloudCredentialsRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL

    def test_detects_service_account_pattern(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["my-app-service-account.json"])
        issues = CloudCredentialsRule().run(ctx)
        assert len(issues) == 1

    def test_detects_client_secret_pattern(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["client_secret_12345.json"])
        issues = CloudCredentialsRule().run(ctx)
        assert len(issues) == 1

    def test_detects_path_pattern(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".aws/credentials"])
        issues = CloudCredentialsRule().run(ctx)
        assert len(issues) == 1

    def test_ignores_normal_json(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["package.json", "tsconfig.json"])
        issues = CloudCredentialsRule().run(ctx)
        assert len(issues) == 0


# ── 3-D: DockerInfraRule ─────────────────────────────────────────────────

class TestDockerInfra:
    def test_detects_secret_in_compose(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("docker-compose.yml", 'POSTGRES_PASSWORD=mysecret123'),
        ])
        issues = DockerInfraRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].rule_id == "SECRET-INFRA"

    def test_detects_secret_in_k8s_yaml(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("k8s/deployment.yaml", '  password: "realsecret123"'),
        ])
        issues = DockerInfraRule().run(ctx)
        assert len(issues) == 1

    def test_ignores_comments(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("docker-compose.yml", '# POSTGRES_PASSWORD=example'),
        ])
        issues = DockerInfraRule().run(ctx)
        assert len(issues) == 0

    def test_ignores_non_infra_file(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", 'POSTGRES_PASSWORD=mysecret123'),
        ])
        issues = DockerInfraRule().run(ctx)
        assert len(issues) == 0


# ── 3-E: CICDPipelineRule ───────────────────────────────────────────────

class TestCICDPipeline:
    def test_detects_secret_in_github_workflow(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".github/workflows/deploy.yml", 'api_key: "hardcoded_secret_123"'),
        ])
        issues = CICDPipelineRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL

    def test_detects_secret_in_gitlab_ci(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".gitlab-ci.yml", 'password: "mypassword1234"'),
        ])
        issues = CICDPipelineRule().run(ctx)
        assert len(issues) == 1

    def test_ignores_variable_references(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".github/workflows/deploy.yml", 'api_key: "${{ secrets.API_KEY }}"'),
        ])
        issues = CICDPipelineRule().run(ctx)
        assert len(issues) == 0

    def test_ignores_non_cicd_file(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("config.yml", 'password: "hardcoded_secret_123"'),
        ])
        issues = CICDPipelineRule().run(ctx)
        assert len(issues) == 0


# ── 3-F: IDESettingsRule ─────────────────────────────────────────────────

class TestIDESettings:
    def test_detects_token_in_npmrc(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".npmrc", "//registry.npmjs.org/:_authToken=npm_abcdef1234567890"),
        ])
        issues = IDESettingsRule().run(ctx)
        assert any(i.severity == Severity.HIGH for i in issues)

    def test_warns_about_npmrc_presence(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".npmrc", "registry=https://registry.npmjs.org/"),
        ])
        issues = IDESettingsRule().run(ctx)
        assert len(issues) >= 1

    def test_ignores_normal_file(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("main.py", "print('hello')"),
        ])
        issues = IDESettingsRule().run(ctx)
        assert len(issues) == 0


# ── 3-G: PrivateKeysRule ────────────────────────────────────────────────

class TestPrivateKeys:
    @pytest.mark.parametrize("filename,expected_sev", [
        ("id_rsa", Severity.CRITICAL),
        ("id_ed25519", Severity.CRITICAL),
        ("known_hosts", Severity.MEDIUM),
    ])
    def test_detects_ssh_key_files(self, tmp_path: Path, filename: str, expected_sev: Severity):
        ctx = make_ctx(tmp_path, all_files=[filename])
        issues = PrivateKeysRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == expected_sev

    @pytest.mark.parametrize("filename,expected_sev", [
        ("server.pem", Severity.CRITICAL),
        ("private.key", Severity.CRITICAL),
        ("cert.p12", Severity.CRITICAL),
        ("app.keystore", Severity.HIGH),
        ("release.jks", Severity.HIGH),
    ])
    def test_detects_certificate_files(self, tmp_path: Path, filename: str, expected_sev: Severity):
        ctx = make_ctx(tmp_path, all_files=[filename])
        issues = PrivateKeysRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == expected_sev

    def test_ignores_normal_files(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py", "README.md"])
        issues = PrivateKeysRule().run(ctx)
        assert len(issues) == 0


# ── 3-H: HardcodedPatternsRule ──────────────────────────────────────────

class TestHardcodedPatterns:
    @pytest.mark.parametrize("line,desc_fragment", [
        ("key = 'sk-abcdefghijklmnopqrstuvwxyz'", "OpenAI"),
        ("key = 'sk-ant-abcdefghijklmnopqrstuvwxyz'", "Anthropic"),
        ("key = 'AKIAIOSFODNN7EXAMPLE'", "AWS"),
        ("key = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'", "GitHub"),
        ("key = 'glpat-abcdefghij1234567890'", "GitLab"),
        ("key = 'xoxb-fake0token0for0testing0only'", "Slack"),
    ])
    def test_detects_api_key_prefixes(self, tmp_path: Path, line: str, desc_fragment: str):
        ctx = make_ctx(tmp_path, text_files=[("app.py", line)])
        issues = HardcodedPatternsRule().run(ctx)
        api_issues = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(api_issues) >= 1
        assert any(desc_fragment in i.message for i in api_issues)

    def test_detects_variable_assignment(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", 'password = "supersecretpassword"'),
        ])
        issues = HardcodedPatternsRule().run(ctx)
        assert any(i.message == "Possible hardcoded secret in variable assignment" for i in issues)

    def test_detects_connection_string(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", 'url = "postgres://admin:password@localhost:5432/db"'),
        ])
        issues = HardcodedPatternsRule().run(ctx)
        assert any("connection string" in i.message.lower() for i in issues)

    def test_detects_webhook_url(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", 'url = "https://hooks.slack.com/services/T00/B00/xxxx"'),
        ])
        issues = HardcodedPatternsRule().run(ctx)
        assert any("Webhook" in i.message for i in issues)

    def test_short_password_not_detected(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", 'password = "short"'),
        ])
        issues = HardcodedPatternsRule().run(ctx)
        var_issues = [i for i in issues if "variable assignment" in i.message]
        assert len(var_issues) == 0

    def test_no_issues_on_clean_code(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", 'import os\ndb_url = os.environ["DATABASE_URL"]'),
        ])
        issues = HardcodedPatternsRule().run(ctx)
        assert len(issues) == 0


# ── 3-I: FrontendEnvRule ─────────────────────────────────────────────────

class TestFrontendEnv:
    @pytest.mark.parametrize("var", [
        "NEXT_PUBLIC_SECRET_KEY",
        "NEXT_PUBLIC_DB_PASSWORD",
        "VITE_SECRET",
        "REACT_APP_PRIVATE_KEY",
        "NUXT_PUBLIC_DATABASE_URL",
        "EXPO_PUBLIC_SECRET",
    ])
    def test_detects_dangerous_frontend_vars(self, tmp_path: Path, var: str):
        ctx = make_ctx(tmp_path, text_files=[
            (".env", f"{var}=some_value"),
        ])
        issues = FrontendEnvRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].rule_id == "SECRET-FRONTEND-ENV"

    def test_ignores_safe_public_key(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".env", "NEXT_PUBLIC_KEY=abc123"),
        ])
        issues = FrontendEnvRule().run(ctx)
        assert len(issues) == 0

    def test_ignores_public_url(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".env", "NEXT_PUBLIC_API_URL=https://api.example.com"),
        ])
        issues = FrontendEnvRule().run(ctx)
        assert len(issues) == 0

    def test_ignores_non_frontend_prefix(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".env", "DB_PASSWORD=secret123"),
        ])
        issues = FrontendEnvRule().run(ctx)
        assert len(issues) == 0

    def test_ignores_comments(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            (".env", "# NEXT_PUBLIC_SECRET=abc"),
        ])
        issues = FrontendEnvRule().run(ctx)
        assert len(issues) == 0


# ── 3-J: DataFilesRule ──────────────────────────────────────────────────

class TestDataFiles:
    @pytest.mark.parametrize("filename,expected_sev", [
        ("dump.sql", Severity.HIGH),
        ("backup.dump", Severity.HIGH),
        ("data.bak", Severity.HIGH),
        ("app.sqlite", Severity.HIGH),
        ("local.db", Severity.HIGH),
        ("access.log", Severity.MEDIUM),
        ("export.csv", Severity.MEDIUM),
    ])
    def test_detects_data_files(self, tmp_path: Path, filename: str, expected_sev: Severity):
        ctx = make_ctx(tmp_path, all_files=[filename])
        issues = DataFilesRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == expected_sev

    def test_ignores_normal_files(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py", "index.js"])
        issues = DataFilesRule().run(ctx)
        assert len(issues) == 0


# ── 3-K: DocSecretsRule ─────────────────────────────────────────────────

class TestDocSecrets:
    def test_detects_api_key_in_readme(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("README.md", 'Set your key: sk-abcdefghijklmnopqrstuvwxyz'),
        ])
        issues = DocSecretsRule().run(ctx)
        assert len(issues) == 1

    def test_detects_password_in_docs(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("docs/setup.md", 'password: "real_password_here"'),
        ])
        issues = DocSecretsRule().run(ctx)
        assert len(issues) == 1

    def test_detects_connection_string_in_docs(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("README.md", 'Use postgres://admin:pass@host/db'),
        ])
        issues = DocSecretsRule().run(ctx)
        assert len(issues) == 1

    def test_ignores_non_doc_files(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", 'key = "sk-abcdefghijklmnopqrstuvwxyz"'),
        ])
        issues = DocSecretsRule().run(ctx)
        assert len(issues) == 0

    def test_no_issues_on_clean_readme(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("README.md", "# My Project\n\nA cool project."),
        ])
        issues = DocSecretsRule().run(ctx)
        assert len(issues) == 0


# ── 3-L: MobileFilesRule ────────────────────────────────────────────────

class TestMobileFiles:
    def test_detects_api_key_in_manifest(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("AndroidManifest.xml", 'api_key = "AIzaSyABCDEFGHIJKLMNOP"'),
        ])
        issues = MobileFilesRule().run(ctx)
        assert len(issues) == 1

    def test_ignores_manifest_without_secrets(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("AndroidManifest.xml", '<manifest package="com.example.app">'),
        ])
        issues = MobileFilesRule().run(ctx)
        assert len(issues) == 0


# ── 3-M: SystemConfigsRule ──────────────────────────────────────────────

class TestSystemConfigs:
    @pytest.mark.parametrize("filename", [".pgpass", ".my.cnf", "kubeconfig"])
    def test_detects_critical_system_files(self, tmp_path: Path, filename: str):
        ctx = make_ctx(tmp_path, all_files=[filename])
        issues = SystemConfigsRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL

    def test_detects_kube_config_path(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".kube/config"])
        issues = SystemConfigsRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.CRITICAL

    def test_ignores_normal_files(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py"])
        issues = SystemConfigsRule().run(ctx)
        assert len(issues) == 0


# ── 3-N: EditorRemnantsRule ─────────────────────────────────────────────

class TestEditorRemnants:
    def test_detects_bash_history(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".bash_history"])
        issues = EditorRemnantsRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.HIGH

    def test_detects_ds_store(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".DS_Store"])
        issues = EditorRemnantsRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.LOW

    def test_detects_vim_swap(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["file.py.swp"])
        issues = EditorRemnantsRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.LOW

    def test_detects_sensitive_dotfile(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=[".ftpconfig"])
        issues = EditorRemnantsRule().run(ctx)
        assert len(issues) == 1
        assert issues[0].severity == Severity.MEDIUM

    def test_ignores_normal_files(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, all_files=["main.py", ".gitignore"])
        issues = EditorRemnantsRule().run(ctx)
        assert len(issues) == 0
