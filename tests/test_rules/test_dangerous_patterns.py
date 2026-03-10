"""Tests for DangerousPatternRule."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import make_ctx
from vibescan.models.issue import Severity
from vibescan.rules.dangerous_patterns import DangerousPatternRule


rule = DangerousPatternRule()


# ── Python patterns ──────────────────────────────────────────────────────

class TestPythonPatterns:
    @pytest.mark.parametrize("code,msg_fragment", [
        ("eval(user_input)", "eval()"),
        ("exec(code_str)", "exec()"),
        ("subprocess.run(cmd, shell=True)", "shell=True"),
        ("os.system('rm -rf /')", "os.system()"),
        ("data = pickle.loads(raw)", "pickle"),
        ("yaml.load(data)", "yaml.load"),
    ])
    def test_detects_dangerous_calls(self, tmp_path: Path, code: str, msg_fragment: str):
        ctx = make_ctx(tmp_path, text_files=[("app.py", code)])
        issues = rule.run(ctx)
        assert any(msg_fragment in i.message for i in issues)

    def test_detects_debug_true(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[("settings.py", "DEBUG = True")])
        issues = rule.run(ctx)
        assert any("DEBUG" in i.message for i in issues)

    def test_detects_allowed_hosts_wildcard(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[("settings.py", "ALLOWED_HOSTS = ['*']")])
        issues = rule.run(ctx)
        assert any("ALLOWED_HOSTS" in i.message for i in issues)

    def test_detects_cors_allow_all(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("settings.py", "CORS_ALLOW_ALL_ORIGINS = True"),
        ])
        issues = rule.run(ctx)
        assert any("CORS" in i.message for i in issues)

    def test_detects_verify_false(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("client.py", "requests.get(url, verify=False)"),
        ])
        issues = rule.run(ctx)
        assert any("SSL" in i.message or "verify" in i.message for i in issues)

    def test_detects_weak_hash(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("auth.py", "h = hashlib.md5(password.encode())"),
        ])
        issues = rule.run(ctx)
        assert any("MD5" in i.message or "SHA1" in i.message for i in issues)

    def test_skips_commented_line(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", "# eval(user_input)"),
        ])
        issues = rule.run(ctx)
        assert len(issues) == 0

    def test_safe_yaml_load(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.py", "data = yaml.safe_load(text)"),
        ])
        issues = rule.run(ctx)
        assert len(issues) == 0

    def test_clean_python_no_issues(self, tmp_path: Path):
        code = (
            "import json\n"
            "import subprocess\n"
            "result = subprocess.run(['ls', '-la'], capture_output=True)\n"
            "data = json.loads(response.text)\n"
        )
        ctx = make_ctx(tmp_path, text_files=[("main.py", code)])
        issues = rule.run(ctx)
        assert len(issues) == 0


# ── JavaScript / TypeScript patterns ────────────────────────────────────

class TestJavaScriptPatterns:
    @pytest.mark.parametrize("code,msg_fragment", [
        ("el.innerHTML = userInput;", "innerHTML"),
        ("<div dangerouslySetInnerHTML={{__html: data}} />", "dangerouslySetInnerHTML"),
        ("child_process.exec(cmd);", "child_process"),
        ("document.write(html);", "document.write"),
    ])
    def test_detects_dangerous_js(self, tmp_path: Path, code: str, msg_fragment: str):
        ctx = make_ctx(tmp_path, text_files=[("app.js", code)])
        issues = rule.run(ctx)
        assert any(msg_fragment in i.message for i in issues)

    def test_detects_cors_wildcard(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("server.js", "app.use(cors({ origin: '*' }))"),
        ])
        issues = rule.run(ctx)
        assert any("CORS" in i.message for i in issues)

    def test_detects_jwt_decode(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("auth.ts", "const payload = jwt.decode(token);"),
        ])
        issues = rule.run(ctx)
        assert any("jwt" in i.message.lower() for i in issues)

    def test_detects_eslint_disable_security(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.js", "// eslint-disable-next-line no-eval, security/detect-eval"),
        ])
        # This is a comment line, so it should be skipped
        issues = rule.run(ctx)
        assert len(issues) == 0

    def test_skips_commented_js(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("app.js", "// el.innerHTML = userInput;"),
        ])
        issues = rule.run(ctx)
        assert len(issues) == 0

    def test_applies_to_tsx(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("Component.tsx", "el.innerHTML = data;"),
        ])
        issues = rule.run(ctx)
        assert len(issues) >= 1

    def test_clean_js_no_issues(self, tmp_path: Path):
        code = (
            "const data = JSON.parse(text);\n"
            "el.textContent = userInput;\n"
            "const result = await fetch('/api');\n"
        )
        ctx = make_ctx(tmp_path, text_files=[("app.js", code)])
        issues = rule.run(ctx)
        assert len(issues) == 0


# ── SQL injection patterns ──────────────────────────────────────────────

class TestSQLPatterns:
    def test_detects_fstring_sql(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("db.py", 'query = f"SELECT * FROM users WHERE id = {user_id}"'),
        ])
        issues = rule.run(ctx)
        sql_issues = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(sql_issues) >= 1

    def test_detects_template_literal_sql(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("db.js", "const q = `SELECT * FROM users WHERE id = ${userId}`;"),
        ])
        issues = rule.run(ctx)
        sql_issues = [i for i in issues if i.severity == Severity.CRITICAL]
        assert len(sql_issues) >= 1

    def test_detects_concat_sql(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("db.py", 'query = "SELECT * FROM users WHERE id = " + user_id'),
        ])
        issues = rule.run(ctx)
        sql_issues = [i for i in issues if "SQL" in i.message or "concatenation" in i.message]
        assert len(sql_issues) >= 1

    def test_safe_parameterized_query(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("db.py", "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"),
        ])
        issues = rule.run(ctx)
        assert len(issues) == 0


# ── Extension routing ───────────────────────────────────────────────────

class TestExtensionRouting:
    def test_ignores_non_code_files(self, tmp_path: Path):
        ctx = make_ctx(tmp_path, text_files=[
            ("notes.md", "eval(something)"),
            ("data.yaml", "eval: true"),
        ])
        issues = rule.run(ctx)
        assert len(issues) == 0

    def test_applies_sql_to_multiple_languages(self, tmp_path: Path):
        fstring_sql = 'f"SELECT * FROM users WHERE id = {uid}"'
        ctx = make_ctx(tmp_path, text_files=[
            ("query.py", fstring_sql),
        ])
        issues = rule.run(ctx)
        assert len(issues) >= 1
