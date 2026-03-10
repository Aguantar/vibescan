"""Internationalization — message translations for VibeScan."""

from __future__ import annotations

import locale
import os

# ---------------------------------------------------------------------------
# Auto-detect system language
# ---------------------------------------------------------------------------

def detect_lang() -> str:
    """Return 'ko' if the system locale is Korean, else 'en'."""
    try:
        loc = locale.getlocale()[0] or ""
    except (ValueError, TypeError):
        loc = ""
    if not loc:
        loc = os.environ.get("LANG", "") or os.environ.get("LANGUAGE", "")
    if loc.startswith("ko"):
        return "ko"
    return "en"


# ---------------------------------------------------------------------------
# Korean translations: English message → Korean message
# Keys are the exact English strings used in Issue.message / .why / .fix
# ---------------------------------------------------------------------------

KO: dict[str, str] = {
    # ── hardcoded_patterns.py ──
    "Possible hardcoded secret in variable assignment":
        "변수에 하드코딩된 시크릿이 포함되어 있을 수 있습니다",
    "Hardcoded API keys in source code can be extracted by anyone with repository access and used to compromise your services.":
        "소스 코드에 하드코딩된 API 키는 저장소에 접근할 수 있는 누구나 추출하여 서비스를 침해하는 데 사용할 수 있습니다.",
    "Move the key to an environment variable or a secrets manager. Rotate the exposed key immediately.":
        "키를 환경변수 또는 시크릿 매니저로 이동하세요. 노출된 키는 즉시 교체하세요.",
    "Secrets stored directly in code are visible to anyone with access to the repository.":
        "코드에 직접 저장된 시크릿은 저장소에 접근할 수 있는 누구나 볼 수 있습니다.",
    "Use environment variables or a secrets manager instead of hardcoding values.":
        "하드코딩 대신 환경변수 또는 시크릿 매니저를 사용하세요.",
    "Database connection string with credentials detected":
        "자격증명이 포함된 데이터베이스 연결 문자열이 감지되었습니다",
    "Connection strings containing passwords expose database access to anyone who can read the code.":
        "비밀번호가 포함된 연결 문자열은 코드를 읽을 수 있는 누구에게나 데이터베이스 접근 권한을 노출합니다.",
    "Use environment variables for connection strings: DATABASE_URL=postgres://...":
        "연결 문자열에 환경변수를 사용하세요: DATABASE_URL=postgres://...",
    "Webhook URL detected in source code":
        "소스 코드에서 Webhook URL이 감지되었습니다",
    "Exposed webhook URLs can be abused to send unauthorized messages.":
        "노출된 Webhook URL은 무단 메시지 전송에 악용될 수 있습니다.",
    "Store webhook URLs in environment variables.":
        "Webhook URL을 환경변수에 저장하세요.",

    # ── env_exposure.py ──
    "Environment files often contain database passwords, API keys, and other secrets. If committed to git, they are exposed in the repository history forever.":
        "환경 파일에는 데이터베이스 비밀번호, API 키 등의 시크릿이 포함되어 있는 경우가 많습니다. Git에 커밋되면 저장소 히스토리에 영구적으로 노출됩니다.",
    "Add the file to .gitignore. If already committed, rotate all secrets and use `git filter-branch` or BFG to purge history.":
        ".gitignore에 파일을 추가하세요. 이미 커밋된 경우, 모든 시크릿을 교체하고 `git filter-branch` 또는 BFG로 히스토리를 삭제하세요.",

    # ── config_hardcode.py ──
    "Configuration files with hardcoded credentials are often committed to version control, exposing secrets to anyone with repository access.":
        "하드코딩된 자격증명이 있는 설정 파일은 버전 관리 시스템에 커밋되는 경우가 많아, 저장소에 접근할 수 있는 누구에게나 시크릿이 노출됩니다.",
    "Use environment variables or a secrets manager. Reference them in config: os.environ['DB_PASSWORD'].":
        "환경변수 또는 시크릿 매니저를 사용하세요. 설정 파일에서는 os.environ['DB_PASSWORD']로 참조하세요.",

    # ── cloud_credentials.py ──
    "Cloud service credential files contain authentication keys that grant access to your cloud infrastructure. Exposure can lead to unauthorized access and data breaches.":
        "클라우드 서비스 자격증명 파일에는 클라우드 인프라에 접근할 수 있는 인증 키가 포함되어 있습니다. 노출 시 무단 접근과 데이터 유출로 이어질 수 있습니다.",
    "Remove the file from version control, add it to .gitignore, and rotate the credentials immediately.":
        "버전 관리에서 파일을 제거하고, .gitignore에 추가한 후, 자격증명을 즉시 교체하세요.",

    # ── docker_infra.py ──
    "Hardcoded secret in infrastructure config":
        "인프라 설정 파일에 하드코딩된 시크릿이 있습니다",
    "Docker and infrastructure configs with hardcoded secrets expose credentials when committed to version control.":
        "하드코딩된 시크릿이 있는 Docker 및 인프라 설정은 버전 관리 시스템에 커밋 시 자격증명을 노출합니다.",
    "Use environment variable substitution: ${DB_PASSWORD} in docker-compose, or Kubernetes Secrets for k8s manifests.":
        "환경변수 치환을 사용하세요: docker-compose에서는 ${DB_PASSWORD}, k8s 매니페스트에서는 Kubernetes Secrets를 사용하세요.",

    # ── cicd_pipeline.py ──
    "Hardcoded secret in CI/CD pipeline config":
        "CI/CD 파이프라인 설정에 하드코딩된 시크릿이 있습니다",
    "CI/CD configs are almost always committed to version control. Hardcoded secrets here are visible to all contributors.":
        "CI/CD 설정은 거의 항상 버전 관리 시스템에 커밋됩니다. 여기에 하드코딩된 시크릿은 모든 기여자에게 노출됩니다.",
    "Use your CI/CD platform's secret management: GitHub Actions secrets, GitLab CI variables, etc.":
        "CI/CD 플랫폼의 시크릿 관리 기능을 사용하세요: GitHub Actions secrets, GitLab CI variables 등.",

    # ── ide_settings.py ──
    "Possible credential in IDE/tool config":
        "IDE/도구 설정에 자격증명이 포함되어 있을 수 있습니다",
    "IDE and tool configs like .npmrc, .pypirc, and .netrc can contain registry auth tokens that grant publish access to packages.":
        ".npmrc, .pypirc, .netrc 등의 IDE/도구 설정 파일에는 패키지 배포 권한을 부여하는 레지스트리 인증 토큰이 포함될 수 있습니다.",
    "Use credential helpers or environment variables instead. Add the file to .gitignore.":
        "자격증명 헬퍼 또는 환경변수를 대신 사용하세요. 파일을 .gitignore에 추가하세요.",
    "These files may contain authentication tokens or registry credentials.":
        "이 파일에는 인증 토큰이나 레지스트리 자격증명이 포함되어 있을 수 있습니다.",
    "Add to .gitignore. Use per-machine config or credential helpers instead.":
        ".gitignore에 추가하세요. 머신별 설정 또는 자격증명 헬퍼를 대신 사용하세요.",

    # ── private_keys.py ──
    "Private SSH keys provide direct authentication to servers and services. If exposed, attackers gain unauthorized remote access.":
        "SSH 개인키는 서버와 서비스에 직접 인증을 제공합니다. 노출 시 공격자가 무단 원격 접근 권한을 얻게 됩니다.",
    "Remove the file, add it to .gitignore, and rotate the key pair immediately.":
        "파일을 제거하고, .gitignore에 추가한 후, 키 쌍을 즉시 교체하세요.",
    "Private keys and certificates should never be stored in version control. Exposure compromises TLS/SSL security and service authentication.":
        "개인키와 인증서는 버전 관리 시스템에 저장하면 안 됩니다. 노출 시 TLS/SSL 보안과 서비스 인증이 침해됩니다.",

    # ── frontend_env.py ──
    "Move the secret to a server-side-only env var (without the public prefix) and access it via an API route instead.":
        "시크릿을 서버 전용 환경변수(public 접두사 없이)로 이동하고, API 라우트를 통해 접근하세요.",

    # ── data_files.py ──
    "Add to .gitignore. If already committed, remove from history with BFG or git filter-branch.":
        ".gitignore에 추가하세요. 이미 커밋된 경우, BFG 또는 git filter-branch로 히스토리에서 제거하세요.",
    "Jupyter Notebook with cell outputs":
        "셀 출력이 포함된 Jupyter Notebook",
    "Notebook outputs can contain API responses, database query results, or error messages that leak secrets.":
        "Notebook 출력에는 API 응답, 데이터베이스 쿼리 결과, 시크릿이 노출될 수 있는 에러 메시지가 포함될 수 있습니다.",
    "Clear all outputs before committing: jupyter nbconvert --clear-output notebook.ipynb":
        "커밋 전 모든 출력을 지우세요: jupyter nbconvert --clear-output notebook.ipynb",
    "Database dump/backup file found":
        "데이터베이스 덤프/백업 파일이 발견되었습니다",
    "Database dumps contain full table data including user records, passwords, and personal information.":
        "데이터베이스 덤프에는 사용자 기록, 비밀번호, 개인정보를 포함한 전체 테이블 데이터가 포함되어 있습니다.",
    "CSV data file found":
        "CSV 데이터 파일이 발견되었습니다",
    "CSV files may contain exported user data, financial records, or other sensitive information.":
        "CSV 파일에는 내보낸 사용자 데이터, 재무 기록 또는 기타 민감 정보가 포함될 수 있습니다.",
    "SQLite database file found":
        "SQLite 데이터베이스 파일이 발견되었습니다",
    "SQLite databases may contain application data including user credentials and session tokens.":
        "SQLite 데이터베이스에는 사용자 자격증명과 세션 토큰을 포함한 애플리케이션 데이터가 포함될 수 있습니다.",
    "Log file found":
        "로그 파일이 발견되었습니다",
    "Log files may contain stack traces, IP addresses, session tokens, or API keys from error messages.":
        "로그 파일에는 에러 메시지의 스택 트레이스, IP 주소, 세션 토큰 또는 API 키가 포함될 수 있습니다.",

    # ── doc_secrets.py ──
    "Developers sometimes paste real credentials in documentation as examples. These are visible to anyone reading the docs.":
        "개발자가 문서에 실제 자격증명을 예시로 붙여넣는 경우가 있습니다. 문서를 읽는 누구나 볼 수 있습니다.",
    "Replace with placeholder values like 'sk-your-api-key-here' or '<YOUR_TOKEN>'.":
        "플레이스홀더 값으로 교체하세요: 'sk-your-api-key-here' 또는 '<YOUR_TOKEN>'.",

    # ── mobile_files.py ──
    "Mobile config files like AndroidManifest.xml and Info.plist are bundled into app packages (APK/IPA) that can be easily decompiled and inspected.":
        "AndroidManifest.xml, Info.plist 등의 모바일 설정 파일은 앱 패키지(APK/IPA)에 포함되며, 쉽게 디컴파일하여 확인할 수 있습니다.",
    "Use build-time secret injection (Gradle buildConfigField, Xcode xcconfig) instead of hardcoding values.":
        "값을 하드코딩하지 말고 빌드 시 시크릿 주입(Gradle buildConfigField, Xcode xcconfig)을 사용하세요.",

    # ── system_configs.py ──
    "System configuration files like .pgpass and kubeconfig contain plaintext credentials for database and cluster access.":
        ".pgpass, kubeconfig 등의 시스템 설정 파일에는 데이터베이스와 클러스터 접근을 위한 평문 자격증명이 포함되어 있습니다.",
    "Remove from repository, add to .gitignore, and rotate affected credentials.":
        "저장소에서 제거하고, .gitignore에 추가한 후, 관련 자격증명을 교체하세요.",
    "This file contains authentication credentials for infrastructure services.":
        "이 파일에는 인프라 서비스에 대한 인증 자격증명이 포함되어 있습니다.",
    "Remove from repository and add to .gitignore.":
        "저장소에서 제거하고 .gitignore에 추가하세요.",

    # ── editor_remnants.py ──
    "Shell history files record commands typed in the terminal, which often include passwords, tokens, and connection strings passed as arguments.":
        "쉘 히스토리 파일에는 터미널에서 입력한 명령이 기록되며, 비밀번호, 토큰, 연결 문자열이 인자로 포함되어 있는 경우가 많습니다.",
    "Remove immediately, add to .gitignore, and rotate any credentials visible in the history.":
        "즉시 제거하고, .gitignore에 추가한 후, 히스토리에 보이는 모든 자격증명을 교체하세요.",
    "Files like .ftpconfig and .s3cfg often contain server credentials and access keys.":
        ".ftpconfig, .s3cfg 등의 파일에는 서버 자격증명과 접근 키가 포함되어 있는 경우가 많습니다.",
    "Remove from repository and add to .gitignore.":
        "저장소에서 제거하고 .gitignore에 추가하세요.",
    "OS-generated files like .DS_Store can leak directory structure information and indicate poor .gitignore configuration.":
        ".DS_Store 같은 OS 생성 파일은 디렉토리 구조 정보를 노출할 수 있으며, .gitignore 설정이 미흡함을 나타냅니다.",
    "Vim swap files contain the contents of files being edited, potentially including sensitive files.":
        "Vim 스왑 파일에는 편집 중인 파일의 내용이 포함되어 있으며, 민감 파일이 포함될 수 있습니다.",

    # ── git_hygiene.py ──
    "No .gitignore file found in project":
        "프로젝트에 .gitignore 파일이 없습니다",
    "Without a .gitignore, all files including secrets, build artifacts, and dependencies can be accidentally committed to the repository.":
        ".gitignore가 없으면 시크릿, 빌드 결과물, 의존성 파일 등이 실수로 저장소에 커밋될 수 있습니다.",
    "Create a .gitignore file. Use gitignore.io or GitHub's template for your language/framework.":
        ".gitignore 파일을 생성하세요. gitignore.io 또는 GitHub 템플릿을 사용하세요.",

    # ── dangerous_patterns.py ── Python
    "Use of eval() detected":
        "eval() 사용이 감지되었습니다",
    "eval() executes arbitrary Python code. If user input reaches eval(), an attacker can run any code on your server (Remote Code Execution).":
        "eval()은 임의의 Python 코드를 실행합니다. 사용자 입력이 eval()에 전달되면, 공격자가 서버에서 임의의 코드를 실행할 수 있습니다(원격 코드 실행).",
    "Use ast.literal_eval() for safe literal parsing, or redesign to avoid dynamic code execution entirely.":
        "안전한 리터럴 파싱을 위해 ast.literal_eval()을 사용하거나, 동적 코드 실행을 완전히 제거하도록 재설계하세요.",
    "Use of exec() detected":
        "exec() 사용이 감지되었습니다",
    "exec() executes arbitrary Python statements. It poses the same Remote Code Execution risk as eval().":
        "exec()은 임의의 Python 문을 실행합니다. eval()과 동일한 원격 코드 실행 위험이 있습니다.",
    "Avoid exec(). Use structured data, dispatch tables, or a safe DSL instead of executing dynamic code.":
        "exec()을 피하세요. 동적 코드 실행 대신 구조화된 데이터, 디스패치 테이블 또는 안전한 DSL을 사용하세요.",
    "subprocess with shell=True detected":
        "subprocess에서 shell=True가 감지되었습니다",
    "shell=True passes the command through the system shell, enabling command injection if any part comes from user input.":
        "shell=True는 시스템 쉘을 통해 명령을 실행하므로, 사용자 입력이 포함되면 명령 주입 공격이 가능합니다.",
    "Use shell=False (the default) and pass arguments as a list: subprocess.run(['cmd', 'arg1', 'arg2']).":
        "shell=False(기본값)를 사용하고 인자를 리스트로 전달하세요: subprocess.run(['cmd', 'arg1', 'arg2']).",
    "Use of os.system() detected":
        "os.system() 사용이 감지되었습니다",
    "os.system() runs commands through the shell, vulnerable to command injection attacks.":
        "os.system()은 쉘을 통해 명령을 실행하며, 명령 주입 공격에 취약합니다.",
    "Use subprocess.run() with shell=False instead.":
        "대신 subprocess.run()을 shell=False와 함께 사용하세요.",
    "Use of pickle.load(s)() detected":
        "pickle.load(s)() 사용이 감지되었습니다",
    "Deserializing untrusted pickle data can execute arbitrary code. This is a known Remote Code Execution vector.":
        "신뢰할 수 없는 pickle 데이터를 역직렬화하면 임의의 코드가 실행될 수 있습니다. 알려진 원격 코드 실행 공격 벡터입니다.",
    "Use JSON or other safe serialization formats for untrusted data. If pickle is required, only load data from trusted sources.":
        "신뢰할 수 없는 데이터에는 JSON 또는 다른 안전한 직렬화 형식을 사용하세요. pickle이 필요하면 신뢰할 수 있는 출처의 데이터만 로드하세요.",
    "yaml.load() without explicit Loader":
        "명시적 Loader 없이 yaml.load()가 사용되었습니다",
    "yaml.load() without a safe Loader can execute arbitrary Python objects embedded in YAML, leading to code execution.":
        "안전한 Loader 없이 yaml.load()를 사용하면 YAML에 포함된 임의의 Python 객체가 실행되어 코드 실행으로 이어질 수 있습니다.",
    "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).":
        "yaml.safe_load() 또는 yaml.load(data, Loader=yaml.SafeLoader)를 사용하세요.",
    "DEBUG = True in code":
        "코드에 DEBUG = True가 설정되어 있습니다",
    "Debug mode in production exposes detailed error pages, stack traces, and internal state to attackers.":
        "프로덕션에서 디버그 모드는 상세한 에러 페이지, 스택 트레이스, 내부 상태를 공격자에게 노출합니다.",
    "Set DEBUG via environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'. Ensure it's False in production.":
        "환경변수로 DEBUG를 설정하세요: DEBUG = os.environ.get('DEBUG', 'False') == 'True'. 프로덕션에서는 반드시 False로 설정하세요.",
    "ALLOWED_HOSTS = ['*'] detected":
        "ALLOWED_HOSTS = ['*']가 감지되었습니다",
    "Allowing all hosts disables Django's host header validation, enabling HTTP Host header attacks.":
        "모든 호스트를 허용하면 Django의 호스트 헤더 검증이 비활성화되어 HTTP 호스트 헤더 공격이 가능합니다.",
    "Set ALLOWED_HOSTS to your actual domain names: ALLOWED_HOSTS = ['example.com', 'www.example.com'].":
        "실제 도메인 이름으로 설정하세요: ALLOWED_HOSTS = ['example.com', 'www.example.com'].",
    "CORS_ALLOW_ALL_ORIGINS = True":
        "CORS_ALLOW_ALL_ORIGINS = True가 설정되어 있습니다",
    "Allowing all CORS origins lets any website make authenticated requests to your API, potentially stealing user data.":
        "모든 CORS 출처를 허용하면 어떤 웹사이트든 API에 인증된 요청을 보낼 수 있어 사용자 데이터가 탈취될 수 있습니다.",
    "Set CORS_ALLOWED_ORIGINS to specific trusted domains.":
        "CORS_ALLOWED_ORIGINS를 신뢰할 수 있는 특정 도메인으로 설정하세요.",
    "SSL verification disabled (verify=False)":
        "SSL 인증서 검증이 비활성화되었습니다 (verify=False)",
    "Disabling SSL certificate verification makes the connection vulnerable to man-in-the-middle attacks.":
        "SSL 인증서 검증을 비활성화하면 중간자(MITM) 공격에 취약해집니다.",
    "Remove verify=False. Fix the underlying certificate issue instead. Use certifi package if CA bundle is missing.":
        "verify=False를 제거하세요. 인증서 문제를 근본적으로 해결하세요. CA 번들이 없으면 certifi 패키지를 사용하세요.",
    "Weak hash algorithm (MD5/SHA1) used":
        "취약한 해시 알고리즘(MD5/SHA1)이 사용되었습니다",
    "MD5 and SHA1 are cryptographically broken. If used for password hashing or security-sensitive operations, they can be attacked.":
        "MD5와 SHA1은 암호학적으로 취약합니다. 비밀번호 해싱이나 보안 관련 작업에 사용되면 공격받을 수 있습니다.",
    "Use hashlib.sha256() or bcrypt/argon2 for password hashing.":
        "hashlib.sha256() 또는 비밀번호 해싱에는 bcrypt/argon2를 사용하세요.",

    # ── dangerous_patterns.py ── JavaScript
    "eval() executes arbitrary JavaScript code. If user input reaches eval(), attackers can steal data or hijack sessions (XSS).":
        "eval()은 임의의 JavaScript 코드를 실행합니다. 사용자 입력이 eval()에 전달되면 데이터 탈취나 세션 하이재킹(XSS)이 가능합니다.",
    "Use JSON.parse() for data, or structured alternatives. Never eval() user-controlled input.":
        "데이터에는 JSON.parse()를 사용하세요. 사용자가 제어하는 입력에 절대 eval()을 사용하지 마세요.",
    "Direct innerHTML assignment detected":
        "innerHTML 직접 할당이 감지되었습니다",
    "Setting innerHTML with unsanitized data is a primary XSS vector. Attackers can inject scripts that steal cookies and credentials.":
        "정제되지 않은 데이터로 innerHTML을 설정하면 주요 XSS 공격 벡터가 됩니다. 공격자가 쿠키와 자격증명을 탈취하는 스크립트를 주입할 수 있습니다.",
    "Use textContent for plain text, or DOMPurify.sanitize() for HTML. In React, avoid dangerouslySetInnerHTML.":
        "일반 텍스트에는 textContent를, HTML에는 DOMPurify.sanitize()를 사용하세요. React에서는 dangerouslySetInnerHTML을 피하세요.",
    "dangerouslySetInnerHTML used in React":
        "React에서 dangerouslySetInnerHTML이 사용되었습니다",
    "This bypasses React's XSS protection. If the HTML comes from user input or an external source, it enables XSS attacks.":
        "이는 React의 XSS 보호를 우회합니다. HTML이 사용자 입력이나 외부 소스에서 오면 XSS 공격이 가능합니다.",
    "Use sanitization libraries like DOMPurify before passing HTML, or restructure to avoid raw HTML injection.":
        "HTML을 전달하기 전에 DOMPurify 같은 정제 라이브러리를 사용하거나, 원시 HTML 주입을 피하도록 재구성하세요.",
    "child_process.exec() detected":
        "child_process.exec()가 감지되었습니다",
    "exec() runs commands through the shell, enabling command injection if arguments include user input.":
        "exec()은 쉘을 통해 명령을 실행하므로, 인자에 사용자 입력이 포함되면 명령 주입이 가능합니다.",
    "Use child_process.execFile() or spawn() with arguments as an array.":
        "child_process.execFile() 또는 spawn()을 인자를 배열로 전달하여 사용하세요.",
    "document.write() detected":
        "document.write()가 감지되었습니다",
    "document.write() can inject arbitrary HTML/scripts into the page, creating XSS vulnerabilities.":
        "document.write()는 페이지에 임의의 HTML/스크립트를 주입할 수 있어 XSS 취약점을 만듭니다.",
    "Use DOM manipulation methods: createElement(), appendChild(), or textContent.":
        "DOM 조작 메서드를 사용하세요: createElement(), appendChild() 또는 textContent.",
    "CORS with wildcard origin: '*'":
        "CORS에 와일드카드 origin '*'이 사용되었습니다",
    "Allowing all CORS origins lets any website make requests to your API, potentially accessing sensitive data.":
        "모든 CORS 출처를 허용하면 어떤 웹사이트든 API에 요청을 보낼 수 있어 민감 데이터에 접근할 수 있습니다.",
    "Set origin to specific trusted domains: cors({ origin: ['https://myapp.com'] }).":
        "신뢰할 수 있는 특정 도메인으로 설정하세요: cors({ origin: ['https://myapp.com'] }).",
    "jwt.decode() without verification":
        "검증 없이 jwt.decode()가 사용되었습니다",
    "jwt.decode() does not verify the token signature. Attackers can forge tokens with arbitrary claims.":
        "jwt.decode()는 토큰 서명을 검증하지 않습니다. 공격자가 임의의 클레임으로 토큰을 위조할 수 있습니다.",
    "Use jwt.verify() instead, which validates the signature.":
        "서명을 검증하는 jwt.verify()를 대신 사용하세요.",
    "Security-related ESLint rule disabled":
        "보안 관련 ESLint 규칙이 비활성화되었습니다",
    "Disabling security ESLint rules removes automated detection of dangerous patterns in this code section.":
        "보안 ESLint 규칙을 비활성화하면 이 코드 구간에서 위험 패턴의 자동 탐지가 제거됩니다.",
    "Fix the underlying issue instead of disabling the rule. If intentional, add a comment explaining why.":
        "규칙을 비활성화하지 말고 근본적인 문제를 수정하세요. 의도적인 경우, 이유를 설명하는 주석을 추가하세요.",

    # ── dangerous_patterns.py ── SQL
    "SQL query built with f-string interpolation":
        "f-string 보간을 사용한 SQL 쿼리가 감지되었습니다",
    "Embedding variables directly in SQL via f-strings enables SQL injection. Attackers can read, modify, or delete all database data.":
        "f-string을 통해 SQL에 변수를 직접 삽입하면 SQL 인젝션이 가능합니다. 공격자가 모든 데이터베이스 데이터를 읽고, 수정하고, 삭제할 수 있습니다.",
    "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)).":
        "파라미터화된 쿼리를 사용하세요: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)).",
    "SQL query built with template literal interpolation":
        "템플릿 리터럴 보간을 사용한 SQL 쿼리가 감지되었습니다",
    "Embedding variables in SQL via template literals enables SQL injection attacks.":
        "템플릿 리터럴을 통해 SQL에 변수를 삽입하면 SQL 인젝션 공격이 가능합니다.",
    "Use parameterized queries with your ORM or query builder: db.query('SELECT * FROM users WHERE id = $1', [userId]).":
        "ORM 또는 쿼리 빌더로 파라미터화된 쿼리를 사용하세요: db.query('SELECT * FROM users WHERE id = $1', [userId]).",
    "SQL query built with string concatenation":
        "문자열 연결을 사용한 SQL 쿼리가 감지되었습니다",
    "Concatenating user input into SQL strings is the classic SQL injection vulnerability.":
        "사용자 입력을 SQL 문자열에 연결하는 것은 고전적인 SQL 인젝션 취약점입니다.",
    "Use parameterized queries or an ORM. Never build SQL from string concatenation.":
        "파라미터화된 쿼리 또는 ORM을 사용하세요. 문자열 연결로 SQL을 만들지 마세요.",
    "SQL clause built with string concatenation":
        "문자열 연결을 사용한 SQL 절이 감지되었습니다",
    "Appending SQL clauses via string concatenation suggests dynamic query building vulnerable to injection.":
        "문자열 연결로 SQL 절을 추가하는 것은 인젝션에 취약한 동적 쿼리 생성을 의미합니다.",
    "Use parameterized queries or a query builder library.":
        "파라미터화된 쿼리 또는 쿼리 빌더 라이브러리를 사용하세요.",

    # ── structure.py ──
    "Essential project files help contributors understand the project, ensure reproducible builds, and prevent accidental exposure of sensitive files.":
        "필수 프로젝트 파일은 기여자가 프로젝트를 이해하고, 재현 가능한 빌드를 보장하며, 민감 파일의 실수 노출을 방지합니다.",
    "Add a README.md describing the project, setup instructions, and usage examples.":
        "프로젝트 설명, 설치 방법, 사용 예시를 포함한 README.md를 추가하세요.",
    "Add a LICENSE file to clarify usage rights. Without one, the code is under exclusive copyright by default.":
        "사용 권한을 명시하는 LICENSE 파일을 추가하세요. 없으면 기본적으로 독점 저작권이 적용됩니다.",
    "Create a .gitignore using a template for your language/framework (see gitignore.io).":
        "사용하는 언어/프레임워크에 맞는 .gitignore 템플릿을 생성하세요 (gitignore.io 참조).",
    "Without a lockfile, dependency versions are not pinned. Different installs may get different versions, causing 'works on my machine' bugs and potential supply chain attacks via version drift.":
        "lockfile이 없으면 의존성 버전이 고정되지 않습니다. 설치 환경마다 다른 버전을 받을 수 있어 '내 머신에서는 되는데' 문제와 버전 드리프트를 통한 공급망 공격이 발생할 수 있습니다.",
    "System credential directories should never exist inside a project repository. They contain private keys and access tokens for infrastructure.":
        "시스템 자격증명 디렉토리는 프로젝트 저장소 안에 절대 있으면 안 됩니다. 인프라의 개인키와 접근 토큰이 포함되어 있습니다.",
    "A flat project structure makes it harder to navigate and maintain. Important files get lost among many others.":
        "평탄한 프로젝트 구조는 탐색과 유지보수를 어렵게 합니다. 많은 파일 사이에서 중요한 파일을 찾기 어려워집니다.",
    "Organize source files into directories: src/, lib/, tests/, docs/, etc.":
        "소스 파일을 디렉토리로 정리하세요: src/, lib/, tests/, docs/ 등.",

    # ── structure.py — health files ──
    "No README.md found":
        "README.md 파일이 없습니다",
    "No .gitignore found":
        ".gitignore 파일이 없습니다",
    "No LICENSE file found":
        "LICENSE 파일이 없습니다",

    # ── structure.py — suspicious dirs ──
    "SSH directory '.ssh' found in project":
        "프로젝트에 SSH 디렉토리 '.ssh'가 발견되었습니다",
    "Remove the .ssh directory from the project. SSH keys should only exist in ~/.ssh.":
        "프로젝트에서 .ssh 디렉토리를 제거하세요. SSH 키는 ~/.ssh에만 있어야 합니다.",
    "AWS config directory '.aws' found in project":
        "프로젝트에 AWS 설정 디렉토리 '.aws'가 발견되었습니다",
    "Remove the .aws directory. AWS credentials should only exist in ~/.aws.":
        ".aws 디렉토리를 제거하세요. AWS 자격증명은 ~/.aws에만 있어야 합니다.",
    "Kubernetes config directory '.kube' found in project":
        "프로젝트에 Kubernetes 설정 디렉토리 '.kube'가 발견되었습니다",
    "Remove the .kube directory. Kubeconfig should only exist in ~/.kube.":
        ".kube 디렉토리를 제거하세요. Kubeconfig는 ~/.kube에만 있어야 합니다.",
}


def translate(text: str, lang: str) -> str:
    """Translate text to the target language. Returns original if no translation."""
    if lang != "ko":
        return text
    return KO.get(text, text)
