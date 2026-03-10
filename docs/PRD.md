# VibeScan — Product Requirements Document

## 1. 프로젝트 한 줄 정의

> VibeScan은 개발자가 자신의 프로젝트 폴더를 **로컬에서 분석**하여 민감정보 노출, 보안 취약점, 설정 실수, 코드 품질 문제를 **초보자도 이해할 수 있는 설명형 리포트**로 제공하는 CLI 기반 코드 점검 도구이다.

### 핵심 철학

- **코드는 서버로 업로드되지 않는다** — 모든 분석은 로컬에서 수행
- **네트워크 통신 없이 동작한다** — 오프라인 환경에서도 사용 가능
- **초보자도 이해할 수 있는 설명을 제공한다** — "왜 문제인지", "어떻게 고치는지"까지 안내

---

## 2. 문제 정의

바이브코딩(AI 기반 코딩) 확산으로 비개발자나 초보 개발자도 빠르게 프로젝트를 만들 수 있게 되었지만, `.env` 파일 노출, API 키 하드코딩, debug 설정 활성화, `.gitignore` 누락 같은 보안·품질 문제가 빈번하게 발생하고 있다.

기존 정적 분석 도구(ESLint, Bandit 등)는 경고 메시지가 난해하고, 왜 문제인지에 대한 설명이 부족하며, 수정 방법 안내가 미흡하여 초보자가 활용하기 어렵다. VibeScan은 이 간극을 메운다.

---

## 3. 타겟 사용자 페르소나

### Persona 1 — 바이브코딩 입문자

ChatGPT, Claude, Cursor 등으로 코드를 생성하는 사용자. 보안 개념이 익숙하지 않고, 코드 품질보다 "동작 여부"에 집중한다. 쉽게 이해할 수 있는 점검 결과와 친절한 수정 가이드가 필요하다.

### Persona 2 — 주니어 개발자

개인 프로젝트나 포트폴리오를 GitHub에 공개하는 개발자. 공개 전 코드 점검, 기본 보안 체크, 코드 품질 개선에 대한 니즈가 있다.

### Persona 3 — 개발 학습자

프로그래밍을 공부 중이며 프로젝트 경험이 부족한 학습자. 코드 실수를 통한 학습과 코드 개선 피드백을 원한다.

---

## 4. 핵심 기능 (우선순위 순)

### P1. 프로젝트 스캔

```bash
vibescan scan ./project
```

프로젝트 폴더를 탐색하여 텍스트 파일을 수집한다. 아래 디렉토리는 자동 제외한다.

제외 대상: `node_modules`, `.git`, `.venv`, `venv`, `build`, `dist`, `coverage`, `__pycache__`, `.next`, `.nuxt`, `.output`, `vendor`, `target`, `.gradle`

---

### P2. Secret 및 민감정보 탐지

VibeScan의 핵심 차별점. 바이브코딩 유저가 실제로 노출하는 모든 경로를 포괄적으로 탐지한다.

#### 2-A. 환경변수 파일 노출

| 탐지 대상 파일 | 설명 |
|---------------|------|
| `.env` | 가장 흔한 시크릿 저장소. AI가 예시 값을 넣어주면 그대로 커밋됨 |
| `.env.local`, `.env.production`, `.env.development` | 환경별 설정 파일. .gitignore 누락 시 전부 노출 |
| `.env.staging`, `.env.test` | 스테이징/테스트 환경도 실제 키가 들어가는 경우 많음 |

탐지 로직: 이 파일들이 프로젝트에 존재하면서 `.gitignore`에 등록되지 않은 경우 → **CRITICAL**

#### 2-B. 설정 파일 하드코딩

| 탐지 대상 | 흔한 실수 패턴 |
|-----------|---------------|
| `config.py`, `settings.py` | `SECRET_KEY = "abc123"`, `DATABASE_URL = "postgres://user:pass@..."` |
| `config.js`, `config.ts` | `apiKey: "sk-..."`, `dbPassword: "mypassword"` |
| `config.yaml`, `config.yml`, `config.toml` | 평문 credential 저장 |
| `application.properties`, `application.yml` | Spring Boot DB 비밀번호, JWT 시크릿 |
| `appsettings.json`, `appsettings.Development.json` | .NET 프로젝트 연결문자열, 키 |
| `wp-config.php` | WordPress DB 비밀번호, AUTH_KEY, SALT |
| `alembic.ini` | `sqlalchemy.url`에 DB 비밀번호 포함 |
| `knexfile.js`, `ormconfig.json`, `prisma/.env` | ORM 설정의 DB 접속 정보 |
| `database.yml`, `secrets.yml` | Rails 프로젝트 DB 비밀번호, master key |

#### 2-C. 클라우드 서비스 인증 파일

| 탐지 대상 | 위험도 | 설명 |
|-----------|--------|------|
| `serviceAccountKey.json`, `*-service-account.json` | CRITICAL | Firebase/GCP 서비스 계정. 노출 시 전체 프로젝트 제어권 탈취 |
| `google-services.json` | HIGH | Android Firebase 설정. API 키, 프로젝트 ID 포함 |
| `GoogleService-Info.plist` | HIGH | iOS Firebase 설정 |
| `credentials.json` (GCP OAuth) | CRITICAL | Google OAuth 클라이언트 시크릿 |
| `application_default_credentials.json` | CRITICAL | GCP ADC 인증 파일 |
| `.boto`, AWS credentials 패턴 | CRITICAL | AWS 인증 파일이 프로젝트에 복사된 경우 |
| `terraform.tfvars` | CRITICAL | Terraform 변수에 비밀번호, 토큰 평문 저장 |
| `terraform.tfstate` | CRITICAL | 인프라 상태 파일에 모든 리소스 정보(비밀번호 포함) 저장 |

#### 2-D. Docker 및 인프라 설정

| 탐지 대상 | 흔한 실수 패턴 |
|-----------|---------------|
| `docker-compose.yml` | `POSTGRES_PASSWORD=mysecret`, `MYSQL_ROOT_PASSWORD=root` |
| `Dockerfile` | `ENV API_KEY=sk-...`, `ARG`로 전달한 시크릿이 레이어에 남음 |
| `nginx.conf` | upstream 서버 인증 정보, proxy_set_header에 토큰 |
| `values.yaml` (Helm) | Kubernetes 배포 설정에 평문 시크릿 |
| `k8s/*.yaml` | Secret 리소스가 base64 인코딩만 된 채 커밋 (암호화 아님) |
| `ansible/inventory`, `ansible/vars/*.yml` | 서버 접속 비밀번호, SSH 키 경로 |

#### 2-E. CI/CD 파이프라인

| 탐지 대상 | 흔한 실수 패턴 |
|-----------|---------------|
| `.github/workflows/*.yml` | 시크릿을 `${{ secrets.X }}` 대신 직접 하드코딩 |
| `.gitlab-ci.yml` | 변수 섹션에 평문 토큰 |
| `Jenkinsfile` | credentials 블록 없이 직접 토큰 사용 |
| `bitbucket-pipelines.yml` | 파이프라인에 직접 키 입력 |
| `vercel.json` | 환경변수에 시크릿 포함 |
| `netlify.toml` | 빌드 환경변수에 키 노출 |

#### 2-F. IDE 및 개발 도구 설정

| 탐지 대상 | 설명 |
|-----------|------|
| `.vscode/settings.json` | 확장 프로그램 토큰, 원격 서버 접속 정보 |
| `.vscode/launch.json` | 디버그 설정에 환경변수로 시크릿 직접 입력 |
| `.idea/` 디렉토리 전체 | JetBrains IDE 설정에 데이터소스 비밀번호 저장 |
| `.npmrc` | npm 레지스트리 인증 토큰 (`//registry.npmjs.org/:_authToken=`) |
| `.pypirc` | PyPI 업로드 토큰 |
| `.netrc` | Git/HTTP 인증 정보 (username, password) |
| `.docker/config.json` | Docker Hub 로그인 인증 정보 |
| `gradle.properties`, `local.properties` | Android 서명 키 비밀번호, SDK 경로 |

#### 2-G. SSH 키 및 인증서 파일

| 탐지 대상 | 위험도 |
|-----------|--------|
| `id_rsa`, `id_ed25519` (private key) | CRITICAL |
| `*.pem`, `*.key` | CRITICAL |
| `*.p12`, `*.pfx`, `*.jks` | CRITICAL — Java/Android 서명 키스토어 |
| `*.crt`와 함께 있는 `*.key` | HIGH — SSL 인증서 개인키 |
| `known_hosts` | LOW — 서버 정보 노출 |

#### 2-H. 코드 내 하드코딩 패턴 (regex + 변수명 기반)

| 패턴 카테고리 | 탐지 대상 |
|-------------|-----------|
| API Key 형식 | `sk-`, `pk_live_`, `pk_test_`, `rk_live_`, `AKIA` (AWS), `ghp_` (GitHub), `glpat-` (GitLab), `xoxb-`/`xoxp-` (Slack), `sk-ant-` (Anthropic) |
| 변수명 패턴 | `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `auth_token`, `access_key`, `private_key`, `client_secret` |
| 연결 문자열 | `mongodb://user:pass@`, `postgres://user:pass@`, `mysql://user:pass@`, `redis://:pass@`, `amqp://user:pass@` |
| Webhook URL | Slack webhook (`hooks.slack.com`), Discord webhook (`discord.com/api/webhooks`) |
| Bearer 토큰 | `Authorization: Bearer` 뒤에 실제 토큰값 하드코딩 |
| Base64 인코딩 시크릿 | `Basic` auth 헤더에 base64로 인코딩된 `user:password` |

#### 2-I. 프론트엔드 환경변수 노출

| 접두사 | 프레임워크 | 문제 |
|--------|-----------|------|
| `NEXT_PUBLIC_` | Next.js | 클라이언트 번들에 포함 → 브라우저에서 노출 |
| `VITE_` | Vite | 동일 |
| `REACT_APP_` | CRA | 동일 |
| `NUXT_PUBLIC_` | Nuxt 3 | 동일 |
| `EXPO_PUBLIC_` | Expo | 동일 |

탐지 로직: 위 접두사 + `SECRET`, `PASSWORD`, `PRIVATE`, `KEY` (단, `PUBLIC_KEY`는 제외) 조합 → **HIGH**

#### 2-J. 데이터 파일 노출

| 탐지 대상 | 설명 |
|-----------|------|
| `*.sql`, `*.dump`, `*.bak` | DB 백업 파일에 실제 사용자 데이터 포함 |
| `*.sqlite`, `*.db` | 로컬 DB 파일이 그대로 커밋 |
| `*.csv` (특정 크기 이상) | 개인정보 포함 가능성 있는 대량 데이터 |
| `*.log` | 로그 파일에 토큰, 요청 헤더, 사용자 정보 기록 |
| `.ipynb` (Jupyter Notebook) | 셀 출력에 API 응답, 토큰, 개인정보가 남아있음 |

#### 2-K. 문서 내 실수

| 탐지 대상 | 흔한 실수 패턴 |
|-----------|---------------|
| `README.md` | curl 예시에 실제 토큰: `curl -H "Authorization: Bearer sk-abc123..."` |
| `CONTRIBUTING.md` | 개발 환경 설정 안내에 실제 키 포함 |
| `docs/*.md` | API 문서에 실제 응답 예시로 민감 데이터 포함 |
| 주석(코드 내) | `// TODO: 나중에 환경변수로 바꾸기` 하고 실제 키가 그 위에 있음 |

---

### P3. Git Hygiene 검사

| 검사 항목 | 심각도 |
|-----------|--------|
| `.gitignore` 파일 존재 여부 | HIGH |
| `.env*` ignore 여부 | CRITICAL |
| `.venv`, `node_modules`, `__pycache__` ignore 여부 | MEDIUM |
| `*.pem`, `*.key`, `*.p12` ignore 여부 | CRITICAL |
| `*.sqlite`, `*.db`, `*.log` ignore 여부 | MEDIUM |
| `serviceAccountKey*.json` ignore 여부 | CRITICAL |
| `.idea/`, `.vscode/` ignore 여부 | LOW |
| `terraform.tfstate`, `*.tfvars` ignore 여부 | CRITICAL |
| `local.properties` (Android) ignore 여부 | HIGH |
| `.docker/config.json` ignore 여부 | HIGH |
| `.npmrc`, `.pypirc`, `.netrc` ignore 여부 | HIGH |

---

### P4. 위험 코드 패턴 검사

#### Python

| 패턴 | 위험도 | 이유 |
|------|--------|------|
| `eval()` | HIGH | 임의 코드 실행 |
| `exec()` | HIGH | 임의 코드 실행 |
| `subprocess(shell=True)` | HIGH | 쉘 인젝션 |
| `os.system()` | HIGH | 쉘 인젝션 |
| `pickle.loads()` | HIGH | 역직렬화 공격 |
| `yaml.load()` (Loader 미지정) | MEDIUM | 임의 코드 실행 (`yaml.safe_load` 사용해야 함) |
| `DEBUG = True` | MEDIUM | 프로덕션에서 디버그 모드 노출 |
| `ALLOWED_HOSTS = ['*']` | MEDIUM | Django 호스트 검증 비활성화 |
| `CORS_ALLOW_ALL_ORIGINS = True` | MEDIUM | 모든 도메인에서 API 접근 허용 |
| `verify=False` (requests) | MEDIUM | SSL 인증서 검증 비활성화 |
| `hashlib.md5()`, `hashlib.sha1()` (비밀번호용) | MEDIUM | 취약한 해시 알고리즘 |

#### JavaScript / TypeScript

| 패턴 | 위험도 | 이유 |
|------|--------|------|
| `eval()` | HIGH | 임의 코드 실행 |
| `innerHTML =` | HIGH | XSS 공격 |
| `dangerouslySetInnerHTML` | HIGH | React XSS |
| `child_process.exec()` | HIGH | 쉘 인젝션 |
| `document.write()` | MEDIUM | XSS 가능성 |
| `window.location = userInput` | MEDIUM | Open redirect |
| `cors({ origin: '*' })` | MEDIUM | 모든 도메인 CORS 허용 |
| `jwt.verify` 없이 `jwt.decode`만 사용 | HIGH | 토큰 서명 검증 누락 |
| `// eslint-disable` (보안 규칙) | LOW | 의도적 보안 규칙 비활성화 |
| `JSON.parse()` without try-catch | LOW | 파싱 에러 미처리 |

#### SQL (raw query 패턴)

| 패턴 | 위험도 | 이유 |
|------|--------|------|
| f-string / template literal로 쿼리 조합 | CRITICAL | SQL 인젝션 |
| 문자열 연결로 쿼리 조합 | CRITICAL | SQL 인젝션 |

---

### P5. 프로젝트 구조 점검

| 검사 항목 | 심각도 | 설명 |
|-----------|--------|------|
| README.md 존재 여부 | LOW | 프로젝트 설명 부재 |
| `.env.example` 존재 여부 | MEDIUM | 환경변수 가이드 부재 시 다른 개발자가 실제 .env를 커밋할 위험 |
| 테스트 파일 존재 여부 | LOW | tests/, __tests__, *.test.*, *.spec.* |
| TODO / FIXME 잔존 | LOW | 미완성 코드 확인 |
| `LICENSE` 파일 존재 여부 | LOW | 오픈소스 공개 시 라이선스 명시 필요 |
| `package-lock.json` 또는 `yarn.lock` 존재 여부 | LOW | 의존성 고정 미비 |
| `requirements.txt` 버전 고정 여부 | MEDIUM | `==` 없이 패키지명만 있으면 취약 버전 설치 위험 |
| `Dockerfile` 베이스 이미지 태그 | MEDIUM | `FROM python:latest` 대신 특정 버전 사용 권장 |

---

## 5. 리포트 출력

VibeScan은 3가지 형식으로 결과를 제공한다.

| 형식 | 용도 | 명령 옵션 |
|------|------|-----------|
| 콘솔 출력 | 터미널에서 즉시 확인 | (기본) |
| JSON 리포트 | CI/CD 연동, 머신 파싱 | `--json report.json` |
| HTML 리포트 | 브라우저에서 시각적 확인 (요약, severity 분포, 수정 가이드) | `--html report.html` |

추가 CLI 옵션:

```bash
vibescan scan ./project --min-severity medium    # 최소 심각도 필터
vibescan scan ./project --ignore-rule RULE_ID    # 특정 규칙 제외
```

### 리포트 심각도 체계

| 등급 | 기준 | 예시 |
|------|------|------|
| CRITICAL | 즉시 악용 가능, 금전적 피해 직결 | AWS 키 노출, DB 비밀번호 노출, 서비스 계정 키 커밋 |
| HIGH | 보안 취약점, 공격 경로 제공 | API 키 하드코딩, eval() 사용, SQL 인젝션 패턴 |
| MEDIUM | 잠재적 위험, 모범 사례 위반 | DEBUG=True, CORS 전체 허용, SSL 검증 비활성화 |
| LOW | 코드 품질, 유지보수성 | README 부재, TODO 잔존, 테스트 미작성 |

---

## 6. 화면 구성 (웹사이트)

웹사이트는 정적 사이트로 운영하며, CLI 도구의 소개·설치·문서 역할을 한다.

| 페이지 | 역할 |
|--------|------|
| **Home** | 제품 소개, 문제 정의, 주요 기능 하이라이트, "Your code never leaves your machine." 메시지 |
| **Install** | 설치 가이드(`pip install vibescan`), CLI 사용법, 옵션 설명 |
| **Sample Report** | HTML 리포트 예시를 임베드하여 결과물 미리보기 제공 |
| **Rules** | 탐지 규칙 목록, 각 규칙의 심각도·설명·수정 가이드 |
| **GitHub** | 오픈소스 저장소 링크 |

---

## 7. 기술 스택

### CLI / 분석 엔진

| 구분 | 선택 | 비고 |
|------|------|------|
| 언어 | Python | 풍부한 정적 분석 생태계, AST 내장 지원 |
| CLI 프레임워크 | typer | 타입 힌트 기반 CLI, 자동 help 생성 |
| 콘솔 출력 | rich | 컬러 테이블, 프로그레스바, 심각도별 색상 표현 |
| 패턴 탐지 | regex (re) | Secret·위험 패턴 탐지 |
| 코드 분석 | ast (내장) | Python 코드의 함수 호출 패턴 분석 |

### 웹사이트

| 구분 | 추천 | 비고 |
|------|------|------|
| 프레임워크 | VitePress 또는 Astro | 마크다운 기반 정적 사이트, 빠른 빌드 |
| 호스팅 | GitHub Pages 또는 Vercel | 무료, 자동 배포 |

### 인프라

| 구분 | 선택 |
|------|------|
| 저장소 | GitHub (소스 코드 공개, 버전 관리, 릴리즈) |
| 패키지 배포 | PyPI (`pip install vibescan`) |
| DB | 없음 — 로컬 전용, 서버리스 설계 |

---

## 8. 보안 설계

VibeScan은 다음 원칙을 따른다.

- 분석은 전부 로컬에서 수행된다
- 코드가 외부 서버로 업로드되지 않는다
- 네트워크 통신 없이 동작한다
- 지정된 프로젝트 폴더만 읽기 전용으로 접근한다

웹사이트와 README에 다음 메시지를 명시한다:

> **Your code never leaves your machine. VibeScan runs entirely locally.**

---

## 9. 참고 레퍼런스

### CLI 도구

| 도구 | 참고 포인트 |
|------|------------|
| ESLint | 규칙 기반 정적 분석, 플러그인 구조 |
| Ruff | Python 린터, 빠른 실행 속도, CLI UX |
| Bandit | Python 보안 분석, 심각도 분류 체계 |
| Semgrep | 패턴 매칭 기반 분석, 다중 언어 지원 |
| Trivy | 취약점 스캐너, 리포트 형식 |
| detect-secrets (Yelp) | Secret 탐지 특화 도구, 플러그인 구조 |
| gitleaks | Git 히스토리 포함 시크릿 탐지 |
| truffleHog | 엔트로피 기반 시크릿 탐지 |

### 웹사이트 UX

| 사이트 | 참고 포인트 |
|--------|------------|
| semgrep.dev | 규칙 문서화, 플레이그라운드 |
| trivy.dev | 제품 소개 랜딩, 설치 가이드 |
| eslint.org | 규칙 카탈로그, 설정 문서 |

---

## 10. 향후 확장 가능 기능

| 기능 | 설명 |
|------|------|
| GitHub Repository Scan | 원격 저장소 직접 분석 |
| Git History Scan | 커밋 히스토리에서 과거 노출된 시크릿 탐지 |
| VSCode Extension | 에디터 내 실시간 점검 |
| CI Integration | GitHub Actions 워크플로우 연동 |
| Rule Customization | 사용자 정의 규칙 추가 (YAML/TOML) |
| AI 기반 코드 설명 | LLM 연동으로 문제 원인·수정 방법 자동 생성 |
| Auto-fix | 간단한 문제 자동 수정 (`.gitignore` 추가, `.env.example` 생성 등) |
| 다국어 리포트 | 한국어, 영어, 일본어 리포트 지원 |

---

*Last updated: 2026-03-09*
