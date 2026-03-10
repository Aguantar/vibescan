# VibeScan — Architecture Design Document

## 1. 데이터 흐름 (파이프라인)

```
사용자 입력
│  vibescan scan ./project --html report.html --min-severity medium
│
▼
┌─────────────────────────────────────────┐
│  1. CLI Parser (typer)                  │
│  - 경로, 옵션, 플래그 파싱              │
│  - 유효성 검증 (경로 존재 여부 등)       │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  1.5. Config Loader                     │
│  - .vibescanrc / vibescan.toml 로드     │
│  - CLI 옵션과 병합 (CLI가 우선)          │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  2. File Collector                      │
│                                         │
│  Track A: 텍스트 파일 수집              │
│  - 재귀 탐색 + 제외 디렉토리 필터링     │
│  - 확장자 + 파일명 기반 판별            │
│    (Dockerfile, Makefile 등 포함)       │
│  - 인코딩 안전 처리 (UTF-8 실패 시 skip)│
│  - 대용량 파일 보호 (상한선 설정)        │
│  - 심볼릭 링크 감지 → 건너뛰기          │
│                                         │
│  Track B: 전체 파일 목록                │
│  - 바이너리 포함 전체 파일 경로 수집     │
│  - 존재 자체가 위험한 파일 탐지용        │
│    (*.pem, *.key, *.sqlite 등)          │
│                                         │
│  Track C: .gitignore 파싱              │
│  - ignore 패턴 목록 추출                │
│  - 중첩 .gitignore 지원 (모노레포)      │
│                                         │
│  Output: ProjectContext                 │
│  {text_files[], all_files[],            │
│   gitignore_patterns[], project_root,   │
│   skipped_files[]}                      │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  3. Rule Engine (핵심)                  │
│                                         │
│  ProjectContext를 받아서 규칙 순회       │
│                                         │
│  각 Rule은 필요한 데이터만 사용:        │
│  - SecretRule → text_files + all_files  │
│                 + gitignore_patterns    │
│  - GitHygieneRule → all_files           │
│                     + gitignore_patterns│
│  - DangerousPatternRule → text_files    │
│  - StructureRule → all_files            │
│                                         │
│  Rule 카테고리:                         │
│  ① SecretRule (11개 서브 카테고리)      │
│  ② GitHygieneRule                      │
│  ③ DangerousPatternRule                │
│  ④ StructureRule                       │
│                                         │
│  Output: Issue[]                        │
│  {rule_id, severity, file, line,        │
│   message, why, fix}                    │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  4. Result Aggregator                   │
│  - severity 필터링 (--min-severity)     │
│  - rule 제외 (--ignore-rule)            │
│  - severity별 카운트 집계               │
│  - 파일별 그룹핑                         │
│  - exit code 결정                       │
│    (CRITICAL/HIGH 발견 시 exit 1)       │
│                                         │
│  Output: ScanResult                     │
│  {issues[], summary, metadata,          │
│   exit_code}                            │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  5. Reporter                            │
│  ┌───────────┬───────────┬───────────┐  │
│  │ Console   │ JSON      │ HTML      │  │
│  │ Reporter  │ Reporter  │ Reporter  │  │
│  │           │           │           │  │
│  │ rich로    │ json      │ Jinja2    │  │
│  │ 컬러 출력 │ dump      │ 템플릿    │  │
│  └───────────┴───────────┴───────────┘  │
│                                         │
│  Console은 항상 출력                     │
│  JSON/HTML은 옵션 지정 시 파일 저장      │
└─────────────┬───────────────────────────┘
              │
              ▼
        exit(scan_result.exit_code)
```

---

## 2. 핵심 설계 원칙

### 플러그인 구조 Rule Engine
각 Rule은 독립 클래스. Rule Engine이 등록된 규칙을 순회 실행.
새 규칙 추가 시 새 클래스만 작성하면 됨. 기존 코드 수정 불필요.

### Issue 객체에 why/fix 포함
기존 도구와의 핵심 차별점. 단순 경고가 아니라 "왜 위험한지", "어떻게 고치는지"를 Issue에 내장.

### ProjectContext 공유 객체
.gitignore 파싱 결과를 SecretRule, GitHygieneRule, StructureRule이 공유.
파일 목록도 중복 탐색 없이 한 번만 수집.

### File Collector 안전장치
- 심볼릭 링크: 감지 시 건너뛰기 (무한 루프 방지, 범위 밖 접근 차단)
- 인코딩: UTF-8 디코딩 실패 시 skip + skipped_files에 기록
- 대용량: 파일 크기 상한선 (기본 5MB) 초과 시 skip
- 바이너리: 존재 감지는 하되 내용 읽기는 안 함

### CI/CD 호환 exit code
- exit 0: 문제 없음 또는 LOW만 발견
- exit 1: CRITICAL 또는 HIGH 발견
- GitHub Actions에서 바로 활용 가능

---

## 3. 전체 탐지 대상 목록 (최종)

### 3-A. 환경변수 파일
`.env`, `.env.local`, `.env.production`, `.env.development`,
`.env.staging`, `.env.test`, `.env.vault`

### 3-B. 설정 파일 하드코딩
`config.py`, `settings.py`, `config.js`, `config.ts`,
`config.yaml`, `config.yml`, `config.toml`,
`application.properties`, `application.yml`,
`appsettings.json`, `appsettings.Development.json`,
`wp-config.php`, `alembic.ini`,
`knexfile.js`, `ormconfig.json`, `prisma/.env`,
`database.yml`, `secrets.yml`

### 3-C. 클라우드 서비스 인증 파일
`serviceAccountKey.json`, `*-service-account.json`,
`google-services.json`, `GoogleService-Info.plist`,
`credentials.json`, `application_default_credentials.json`,
`token.json`, `client_secret*.json`,
`.boto`, AWS credentials 패턴,
`terraform.tfvars`, `terraform.tfstate`,
`firebase.json`, `.firebaserc`,
`supabase/config.toml`, `wrangler.toml`, `fly.toml`,
`amplify/team-provider-info.json`, `sentry.properties`

### 3-D. Docker 및 인프라 설정
`docker-compose.yml`, `docker-compose.*.yml`,
`Dockerfile`,
`nginx.conf`, `values.yaml` (Helm),
`k8s/*.yaml`,
`ansible/inventory`, `ansible/vars/*.yml`,
`Caddyfile`

### 3-E. CI/CD 파이프라인
`.github/workflows/*.yml`, `.gitlab-ci.yml`,
`Jenkinsfile`, `bitbucket-pipelines.yml`,
`vercel.json`, `netlify.toml`,
`.travis.yml`, `.circleci/config.yml`,
`Procfile`

### 3-F. IDE 및 개발 도구 설정
`.vscode/settings.json`, `.vscode/launch.json`,
`.idea/` 전체,
`.npmrc`, `.pypirc`, `.netrc`,
`.docker/config.json`,
`gradle.properties`, `local.properties`

### 3-G. SSH 키 및 인증서 파일
`id_rsa`, `id_ed25519`,
`*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`,
`known_hosts`

### 3-H. 코드 내 하드코딩 패턴 (regex + 변수명)
API Key 형식: `sk-`, `pk_live_`, `pk_test_`, `rk_live_`, `AKIA`,
`ghp_`, `glpat-`, `xoxb-`/`xoxp-`, `sk-ant-`
변수명: password, passwd, secret, token, api_key, apikey,
auth_token, access_key, private_key, client_secret
연결 문자열: mongodb://, postgres://, mysql://, redis://, amqp://
Webhook: hooks.slack.com, discord.com/api/webhooks
인증 헤더: Authorization: Bearer, Basic auth base64

### 3-I. 프론트엔드 환경변수 노출
`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_`
+ SECRET, PASSWORD, PRIVATE, KEY 조합 (PUBLIC_KEY 제외)

### 3-J. 데이터 파일 노출
`*.sql`, `*.dump`, `*.bak`,
`*.sqlite`, `*.db`,
`*.csv` (대용량),
`*.log`,
`.ipynb` (Jupyter Notebook 셀 출력)

### 3-K. 문서 내 실수
`README.md`, `CONTRIBUTING.md`, `docs/*.md`,
코드 내 주석

### 3-L. 모바일 앱 파일 (신규)
`Info.plist`, `AndroidManifest.xml`, `strings.xml`,
`*.keystore`, `Fastfile`

### 3-M. DB 클라이언트 / 시스템 설정 (신규)
`.pgpass`, `.my.cnf`,
`.kube/config`, `kubeconfig`,
`build.gradle`, `build.gradle.kts`,
`Makefile`,
`composer.json` (PHP private registry),
`Gemfile` (Ruby private gem)

### 3-N. 숨김 파일 / 에디터 잔여물 (신규)
`.bash_history`, `.zsh_history`,
`.htaccess`,
`.ftpconfig`, `.sftp-config.json`,
`.s3cfg`,
`*.swp`, `*.swo` (Vim swap),
`.DS_Store`, `Thumbs.db`

---

## 4. 제외 디렉토리 (File Collector)

`node_modules`, `.git`, `.venv`, `venv`,
`build`, `dist`, `coverage`, `__pycache__`,
`.next`, `.nuxt`, `.output`,
`vendor`, `target`, `.gradle`,
`.tox`, `eggs`, `*.egg-info`,
`.mypy_cache`, `.pytest_cache`

---

## 5. 위험 코드 패턴 (최종)

### Python
eval(), exec(), subprocess(shell=True), os.system(),
pickle.loads(), yaml.load() (Loader 미지정),
DEBUG = True, ALLOWED_HOSTS = ['*'],
CORS_ALLOW_ALL_ORIGINS = True, verify=False (requests),
hashlib.md5()/sha1() (비밀번호용)

### JavaScript / TypeScript
eval(), innerHTML, dangerouslySetInnerHTML,
child_process.exec(), document.write(),
window.location = userInput,
cors({ origin: '*' }),
jwt.decode without jwt.verify,
eslint-disable (보안 규칙),
JSON.parse() without try-catch

### SQL (raw query)
f-string / template literal 쿼리 조합,
문자열 연결 쿼리 조합

---

*Last updated: 2026-03-10*
