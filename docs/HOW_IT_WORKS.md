# VibeScan 동작 원리

VibeScan은 **100% 로컬에서 동작하는 정적 분석(Static Analysis) 도구**입니다.
네트워크 통신 없이, 프로젝트 디렉토리의 파일을 읽고 정규표현식 기반 패턴 매칭으로 보안 이슈를 탐지합니다.

---

## 전체 파이프라인

```
사용자 입력          내부 처리                        사용자 출력
───────────    ─────────────────────────────    ──────────────
vibescan       ┌──────────┐   ┌────────────┐
scan ./        │  File    │──▶│  Project   │
my-project     │ Collector│   │  Context   │
               └──────────┘   └─────┬──────┘
                                    │
                              ┌─────▼──────┐
                              │   Rule     │──▶ Issue 목록
                              │   Engine   │
                              └─────┬──────┘
                                    │
                              ┌─────▼──────┐
                              │  Reporter  │──▶ 콘솔 출력
                              └────────────┘
```

**6단계 요약:**

1. **CLI Parser** — 사용자 명령 해석 (`typer`)
2. **File Collector** — 프로젝트 파일 수집 (텍스트 파일 읽기 + 전체 파일 목록)
3. **GitIgnore Parser** — `.gitignore` 패턴 수집
4. **Rule Engine** — 17개 규칙으로 보안 이슈 탐지
5. **Aggregator** — 이슈 필터링 + 정렬
6. **Console Reporter** — 컬러 출력 (`rich`)

---

## 1단계: CLI Parser

**파일:** `src/vibescan/cli.py`

```python
@app.command()
def scan(
    path: Path = typer.Argument(".", ...),
    min_severity: str = typer.Option("info", "--min-severity", "-s"),
    version: bool = typer.Option(False, "--version", "-v"),
) -> None:
```

[typer](https://typer.tiangolo.com/) 라이브러리로 CLI를 구성합니다.
사용자가 `vibescan scan ./my-project`을 실행하면:

1. `path`를 `Path` 객체로 변환 (존재 여부 검증 포함)
2. `min_severity`를 `Severity` enum으로 변환
3. File Collector → Rule Engine → Reporter 파이프라인을 순서대로 실행
4. CRITICAL 또는 HIGH 이슈가 있으면 **exit code 1** 반환 (CI/CD 연동용)

---

## 2단계: File Collector

**파일:** `src/vibescan/collector/file_collector.py`

File Collector는 프로젝트 디렉토리를 재귀 탐색하며 **3개 트랙**으로 데이터를 수집합니다.

### Track A: 텍스트 파일 읽기 (`text_files`)

```python
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".env", ".yaml", ".json", ...}  # 50+개
TEXT_FILENAMES = {"Dockerfile", "Makefile", ".gitignore", ".npmrc", ...}
```

- 확장자 또는 파일명이 알려진 텍스트 파일이면 **내용을 읽어서** `TextFile(path, content)` 객체로 저장
- 이 내용을 기반으로 정규표현식 패턴 매칭 수행 (Secret 탐지, 위험 코드 패턴 등)

### Track B: 전체 파일 목록 (`all_files`)

- 모든 파일의 **상대 경로**를 문자열 리스트로 저장
- 내용은 읽지 않음 — 파일 이름과 확장자만으로 판단하는 규칙에 사용
- 예: `.env` 파일 존재 여부, `.pem` 파일 추적 여부, 프로젝트 구조 검사

### Track C: .gitignore 패턴 (`gitignore_patterns`)

```python
def parse_gitignore_files(root: Path) -> list[str]:
    for gitignore in root.rglob(".gitignore"):
        for line in text.splitlines():
            if stripped and not stripped.startswith("#"):
                patterns.append(stripped)
```

- 프로젝트 내 모든 `.gitignore` 파일을 찾아 패턴 추출
- 주석(`#`)과 빈 줄 제외
- Git Hygiene 규칙에서 "이 파일이 .gitignore에 등록되어 있는가?" 판단에 사용

### 안전장치

| 보호 | 구현 |
|------|------|
| 심볼릭 링크 | `is_symlink()` → 건너뜀 (무한 루프 방지) |
| 인코딩 에러 | `UnicodeDecodeError` 예외 처리 → skipped 목록에 추가 |
| 대용량 파일 | 5MB 초과 → 건너뜀 (메모리 보호) |
| 권한 없음 | `PermissionError` → 건너뜀 |
| 불필요한 디렉토리 | `node_modules`, `.git`, `__pycache__` 등 18개 디렉토리 제외 |

### 최종 산출물: ProjectContext

```python
@dataclass
class ProjectContext:
    project_root: Path
    text_files: list[TextFile]     # Track A — 내용 포함
    all_files: list[str]           # Track B — 경로만
    gitignore_patterns: list[str]  # Track C — .gitignore 패턴
    skipped_files: list[str]       # 건너뛴 파일들
```

이 `ProjectContext` 객체가 모든 규칙의 **공유 입력**입니다.

---

## 3단계: Rule Engine

**파일:** `src/vibescan/rules/`

### 플러그인 아키텍처

모든 규칙은 `BaseRule` 추상 클래스를 상속합니다:

```python
class BaseRule(ABC):
    @abstractmethod
    def run(self, ctx: ProjectContext) -> list[Issue]:
        ...
```

새 규칙 추가 = 새 클래스 작성 + `registry.py`에 등록. 기존 코드 수정 불필요.

### 17개 규칙 목록

Registry(`src/vibescan/rules/registry.py`)에서 모든 규칙 인스턴스를 생성합니다:

#### Secret 탐지 규칙 (14개)

| 규칙 ID | 클래스 | 탐지 대상 | 탐지 방식 |
|---------|--------|----------|----------|
| SECRET-ENV | `EnvExposureRule` | `.env` 파일 존재 | 파일명 패턴 매칭 (Track B) |
| SECRET-CONFIG | `ConfigHardcodeRule` | `config.py`, `settings.yml` 등의 하드코딩 | 정규표현식 (Track A) |
| SECRET-CLOUD | `CloudCredentialsRule` | `serviceAccountKey.json`, `terraform.tfstate` | 파일명 매칭 (Track B) |
| SECRET-INFRA | `DockerInfraRule` | `docker-compose.yml`의 평문 비밀번호 | 정규표현식 (Track A) |
| SECRET-CICD | `CICDPipelineRule` | GitHub Actions yml의 하드코딩된 시크릿 | 정규표현식 (Track A) |
| SECRET-IDE | `IDESettingsRule` | `.vscode/launch.json`, `.npmrc` 토큰 | 파일명 + 정규표현식 |
| SECRET-KEY | `PrivateKeysRule` | `*.pem`, `*.key`, `*.jks` 파일 | 확장자 매칭 (Track B) |
| SECRET-HARDCODED | `HardcodedPatternsRule` | `sk-`, `AKIA`, `ghp_` 등 코드 내 키 | 정규표현식 (Track A) |
| SECRET-FRONTEND-ENV | `FrontendEnvRule` | `NEXT_PUBLIC_SECRET`, `VITE_API_KEY` | 정규표현식 (Track A) |
| SECRET-DATA | `DataFilesRule` | `.sqlite`, `.sql`, Jupyter 출력 | 파일명 + 정규표현식 |
| SECRET-DOC | `DocSecretsRule` | README의 curl 예시에 실제 토큰 | 정규표현식 (Track A) |
| SECRET-MOBILE | `MobileFilesRule` | AndroidManifest, Info.plist의 API 키 | 파일명 + 정규표현식 |
| SECRET-SYSTEM | `SystemConfigsRule` | `.pgpass`, `.kube/config` | 파일명 매칭 (Track B) |
| SECRET-REMNANT | `EditorRemnantsRule` | `.bash_history`, Vim swap, `.htaccess` | 파일명 매칭 (Track B) |

#### Git Hygiene 규칙 (4개 하위 체크)

| 규칙 ID | 체크 내용 |
|---------|----------|
| GIT-NO-GITIGNORE | `.gitignore` 파일 자체가 없음 |
| GIT-MISSING-PATTERN | `.env`, `node_modules` 등 필수 패턴 미등록 |
| GIT-DANGEROUS-TRACKED | `.pem`, `.key` 등 위험 확장자 파일이 gitignore 안 됨 |
| GIT-BLOAT | `node_modules` 같은 디렉토리에 파일이 100개 이상 (추적 의심) |

#### 위험 코드 패턴 규칙

| 언어 | 탐지 패턴 |
|------|----------|
| Python | `eval()`, `exec()`, `subprocess(shell=True)`, `os.system()`, `pickle.loads()`, `yaml.load()`, `DEBUG=True`, `ALLOWED_HOSTS=['*']`, `verify=False`, 약한 해시 |
| JS/TS | `eval()`, `.innerHTML=`, `dangerouslySetInnerHTML`, `child_process.exec()`, `document.write()`, CORS `origin:'*'`, `jwt.decode()`, eslint-disable |
| SQL | f-string 쿼리, 템플릿 리터럴 쿼리, 문자열 연결 쿼리 |

**파일 확장자 기반 라우팅:**
`.py` → Python + SQL 패턴 적용, `.js`/`.ts` → JS + SQL 패턴 적용

**주석 건너뛰기:** `#` 또는 `//`로 시작하는 줄은 무시 (오탐 방지)

#### 프로젝트 구조 규칙

| 규칙 ID | 체크 내용 |
|---------|----------|
| STRUCTURE-HEALTH | README, .gitignore, LICENSE 존재 여부 |
| STRUCTURE-LOCKFILE | package.json이 있는데 lockfile이 없으면 경고 |
| STRUCTURE-SUSPICIOUS-DIR | `.ssh/`, `.aws/`, `.kube/` 디렉토리가 프로젝트 안에 있으면 경고 |
| STRUCTURE-FLAT | 루트에 파일 20개 초과 → 구조 정리 권고 |

### 탐지 원리: 정규표현식 패턴 매칭

VibeScan의 핵심 탐지 엔진은 **정규표현식(regex)**입니다. 예시:

```python
# AWS Access Key는 항상 AKIA로 시작하고 16자리 대문자+숫자
re.compile(r'AKIA[0-9A-Z]{16}')

# OpenAI API 키는 sk-로 시작하고 20자 이상
re.compile(r'sk-[a-zA-Z0-9]{20,}')

# f-string SQL 인젝션: f"SELECT ... {변수}"
re.compile(r'''f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{''')
```

**왜 정규표현식인가?**
- 외부 의존성 없음 — Python 표준 라이브러리 `re`만 사용
- 빠름 — 수천 개 파일도 몇 초 내 처리
- 투명함 — 각 패턴이 무엇을 잡는지 코드에서 바로 읽힘
- 오프라인 — AI/ML 모델 불필요, 네트워크 불필요

---

## 4단계: 이슈 모델과 심각도 체계

**파일:** `src/vibescan/models/issue.py`

### Issue 데이터 구조

```python
@dataclass
class Issue:
    rule_id: str          # "SECRET-ENV", "DANGER-CODE" 등
    severity: Severity    # CRITICAL ~ INFO
    file: str             # 상대 파일 경로
    line: int | None      # 줄 번호 (해당 시 표시)
    message: str          # 무엇이 발견되었는가
    why: str              # 왜 위험한가
    fix: str              # 어떻게 고치는가
```

모든 이슈는 `message`(무엇), `why`(왜), `fix`(어떻게)를 포함합니다.
이것이 VibeScan의 핵심 철학입니다 — **경고만 하지 않고, 이유와 해결법까지 안내합니다.**

### Severity 비교 연산

```python
class Severity(str, Enum):
    CRITICAL = "critical"   # rank 4
    HIGH = "high"           # rank 3
    MEDIUM = "medium"       # rank 2
    LOW = "low"             # rank 1
    INFO = "info"           # rank 0
```

`Severity`에 `__ge__`, `__gt__`, `__le__`, `__lt__`를 구현하여 비교가 가능합니다:

```python
# --min-severity medium 이면 MEDIUM 이상만 표시
filtered = [i for i in all_issues if i.severity >= threshold]
```

### Exit Code 결정

```python
@property
def exit_code(self) -> int:
    for issue in self.issues:
        if issue.severity in (Severity.CRITICAL, Severity.HIGH):
            return 1
    return 0
```

- **exit 1** = CRITICAL 또는 HIGH 이슈 존재 → CI/CD에서 빌드 실패로 활용
- **exit 0** = 심각한 이슈 없음

---

## 5단계: Aggregator (필터링 + 정렬)

**파일:** `src/vibescan/cli.py` 내부 (별도 모듈 없이 CLI에서 직접 처리)

```python
# 모든 규칙 실행
all_issues = []
for rule in get_all_rules():
    all_issues.extend(rule.run(ctx))

# 심각도 필터링
filtered = [i for i in all_issues if i.severity >= threshold]

# CRITICAL → HIGH → MEDIUM → LOW → INFO 순으로 정렬
filtered.sort(key=lambda i: -i.severity.rank)
```

---

## 6단계: Console Reporter

**파일:** `src/vibescan/reporters/console.py`

[rich](https://rich.readthedocs.io/) 라이브러리로 컬러풀한 터미널 출력을 생성합니다.

```
┌─────────────── Scan Complete ────────────────┐
│ VibeScan scanned 147 files in ./my-project   │
└──────────────────────────────────────────────┘

 Summary
  CRITICAL   2
  HIGH       2
  MEDIUM     1

config.py
  [!] Hardcoded AWS access key detected (AKIA...)
      Line 23
      Why: Hardcoded API keys in source code can be extracted...
      Fix: Move the key to an environment variable...
```

- 파일별 그룹핑
- 심각도별 색상 (CRITICAL=빨강 볼드, HIGH=빨강, MEDIUM=노랑, LOW=시안)
- 각 이슈마다 Why/Fix 표시

---

## 디렉토리 구조

```
src/vibescan/
├── __init__.py              # 버전 정보
├── __main__.py              # python -m vibescan 지원
├── cli.py                   # CLI 진입점 (typer)
├── collector/
│   ├── context.py           # ProjectContext, TextFile 데이터 클래스
│   ├── file_collector.py    # 파일 수집기
│   └── gitignore_parser.py  # .gitignore 파서
├── models/
│   ├── issue.py             # Issue, Severity 모델
│   └── scan_result.py       # ScanResult (summary, exit_code)
├── rules/
│   ├── base.py              # BaseRule 추상 클래스
│   ├── registry.py          # 전체 규칙 등록소
│   ├── git_hygiene.py       # Git 위생 규칙
│   ├── dangerous_patterns.py # 위험 코드 패턴 규칙
│   ├── structure.py         # 프로젝트 구조 규칙
│   └── secret/              # 14개 시크릿 탐지 규칙
│       ├── env_exposure.py
│       ├── config_hardcode.py
│       ├── cloud_credentials.py
│       ├── docker_infra.py
│       ├── cicd_pipeline.py
│       ├── ide_settings.py
│       ├── private_keys.py
│       ├── hardcoded_patterns.py
│       ├── frontend_env.py
│       ├── data_files.py
│       ├── doc_secrets.py
│       ├── mobile_files.py
│       ├── system_configs.py
│       └── editor_remnants.py
└── reporters/
    └── console.py           # Rich 콘솔 리포터
```

---

## 설계 원칙

### 1. 완전한 로컬 실행

```
네트워크 통신 = 0
외부 API 호출 = 0
데이터 업로드 = 0
```

코드가 어디에도 전송되지 않습니다. `import` 목록에 `requests`, `urllib`, `http` 같은 네트워크 모듈이 없습니다.

### 2. 플러그인 구조

규칙 추가 과정:
1. `BaseRule`을 상속한 새 클래스 작성
2. `run(ctx) -> list[Issue]` 메서드 구현
3. `registry.py`에 import + 등록

기존 코드를 수정할 필요가 없습니다 (Open/Closed Principle).

### 3. 설명형 리포트

모든 이슈에 3가지 정보 포함:
- **message** — 무엇이 발견되었는가
- **why** — 왜 위험한가 (초보자도 이해 가능한 설명)
- **fix** — 구체적으로 어떻게 고치는가

### 4. 최소 의존성

```toml
dependencies = [
    "typer>=0.9.0",    # CLI 프레임워크
    "rich>=13.0.0",    # 터미널 출력
]
```

2개 라이브러리만 사용합니다. 나머지는 모두 Python 표준 라이브러리(`re`, `pathlib`, `dataclasses`, `enum`, `abc`).

### 5. CI/CD 호환

```python
# CRITICAL 또는 HIGH 이슈 → exit code 1 → CI 빌드 실패
raise typer.Exit(code=result.exit_code)
```

GitHub Actions, GitLab CI 등에서 바로 사용 가능:

```yaml
- name: Security scan
  run: |
    pip install vibescan-cli
    vibescan scan .
```

---

## 데이터 흐름 요약

```
vibescan scan ./my-project
        │
        ▼
   ┌─────────────────────────────────────────┐
   │  File Collector                         │
   │  ├─ Track A: 텍스트 파일 내용 읽기      │
   │  ├─ Track B: 전체 파일 경로 수집        │
   │  └─ Track C: .gitignore 패턴 파싱       │
   └──────────────┬──────────────────────────┘
                  │ ProjectContext
                  ▼
   ┌─────────────────────────────────────────┐
   │  Rule Engine (17 rules)                 │
   │  ├─ 14 Secret Rules      → Track A + B │
   │  ├─  1 Git Hygiene Rule  → Track B + C │
   │  ├─  1 Dangerous Pattern → Track A     │
   │  └─  1 Structure Rule    → Track B     │
   └──────────────┬──────────────────────────┘
                  │ list[Issue]
                  ▼
   ┌─────────────────────────────────────────┐
   │  Filter + Sort                          │
   │  ├─ --min-severity 필터                 │
   │  └─ 심각도 내림차순 정렬                │
   └──────────────┬──────────────────────────┘
                  │ ScanResult
                  ▼
   ┌─────────────────────────────────────────┐
   │  Console Reporter (rich)                │
   │  ├─ 파일별 그룹핑                       │
   │  ├─ 심각도 컬러링                       │
   │  └─ Why / Fix 설명                      │
   └──────────────┬──────────────────────────┘
                  │
                  ▼
            exit code 0 or 1
```
