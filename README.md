# 🛡️ VibeScan

**Push 전에, 코드를 점검하세요.**

VibeScan은 바이브코딩(AI 기반 코딩) 시대에 맞춘 **로컬 코드 보안 점검 도구**입니다.  
민감정보 노출, 보안 취약점, 설정 실수를 초보자도 이해할 수 있는 설명형 리포트로 제공합니다.

```bash
pip install vibescan
vibescan scan ./my-project
```

> **Your code never leaves your machine.** VibeScan runs entirely locally.

---

## 왜 VibeScan인가

AI가 만들어준 코드를 그대로 push하면 이런 일이 생깁니다.

- `.env`에 실제 API 키가 들어간 채로 GitHub에 올라감
- `docker-compose.yml`에 DB 비밀번호가 평문으로 노출
- `serviceAccountKey.json`이 프로젝트 루트에 방치
- `NEXT_PUBLIC_SECRET_KEY` 같은 환경변수가 브라우저에 노출

기존 보안 도구는 경고 메시지가 어렵고, 수정 방법도 알려주지 않습니다.  
VibeScan은 **왜 위험한지**, **어떻게 고치는지**까지 안내합니다.

---

## 주요 기능

### 🔐 Secret 탐지 (14개 카테고리)

| 카테고리 | 예시 |
|---------|------|
| 환경변수 파일 | `.env`, `.env.production` 노출 |
| 설정 파일 하드코딩 | `config.py`, `application.yml`의 비밀번호 |
| 클라우드 인증 파일 | `serviceAccountKey.json`, `terraform.tfstate` |
| Docker/인프라 | `docker-compose.yml`의 평문 비밀번호 |
| CI/CD 파이프라인 | GitHub Actions yml에 시크릿 직접 입력 |
| IDE 설정 | `.npmrc`, `.vscode/launch.json`의 토큰 |
| SSH 키/인증서 | `*.pem`, `*.key`, `*.jks` |
| 코드 내 하드코딩 | `sk-`, `AKIA`, `ghp_` 패턴, DB 연결 문자열 |
| 프론트엔드 환경변수 | `NEXT_PUBLIC_`, `VITE_` + 시크릿 조합 |
| 데이터 파일 | `.sqlite`, `.sql`, Jupyter Notebook 출력 |
| 문서 내 실수 | README curl 예시에 실제 토큰 |
| 모바일 앱 파일 | `AndroidManifest.xml`, `Info.plist`의 API 키 |
| DB/시스템 설정 | `.pgpass`, `.kube/config` |
| 에디터 잔여물 | `.bash_history`, `.htaccess`, Vim swap |

### ⚠️ 위험 코드 패턴

**Python:** `eval()`, `exec()`, `subprocess(shell=True)`, `pickle.loads()`, `DEBUG=True`, `verify=False`  
**JS/TS:** `eval()`, `innerHTML`, `dangerouslySetInnerHTML`, `child_process.exec()`, `jwt.decode` without verify  
**SQL:** f-string/template literal 쿼리 조합 (인젝션)

### 📋 Git Hygiene

`.gitignore` 존재 여부, `.env*` / `*.pem` / `*.key` / `terraform.tfstate` 등의 ignore 등록 여부 검사

### 🏗️ 프로젝트 구조

README, `.env.example`, 테스트 파일, 라이선스, 의존성 버전 고정 검사

---

## 사용법

```bash
# 기본 스캔 (콘솔 출력)
vibescan scan ./project

# HTML 리포트 생성
vibescan scan ./project --html report.html

# JSON 리포트 생성 (CI/CD 연동)
vibescan scan ./project --json report.json

# MEDIUM 이상만 표시
vibescan scan ./project --min-severity medium

# 특정 규칙 제외
vibescan scan ./project --ignore-rule SEC001
```

---

## 출력 예시

```
🔍 Scanning 147 files...

CRITICAL  config.py:23         Hardcoded AWS access key detected (AKIA...)
CRITICAL  docker-compose.yml:8 POSTGRES_PASSWORD in plaintext
HIGH      src/api.js:45        API key hardcoded: sk-proj-...
HIGH      .env not in .gitignore
MEDIUM    settings.py:1        DEBUG = True (production risk)
MEDIUM    app.js:12            cors({ origin: '*' }) allows all domains
LOW       No README.md found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Scanned 147 files  •  Found 7 issues
  CRITICAL: 2  HIGH: 2  MEDIUM: 2  LOW: 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 심각도 체계

| 등급 | 기준 | 예시 |
|------|------|------|
| **CRITICAL** | 즉시 악용 가능, 금전적 피해 | AWS 키, DB 비밀번호, 서비스 계정 키 |
| **HIGH** | 보안 취약점, 공격 경로 | API 키 하드코딩, eval(), SQL 인젝션 |
| **MEDIUM** | 잠재적 위험, 모범 사례 위반 | DEBUG=True, CORS 전체 허용 |
| **LOW** | 코드 품질, 유지보수성 | README 부재, TODO 잔존 |

---

## 아키텍처

```
CLI Parser → Config Loader → File Collector → Rule Engine → Aggregator → Reporter
                                    │
                              ProjectContext
                           (텍스트 파일, 전체 목록,
                            .gitignore 패턴)
```

- **100% 로컬** — 네트워크 통신 없음, 오프라인 동작
- **플러그인 구조** — 규칙 추가 시 새 클래스만 작성
- **안전 설계** — 심볼릭 링크 건너뛰기, 인코딩 안전 처리, 대용량 파일 보호
- **CI/CD 호환** — CRITICAL/HIGH 발견 시 exit code 1 반환

---

## 기술 스택

| 구분 | 선택 |
|------|------|
| 언어 | Python 3.8+ |
| CLI | typer |
| 콘솔 출력 | rich |
| 패턴 탐지 | regex (re), ast |
| HTML 리포트 | Jinja2 |
| 패키지 배포 | PyPI |
| 테스트 | pytest |

---

## 로드맵

- [x] PRD 작성
- [x] 아키텍처 설계
- [ ] MVP 구현 (File Collector + Secret Rule + Console Reporter)
- [ ] Git Hygiene / Dangerous Pattern / Structure Rule
- [ ] JSON / HTML Reporter
- [ ] PyPI 배포
- [ ] 소개 웹사이트
- [ ] Git History Scan
- [ ] VSCode Extension
- [ ] GitHub Actions 연동
- [ ] AI 기반 코드 설명

---

## 보안 원칙

```
Your code never leaves your machine.
VibeScan runs entirely locally.
No network. No upload. No tracking.
```

---

## 라이선스

MIT License

---

## 관련 문서

- [PRD (Product Requirements Document)](./docs/PRD.md)
- [Architecture Design](./docs/ARCHITECTURE.md)
- [Directory Structure](./docs/DIRECTORY_STRUCTURE.md)
- [탐지 규칙 문서](./docs/rules.md)

---

## 개발 블로그

- [VibeScan 개발기 — 바이브코더를 위한 보안 점검 도구를 만듭니다](https://calme.tistory.com)
