# VibeScan

**Push 전에, 코드를 점검하세요.**

VibeScan은 바이브코딩(AI 기반 코딩) 시대에 맞춘 로컬 코드 보안 점검 도구입니다.
민감정보 노출, 보안 취약점, 설정 실수를 초보자도 이해할 수 있는 설명형 리포트로 제공합니다.

```bash
pip install vibescan-cli
vibescan scan .
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

### Secret 탐지 (14개 카테고리)

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

### 위험 코드 패턴

**Python:** `eval()`, `exec()`, `subprocess(shell=True)`, `pickle.loads()`, `DEBUG=True`, `verify=False`
**JS/TS:** `eval()`, `innerHTML`, `dangerouslySetInnerHTML`, `child_process.exec()`, `jwt.decode` without verify
**SQL:** f-string/template literal 쿼리 조합 (인젝션)

### Git Hygiene

`.gitignore` 존재 여부, `.env*` / `*.pem` / `*.key` 등의 ignore 등록 여부 검사

### 프로젝트 구조

README, LICENSE, lockfile 존재 여부, `.ssh`/`.aws` 같은 위험 디렉토리 검사

---

## 사용법

```bash
# 설치
pip install vibescan-cli

# 기본 스캔 (콘솔 출력, 시스템 언어 자동 감지)
vibescan scan .

# python -m으로 실행 (PATH 문제 시)
python -m vibescan .

# HTML 리포트 생성
vibescan scan . --format html

# JSON 리포트 생성 (CI/CD 연동)
vibescan scan . --format json -o result.json

# MEDIUM 이상만 표시
vibescan scan . --min-severity medium

# 한국어/영어 강제 지정
vibescan scan . --lang ko
vibescan scan . --lang en
```

---

## 출력 예시

```
┌─────────────── 스캔 완료 ────────────────┐
│ VibeScan이 ./my-project에서 147개 파일을 스캔했습니다 │
└──────────────────────────────────────────────┘
 요약
  CRITICAL   2
  HIGH       2
  MEDIUM     1

config.py
  [!] 변수에 하드코딩된 시크릿이 포함되어 있을 수 있습니다
      라인 23
      원인: 코드에 직접 저장된 시크릿은 저장소에 접근할 수 있는 누구나 볼 수 있습니다.
      해결: 하드코딩 대신 환경변수 또는 시크릿 매니저를 사용하세요.

Exit code 1: CRITICAL 또는 HIGH 이슈가 발견되었습니다.
규칙에 대한 자세한 정보: https://vibescan.calmee.store/#rules
```

---

## 심각도 체계

| 등급 | 기준 | 예시 |
|------|------|------|
| **CRITICAL** | 즉시 악용 가능, 금전적 피해 | AWS 키, DB 비밀번호, 서비스 계정 키 |
| **HIGH** | 보안 취약점, 공격 경로 | API 키 하드코딩, eval(), SQL 인젝션 |
| **MEDIUM** | 잠재적 위험, 모범 사례 위반 | DEBUG=True, CORS 전체 허용 |
| **LOW** | 코드 품질, 유지보수성 | README 부재, LICENSE 미작성 |

---

## 기술 스택

| 구분 | 선택 |
|------|------|
| 언어 | Python 3.10+ |
| CLI | typer |
| 콘솔 출력 | rich |
| 패턴 탐지 | re (정규표현식) |
| 다국어 | i18n (한국어/영어, 로케일 자동 감지) |
| 빌드 | hatchling |
| 패키지 배포 | PyPI |
| 테스트 | pytest (196 tests) |
| 외부 의존성 | 2개 (typer, rich) |

---

## 로드맵

- [x] 코어 엔진 (17개 규칙, File Collector, Rule Engine)
- [x] 테스트 (196 tests passing)
- [x] PyPI 배포 (`pip install vibescan-cli`)
- [x] 소개 웹사이트 (https://vibescan.calmee.store)
- [x] 콘솔/JSON/HTML 리포트
- [x] 한국어 지원 (시스템 로케일 자동 감지)
- [x] 오탐 필터 (한국어 에러 메시지, 플레이스홀더, 환경변수 참조 제외)
- [ ] VSCode Extension
- [ ] Git History Scan
- [ ] GitHub Actions 연동

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

## 링크

- 웹사이트: https://vibescan.calmee.store
- PyPI: https://pypi.org/project/vibescan-cli/
- 동작 원리: [docs/HOW_IT_WORKS.md](./docs/HOW_IT_WORKS.md)
- 블로그: https://calme.tistory.com
