# VibeScan

**Push 전에, 코드를 점검하세요.**

VibeScan은 바이브코딩(AI 기반 코딩) 시대에 맞춘 로컬 코드 보안 점검 도구입니다.
민감정보 노출, 보안 취약점, 설정 실수를 초보자도 이해할 수 있는 설명형 리포트로 제공합니다.

```bash
pip install vibescan-cli
python -m vibescan .
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

## 보안 표준 매핑

각 규칙이 실제로 탐지하는 로직(정규표현식·파일명 판정)을 코드 기준으로 확인하여, 국제 표준 취약점 분류인 **CWE**와 **OWASP Top 10:2025**(2026-01 배포)에 매핑했습니다. OWASP 카테고리는 부여한 CWE의 공식 2025 분류를 따릅니다.

| 규칙 ID | 규칙명 | 탐지 내용 | CWE | OWASP:2025 |
|---------|--------|-----------|-----|------------|
| SECRET-ENV | 환경변수 파일 | `.env` / `.env.*` 파일 노출 (gitignore 여부로 심각도) | CWE-312, CWE-260 | A04 암호화 실패 |
| SECRET-CONFIG | 설정파일 하드코딩 | `config.py`·`application.yml`의 `password`/`secret`/`token` 리터럴 | CWE-260, CWE-798 | A02 보안 설정오류 |
| SECRET-CLOUD | 클라우드 인증파일 | `serviceAccountKey.json`, `.aws/credentials`, `terraform.tfstate` | CWE-312, CWE-522 | A04 암호화 실패 |
| SECRET-INFRA | Docker/인프라 | `docker-compose`·k8s yaml의 하드코딩 시크릿 (env 참조 제외) | CWE-260, CWE-798 | A02 보안 설정오류 |
| SECRET-CICD | CI/CD 파이프라인 | GitHub Actions·GitLab CI yml의 하드코딩 시크릿 | CWE-260, CWE-798 | A02 보안 설정오류 |
| SECRET-IDE | IDE/도구 설정 | `.npmrc`·`.pypirc`·`.netrc`·`.vscode`의 인증 토큰 | CWE-798, CWE-522 | A07 인증 실패 |
| SECRET-KEY | SSH키/인증서 | `.pem`·`.key`·`.jks`·`id_rsa` 등 개인키·인증서 파일 | CWE-312, CWE-321 | A04 암호화 실패 |
| SECRET-HARDCODED | 코드 내 하드코딩 | `sk-`·`AKIA`·`ghp_` 키, `password=`, DB 접속문자열, 웹훅 | CWE-798, CWE-259 | A07 인증 실패 |
| SECRET-FRONTEND-ENV | 프론트엔드 환경변수 | `NEXT_PUBLIC_`·`VITE_` + 시크릿 조합 (클라이언트 번들 노출) | CWE-200, CWE-312 | A01 접근통제 취약 |
| SECRET-DATA | 데이터 파일 | `.sql`·`.db`·`.csv`·`.log`, 출력이 남은 `.ipynb` | CWE-312, CWE-540 | A04 암호화 실패 |
| SECRET-DOC | 문서 내 시크릿 | README·docs에 붙여넣은 실제 토큰·시크릿 | CWE-540, CWE-798 | A01 접근통제 취약 |
| SECRET-MOBILE | 모바일 앱 파일 | `Info.plist`·`AndroidManifest.xml`의 api_key·secret | CWE-798, CWE-312 | A07 인증 실패 |
| SECRET-SYSTEM | DB/시스템 설정 | `.pgpass`·`.my.cnf`·`kubeconfig`·`.kube/config` | CWE-522, CWE-260 | A07 인증 실패 |
| SECRET-REMNANT | 에디터 잔여물 | `.bash_history`·`.s3cfg`·`.htaccess`·`.DS_Store`·`*.swp` | CWE-200, CWE-312 | A01 접근통제 취약 |
| GIT-* | Git Hygiene | 위험 확장자(`.pem`/`.key`/`.db`) 미ignore 추적 등 | CWE-538 | A01 접근통제 취약 |
| DANGER-CODE | 위험 코드 패턴 | Python·JS·SQL 위험 패턴 다수 (아래 세부표) | (다수) | A05·A04·A02·A07·A08 |
| STRUCTURE-* | 프로젝트 구조 | `.ssh`/`.aws`/`.kube` 디렉토리, lockfile 정합 | CWE-540, CWE-1104 | A01·A03 공급망 |

`DANGER-CODE`는 단일 규칙에서 여러 취약점 유형을 탐지합니다.

| 탐지 패턴 | CWE | OWASP:2025 |
|-----------|-----|------------|
| `eval()`·`exec()` | CWE-95 | A05 인젝션 |
| `subprocess(shell=True)`·`os.system()`·`child_process.exec()` | CWE-78 | A05 인젝션 |
| SQL f-string·템플릿리터럴·문자열 결합 쿼리 | CWE-89 | A05 인젝션 |
| `innerHTML`·`dangerouslySetInnerHTML`·`document.write()` | CWE-79 | A05 인젝션 |
| `pickle.loads()`·`yaml.load()` (Loader 미지정) | CWE-502 | A08 무결성 실패 |
| `hashlib.md5`/`sha1` | CWE-327 | A04 암호화 실패 |
| `jwt.decode()` (서명 미검증) | CWE-347 | A04 암호화 실패 |
| `verify=False` (SSL 검증 비활성) | CWE-295 | A07 인증 실패 |
| `DEBUG=True` | CWE-489 | A02 보안 설정오류 |
| CORS 와일드카드·`ALLOWED_HOSTS=['*']` | CWE-942, CWE-16 | A02 보안 설정오류 |

> `GIT-*`·`STRUCTURE-*`는 보안 관련 하위 점검(위험 파일 추적, 자격증명 디렉토리, lockfile)만 매핑했습니다. README·LICENSE 존재 여부, 평탄한 디렉토리 구조 등 코드 품질 점검은 취약점 분류에 해당하지 않아 제외했습니다.

매핑 범위: 고유 CWE 20종, OWASP Top 10:2025 중 7개 카테고리(A01·A02·A03·A04·A05·A07·A08) 커버.

---

## 기존 SAST 도구와의 차이

VibeScan은 Bandit·Semgrep과 탐지 깊이로 경쟁하는 도구가 아니라, 세 지점을 다르게 겨냥합니다.

- **탐지 초점**: 17개 규칙 중 14개가 시크릿·자격증명 파일과 커밋되면 안 되는 파일에 집중되어, 코드 로직 취약점보다 "AI가 생성한 코드를 push할 때 무엇이 유출되는가"라는 저장소 위생·시크릿 노출에 무게가 있습니다. 이 영역은 Bandit/Semgrep보다 gitleaks·trufflehog에 가깝습니다.
- **분석 기법**: Bandit은 Python AST를, Semgrep은 다중언어 시맨틱·데이터플로우(테인트) 분석을 사용하지만, VibeScan은 정규표현식과 파일명 휴리스틱만 사용합니다. 데이터플로우 기반 인젝션 탐지 깊이를 포기하는 대신, AST 파싱 없이 확장자만으로 언어를 넘나들고 설정이 필요 없는 경량성을 얻습니다.
- **대상 사용자**: 바이브코딩·초보 사용자를 겨냥해 각 이슈에 "왜 위험한지"와 "어떻게 고치는지"를 한국어/영어로 설명하고, 완전 로컬(no-network)·의존성 2개로 push 직전에 실행하는 도구입니다.

한계도 분명합니다. 테인트·AST 분석이 없어 복잡한 인젝션의 정오탐이 전문 SAST보다 약하고, 규칙 셋의 범위도 좁습니다. VibeScan의 자리는 "더 좋은 SAST"가 아니라 "push 직전 시크릿·위생 점검"입니다.

---

## 사용법

```bash
# 설치
pip install vibescan-cli

# 기본 스캔 (콘솔 출력, 시스템 언어 자동 감지)
python -m vibescan .

# PATH가 설정되어 있다면 이렇게도 가능
vibescan scan .

# HTML 리포트 생성
python -m vibescan . --format html

# JSON 리포트 생성 (CI/CD 연동)
python -m vibescan . --format json -o result.json

# MEDIUM 이상만 표시
python -m vibescan . --min-severity medium

# 한국어/영어 강제 지정
python -m vibescan . --lang ko
python -m vibescan . --lang en
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
