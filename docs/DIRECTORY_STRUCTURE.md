# VibeScan — 프로젝트 디렉토리 구조

```
vibescan/
│
├── pyproject.toml              # 패키지 메타데이터, 의존성, 빌드 설정
├── README.md                   # GitHub README
├── LICENSE                     # MIT License
├── CHANGELOG.md                # 버전별 변경 사항
├── .gitignore                  # Git 제외 파일
│
├── src/
│   └── vibescan/
│       ├── __init__.py         # 패키지 초기화, 버전 정보
│       ├── __main__.py         # python -m vibescan 진입점
│       ├── cli.py              # CLI Parser (typer)
│       ├── config.py           # Config Loader (.vibescanrc, vibescan.toml)
│       │
│       ├── collector/
│       │   ├── __init__.py
│       │   ├── file_collector.py   # Track A: 텍스트 파일 수집
│       │   ├── file_inventory.py   # Track B: 전체 파일 목록 (바이너리 포함)
│       │   ├── gitignore_parser.py # Track C: .gitignore 파싱
│       │   └── context.py          # ProjectContext 정의
│       │
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── base.py             # BaseRule 추상 클래스
│       │   ├── registry.py         # Rule 등록/조회
│       │   │
│       │   ├── secret/
│       │   │   ├── __init__.py
│       │   │   ├── env_exposure.py       # 2-A: 환경변수 파일 노출
│       │   │   ├── config_hardcode.py    # 2-B: 설정 파일 하드코딩
│       │   │   ├── cloud_credentials.py  # 2-C: 클라우드 인증 파일
│       │   │   ├── docker_infra.py       # 2-D: Docker/인프라 설정
│       │   │   ├── cicd_pipeline.py      # 2-E: CI/CD 파이프라인
│       │   │   ├── ide_settings.py       # 2-F: IDE/개발 도구 설정
│       │   │   ├── private_keys.py       # 2-G: SSH 키/인증서
│       │   │   ├── hardcoded_patterns.py # 2-H: 코드 내 하드코딩
│       │   │   ├── frontend_env.py       # 2-I: 프론트엔드 환경변수
│       │   │   ├── data_files.py         # 2-J: 데이터 파일 노출
│       │   │   ├── doc_secrets.py        # 2-K: 문서 내 실수
│       │   │   ├── mobile_files.py       # 2-L: 모바일 앱 파일
│       │   │   ├── system_configs.py     # 2-M: DB/시스템 설정
│       │   │   └── editor_remnants.py    # 2-N: 에디터 잔여물
│       │   │
│       │   ├── git_hygiene.py      # Git Hygiene 검사
│       │   ├── dangerous_patterns.py # 위험 코드 패턴
│       │   └── structure.py        # 프로젝트 구조 점검
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── issue.py            # Issue 데이터 클래스
│       │   └── scan_result.py      # ScanResult 데이터 클래스
│       │
│       ├── aggregator/
│       │   ├── __init__.py
│       │   └── result_aggregator.py # 필터링, 집계, exit code
│       │
│       ├── reporters/
│       │   ├── __init__.py
│       │   ├── console.py          # Console Reporter (rich)
│       │   ├── json_reporter.py    # JSON Reporter
│       │   └── html_reporter.py    # HTML Reporter (Jinja2)
│       │
│       └── templates/
│           └── report.html         # HTML 리포트 Jinja2 템플릿
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                 # pytest fixture (샘플 프로젝트 등)
│   │
│   ├── test_cli.py
│   ├── test_config.py
│   │
│   ├── test_collector/
│   │   ├── test_file_collector.py
│   │   ├── test_file_inventory.py
│   │   └── test_gitignore_parser.py
│   │
│   ├── test_rules/
│   │   ├── test_secret_rules.py
│   │   ├── test_git_hygiene.py
│   │   ├── test_dangerous_patterns.py
│   │   └── test_structure.py
│   │
│   ├── test_aggregator.py
│   ├── test_reporters.py
│   │
│   └── fixtures/                   # 테스트용 가짜 프로젝트 폴더
│       ├── clean_project/          # 문제 없는 프로젝트
│       ├── leaky_project/          # 시크릿 가득한 프로젝트
│       └── mixed_project/          # 일부 문제 있는 프로젝트
│
├── docs/
│   ├── rules.md                    # 탐지 규칙 전체 문서
│   └── contributing.md             # 기여 가이드
│
└── website/                        # 소개 웹사이트 (별도 배포)
    └── (VitePress 또는 Astro)
```

## 설계 의도

### src 레이아웃
`src/vibescan/` 구조를 사용합니다. 이는 PyPI 패키지 배포 시 권장되는 레이아웃이며,
`import vibescan`이 프로젝트 루트가 아닌 설치된 패키지를 참조하도록 보장합니다.

### rules/secret/ 서브 패키지
Secret 탐지 규칙이 14개 서브 카테고리로 가장 많기 때문에 별도 패키지로 분리합니다.
각 파일이 하나의 카테고리를 담당하여 유지보수와 테스트가 용이합니다.

### models/ 분리
Issue, ScanResult 같은 데이터 클래스를 별도 패키지로 분리하여
순환 참조를 방지하고, 모든 모듈이 동일한 데이터 구조를 공유합니다.

### fixtures/ 테스트 전략
실제 프로젝트 구조를 모방한 fixture 폴더를 사용하여
통합 테스트에서 end-to-end 스캔을 검증합니다.

### website/ 분리
웹사이트는 CLI 패키지와 별도로 배포되므로 최상위에 분리합니다.
PyPI 패키지에는 포함되지 않습니다.
