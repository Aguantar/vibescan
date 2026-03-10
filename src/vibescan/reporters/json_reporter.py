"""JSON Reporter - machine-readable output for CI/CD integration."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from vibescan.models.scan_result import ScanResult


def write_json_report(
    result: ScanResult,
    output: Path | None = None,
) -> None:
    data = {
        "project_root": result.project_root,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "summary": result.summary,
        "exit_code": result.exit_code,
        "issues": [
            {
                "rule_id": issue.rule_id,
                "severity": issue.severity.value.upper(),
                "file": issue.file,
                "line": issue.line,
                "message": issue.message,
                "why": issue.why,
                "fix": issue.fix,
            }
            for issue in result.issues
        ],
    }

    text = json.dumps(data, ensure_ascii=False, indent=2)

    if output:
        output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
