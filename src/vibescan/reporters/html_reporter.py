"""HTML Reporter - visual dashboard report."""

from __future__ import annotations

from pathlib import Path

from vibescan.i18n import translate
from vibescan.models.issue import Severity
from vibescan.models.scan_result import ScanResult

SEV_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f59e0b",
    "MEDIUM": "#10b981",
    "LOW": "#3b82f6",
    "INFO": "#6b7280",
}


def write_html_report(
    result: ScanResult,
    output: Path,
    lang: str = "en",
) -> None:
    labels = _LABELS_KO if lang == "ko" else _LABELS_EN
    summary = result.summary

    summary_cards = ""
    for sev in Severity:
        count = summary[sev.value]
        if count > 0:
            color = SEV_COLORS[sev.value.upper()]
            summary_cards += (
                f'<div class="sev-card" style="border-color:{color}">'
                f'<span class="sev-count" style="color:{color}">{count}</span>'
                f'<span class="sev-label" style="color:{color}">{sev.value.upper()}</span>'
                f'</div>\n'
            )

    t = lambda s: translate(s, lang)
    issue_rows = ""
    for issue in result.issues:
        color = SEV_COLORS[issue.severity.value.upper()]
        line_str = f":{issue.line}" if issue.line else ""
        issue_rows += (
            f'<div class="issue">'
            f'<div class="issue-header">'
            f'<span class="badge" style="background:{color}20;color:{color};border:1px solid {color}40">{issue.severity.value.upper()}</span>'
            f'<span class="issue-file">{issue.file}{line_str}</span>'
            f'</div>'
            f'<div class="issue-msg">{t(issue.message)}</div>'
            f'<div class="issue-detail"><strong>{labels["why"]}:</strong> {t(issue.why)}</div>'
            f'<div class="issue-detail"><strong>{labels["fix"]}:</strong> {t(issue.fix)}</div>'
            f'</div>\n'
        )

    html = _TEMPLATE.format(
        title=labels["title"],
        scanned=labels["scanned"].format(
            files=result.files_scanned, root=result.project_root
        ),
        summary_title=labels["summary"],
        summary_cards=summary_cards,
        issues_title=labels["issues"],
        issue_rows=issue_rows if issue_rows else f'<p class="clean">{labels["no_issues"]}</p>',
        total=len(result.issues),
    )

    output.write_text(html, encoding="utf-8")


_LABELS_EN = {
    "title": "VibeScan Report",
    "scanned": "Scanned {files} files in {root}",
    "summary": "Summary",
    "issues": "Issues",
    "why": "Why",
    "fix": "Fix",
    "no_issues": "No issues found. Your project looks clean!",
}

_LABELS_KO = {
    "title": "VibeScan 리포트",
    "scanned": "{root}에서 {files}개 파일 스캔 완료",
    "summary": "요약",
    "issues": "발견된 이슈",
    "why": "원인",
    "fix": "해결",
    "no_issues": "이슈가 발견되지 않았습니다. 프로젝트가 안전합니다!",
}

_TEMPLATE = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#0a0a0a;color:#e5e5e5;padding:40px 24px}}
.container{{max-width:900px;margin:0 auto}}
h1{{font-size:28px;font-weight:800;margin-bottom:8px}}
.subtitle{{color:#888;font-size:14px;margin-bottom:32px}}
h2{{font-size:18px;font-weight:700;margin-bottom:16px;color:#ccc}}
.sev-grid{{display:flex;gap:12px;margin-bottom:40px;flex-wrap:wrap}}
.sev-card{{border:1px solid;border-radius:12px;padding:16px 24px;text-align:center;min-width:100px}}
.sev-count{{display:block;font-size:28px;font-weight:800}}
.sev-label{{display:block;font-size:11px;font-weight:700;letter-spacing:1px;margin-top:4px}}
.issue{{background:#161616;border:1px solid #262626;border-radius:12px;padding:20px;margin-bottom:12px}}
.issue-header{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.badge{{padding:4px 12px;border-radius:999px;font-size:11px;font-weight:700}}
.issue-file{{font-family:monospace;font-size:13px;color:#aaa}}
.issue-msg{{font-weight:600;margin-bottom:10px}}
.issue-detail{{font-size:13px;color:#999;margin-bottom:4px;line-height:1.6}}
.issue-detail strong{{color:#bbb}}
.clean{{color:#10b981;font-weight:600;font-size:16px;text-align:center;padding:40px}}
</style>
</head>
<body>
<div class="container">
<h1>{title}</h1>
<p class="subtitle">{scanned}</p>
<h2>{summary_title}</h2>
<div class="sev-grid">{summary_cards}</div>
<h2>{issues_title} ({total})</h2>
{issue_rows}
</div>
</body>
</html>
"""
