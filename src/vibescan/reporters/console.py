"""Console Reporter - rich-based colored terminal output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vibescan.i18n import translate
from vibescan.models.issue import Severity
from vibescan.models.scan_result import ScanResult

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "[!]",
    Severity.HIGH: "[H]",
    Severity.MEDIUM: "[M]",
    Severity.LOW: "[L]",
    Severity.INFO: "[i]",
}

LABELS_EN = {
    "scan_complete": "Scan Complete",
    "scanned": "VibeScan scanned {files} files in {root}",
    "no_issues": "No issues found. Your project looks clean!",
    "summary": "Summary",
    "line": "Line",
    "why": "Why",
    "fix": "Fix",
    "exit1": "Exit code 1: CRITICAL or HIGH issues found.",
    "exit0": "Exit code 0: No critical issues.",
}

LABELS_KO = {
    "scan_complete": "스캔 완료",
    "scanned": "VibeScan이 {root}에서 {files}개 파일을 스캔했습니다",
    "no_issues": "이슈가 발견되지 않았습니다. 프로젝트가 안전합니다!",
    "summary": "요약",
    "line": "라인",
    "why": "원인",
    "fix": "해결",
    "exit1": "Exit code 1: CRITICAL 또는 HIGH 이슈가 발견되었습니다.",
    "exit0": "Exit code 0: 심각한 이슈가 없습니다.",
}


def print_report(
    result: ScanResult,
    console: Console | None = None,
    lang: str = "en",
) -> None:
    console = console or Console()
    labels = LABELS_KO if lang == "ko" else LABELS_EN
    t = lambda s: translate(s, lang)

    # Header
    console.print()
    console.print(
        Panel(
            labels["scanned"].format(
                files=f"[cyan]{result.files_scanned}[/cyan]",
                root=f"[cyan]{result.project_root}[/cyan]",
            ),
            title=labels["scan_complete"],
            border_style="blue",
        )
    )

    if not result.issues:
        console.print(f"\n[bold green]{labels['no_issues']}[/bold green]\n")
        return

    # Summary table
    summary = result.summary
    summary_table = Table(title=labels["summary"], show_header=False, box=None, padding=(0, 2))
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    for sev in Severity:
        count = summary[sev.value]
        if count > 0:
            style = SEVERITY_COLORS[sev]
            summary_table.add_row(
                Text(sev.value.upper(), style=style),
                Text(str(count), style=style),
            )
    console.print(summary_table)
    console.print()

    # Issues sorted by severity, then by file
    for issue in result.issues:
        sev = issue.severity
        icon = SEVERITY_ICONS[sev]
        color = SEVERITY_COLORS[sev]

        console.print(f"[bold underline]{issue.file}[/bold underline]")
        console.print(f"  [{color}]{icon}[/{color}] {t(issue.message)}")
        if issue.line:
            console.print(f"      {labels['line']} {issue.line}")
        console.print(f"      [dim]{labels['why']}:[/dim] {t(issue.why)}")
        console.print(f"      [dim]{labels['fix']}:[/dim] {t(issue.fix)}")
        console.print()

    # Exit code hint
    if result.exit_code != 0:
        console.print(f"[bold red]{labels['exit1']}[/bold red]")
    else:
        console.print(f"[bold green]{labels['exit0']}[/bold green]")
    console.print()
