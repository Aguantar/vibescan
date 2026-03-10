"""Console Reporter - rich-based colored terminal output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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


def print_report(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]VibeScan[/bold] scanned [cyan]{result.files_scanned}[/cyan] files "
            f"in [cyan]{result.project_root}[/cyan]",
            title="Scan Complete",
            border_style="blue",
        )
    )

    if not result.issues:
        console.print("\n[bold green]No issues found. Your project looks clean![/bold green]\n")
        return

    # Summary table
    summary = result.summary
    summary_table = Table(title="Summary", show_header=False, box=None, padding=(0, 2))
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

    # Issues grouped by file
    issues_by_file: dict[str, list] = {}
    for issue in result.issues:
        issues_by_file.setdefault(issue.file, []).append(issue)

    for file_path, issues in sorted(issues_by_file.items()):
        console.print(f"[bold underline]{file_path}[/bold underline]")
        for issue in issues:
            sev = issue.severity
            icon = SEVERITY_ICONS[sev]
            color = SEVERITY_COLORS[sev]
            loc = f":{issue.line}" if issue.line else ""

            console.print(f"  [{color}]{icon}[/{color}] {issue.message}")
            if issue.line:
                console.print(f"      Line {issue.line}")
            console.print(f"      [dim]Why:[/dim] {issue.why}")
            console.print(f"      [dim]Fix:[/dim] {issue.fix}")
            console.print()

    # Exit code hint
    if result.exit_code != 0:
        console.print("[bold red]Exit code 1: CRITICAL or HIGH issues found.[/bold red]")
    else:
        console.print("[bold green]Exit code 0: No critical issues.[/bold green]")
    console.print()
