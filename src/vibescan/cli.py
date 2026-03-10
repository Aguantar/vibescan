"""CLI entry point using typer."""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from vibescan import __version__

app = typer.Typer(
    name="vibescan",
    help="Scan your project for leaked secrets and security issues.",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vibescan {__version__}")
        raise typer.Exit()


_PROMPT_EN = (
    "\nSelect report format (enter number or press Enter to skip)\n"
    "  [1] Console (view in terminal)\n"
    "  [2] HTML report\n"
    "  [3] JSON report\n"
    "  Choice: "
)

_PROMPT_KO = (
    "\n보고서 형식을 선택하세요 (번호 입력 또는 Enter로 건너뛰기)\n"
    "  [1] 콘솔 (터미널에서 보기)\n"
    "  [2] HTML 보고서\n"
    "  [3] JSON 보고서\n"
    "  선택: "
)


def _prompt_report(result, lang: str, project_root: str) -> None:
    """Ask user if they want to save a report after console output."""
    from rich.console import Console

    from vibescan.reporters.html_reporter import write_html_report
    from vibescan.reporters.json_reporter import write_json_report

    console = Console()
    prompt = _PROMPT_KO if lang == "ko" else _PROMPT_EN

    try:
        choice = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not choice:
        return

    if choice == "1":
        from vibescan.reporters.console import print_report
        print_report(result, console=console, lang=lang)
        return

    saved = []
    if choice in ("2",):
        html_path = Path("vibescan-report.html")
        write_html_report(result, output=html_path, lang=lang)
        saved.append(f"HTML → {html_path}")
    if choice in ("3",):
        json_path = Path("vibescan-report.json")
        write_json_report(result, output=json_path)
        saved.append(f"JSON → {json_path}")

    if saved:
        label = "저장 완료" if lang == "ko" else "Saved"
        for s in saved:
            console.print(f"[bold green]{label}:[/bold green] {s}")
        console.print()


@app.command()
def scan(
    path: Path = typer.Argument(
        ".",
        help="Project directory to scan.",
        exists=True,
        file_okay=False,
        resolve_path=True,
    ),
    min_severity: str = typer.Option(
        "info",
        "--min-severity", "-s",
        help="Minimum severity to report: critical, high, medium, low, info.",
    ),
    output_format: str = typer.Option(
        "",
        "--format", "-f",
        help="Output format: console, json, html. If omitted, shows console and prompts for report.",
    ),
    lang: str = typer.Option(
        "auto",
        "--lang", "-l",
        help="Output language: auto, en, ko. 'auto' detects system locale.",
    ),
    output_file: str = typer.Option(
        "",
        "--output", "-o",
        help="Output file path (for json/html format).",
    ),
    version: bool = typer.Option(
        False,
        "--version", "-v",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Scan a project directory for security issues."""
    from vibescan.collector import collect
    from vibescan.models import ScanResult, Severity
    from vibescan.rules import get_all_rules

    # Validate min_severity
    try:
        threshold = Severity(min_severity.lower())
    except ValueError:
        typer.echo(f"Error: Invalid severity '{min_severity}'. "
                   f"Choose from: critical, high, medium, low, info.")
        raise typer.Exit(code=2)

    # Validate format
    fmt = output_format.lower() if output_format else ""
    if fmt and fmt not in ("console", "json", "html"):
        typer.echo(f"Error: Invalid format '{output_format}'. "
                   f"Choose from: console, json, html.")
        raise typer.Exit(code=2)

    # Resolve language
    lang = lang.lower()
    if lang == "auto":
        from vibescan.i18n import detect_lang
        lang = detect_lang()
    if lang not in ("en", "ko"):
        typer.echo(f"Error: Invalid language '{lang}'. Choose from: auto, en, ko.")
        raise typer.Exit(code=2)

    # Collect project context
    ctx = collect(path)

    # Run rules
    all_issues = []
    for rule in get_all_rules():
        all_issues.extend(rule.run(ctx))

    # Filter by severity
    filtered = [i for i in all_issues if i.severity >= threshold]

    # Sort: critical first, then by file, then by line
    filtered.sort(key=lambda i: (-i.severity.rank, i.file, i.line or 0))

    # Build result
    result = ScanResult(
        issues=filtered,
        project_root=str(ctx.project_root),
        files_scanned=len(ctx.text_files),
        files_skipped=len(ctx.skipped_files),
    )

    # Report
    if fmt == "json":
        from vibescan.reporters.json_reporter import write_json_report
        out = Path(output_file) if output_file else None
        write_json_report(result, output=out)
        if out:
            typer.echo(f"JSON report saved → {out}")
    elif fmt == "html":
        from vibescan.reporters.html_reporter import write_html_report
        out = Path(output_file) if output_file else Path("vibescan-report.html")
        write_html_report(result, output=out, lang=lang)
        typer.echo(f"HTML report saved → {out}")
    else:
        from vibescan.reporters.console import print_report
        print_report(result, lang=lang)

        # Interactive prompt: only when format not specified, issues exist, and terminal is interactive
        if not fmt and result.issues and sys.stdin.isatty():
            _prompt_report(result, lang=lang, project_root=str(ctx.project_root))

    raise typer.Exit(code=result.exit_code)
