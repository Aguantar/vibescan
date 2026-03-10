"""CLI entry point using typer."""

from __future__ import annotations

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
    from vibescan.reporters.console import print_report
    from vibescan.rules import get_all_rules

    # Validate min_severity
    try:
        threshold = Severity(min_severity.lower())
    except ValueError:
        typer.echo(f"Error: Invalid severity '{min_severity}'. "
                   f"Choose from: critical, high, medium, low, info.")
        raise typer.Exit(code=2)

    # Collect project context
    ctx = collect(path)

    # Run rules
    all_issues = []
    for rule in get_all_rules():
        all_issues.extend(rule.run(ctx))

    # Filter by severity
    filtered = [i for i in all_issues if i.severity >= threshold]

    # Sort: critical first
    filtered.sort(key=lambda i: -i.severity.rank)

    # Build result
    result = ScanResult(
        issues=filtered,
        project_root=str(ctx.project_root),
        files_scanned=len(ctx.text_files),
        files_skipped=len(ctx.skipped_files),
    )

    # Report
    print_report(result)

    raise typer.Exit(code=result.exit_code)
