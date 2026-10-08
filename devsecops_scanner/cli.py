"""Command-line interface."""

from pathlib import Path

import click
from rich.console import Console

from devsecops_scanner import __version__
from devsecops_scanner.models import Severity
from devsecops_scanner.reporter.report import write_report
from devsecops_scanner.scanner import scan_path


console = Console()


@click.group()
@click.version_option(__version__, prog_name="devsecops-scanner")
def main() -> None:
    """Scan source code and dependency manifests for security issues."""


@main.command()
@click.option("--path", "scan_root", type=click.Path(path_type=Path, exists=True),
              default=Path("."), show_default=True, help="File or directory to scan.")
@click.option("--output", type=click.Path(path_type=Path), default=Path("report.html"),
              show_default=True, help="Report destination (.html, .json, or .md).")
@click.option("--fail-on", type=click.Choice(
    ["critical", "high", "medium", "low"], case_sensitive=False,
), default=None, help="Exit with status 1 if a finding meets or exceeds this severity.")
@click.option("--exclude", multiple=True, help="Additional relative glob to exclude (repeatable).")
def scan(scan_root: Path, output: Path, fail_on: str | None, exclude: tuple[str, ...]) -> None:
    """Scan a repository and write a report."""
    try:
        findings = scan_path(scan_root, exclude)
        write_report(output, findings, str(scan_root))
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc

    totals = {severity: sum(item.severity == severity for item in findings)
              for severity in Severity}
    console.print(f"Scan complete: {len(findings)} finding(s)")
    for severity in reversed(list(Severity)):
        console.print(f"  {severity.name.title():<8} {totals[severity]}")
    console.print(f"Report written to {output}")
    if fail_on and any(item.severity >= Severity.parse(fail_on) for item in findings):
        raise click.exceptions.Exit(1)
