"""dscan command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from dscan import __version__

console = Console()

_SEVERITY_ORDER = ["high", "medium", "low"]
_SEVERITY_STYLE = {"high": "bold red", "medium": "#f59e0b", "low": "cyan"}


def _ok(message: str) -> None:
    console.print(f"[green]✓[/green] {message}")


def _warn(message: str) -> None:
    console.print(f"[#f59e0b]⚠[/#f59e0b] {message}")


def _err(message: str) -> None:
    console.print(f"[red]✗[/red] {message}")


@click.group()
@click.version_option(__version__, prog_name="dscan")
def main() -> None:
    """dscan — an open source agent security suite.

    Trace and redact your agent's tool calls (@watch), statically scan
    prompts and MCP configs (dscan scan), and inspect everything in a
    local dashboard (dscan dashboard).
    """


@main.command()
def watch() -> None:
    """Show how to instrument an agent (it's a decorator, not a command)."""
    _warn("Add @watch to your agent function. See README for usage.")


@main.command()
@click.argument("path", required=False, default=".")
@click.option(
    "--prompt",
    "prompt_file",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Scan a single system-prompt file instead of a directory.",
)
def scan(path: str, prompt_file: str | None) -> None:
    """Statically analyze agent configs and system prompts."""
    from dscan.scanner import scan_directory, scan_file

    findings = scan_file(prompt_file) if prompt_file else scan_directory(path)
    _render_findings(findings)
    if any(f.severity == "high" for f in findings):
        sys.exit(1)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind.")
@click.option("--port", default=4321, show_default=True, help="Port to bind.")
@click.option(
    "--open/--no-open",
    "open_browser",
    default=True,
    show_default=True,
    help="Open the dashboard in a browser.",
)
def dashboard(host: str, port: int, open_browser: bool) -> None:
    """Launch the local trace dashboard."""
    with console.status(
        f"Starting dashboard at localhost:{port}...", spinner="dots"
    ):
        from dscan.dashboard.server import serve

    _ok(f"Dashboard at [cyan]http://{host}:{port}[/cyan]  [dim](Ctrl-C to stop)[/dim]")
    serve(host=host, port=port, open_browser=open_browser)


def _render_findings(findings: list) -> None:
    if not findings:
        _ok("No findings.")
        return

    for severity in _SEVERITY_ORDER:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        table = Table(
            title=f"{severity.upper()} ({len(group)})",
            title_style=_SEVERITY_STYLE[severity],
            header_style="bold",
            title_justify="left",
        )
        table.add_column("Rule")
        table.add_column("File")
        table.add_column("Line", justify="right")
        table.add_column("Message")
        table.add_column("Snippet")
        for f in sorted(group, key=lambda x: (x.file, x.line, x.rule)):
            table.add_row(
                f.rule,
                Path(f.file).name,
                str(f.line),
                f.message,
                f.snippet,
            )
        console.print(table)

    high = sum(1 for f in findings if f.severity == "high")
    if high:
        _err(f"{high} high-severity finding(s).")
    else:
        _warn(f"{len(findings)} finding(s), none high severity.")


if __name__ == "__main__":
    main()
