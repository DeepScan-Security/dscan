"""dscan command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from dscan import __version__
from dscan.trail import TrailAnalyzer

console = Console()

_SEVERITY_ORDER = ["high", "medium", "low"]
_SEVERITY_STYLE = {"high": "bold red", "medium": "#f59e0b", "low": "cyan"}

# Trail severities, lowest to highest, plus per-row table styles.
_TRAIL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_TRAIL_DISPLAY_ORDER = ["critical", "high", "medium", "low"]
_TRAIL_ROW_STYLE = {"critical": "red", "high": "#f59e0b", "medium": "yellow", "low": None}


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


@main.command()
@click.argument("path")
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    show_default=True,
    help="Hide findings below this severity (display only; exit code still "
    "reflects any high/critical finding).",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Output raw JSON instead of a rich table.",
)
def trail(path: str, min_severity: str, as_json: bool) -> None:
    """Detect suspicious tool-call chains (CWAT) in trace files.

    PATH is a trace file (.ndjson) or a directory of trace files.
    """
    target = Path(path)
    if not target.exists():
        _err(f"path not found: {path}")
        sys.exit(2)

    try:
        traces = _load_trace_dicts(target)
    except OSError as exc:  # pragma: no cover - defensive
        _err(f"could not read traces from {path}: {exc}")
        sys.exit(2)

    # Analyze each session independently so chains never bridge unrelated
    # agent runs (a read in one session + a send in another is not exfil).
    analyzer = TrailAnalyzer()
    all_findings: list = []
    for session in _group_by_session(traces):
        all_findings.extend(analyzer.analyze(session))

    threshold = _TRAIL_RANK[min_severity]
    shown = [f for f in all_findings if _TRAIL_RANK.get(f.severity, 0) >= threshold]
    total_calls = len(traces)

    if as_json:
        console.print_json(data=[f.to_dict() for f in shown])
    elif not all_findings:
        _ok(f"No issues found in {total_calls} tool calls")
    elif not shown:
        console.print(
            f"[dim]No findings at or above {min_severity.upper()} — "
            f"{len(all_findings)} lower-severity finding(s) hidden.[/dim]"
        )
    else:
        _render_trail(shown, total_calls)

    if any(f.severity in ("high", "critical") for f in all_findings):
        sys.exit(1)


def _read_ndjson(path: Path) -> list[dict]:
    traces: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue  # skip malformed lines
        if isinstance(obj, dict):
            traces.append(obj)
    return traces


def _load_trace_dicts(target: Path) -> list[dict]:
    files = [target] if target.is_file() else sorted(target.glob("*.ndjson"))
    traces: list[dict] = []
    for file in files:
        traces.extend(_read_ndjson(file))
    return traces


def _group_by_session(traces: list[dict]) -> list[list[dict]]:
    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for trace in traces:
        sid = str(trace.get("session_id") or "")
        if sid not in groups:
            groups[sid] = []
            order.append(sid)
        groups[sid].append(trace)
    return [
        sorted(groups[sid], key=lambda t: str(t.get("ts") or "")) for sid in order
    ]


def _render_trail(findings: list, total_calls: int) -> None:
    table = Table(header_style="bold")
    table.add_column("Severity")
    table.add_column("Pattern")
    table.add_column("Tools Involved")
    table.add_column("Message")
    table.add_column("Confidence", justify="right")
    for severity in _TRAIL_DISPLAY_ORDER:
        for f in (x for x in findings if x.severity == severity):
            table.add_row(
                severity.upper(),
                f.pattern,
                " → ".join(f.calls_involved),
                f.message,
                f"{round(f.confidence * 100)}%",
                style=_TRAIL_ROW_STYLE.get(severity),
            )
    console.print(table)
    console.print(
        f"[bold]{len(findings)}[/bold] findings across "
        f"[bold]{total_calls}[/bold] tool calls analysed"
    )


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
