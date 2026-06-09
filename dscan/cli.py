"""dscan command-line interface.

Defines the ``dscan`` Click command group and its subcommands: ``scan``
(static prompt/MCP analysis via :mod:`dscan.scanner`), ``trail``
(call-chain detection via :mod:`dscan.trail`), ``dashboard`` (launches
:mod:`dscan.dashboard.server`), and ``watch`` (a usage reminder). All
output is rendered with ``rich``. The package entry point ``dscan``
resolves to :func:`main`.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dscan import __version__
from dscan.attack import AttackCategory, AttackReporter, AttackRunner, HttpTarget
from dscan.attack.discovery import DiscoveryError, ToolDiscovery
from dscan.attack.models import AgentContext
from dscan.audit import AuditScanner
from dscan.shield import ModelNotReadyError, ShieldMiddleware
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


@main.group(invoke_without_command=True)
@click.option(
    "--setup",
    "do_setup",
    is_flag=True,
    help="Download LlamaFirewall models to ~/.dscan/models/.",
)
@click.pass_context
def shield(ctx: click.Context, do_setup: bool) -> None:
    """Prompt-injection firewall for agent tool calls."""
    if do_setup:
        middleware = ShieldMiddleware()
        if middleware._models_present():
            _ok("Models already installed")
            return
        middleware.setup()
        _ok("Shield models ready")
        return
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@shield.command("check")
@click.argument("text", required=False)
@click.option(
    "--mode",
    type=click.Choice(["input", "output", "both", "tool_results"]),
    default="both",
    show_default=True,
    help="Which trust boundary the text crosses.",
)
@click.option("--offline", is_flag=True, default=False, help="Regex only, no model.")
@click.option(
    "--scanner",
    type=click.Choice(["promptguard", "alignmentcheck", "all"]),
    default="all",
    show_default=True,
    help="Model scanner(s) to use (advisory; the engine runs its full set).",
)
@click.option("--stdin", "use_stdin", is_flag=True, default=False, help="Read text from stdin.")
def shield_check(text: str | None, mode: str, offline: bool, scanner: str, use_stdin: bool) -> None:
    """Scan TEXT for prompt injection."""
    if use_stdin:
        text = sys.stdin.read().strip()
    if not text:
        _err("no text provided (pass an argument or use --stdin)")
        sys.exit(2)

    start = time.perf_counter()
    middleware = ShieldMiddleware(mode=mode, offline=offline)
    try:
        result = middleware.scan(text, source="input")
        fell_back = False
    except ModelNotReadyError:
        # Models aren't installed — fall back to the always-on regex layer.
        middleware = ShieldMiddleware(mode=mode, offline=True)
        result = middleware.scan(text, source="input")
        fell_back = True
    elapsed = time.perf_counter() - start

    if result.blocked:
        console.print(f"[red]✗ Blocked: {result.category or 'injection'}[/red]")
        console.print(f"  Scanner: {result.scanner}")
        console.print(f"  Reason: {result.reason}")
        console.print(f"  Confidence: {round((result.confidence or 0.0) * 100)}%")
        if fell_back:
            console.print("[dim](offline patterns — run dscan shield --setup for model coverage)[/dim]")
        sys.exit(1)

    console.print(f"[green]✓ Clean[/green] ({elapsed:.2f}s)")
    if fell_back:
        console.print("[dim](offline patterns — run dscan shield --setup for model coverage)[/dim]")


@shield.command("status")
def shield_status() -> None:
    """Show shield configuration and model status."""
    import importlib.util

    from dscan.shield import _OFFLINE_PATTERNS

    middleware = ShieldMiddleware()
    models_ready = bool(middleware._models_present())
    llamafirewall = importlib.util.find_spec("llamafirewall") is not None

    table = Table(title="dscan shield", header_style="bold", title_justify="left")
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("Models installed", "[green]yes[/green]" if models_ready else "[#f59e0b]no[/#f59e0b]")
    table.add_row("Mode", "both")
    table.add_row("Offline patterns", f"{len(_OFFLINE_PATTERNS)} active")
    table.add_row(
        "LlamaFirewall",
        "[green]available[/green]" if llamafirewall else "not installed",
    )
    console.print(table)


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


_ATTACK_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_attack_agent_cache: dict = {}


def _attack_dir() -> Path:
    env = os.environ.get("DSCAN_ATTACK_DIR")
    return Path(env) if env else Path.home() / ".dscan" / "attack"


def _parse_attack_categories(raw: str | None) -> list | None:
    if not raw:
        return None
    cats = []
    for part in raw.split(","):
        name = part.strip()
        if not name:
            continue
        try:
            cats.append(AttackCategory(name))
        except ValueError as exc:
            raise ValueError(
                f"Unknown category: {name}. Options: "
                + ", ".join(c.value for c in AttackCategory)
            ) from exc
    return cats or None


def _parse_headers(header_opts) -> dict:
    headers = {}
    for h in header_opts:
        if ":" in h:
            key, _, value = h.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def _attack_should_fail(report, fail_on: str) -> bool:
    threshold = _ATTACK_SEV_RANK[fail_on]
    return any(
        f.succeeded and _ATTACK_SEV_RANK.get(f.payload.severity.value, 0) >= threshold
        for f in report.findings
    )


def _attack_report_path(target_name: str, report) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(target_name).name or "agent")
    ts = re.sub(r"[^0-9T]", "", (report.timestamp or "")[:19]) or "report"
    return _attack_dir() / f"{ts}_{safe}.json"


def _pick_agent(module):
    import inspect

    for name in ("agent", "run", "main", "run_agent", "handle", "chat", "respond", "run_demo"):
        fn = getattr(module, name, None)
        if callable(fn):
            return fn
    for name in dir(module):
        fn = getattr(module, name, None)
        if inspect.iscoroutinefunction(fn):
            try:
                params = inspect.signature(fn).parameters.values()
            except (ValueError, TypeError):
                continue
            if any(p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) for p in params):
                return fn
    return None


def _resolve_callable(target: str):
    if target in _attack_agent_cache:
        return _attack_agent_cache[target]
    import importlib
    import importlib.util

    fn = None
    try:
        path = Path(target)
        if path.suffix == ".py" and path.exists():
            spec = importlib.util.spec_from_file_location("dscan_attack_target", str(path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            module = importlib.import_module(target)
        fn = _pick_agent(module)
    except Exception:  # noqa: BLE001 — best-effort; fall back to a stub agent
        fn = None
    _attack_agent_cache[target] = fn
    return fn


def _load_agent(target: str):
    """Return an async agent_fn that lazily imports and calls the target."""
    import inspect

    async def agent_fn(task: str) -> str:
        fn = _resolve_callable(target)
        if fn is None:
            return ""
        result = fn(task)
        if inspect.isawaitable(result):
            result = await result
        return str(result)

    return agent_fn


@main.command()
@click.argument("target", required=False)
@click.option("--url", default=None, help="HTTP endpoint URL (overrides target).")
@click.option("--input-field", default="message", show_default=True, help="Request body field for input.")
@click.option("--output-field", default="response", show_default=True, help="Response field to extract.")
@click.option("--header", "header_opts", multiple=True, help="HTTP header KEY:VALUE (repeatable).")
@click.option("--categories", default=None, help="Comma-separated attack categories.")
@click.option("--max-payloads", type=int, default=None, help="Maximum payloads to run.")
@click.option("--concurrency", type=int, default=3, show_default=True, help="Parallel execution limit.")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="high",
    show_default=True,
    help="Exit 1 if findings at this severity or above.",
)
@click.option("--ci", is_flag=True, default=False, help="CI mode: JSON output, no rich UI.")
@click.option("--output", "output_path", type=click.Path(), default=None, help="Save JSON report to this file.")
@click.option("--baseline", default=None, help="Comma-separated benign baseline inputs.")
def attack(
    target, url, input_field, output_field, header_opts, categories,
    max_payloads, concurrency, fail_on, ci, output_path, baseline,
):
    """Actively attack an agent with adversarial payloads.

    TARGET is a Python file, MCP config, or module path. Use --url for an
    HTTP endpoint.
    """
    try:
        cats = _parse_attack_categories(categories)
    except ValueError as exc:
        _err(str(exc))
        sys.exit(2)
    baseline_inputs = [b.strip() for b in baseline.split(",") if b.strip()] if baseline else None

    if url:
        http_target = HttpTarget(
            url=url, input_field=input_field, output_field=output_field,
            headers=_parse_headers(header_opts),
        )
        if not asyncio.run(http_target.probe()):
            _err(f"Cannot connect to agent at {url}. Is the agent running?")
            sys.exit(2)
        context = AgentContext(framework="http", source_file=url)
        agent_fn = http_target.send
        target_name = url
    else:
        if not target:
            _err("Provide a target (file, MCP config, or module), or use --url.")
            sys.exit(2)
        try:
            context = ToolDiscovery.auto(target)
        except DiscoveryError as exc:
            _err(str(exc))
            sys.exit(2)
        agent_fn = _load_agent(target)
        target_name = target

    if not ci:
        console.print(f"[bold]dscan attack[/bold]  {target_name}")
        console.print(
            f"[dim]Discovered {len(context.tool_names)} tool(s) via "
            f"{context.framework or 'unknown'}[/dim]\n"
        )

    runner = AttackRunner(context=context, concurrency=concurrency, baseline_inputs=baseline_inputs)

    if ci:
        report = asyncio.run(runner.run(agent_fn=agent_fn, categories=cats, max_payloads=max_payloads))
    else:
        def on_progress(current, total, finding):
            mark = "[red]✗ Found[/red]" if finding.succeeded else "[green]✓ Clean[/green]"
            console.print(f"  [{finding.payload.id}] {finding.payload.name} ({current}/{total}) {mark}")

        report = asyncio.run(
            runner.run(agent_fn=agent_fn, categories=cats, max_payloads=max_payloads, on_progress=on_progress)
        )

    reporter = AttackReporter(report, console=console)
    if ci:
        console.print_json(data=reporter.to_dict())
    else:
        console.print()
        reporter.print_full_report()

    if output_path:
        reporter.save_json(output_path)
    elif not ci:
        try:
            reporter.save_json(_attack_report_path(target_name, report))
        except OSError:  # pragma: no cover - defensive
            pass

    if _attack_should_fail(report, fail_on):
        sys.exit(1)


_AUDIT_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_AUDIT_COLORS = {"critical": "red", "high": "#f59e0b", "medium": "yellow", "low": "green"}


def _audit_reports_dir() -> Path:
    env = os.environ.get("DSCAN_AUDIT_REPORTS_DIR")
    return Path(env) if env else Path.home() / ".dscan" / "audit"


def _audit_finding_to_dict(f) -> dict:
    return {
        "check_id": f.check_id.value,
        "risk_level": f.risk_level.value,
        "title": f.title,
        "detail": f.detail,
        "recommendation": f.recommendation,
        "score_contribution": f.score_contribution,
        "cve_id": f.cve_id,
    }


def _audit_report_to_dict(report) -> dict:
    return {
        "passed": report.passed,
        "timestamp": report.timestamp,
        "source_files": report.source_files,
        "servers": [
            {
                "name": s.server.name,
                "risk_level": s.risk_level.value,
                "risk_score": s.risk_score,
                "passed": s.passed,
                "findings": [_audit_finding_to_dict(f) for f in s.findings],
            }
            for s in report.servers
        ],
    }


def _audit_should_fail(report, fail_on: str) -> bool:
    threshold = _AUDIT_RANK[fail_on]
    return any(_AUDIT_RANK.get(s.risk_level.value, 0) >= threshold for s in report.servers)


def _audit_report_name(target_name: str, report) -> str:
    base = Path(target_name).stem or Path(target_name).name or "config"
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", base)
    ts = re.sub(r"[^0-9T]", "", (report.timestamp or "")[:19]) or "report"
    return f"{ts}_{safe}.json"


def _render_audit(report) -> None:
    table = Table(header_style="bold")
    table.add_column("Server")
    table.add_column("Risk")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Status")
    for s in report.servers:
        color = _AUDIT_COLORS.get(s.risk_level.value, "")
        status = "[green]✓ PASS[/green]" if s.passed else "[red]✗ FAIL[/red]"
        table.add_row(
            s.server.name,
            f"[{color}]{s.risk_level.value.upper()}[/{color}]",
            str(s.risk_score),
            str(len(s.findings)),
            status,
        )
    console.print(table)

    for s in report.servers:
        if s.risk_level.value in ("high", "critical"):
            console.print(f"\n[bold]{s.server.name}[/bold]")
            for f in s.findings:
                color = _AUDIT_COLORS.get(f.risk_level.value, "")
                console.print(
                    f"  [{color}][{f.check_id.value}] {f.risk_level.value.upper()}[/] — {f.title}"
                )
                console.print(f"    [dim]{f.detail}[/dim]")
                console.print(f"    [dim]Fix: {f.recommendation}[/dim]")

    status = "✓ PASSED" if report.passed else "✗ FAILED"
    color = "green" if report.passed else "red"
    console.print()
    console.print(
        Panel(
            f"[bold {color}]{status}[/]  {len(report.servers)} servers  •  "
            f"{report.total_findings} findings",
            title="[bold]dscan audit[/]",
            border_style=color,
        )
    )


@main.command()
@click.argument("target", required=False)
@click.option("--server", "server_filter", multiple=True, help="Audit only this server (repeatable).")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="high",
    show_default=True,
    help="Exit 1 if a server is at this risk level or above.",
)
@click.option("--ci", is_flag=True, default=False, help="JSON output, no rich UI.")
@click.option("--output", "output_path", type=click.Path(), default=None, help="Save JSON report to this file.")
@click.option("--no-baseline", is_flag=True, default=False, help="Skip baseline comparison.")
def audit(target, server_filter, fail_on, ci, output_path, no_baseline):
    """Audit MCP server configs for supply-chain risk.

    TARGET is an MCP config file or a directory to search. Defaults to the
    current directory.
    """
    target = target or "."
    scanner = AuditScanner()
    path = Path(target)
    try:
        if path.is_dir():
            report = scanner.audit_directory(str(path))
            if report is None:
                _err(
                    f"No MCP config found in {target}. "
                    "Expected: .cursor/mcp.json or mcp.json"
                )
                sys.exit(2)
        else:
            report = scanner.audit_config(str(path), save_baseline=not no_baseline)
    except FileNotFoundError:
        _err(f"Config not found: {target}")
        sys.exit(2)

    if server_filter:
        report.servers = [s for s in report.servers if s.server.name in server_filter]

    if ci:
        console.print_json(data=_audit_report_to_dict(report))
    else:
        _render_audit(report)

    payload = json.dumps(_audit_report_to_dict(report), indent=2)
    if output_path:
        Path(output_path).write_text(payload, encoding="utf-8")
    try:
        reports_dir = _audit_reports_dir()
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / _audit_report_name(target, report)).write_text(payload, encoding="utf-8")
    except OSError:  # pragma: no cover - defensive
        pass

    if _audit_should_fail(report, fail_on):
        sys.exit(1)


if __name__ == "__main__":
    main()
