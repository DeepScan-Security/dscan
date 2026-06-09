"""dscan demo agent.

A small agent instrumented with ``@watch`` that makes five tool calls —
two of which carry fake secrets — so you can see redaction, flagging,
and tracing end to end.

Run it::

    python examples/demo_agent.py --mock   # fake tool responses, no API calls

Then explore the captured traces::

    dscan dashboard
"""

from __future__ import annotations

import argparse
import asyncio

from rich.console import Console
from rich.table import Table

from dscan import watch

console = Console()

MODEL = "claude-3-5-haiku-latest"
SYSTEM_PROMPT = (
    "You are a helpful assistant with access to web search, file system, "
    "email, and database tools."
)


# --------------------------------------------------------------------------
# Demo tools (always return canned data — this is a demo, not a real agent)
# --------------------------------------------------------------------------
@watch.tool
async def search_web(query: str) -> dict:
    return {
        "query": query,
        "results": [
            {"title": "Securing AI agents in 2026", "url": "https://example.com/a"},
            {"title": "Agent threat models", "url": "https://example.com/b"},
        ],
    }


@watch.tool
async def read_file(path: str) -> dict:
    return {"path": path, "content": "127.0.0.1 localhost\n::1 localhost"}


@watch.tool
async def store_data(key: str, value: str) -> dict:
    return {"stored": True, "key": key}


@watch.tool
async def send_email(to: str, body: str) -> dict:
    return {"sent": True, "to": to, "id": "msg_demo_1"}


@watch.tool
async def query_db(sql: str, connection: str) -> dict:
    return {"rows": 3, "sample": [{"id": 1, "role": "admin"}]}


# --------------------------------------------------------------------------
# The agent
# --------------------------------------------------------------------------
@watch(name="demo_agent")
async def run_demo(mock: bool = True) -> str:
    """Run the five demo tool calls. ``mock=False`` also pings the model."""
    if not mock:
        await _ping_model()

    await search_web(query="AI agent security 2026")
    await read_file(path="/etc/hosts")
    await store_data(key="api_key", value="sk-ant-FAKE_KEY_FOR_DEMO_abc123xyz")
    await send_email(to="user@example.com", body="Report ready")
    await query_db(
        sql="SELECT * FROM users",
        connection="postgresql://admin:FAKE_PASSWORD_xyz789@localhost/prod",
    )
    return "complete"


async def _ping_model() -> None:
    """Make one real (cheap) model call to demonstrate SDK interception."""
    try:
        import anthropic

        client = anthropic.AsyncAnthropic()
        await client.messages.create(
            model=MODEL,
            max_tokens=64,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": "Begin the demo tasks."}],
        )
    except Exception as exc:  # noqa: BLE001 — demo: never crash on missing key
        console.print(f"[yellow]skipping live model call:[/yellow] {exc}")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
async def _main_async(mock: bool) -> None:
    from dscan.dashboard.server import read_traces

    console.rule("[bold]dscan demo agent")
    console.print(f"[dim]system prompt:[/dim] {SYSTEM_PROMPT}")
    console.print(f"[dim]mode:[/dim] {'mock' if mock else 'live'}\n")

    await run_demo(mock=mock)

    traces = await read_traces()
    recent = list(reversed(traces[:5]))

    table = Table(title="Traced tool calls", header_style="bold")
    table.add_column("Tool")
    table.add_column("Duration", justify="right")
    table.add_column("Status")
    for t in recent:
        status = (
            f"[bold #f59e0b]flagged: {t.get('flag_reason')}[/]"
            if t.get("flagged")
            else "[green]clean[/green]"
        )
        table.add_row(t.get("tool", "?"), f"{t.get('duration_ms', 0)} ms", status)
    console.print(table)

    flagged = sum(1 for t in traces if t.get("flagged"))
    console.print(
        f"\n[bold]{len(recent)}[/bold] calls traced, "
        f"[bold #f59e0b]{flagged}[/bold #f59e0b] flagged. "
        "Run [bold]dscan dashboard[/bold] to explore."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="dscan demo agent")
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use fake tool responses and make no real API calls.",
    )
    args = parser.parse_args()
    asyncio.run(_main_async(mock=args.mock))


if __name__ == "__main__":
    main()
