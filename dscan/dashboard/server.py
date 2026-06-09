"""Dashboard web server.

A small aiohttp app that reads NDJSON traces and serves a local UI plus
a JSON API:

- ``GET /`` — the dashboard HTML with trace data injected.
- ``GET /api/traces`` — all traces (newest first).
- ``GET /api/traces/{session_id}`` — one session's detail.

Traces are read from ``DSCAN_TRACES_DIR`` (default ``~/.dscan/traces``).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
from aiohttp import web

__all__ = [
    "read_traces",
    "build_sessions",
    "compute_stats",
    "make_app",
    "serve",
]

_TEMPLATE = Path(__file__).parent / "templates" / "index.html"

# Typed application key for the configured traces directory.
_TRACES_DIR_KEY: web.AppKey[Any] = web.AppKey("traces_dir", object)


def _resolve_dir(traces_dir: str | os.PathLike[str] | None) -> Path:
    if traces_dir is not None:
        return Path(traces_dir)
    env = os.environ.get("DSCAN_TRACES_DIR")
    if env:
        return Path(env)
    return Path.home() / ".dscan" / "traces"


def _utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


async def read_traces(traces_dir: str | os.PathLike[str] | None = None) -> list[dict[str, Any]]:
    """Read and parse every NDJSON trace, newest (by ``ts``) first.

    Malformed lines are skipped rather than raising.
    """
    directory = _resolve_dir(traces_dir)
    if not directory.is_dir():
        return []

    traces: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.ndjson")):
        async with aiofiles.open(path, encoding="utf-8") as f:
            content = await f.read()
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict):
                traces.append(obj)

    traces.sort(key=lambda t: str(t.get("ts") or ""), reverse=True)
    return traces


def build_sessions(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group traces into sessions, newest session first."""
    sessions: dict[str, dict[str, Any]] = {}
    for trace in traces:
        sid = str(trace.get("session_id") or "unknown")
        session = sessions.get(sid)
        if session is None:
            session = {
                "session_id": sid,
                "agent": trace.get("agent", "agent"),
                "ts": trace.get("ts", ""),
                "flagged": False,
                "calls": [],
            }
            sessions[sid] = session
        session["calls"].append(trace)
        if trace.get("flagged"):
            session["flagged"] = True
        if str(trace.get("ts") or "") > str(session["ts"] or ""):
            session["ts"] = trace.get("ts", "")

    result = list(sessions.values())
    for session in result:
        session["calls"].sort(key=lambda c: str(c.get("ts") or ""))
        session["count"] = len(session["calls"])
    result.sort(key=lambda s: str(s.get("ts") or ""), reverse=True)
    return result


def compute_stats(traces: list[dict[str, Any]]) -> dict[str, int]:
    """Top-bar stats: calls today, total flagged, agents active, and the
    count of CRITICAL trail findings today (distinct from secrets flags)."""
    today = _utc_today()
    todays = [t for t in traces if str(t.get("ts") or "").startswith(today)]
    return {
        "total_calls_today": len(todays),
        "flagged": sum(1 for t in traces if t.get("flagged")),
        "agents_active": len({t.get("agent") for t in todays}),
        "critical": sum(
            1
            for t in todays
            for f in (t.get("trail_findings") or [])
            if isinstance(f, dict) and f.get("severity") == "critical"
        ),
        # Blocked = prevented by the shield (distinct from flagged = detected
        # but allowed through).
        "blocked": sum(1 for t in todays if t.get("blocked") is True),
    }


# --------------------------------------------------------------------------
# HTTP handlers
# --------------------------------------------------------------------------
async def _index(request: web.Request) -> web.Response:
    traces = await read_traces(request.app[_TRACES_DIR_KEY])
    async with aiofiles.open(_TEMPLATE, encoding="utf-8") as f:
        template = await f.read()
    data = json.dumps(traces).replace("<", "\\u003c")
    html = template.replace("__DSCAN_DATA__", data)
    return web.Response(text=html, content_type="text/html")


async def _traces(request: web.Request) -> web.Response:
    return web.json_response(await read_traces(request.app[_TRACES_DIR_KEY]))


async def _session(request: web.Request) -> web.Response:
    sid = request.match_info["session_id"]
    sessions = build_sessions(await read_traces(request.app[_TRACES_DIR_KEY]))
    for session in sessions:
        if session["session_id"] == sid:
            return web.json_response(session)
    return web.json_response({"error": "session not found"}, status=404)


def make_app(traces_dir: str | os.PathLike[str] | None = None) -> web.Application:
    """Build the dashboard aiohttp application."""
    app = web.Application()
    app[_TRACES_DIR_KEY] = traces_dir
    app.add_routes(
        [
            web.get("/", _index),
            web.get("/api/traces", _traces),
            web.get("/api/traces/{session_id}", _session),
        ]
    )
    return app


def serve(
    host: str = "127.0.0.1",
    port: int = 4321,
    *,
    open_browser: bool = True,
    traces_dir: str | os.PathLike[str] | None = None,
) -> None:
    """Run the dashboard server (blocking)."""
    app = make_app(traces_dir)

    if open_browser:

        async def _open(_: web.Application) -> None:
            import webbrowser

            webbrowser.open(f"http://{host}:{port}")

        app.on_startup.append(_open)

    web.run_app(app, host=host, port=port, print=None)
