"""Tests for the dashboard data layer and HTTP endpoints."""

import json
from datetime import datetime, timezone

import pytest
from aiohttp.test_utils import TestClient, TestServer

from dscan.dashboard.server import (
    build_sessions,
    compute_stats,
    make_app,
    read_traces,
)


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def entry(**over):
    base = {
        "ts": f"{_today()}T01:00:00Z",
        "session_id": "s1",
        "agent": "my_agent",
        "tool": "read_file",
        "params": {"path": "/x"},
        "result": {"ok": True},
        "duration_ms": 10,
        "flagged": False,
        "flag_reason": None,
    }
    base.update(over)
    return base


def write_ndjson(path, entries):
    path.write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8"
    )
    return path


# --------------------------------------------------------------------------
# read_traces
# --------------------------------------------------------------------------
class TestReadTraces:
    async def test_parses_ndjson(self, tmp_path):
        write_ndjson(tmp_path / f"{_today()}_a.ndjson", [entry(tool="a"), entry(tool="b")])
        traces = await read_traces(tmp_path)
        assert len(traces) == 2
        assert {t["tool"] for t in traces} == {"a", "b"}

    async def test_skips_malformed_lines(self, tmp_path):
        path = tmp_path / f"{_today()}_a.ndjson"
        path.write_text(
            json.dumps(entry(tool="good1"))
            + "\n{ this is not json\n\n"
            + json.dumps(entry(tool="good2"))
            + "\n",
            encoding="utf-8",
        )
        traces = await read_traces(tmp_path)
        assert len(traces) == 2
        assert {t["tool"] for t in traces} == {"good1", "good2"}

    async def test_sorted_by_ts_desc(self, tmp_path):
        write_ndjson(
            tmp_path / f"{_today()}_a.ndjson",
            [
                entry(ts="2026-06-01T00:00:00Z", tool="old"),
                entry(ts="2026-06-09T00:00:00Z", tool="new"),
                entry(ts="2026-06-05T00:00:00Z", tool="mid"),
            ],
        )
        traces = await read_traces(tmp_path)
        assert [t["tool"] for t in traces] == ["new", "mid", "old"]

    async def test_flagged_identified(self, tmp_path):
        write_ndjson(
            tmp_path / f"{_today()}_a.ndjson",
            [entry(tool="clean"), entry(tool="bad", flagged=True, flag_reason="secrets_in_params")],
        )
        traces = await read_traces(tmp_path)
        flagged = [t for t in traces if t["flagged"]]
        assert len(flagged) == 1
        assert flagged[0]["tool"] == "bad"

    async def test_missing_dir_returns_empty(self, tmp_path):
        assert await read_traces(tmp_path / "nope") == []

    async def test_reads_from_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
        write_ndjson(tmp_path / f"{_today()}_a.ndjson", [entry()])
        traces = await read_traces()
        assert len(traces) == 1


# --------------------------------------------------------------------------
# build_sessions / compute_stats
# --------------------------------------------------------------------------
class TestSessions:
    def test_groups_by_session_id(self):
        traces = [
            entry(session_id="s1", tool="a", ts="2026-06-09T01:00:00Z"),
            entry(session_id="s1", tool="b", ts="2026-06-09T02:00:00Z"),
            entry(session_id="s2", tool="c", ts="2026-06-09T03:00:00Z"),
        ]
        sessions = build_sessions(traces)
        assert len(sessions) == 2
        s1 = next(s for s in sessions if s["session_id"] == "s1")
        assert [c["tool"] for c in s1["calls"]] == ["a", "b"]  # calls in time order

    def test_session_flagged_if_any_call_flagged(self):
        traces = [
            entry(session_id="s1", flagged=False),
            entry(session_id="s1", flagged=True),
        ]
        (s1,) = build_sessions(traces)
        assert s1["flagged"] is True

    def test_sessions_sorted_latest_first(self):
        traces = [
            entry(session_id="old", ts="2026-06-01T00:00:00Z"),
            entry(session_id="new", ts="2026-06-09T00:00:00Z"),
        ]
        sessions = build_sessions(traces)
        assert [s["session_id"] for s in sessions] == ["new", "old"]

    def test_compute_stats(self):
        traces = [
            entry(agent="a", flagged=True),
            entry(agent="a", flagged=False),
            entry(agent="b", flagged=False),
            entry(agent="c", ts="2020-01-01T00:00:00Z"),  # not today
        ]
        stats = compute_stats(traces)
        assert stats["total_calls_today"] == 3
        assert stats["flagged"] == 1
        assert stats["agents_active"] == 2  # a, b today (c is old)


# --------------------------------------------------------------------------
# HTTP endpoints
# --------------------------------------------------------------------------
class TestEndpoints:
    async def test_api_traces(self, tmp_path):
        write_ndjson(tmp_path / f"{_today()}_a.ndjson", [entry(tool="a"), entry(tool="b")])
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            resp = await client.get("/api/traces")
            assert resp.status == 200
            data = await resp.json()
            assert len(data) == 2

    async def test_api_session_detail(self, tmp_path):
        write_ndjson(
            tmp_path / f"{_today()}_a.ndjson",
            [entry(session_id="abc", tool="a"), entry(session_id="abc", tool="b")],
        )
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            resp = await client.get("/api/traces/abc")
            assert resp.status == 200
            data = await resp.json()
            assert data["session_id"] == "abc"
            assert len(data["calls"]) == 2

    async def test_api_session_not_found(self, tmp_path):
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            resp = await client.get("/api/traces/missing")
            assert resp.status == 404

    async def test_index_serves_html_with_injected_data(self, tmp_path):
        write_ndjson(tmp_path / f"{_today()}_a.ndjson", [entry(tool="unique_tool")])
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            resp = await client.get("/")
            assert resp.status == 200
            assert resp.content_type == "text/html"
            body = await resp.text()
            assert "unique_tool" in body  # data injected
            assert "__DSCAN_DATA__" not in body  # placeholder replaced

    async def test_index_has_no_external_dependencies(self, tmp_path):
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            body = await (await client.get("/")).text()
            assert 'src="http' not in body
            assert 'href="http' not in body
            assert "cdn" not in body.lower()
