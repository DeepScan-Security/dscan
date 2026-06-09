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


def trail_finding(pattern="INJECTION_RELAY", severity="critical", confidence=0.85):
    return {
        "pattern": pattern,
        "severity": severity,
        "calls_involved": ["search_web", "send_email"],
        "call_indices": [0, 1],
        "message": "untrusted read relayed to send",
        "confidence": confidence,
    }


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


# --------------------------------------------------------------------------
# Trail findings
# --------------------------------------------------------------------------
class TestTrailFindings:
    async def test_api_traces_includes_trail_findings(self, tmp_path):
        findings = [trail_finding(severity="critical")]
        write_ndjson(
            tmp_path / f"{_today()}_a.ndjson",
            [entry(tool="send_email", trail_findings=findings)],
        )
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/traces")).json()
        assert data[0]["trail_findings"] == findings

    async def test_critical_trail_finding_is_flagged(self, tmp_path):
        write_ndjson(
            tmp_path / f"{_today()}_a.ndjson",
            [
                entry(
                    tool="send_email",
                    flagged=True,
                    flag_reason="trail:INJECTION_RELAY",
                    trail_findings=[trail_finding(severity="critical")],
                )
            ],
        )
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/traces")).json()
        assert data[0]["flagged"] is True
        assert data[0]["trail_findings"][0]["severity"] == "critical"

    async def test_session_detail_includes_trail_findings(self, tmp_path):
        findings = [trail_finding(severity="critical")]
        write_ndjson(
            tmp_path / f"{_today()}_a.ndjson",
            [
                entry(session_id="abc", tool="search_web", ts=f"{_today()}T01:00:00Z"),
                entry(
                    session_id="abc",
                    tool="send_email",
                    ts=f"{_today()}T02:00:00Z",
                    trail_findings=findings,
                ),
            ],
        )
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/traces/abc")).json()
        send = next(c for c in data["calls"] if c["tool"] == "send_email")
        assert send["trail_findings"] == findings

    async def test_api_traces_includes_blocked_fields(self, tmp_path):
        write_ndjson(
            tmp_path / f"{_today()}_a.ndjson",
            [
                entry(
                    tool="send_data",
                    flagged=True,
                    blocked=True,
                    block_reason="injection:PromptGuard",
                )
            ],
        )
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/traces")).json()
        assert data[0]["blocked"] is True
        assert data[0]["block_reason"] == "injection:PromptGuard"

    def test_compute_stats_counts_blocked_separately_from_flagged(self):
        traces = [
            entry(flagged=True, flag_reason="secrets_in_params"),  # flagged only
            entry(
                flagged=True,
                blocked=True,
                flag_reason="shield:PromptGuard",
                block_reason="injection:PromptGuard",
            ),  # blocked
            entry(flagged=False),  # clean
        ]
        stats = compute_stats(traces)
        assert stats["flagged"] == 2  # both flagged calls
        assert stats["blocked"] == 1  # only the prevented call

    def test_compute_stats_counts_critical_separately_from_secrets(self):
        traces = [
            # Secrets-flagged, but NOT a trail finding.
            entry(flagged=True, flag_reason="secrets_in_params"),
            # Critical trail finding (also flagged).
            entry(
                flagged=True,
                flag_reason="trail:INJECTION_RELAY",
                trail_findings=[trail_finding(severity="critical")],
            ),
            # A non-critical trail finding must not count toward critical.
            entry(
                flagged=True,
                flag_reason="trail:EXFIL_SEQUENCE",
                trail_findings=[trail_finding(pattern="EXFIL_SEQUENCE", severity="high")],
            ),
            entry(flagged=False),  # clean
        ]
        stats = compute_stats(traces)
        assert stats["flagged"] == 3  # all flagged calls
        assert stats["critical"] == 1  # only the CRITICAL trail finding


# --------------------------------------------------------------------------
# Attack reports
# --------------------------------------------------------------------------
def _attack_report(target, timestamp, passed, critical, high, findings=None):
    return {
        "target": target,
        "summary": {
            "timestamp": timestamp,
            "passed": passed,
            "critical_count": critical,
            "high_count": high,
        },
        "findings": findings or [],
    }


class TestAttackReports:
    async def test_empty_when_dir_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_ATTACK_DIR", str(tmp_path / "nope"))
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/attack-reports")).json()
        assert data == []

    async def test_lists_summaries_sorted(self, tmp_path, monkeypatch):
        adir = tmp_path / "attack"
        adir.mkdir()
        (adir / "r1.json").write_text(
            json.dumps(_attack_report("a.py", "2026-06-09T01:00:00Z", False, 1, 2))
        )
        (adir / "r2.json").write_text(
            json.dumps(_attack_report("b.py", "2026-06-09T02:00:00Z", True, 0, 0))
        )
        monkeypatch.setenv("DSCAN_ATTACK_DIR", str(adir))
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/attack-reports")).json()
        assert len(data) == 2
        assert data[0]["timestamp"] == "2026-06-09T02:00:00Z"  # newest first
        assert set(data[0]) >= {
            "filename", "target", "timestamp", "passed", "critical_count", "high_count",
        }
        first = next(d for d in data if d["filename"] == "r1.json")
        assert first["target"] == "a.py"
        assert first["passed"] is False
        assert first["critical_count"] == 1
        assert first["high_count"] == 2

    async def test_full_report(self, tmp_path, monkeypatch):
        adir = tmp_path / "attack"
        adir.mkdir()
        full = _attack_report("a.py", "t", False, 1, 0, findings=[{"id": "PI-001"}])
        (adir / "r1.json").write_text(json.dumps(full))
        monkeypatch.setenv("DSCAN_ATTACK_DIR", str(adir))
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/attack-reports/r1.json")).json()
        assert data == full

    async def test_full_report_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_ATTACK_DIR", str(tmp_path))
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            resp = await client.get("/api/attack-reports/missing.json")
        assert resp.status == 404


# --------------------------------------------------------------------------
# Audit reports
# --------------------------------------------------------------------------
def _audit_report_json(passed, timestamp, servers):
    return {
        "passed": passed,
        "timestamp": timestamp,
        "source_files": ["mcp.json"],
        "servers": servers,
    }


class TestAuditReports:
    async def test_empty_when_dir_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_AUDIT_REPORTS_DIR", str(tmp_path / "nope"))
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/audit-reports")).json()
        assert data == []

    async def test_lists_summaries(self, tmp_path, monkeypatch):
        adir = tmp_path / "audit"
        adir.mkdir()
        (adir / "r1.json").write_text(json.dumps(_audit_report_json(
            False, "2026-06-09T01:00:00Z",
            [{"name": "fs", "risk_level": "critical"}, {"name": "x", "risk_level": "high"}],
        )))
        (adir / "r2.json").write_text(json.dumps(_audit_report_json(
            True, "2026-06-09T02:00:00Z", [{"name": "y", "risk_level": "low"}],
        )))
        monkeypatch.setenv("DSCAN_AUDIT_REPORTS_DIR", str(adir))
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/audit-reports")).json()
        assert len(data) == 2
        assert data[0]["timestamp"] == "2026-06-09T02:00:00Z"  # newest first
        r1 = next(d for d in data if d["filename"] == "r1.json")
        assert set(r1) >= {"filename", "passed", "timestamp", "server_count", "critical_count", "high_count"}
        assert r1["server_count"] == 2
        assert r1["critical_count"] == 1
        assert r1["high_count"] == 1
        assert r1["passed"] is False

    async def test_full_report(self, tmp_path, monkeypatch):
        adir = tmp_path / "audit"
        adir.mkdir()
        full = _audit_report_json(False, "t", [{"name": "fs", "risk_level": "critical", "findings": [{"check_id": "AU006"}]}])
        (adir / "r1.json").write_text(json.dumps(full))
        monkeypatch.setenv("DSCAN_AUDIT_REPORTS_DIR", str(adir))
        async with TestClient(TestServer(make_app(str(tmp_path)))) as client:
            data = await (await client.get("/api/audit-reports/r1.json")).json()
        assert data == full
