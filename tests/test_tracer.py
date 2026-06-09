"""Tests for dscan.tracer.

The tracer writes one NDJSON line per recorded event to
``<traces_dir>/YYYY-MM-DD_<agent>.ndjson``.
"""

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone

import pytest

from dscan.tracer import Tracer

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _utc_today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _read_lines(path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


async def _record_one(tracer: Tracer, **overrides):
    payload = {
        "tool": "read_file",
        "params": {"path": "/tmp/x"},
        "result": {"ok": True},
        "duration_ms": 142,
    }
    payload.update(overrides)
    return await tracer.record(**payload)


# --------------------------------------------------------------------------
# File creation / location
# --------------------------------------------------------------------------
class TestFileLocation:
    async def test_creates_trace_file(self, tmp_path):
        tracer = Tracer("my_agent", traces_dir=tmp_path)
        await _record_one(tracer)
        expected = tmp_path / f"{_utc_today()}_my_agent.ndjson"
        assert expected.exists()

    async def test_filename_format(self, tmp_path):
        tracer = Tracer("my_agent", traces_dir=tmp_path)
        await _record_one(tracer)
        (name,) = [p.name for p in tmp_path.iterdir()]
        assert name == f"{_utc_today()}_my_agent.ndjson"
        assert name.endswith(".ndjson")

    async def test_creates_dir_if_missing(self, tmp_path):
        nested = tmp_path / "does" / "not" / "exist"
        assert not nested.exists()
        tracer = Tracer("agent", traces_dir=nested)
        await _record_one(tracer)
        assert nested.is_dir()
        assert (nested / f"{_utc_today()}_agent.ndjson").exists()

    def test_default_dir_is_home_dscan_traces(self, monkeypatch):
        monkeypatch.delenv("DSCAN_TRACES_DIR", raising=False)
        from pathlib import Path

        tracer = Tracer("agent")
        assert tracer.traces_dir == Path.home() / ".dscan" / "traces"

    def test_env_var_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
        tracer = Tracer("agent")
        assert tracer.traces_dir == tmp_path

    async def test_env_var_override_writes_there(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
        tracer = Tracer("agent")
        await _record_one(tracer)
        assert (tmp_path / f"{_utc_today()}_agent.ndjson").exists()

    def test_explicit_dir_beats_env_var(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path / "from_env"))
        explicit = tmp_path / "explicit"
        tracer = Tracer("agent", traces_dir=explicit)
        assert tracer.traces_dir == explicit


# --------------------------------------------------------------------------
# Entry format / schema
# --------------------------------------------------------------------------
class TestEntrySchema:
    async def test_entry_is_single_line_valid_json(self, tmp_path):
        tracer = Tracer("agent", traces_dir=tmp_path)
        await _record_one(tracer)
        path = tmp_path / f"{_utc_today()}_agent.ndjson"
        lines = _read_lines(path)
        assert len(lines) == 1
        entry = json.loads(lines[0])  # must parse
        assert isinstance(entry, dict)

    async def test_entry_has_full_schema(self, tmp_path):
        tracer = Tracer("my_agent", traces_dir=tmp_path)
        entry = await tracer.record(
            tool="read_file",
            params={"path": "/etc/hosts"},
            result={"bytes": 10},
            duration_ms=142,
        )
        path = tmp_path / f"{_utc_today()}_my_agent.ndjson"
        on_disk = json.loads(_read_lines(path)[0])
        assert on_disk == entry  # returned entry matches what was written

        assert set(entry) == {
            "ts",
            "session_id",
            "agent",
            "tool",
            "params",
            "result",
            "duration_ms",
            "flagged",
            "flag_reason",
        }
        assert TS_RE.match(entry["ts"])
        assert entry["agent"] == "my_agent"
        assert entry["tool"] == "read_file"
        assert entry["params"] == {"path": "/etc/hosts"}
        assert entry["result"] == {"bytes": 10}
        assert isinstance(entry["duration_ms"], int)
        assert entry["duration_ms"] == 142
        assert entry["flagged"] is False
        assert entry["flag_reason"] is None
        assert uuid.UUID(entry["session_id"]).version == 4

    async def test_duration_coerced_to_int(self, tmp_path):
        tracer = Tracer("agent", traces_dir=tmp_path)
        entry = await _record_one(tracer, duration_ms=142.9)
        assert isinstance(entry["duration_ms"], int)
        assert entry["duration_ms"] == 142

    async def test_flag_fields(self, tmp_path):
        tracer = Tracer("agent", traces_dir=tmp_path)
        entry = await _record_one(
            tracer, flagged=True, flag_reason="exfiltration attempt"
        )
        assert entry["flagged"] is True
        assert entry["flag_reason"] == "exfiltration attempt"


# --------------------------------------------------------------------------
# Session identity
# --------------------------------------------------------------------------
class TestSession:
    def test_session_id_is_uuid4(self):
        tracer = Tracer("agent")
        assert uuid.UUID(tracer.session_id).version == 4

    def test_distinct_tracers_have_distinct_sessions(self):
        assert Tracer("agent").session_id != Tracer("agent").session_id

    async def test_session_id_stable_across_records(self, tmp_path):
        tracer = Tracer("agent", traces_dir=tmp_path)
        await _record_one(tracer)
        await _record_one(tracer)
        path = tmp_path / f"{_utc_today()}_agent.ndjson"
        ids = {json.loads(line)["session_id"] for line in _read_lines(path)}
        assert ids == {tracer.session_id}


# --------------------------------------------------------------------------
# Append + concurrency safety
# --------------------------------------------------------------------------
class TestAppendAndConcurrency:
    async def test_appends_not_overwrites(self, tmp_path):
        tracer = Tracer("agent", traces_dir=tmp_path)
        await _record_one(tracer, tool="a")
        await _record_one(tracer, tool="b")
        await _record_one(tracer, tool="c")
        path = tmp_path / f"{_utc_today()}_agent.ndjson"
        lines = _read_lines(path)
        assert len(lines) == 3
        assert [json.loads(line)["tool"] for line in lines] == ["a", "b", "c"]

    async def test_concurrent_writes_do_not_corrupt(self, tmp_path):
        tracer = Tracer("agent", traces_dir=tmp_path)
        n = 100
        await asyncio.gather(
            *(_record_one(tracer, params={"i": i}) for i in range(n))
        )
        path = tmp_path / f"{_utc_today()}_agent.ndjson"
        lines = _read_lines(path)
        assert len(lines) == n
        # Every line must be independently valid JSON (no interleaving).
        seen = {json.loads(line)["params"]["i"] for line in lines}
        assert seen == set(range(n))

    async def test_concurrent_writes_from_two_tracers_same_file(self, tmp_path):
        # Same agent + date -> same file; both sessions must land intact.
        a = Tracer("agent", traces_dir=tmp_path)
        b = Tracer("agent", traces_dir=tmp_path)
        await asyncio.gather(
            *(_record_one(a, params={"src": "a", "i": i}) for i in range(50)),
            *(_record_one(b, params={"src": "b", "i": i}) for i in range(50)),
        )
        path = tmp_path / f"{_utc_today()}_agent.ndjson"
        lines = _read_lines(path)
        assert len(lines) == 100
        entries = [json.loads(line) for line in lines]
        assert sum(e["params"]["src"] == "a" for e in entries) == 50
        assert sum(e["params"]["src"] == "b" for e in entries) == 50
