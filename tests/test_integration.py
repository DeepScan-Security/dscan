"""End-to-end integration test for the full dscan pipeline.

Runs the demo agent (mocked, no real API calls) and verifies the trace
is written, secrets are redacted and flagged, the dashboard data layer
reads it back, and the scanner detects a hardcoded secret.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load_demo():
    path = Path(__file__).resolve().parent.parent / "examples" / "demo_agent.py"
    spec = importlib.util.spec_from_file_location("demo_agent", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def demo():
    return _load_demo()


def _trace_file(tmp_path):
    files = list(tmp_path.glob("*_demo_agent.ndjson"))
    assert len(files) == 1, f"expected one trace file, got {files}"
    return files[0]


def _entries(tmp_path):
    content = _trace_file(tmp_path).read_text(encoding="utf-8")
    return [json.loads(line) for line in content.splitlines() if line.strip()]


class TestEndToEnd:
    async def test_full_pipeline(self, demo, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))

        # 1 + 2: @watch-decorated demo agent runs with mocked tool calls.
        result = await demo.run_demo(mock=True)
        assert result == "complete"

        # 3: trace file written to the temp dir, with all five calls.
        entries = _entries(tmp_path)
        assert {e["tool"] for e in entries} == {
            "search_web",
            "read_file",
            "store_data",
            "send_email",
            "query_db",
        }

        # 4: secrets redacted — the fake key never reaches the trace.
        raw = _trace_file(tmp_path).read_text(encoding="utf-8")
        assert "FAKE_KEY" not in raw
        assert "[REDACTED:API_KEY]" in raw

        # 5: the store_data call is flagged for secrets in params.
        store = next(e for e in entries if e["tool"] == "store_data")
        assert store["flagged"] is True
        assert store["flag_reason"] == "secrets_in_params"
        assert store["params"]["value"] == "[REDACTED:API_KEY]"

    async def test_dashboard_reads_traces(self, demo, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
        await demo.run_demo(mock=True)

        # 6: the dashboard data layer reads the same data back.
        from dscan.dashboard.server import build_sessions, read_traces

        traces = await read_traces(tmp_path)
        assert len(traces) == 5
        sessions = build_sessions(traces)
        assert len(sessions) == 1
        assert sessions[0]["agent"] == "demo_agent"
        assert sessions[0]["flagged"] is True

    def test_scanner_finds_hardcoded_secret(self):
        # 7: the scanner independently flags a hardcoded secret (SP003).
        from dscan.scanner import scan_system_prompt

        prompt = "You are an agent. Authenticate with sk-ant-api03-realsecret123."
        findings = scan_system_prompt(prompt)
        assert any(f.rule == "SP003" for f in findings)

    def test_demo_main_mock(self, demo, tmp_path, monkeypatch):
        # Exercises the script entry point end to end (sync: no running loop).
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
        monkeypatch.setattr(sys, "argv", ["demo_agent.py", "--mock"])
        demo.main()
        assert len(_entries(tmp_path)) == 5
