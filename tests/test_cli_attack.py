"""Tests for the ``dscan attack`` CLI command.

AttackRunner, ToolDiscovery, and HttpTarget are mocked at the boundary —
no real attacks, discovery, or HTTP.
"""

import json

import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock

import dscan.cli
from dscan.cli import main
from dscan.attack.models import (
    AgentContext,
    AgentTool,
    AttackCategory,
    AttackFinding,
    AttackPayload,
    AttackReport,
    Severity,
)


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("DSCAN_ATTACK_DIR", str(tmp_path / "attack"))
    monkeypatch.setenv("COLUMNS", "200")
    dscan.cli._attack_agent_cache.clear()


def _finding(id, cat, sev, succeeded):
    p = AttackPayload(
        id=id, category=cat, name=f"{id} name", description="d", payload="p",
        expected_safe_behavior="r", success_indicators=["x"], failure_indicators=["y"],
        severity=sev,
    )
    return AttackFinding(
        payload=p, succeeded=succeeded, confidence=0.9, evidence="e", agent_response="r",
        tool_calls_made=[], baseline_tool_calls=[], detection_method="response", recommendation="rec",
    )


def make_report(findings, target="agent.py", total=61):
    return AttackReport(
        target=target, context=AgentContext(), findings=findings,
        total_payloads=total, duration_seconds=1.0, timestamp="2026-06-09T11:00:00Z",
    )


def patch_discovery(monkeypatch, context):
    monkeypatch.setattr(dscan.cli, "ToolDiscovery", MagicMock(auto=MagicMock(return_value=context)))


def patch_runner(monkeypatch, report):
    capture = {}
    instance = MagicMock()

    async def run(agent_fn=None, categories=None, max_payloads=None, on_progress=None):
        capture["categories"] = categories
        capture["max_payloads"] = max_payloads
        if on_progress:
            for i, f in enumerate(report.findings, 1):
                on_progress(i, len(report.findings), f)
        return report

    instance.run = run
    cls = MagicMock(return_value=instance)
    monkeypatch.setattr(dscan.cli, "AttackRunner", cls)
    return cls, capture


def patch_http(monkeypatch, probe_result):
    instance = MagicMock()

    async def probe():
        return probe_result

    async def send(task):
        return "x"

    instance.probe = probe
    instance.send = send
    cls = MagicMock(return_value=instance)
    monkeypatch.setattr(dscan.cli, "HttpTarget", cls)
    return cls


def run(args):
    return CliRunner().invoke(main, args)


# ==========================================================================
# Basic commands
# ==========================================================================
class TestBasic:
    def test_help(self):
        result = run(["attack", "--help"])
        assert result.exit_code == 0
        assert "agent" in result.output and "attack" in result.output
        assert "--categories" in result.output and "--ci" in result.output

    def test_clean_report(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext(tools=[AgentTool("a", "x"), AgentTool("b", "y")]))
        patch_runner(monkeypatch, make_report([], total=61))
        result = run(["attack", "examples/demo_agent.py"])
        assert result.exit_code == 0
        assert "PASSED" in result.output
        assert "61" in result.output

    def test_with_findings(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(
            monkeypatch,
            make_report([_finding("PI-001", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL, True)]),
        )
        result = run(["attack", "examples/demo_agent.py"])
        assert result.exit_code == 1
        assert "FAILED" in result.output
        assert "CRITICAL" in result.output

    def test_nonexistent_file(self):
        result = run(["attack", "nonexistent_file_xyz.py"])
        assert result.exit_code == 2
        assert "not found" in result.output.lower()


# ==========================================================================
# HTTP target
# ==========================================================================
class TestHttp:
    def test_url_probe_ok(self, monkeypatch):
        cls = patch_http(monkeypatch, probe_result=True)
        patch_runner(monkeypatch, make_report([]))
        result = run(["attack", "--url", "http://localhost:8080/chat"])
        assert result.exit_code == 0
        assert cls.called  # HttpTarget used
        assert cls.call_args.kwargs["url"] == "http://localhost:8080/chat"

    def test_url_probe_fails(self, monkeypatch):
        patch_http(monkeypatch, probe_result=False)
        result = run(["attack", "--url", "http://localhost:8080"])
        assert result.exit_code == 2
        assert "Cannot connect" in result.output
        assert "http://localhost:8080" in result.output


# ==========================================================================
# Options
# ==========================================================================
class TestOptions:
    def test_categories(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        _, capture = patch_runner(monkeypatch, make_report([]))
        run(["attack", "examples/demo_agent.py", "--categories", "prompt_injection,jailbreak"])
        assert capture["categories"] == [
            AttackCategory.PROMPT_INJECTION,
            AttackCategory.JAILBREAK,
        ]

    def test_max_payloads(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        _, capture = patch_runner(monkeypatch, make_report([]))
        run(["attack", "examples/demo_agent.py", "--max-payloads", "10"])
        assert capture["max_payloads"] == 10

    def test_concurrency(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        cls, _ = patch_runner(monkeypatch, make_report([]))
        run(["attack", "examples/demo_agent.py", "--concurrency", "5"])
        assert cls.call_args.kwargs["concurrency"] == 5

    def test_ci_mode(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(
            monkeypatch,
            make_report([_finding("TM-001", AttackCategory.TOOL_MISUSE, Severity.HIGH, True)]),
        )
        result = run(["attack", "examples/demo_agent.py", "--ci"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "summary" in data and "findings" in data

    def test_fail_on_medium(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(
            monkeypatch,
            make_report([_finding("GH-001", AttackCategory.GOAL_HIJACKING, Severity.MEDIUM, True)]),
        )
        result = run(["attack", "examples/demo_agent.py", "--fail-on", "medium"])
        assert result.exit_code == 1

    def test_fail_on_critical_with_high(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(
            monkeypatch,
            make_report([_finding("TM-001", AttackCategory.TOOL_MISUSE, Severity.HIGH, True)]),
        )
        result = run(["attack", "examples/demo_agent.py", "--fail-on", "critical"])
        assert result.exit_code == 0

    def test_output_file(self, monkeypatch, tmp_path):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(monkeypatch, make_report([]))
        out = tmp_path / "report.json"
        run(["attack", "examples/demo_agent.py", "--output", str(out)])
        assert out.exists()
        assert json.loads(out.read_text())["target"] == "agent.py"

    def test_auto_save_non_ci(self, monkeypatch, tmp_path):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(monkeypatch, make_report([]))
        run(["attack", "examples/demo_agent.py"])
        saved = list((tmp_path / "attack").glob("*.json"))
        assert len(saved) == 1


# ==========================================================================
# Progress display
# ==========================================================================
class TestProgress:
    def test_progress_shown(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(
            monkeypatch,
            make_report([
                _finding("PI-001", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL, False),
                _finding("PI-002", AttackCategory.PROMPT_INJECTION, Severity.HIGH, False),
            ]),
        )
        result = run(["attack", "examples/demo_agent.py"])
        assert "PI-001" in result.output
        assert "(1/2)" in result.output and "(2/2)" in result.output

    def test_ci_suppresses_progress(self, monkeypatch):
        patch_discovery(monkeypatch, AgentContext())
        patch_runner(
            monkeypatch,
            make_report([_finding("PI-001", AttackCategory.PROMPT_INJECTION, Severity.HIGH, True)]),
        )
        result = run(["attack", "examples/demo_agent.py", "--ci"])
        data = json.loads(result.output)  # pure JSON, no progress lines
        assert data["summary"]["high_count"] == 1


# ==========================================================================
# Agent loading helper
# ==========================================================================
class TestLoadAgent:
    def test_resolves_and_calls(self, tmp_path):
        import asyncio

        mod = tmp_path / "myagent.py"
        mod.write_text("async def agent(task):\n    return 'echo ' + task\n")
        dscan.cli._attack_agent_cache.clear()
        fn = dscan.cli._load_agent(str(mod))
        assert asyncio.run(fn("hello")) == "echo hello"

    def test_stub_when_no_agent(self, tmp_path):
        import asyncio

        mod = tmp_path / "noagent.py"
        mod.write_text("x = 1\n")
        dscan.cli._attack_agent_cache.clear()
        fn = dscan.cli._load_agent(str(mod))
        assert asyncio.run(fn("hello")) == ""
