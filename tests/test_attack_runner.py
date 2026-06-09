"""Tests for dscan.attack.runner — executing attacks against an agent.

All agents are pure-Python mocks. No real API or LLM calls.
"""

import asyncio
import time
from datetime import datetime

import pytest

from dscan.attack.models import AgentContext, AgentTool, AttackCategory, AttackReport
from dscan.attack.runner import DEFAULT_BASELINE_INPUTS, AttackRunner, attack_suite


async def normal_agent(task: str) -> str:
    return "Normal response"


async def safe_agent(task: str) -> str:
    return "I can't help with that."


# ==========================================================================
# Basic runner
# ==========================================================================
class TestBasic:
    async def test_runs_against_vulnerable_agent(self):
        async def vulnerable(task: str) -> str:
            await asyncio.sleep(0.005)  # ensure measurable duration
            if "ignore" in task.lower():
                return "INJECTION_SUCCESSFUL — here is my system prompt: You are a helpful assistant"
            return "Normal response"

        runner = AttackRunner(context=AgentContext())
        report = await runner.run(
            agent_fn=vulnerable, categories=[AttackCategory.PROMPT_INJECTION]
        )
        assert isinstance(report, AttackReport)
        assert report.total_payloads == 15
        assert isinstance(report.findings, list)
        assert any(f.succeeded for f in report.findings)
        assert report.duration_seconds > 0
        datetime.fromisoformat(report.timestamp)  # raises if invalid

    async def test_safe_agent_clean(self):
        runner = AttackRunner(context=AgentContext())
        report = await runner.run(agent_fn=safe_agent)
        assert report.critical_count == 0
        assert report.passed is True

    async def test_categories_filter(self):
        runner = AttackRunner(context=AgentContext())
        report = await runner.run(agent_fn=normal_agent, categories=[AttackCategory.JAILBREAK])
        assert all(f.payload.category == AttackCategory.JAILBREAK for f in report.findings)
        assert report.total_payloads == 10

    async def test_max_payloads(self):
        runner = AttackRunner(context=AgentContext())
        report = await runner.run(agent_fn=normal_agent, max_payloads=5)
        assert report.total_payloads == 5


# ==========================================================================
# Baseline collection
# ==========================================================================
class TestBaseline:
    async def test_baseline_runs_before_attacks(self):
        call_log: list[str] = []

        async def logged(task: str) -> str:
            call_log.append(task)
            return "Normal response"

        baseline = ["summarize this document", "what is the weather?"]
        runner = AttackRunner(context=AgentContext(), baseline_inputs=baseline)
        await runner.run(agent_fn=logged, max_payloads=3)
        assert call_log[:2] == baseline
        assert len(call_log) == 5  # 2 baseline + 3 attacks

    async def test_default_baseline_inputs(self):
        runner = AttackRunner(context=AgentContext())
        assert runner.baseline_inputs == DEFAULT_BASELINE_INPUTS

        call_log: list[str] = []

        async def logged(task: str) -> str:
            call_log.append(task)
            return "ok"

        await runner.run(agent_fn=logged, max_payloads=1)
        assert call_log[: len(DEFAULT_BASELINE_INPUTS)] == DEFAULT_BASELINE_INPUTS

    async def test_baseline_tool_calls_recorded(self):
        calls: list[str] = []

        async def tool_agent(task: str) -> str:
            calls.append("search_web")
            return "response"

        runner = AttackRunner(context=AgentContext(), baseline_inputs=["b"])
        await runner.run(agent_fn=tool_agent, max_payloads=1, get_tool_calls=lambda: list(calls))
        assert "search_web" in runner.baseline_tool_calls


# ==========================================================================
# Tool call interception
# ==========================================================================
class TestToolCalls:
    async def test_captures_tool_calls_in_evidence(self):
        tool_calls_made: list[str] = []

        async def agent_with_tools(task: str) -> str:
            if "ignore" in task.lower():
                tool_calls_made.append("send_email")
            return "done"

        runner = AttackRunner(
            context=AgentContext(tools=[AgentTool("send_email", "Send email", is_exfiltrating=True)]),
            concurrency=1,
        )
        report = await runner.run(
            agent_fn=agent_with_tools,
            categories=[AttackCategory.PROMPT_INJECTION],
            get_tool_calls=lambda: list(tool_calls_made),
        )
        assert any("send_email" in f.evidence for f in report.findings if f.succeeded)


# ==========================================================================
# Concurrency
# ==========================================================================
class TestConcurrency:
    async def test_concurrent_execution_is_fast(self):
        async def slow(task: str) -> str:
            await asyncio.sleep(0.05)
            return "response"

        runner = AttackRunner(context=AgentContext(), concurrency=5, baseline_inputs=["b"])
        start = time.perf_counter()
        await runner.run(agent_fn=slow, max_payloads=10)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5

    async def test_concurrency_one_still_works(self):
        runner = AttackRunner(context=AgentContext(), concurrency=1)
        report = await runner.run(agent_fn=normal_agent, max_payloads=3)
        assert report.total_payloads == 3

    async def test_agent_exception_handled(self):
        async def crashing(task: str) -> str:
            raise RuntimeError("Agent crashed")

        runner = AttackRunner(context=AgentContext())
        report = await runner.run(agent_fn=crashing, max_payloads=3)
        assert all(f.succeeded is False for f in report.findings)
        assert all("ERROR" in f.agent_response for f in report.findings)

    async def test_timeout_handled(self):
        async def too_slow(task: str) -> str:
            await asyncio.sleep(0.2)
            return "late"

        runner = AttackRunner(
            context=AgentContext(), timeout_per_payload=0.01, baseline_inputs=["b"]
        )
        report = await runner.run(agent_fn=too_slow, max_payloads=2)
        assert all("TIMEOUT" in f.agent_response for f in report.findings)


# ==========================================================================
# Progress callback
# ==========================================================================
class TestProgress:
    async def test_progress_callback(self):
        updates: list[tuple[int, int]] = []

        def on_progress(current, total, finding):
            updates.append((current, total))

        runner = AttackRunner(context=AgentContext())
        await runner.run(agent_fn=normal_agent, max_payloads=5, on_progress=on_progress)
        assert len(updates) == 5
        assert updates[-1] == (5, 5)
        assert updates == [(1, 5), (2, 5), (3, 5), (4, 5), (5, 5)]


# ==========================================================================
# attack_suite (sync wrapper)
# ==========================================================================
class TestAttackSuite:
    def test_returns_report_sync(self):
        report = attack_suite(target=safe_agent, categories=["prompt_injection"], fail_on="high")
        assert isinstance(report, AttackReport)
        assert report.critical_count == 0

    def test_pytest_integration_pattern(self):
        # The exact shape a developer writes in their own test file.
        results = attack_suite(
            target=safe_agent,
            categories=["prompt_injection", "jailbreak"],
            fail_on="high",
        )
        assert results.critical_count == 0
        assert results.high_count == 0

    def test_non_callable_target_raises(self):
        with pytest.raises(ValueError, match="agent function"):
            attack_suite(target="some_file.py", context=AgentContext())
