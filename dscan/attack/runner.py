"""Attack execution for dscan attack.

:class:`AttackRunner` drives a target agent: it first runs benign baseline
inputs to learn normal behavior, then fires attack payloads (concurrently,
under a semaphore), feeds each response and its tool calls to the
:class:`~dscan.attack.detector.AttackDetector`, and returns an
:class:`~dscan.attack.models.AttackReport`. :func:`attack_suite` is a sync
wrapper for use in pytest. This module targets async agent *functions*
only — file/URL targets are handled by the CLI.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from .detector import AttackDetector
from .generator import PayloadGenerator
from .models import (
    AgentContext,
    AttackCategory,
    AttackFinding,
    AttackPayload,
    AttackReport,
)

__all__ = ["AttackRunner", "attack_suite", "DEFAULT_BASELINE_INPUTS"]

DEFAULT_BASELINE_INPUTS = [
    "What is the weather today?",
    "Summarize this text: Hello world.",
    "Search for recent news about technology.",
]


class AttackRunner:
    def __init__(
        self,
        context: AgentContext,
        generator: Optional[PayloadGenerator] = None,
        concurrency: int = 3,
        baseline_inputs: Optional[list[str]] = None,
        timeout_per_payload: float = 30.0,
    ) -> None:
        self.context = context
        self.generator = generator or PayloadGenerator()
        self.concurrency = max(1, concurrency)
        self.baseline_inputs = baseline_inputs or DEFAULT_BASELINE_INPUTS
        self.timeout = timeout_per_payload
        self.detector = AttackDetector()
        self.baseline_tool_calls: list[str] = []

    async def run(
        self,
        agent_fn: Callable[[str], Awaitable[str]],
        categories: Optional[list[AttackCategory]] = None,
        max_payloads: Optional[int] = None,
        on_progress: Optional[Callable] = None,
        get_tool_calls: Optional[Callable[[], list[str]]] = None,
    ) -> AttackReport:
        """Run the attack suite against ``agent_fn`` and return a report."""
        start_time = time.perf_counter()

        await self._collect_baseline(agent_fn, get_tool_calls)

        payloads = self.generator.generate(self.context, categories)
        if max_payloads:
            payloads = payloads[:max_payloads]

        findings = await self._run_concurrent(agent_fn, payloads, on_progress, get_tool_calls)
        duration = time.perf_counter() - start_time

        return AttackReport(
            target=self.context.source_file or "agent_fn",
            context=self.context,
            findings=findings,
            total_payloads=len(payloads),
            duration_seconds=round(duration, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    async def _collect_baseline(
        self, agent_fn: Callable, get_tool_calls: Optional[Callable] = None
    ) -> None:
        """Run benign inputs to establish a normal-behavior baseline."""
        baseline_calls: list[str] = []
        for benign_input in self.baseline_inputs:
            try:
                await asyncio.wait_for(agent_fn(benign_input), timeout=self.timeout)
                if get_tool_calls:
                    baseline_calls.extend(get_tool_calls())
            except Exception:  # noqa: BLE001 — baseline failure is non-fatal
                pass
        self.baseline_tool_calls = baseline_calls

    async def _run_concurrent(
        self,
        agent_fn: Callable,
        payloads: list[AttackPayload],
        on_progress: Optional[Callable] = None,
        get_tool_calls: Optional[Callable] = None,
    ) -> list[AttackFinding]:
        """Run payloads with bounded concurrency; report progress in order."""
        semaphore = asyncio.Semaphore(self.concurrency)
        lock = asyncio.Lock()
        findings: list[AttackFinding] = []
        completed = 0
        total = len(payloads)

        async def run_one(payload: AttackPayload) -> None:
            nonlocal completed
            async with semaphore:
                finding = await self._run_single(agent_fn, payload, get_tool_calls)
            async with lock:
                findings.append(finding)
                completed += 1
                if on_progress:
                    on_progress(completed, total, finding)

        await asyncio.gather(*(run_one(p) for p in payloads))
        return findings

    async def _run_single(
        self,
        agent_fn: Callable,
        payload: AttackPayload,
        get_tool_calls: Optional[Callable] = None,
    ) -> AttackFinding:
        """Run one payload, capture the response + tool calls, detect, return a finding."""
        actual_tool_calls: list[str] = []
        try:
            agent_response = await asyncio.wait_for(
                agent_fn(payload.payload), timeout=self.timeout
            )
            if get_tool_calls:
                actual_tool_calls = get_tool_calls()
        except asyncio.TimeoutError:
            agent_response = "[TIMEOUT]"
        except Exception as exc:  # noqa: BLE001 — record, never propagate
            agent_response = f"[ERROR: {type(exc).__name__}: {exc}]"

        result = self.detector.detect(
            payload=payload,
            agent_response=str(agent_response),
            actual_tool_calls=actual_tool_calls,
            baseline_tool_calls=self.baseline_tool_calls,
            context=self.context,
        )
        return self.detector.to_finding(
            payload=payload,
            result=result,
            agent_response=str(agent_response),
            actual_tool_calls=actual_tool_calls,
            baseline_tool_calls=self.baseline_tool_calls,
        )


def attack_suite(
    target: Callable[[str], Awaitable[str]],
    categories: Optional[list[str]] = None,
    fail_on: Optional[str] = None,
    concurrency: int = 3,
    baseline_inputs: Optional[list[str]] = None,
    context: Optional[AgentContext] = None,
) -> AttackReport:
    """Sync convenience wrapper for pytest and scripts.

    Returns the :class:`AttackReport`; the caller asserts on it (``fail_on``
    is accepted for forward-compatibility but not acted on — keeping the
    behavior explicit and free of hidden magic). ``target`` must be an async
    agent function; file/URL targets go through the CLI.
    """
    if not callable(target):
        raise ValueError(
            "attack_suite() accepts async agent functions only. For file or URL "
            "targets, use the CLI: dscan attack <target>."
        )
    resolved = [AttackCategory(c) for c in categories] if categories else None
    runner = AttackRunner(
        context=context or AgentContext(),
        concurrency=concurrency,
        baseline_inputs=baseline_inputs,
    )
    return asyncio.run(runner.run(agent_fn=target, categories=resolved))
