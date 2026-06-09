"""Data structures for dscan attack — the adversarial testing suite.

Defines the enums and dataclasses shared across the attack package: the
attack taxonomy (:class:`AttackCategory`, :class:`Severity`), what dscan
knows about a target (:class:`AgentTool`, :class:`AgentContext`), a single
adversarial test (:class:`AttackPayload`), and the results of running them
(:class:`AttackFinding`, :class:`AttackReport`). Pure data — no runner,
detector, or I/O lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "AttackCategory",
    "Severity",
    "AgentTool",
    "AgentContext",
    "AttackPayload",
    "AttackFinding",
    "AttackReport",
]


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    TOOL_MISUSE = "tool_misuse"
    INDIRECT_INJECTION = "indirect_injection"
    GOAL_HIJACKING = "goal_hijacking"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AgentTool:
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    is_destructive: bool = False  # delete/modify/write operations
    is_exfiltrating: bool = False  # send/post/email/upload operations


@dataclass
class AgentContext:
    """Everything dscan knows about the target agent."""

    tools: list[AgentTool] = field(default_factory=list)
    system_prompt: str = ""
    goal: str = ""
    framework: str = ""  # anthropic | langchain | crewai | openai | mcp | unknown
    source_file: str = ""
    entry_function: str = ""

    @property
    def tool_names(self) -> list[str]:
        return [t.name for t in self.tools]

    @property
    def destructive_tools(self) -> list[AgentTool]:
        return [t for t in self.tools if t.is_destructive]

    @property
    def exfiltrating_tools(self) -> list[AgentTool]:
        return [t for t in self.tools if t.is_exfiltrating]

    @property
    def has_dangerous_tools(self) -> bool:
        return bool(self.destructive_tools or self.exfiltrating_tools)


@dataclass
class AttackPayload:
    id: str  # "PI-001", "JB-003", etc.
    category: AttackCategory
    name: str
    description: str
    payload: str
    expected_safe_behavior: str
    success_indicators: list[str]  # substrings in response => attack succeeded
    failure_indicators: list[str]  # substrings in response => agent resisted
    severity: Severity
    requires_tools: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class AttackFinding:
    payload: AttackPayload
    succeeded: bool
    confidence: float  # 0.0-1.0
    evidence: str
    agent_response: str  # raw response (truncated 500 chars)
    tool_calls_made: list[str]
    baseline_tool_calls: list[str]
    detection_method: str  # tool_call | response | behavioral | combined
    recommendation: str


@dataclass
class AttackReport:
    target: str
    context: AgentContext
    findings: list[AttackFinding]
    total_payloads: int
    duration_seconds: float
    timestamp: str  # ISO8601

    @property
    def critical_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if f.succeeded and f.payload.severity == Severity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1
            for f in self.findings
            if f.succeeded and f.payload.severity == Severity.HIGH
        )

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0
