"""dscan attack payload library.

Aggregates the six category payload lists into :data:`ALL_PAYLOADS` and
provides filtering helpers used by the generator: by category, by
severity, and by an agent's available tools.
"""

from __future__ import annotations

from ..models import AgentContext, AttackCategory, AttackPayload, Severity
from .goal_hijacking import GOAL_HIJACKING_PAYLOADS
from .indirect_injection import INDIRECT_INJECTION_PAYLOADS
from .jailbreak import JAILBREAK_PAYLOADS
from .privilege_escalation import PRIVILEGE_ESCALATION_PAYLOADS
from .prompt_injection import PROMPT_INJECTION_PAYLOADS
from .tool_misuse import TOOL_MISUSE_PAYLOADS

__all__ = [
    "PROMPT_INJECTION_PAYLOADS",
    "JAILBREAK_PAYLOADS",
    "TOOL_MISUSE_PAYLOADS",
    "INDIRECT_INJECTION_PAYLOADS",
    "GOAL_HIJACKING_PAYLOADS",
    "PRIVILEGE_ESCALATION_PAYLOADS",
    "ALL_PAYLOADS",
    "get_payloads_by_category",
    "get_payloads_by_severity",
    "get_payloads_for_context",
]

ALL_PAYLOADS: list[AttackPayload] = (
    PROMPT_INJECTION_PAYLOADS
    + JAILBREAK_PAYLOADS
    + TOOL_MISUSE_PAYLOADS
    + INDIRECT_INJECTION_PAYLOADS
    + GOAL_HIJACKING_PAYLOADS
    + PRIVILEGE_ESCALATION_PAYLOADS
)


def get_payloads_by_category(category: AttackCategory) -> list[AttackPayload]:
    """All payloads in a given attack category."""
    return [p for p in ALL_PAYLOADS if p.category == category]


def get_payloads_by_severity(severity: Severity) -> list[AttackPayload]:
    """All payloads of a given severity."""
    return [p for p in ALL_PAYLOADS if p.severity == severity]


def get_payloads_for_context(context: AgentContext) -> list[AttackPayload]:
    """Payloads relevant to this agent.

    Payloads with ``requires_tools == []`` always apply. Payloads with
    tool requirements apply only if the agent has at least one matching
    tool.
    """
    tool_set = set(context.tool_names)
    relevant: list[AttackPayload] = []
    for payload in ALL_PAYLOADS:
        if not payload.requires_tools:
            relevant.append(payload)
        elif any(tool in tool_set for tool in payload.requires_tools):
            relevant.append(payload)
    return relevant
