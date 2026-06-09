"""Payload generation for dscan attack.

:class:`PayloadGenerator` selects and orders payloads from the static
library for a given :class:`~dscan.attack.models.AgentContext`.
:class:`LLMPayloadGenerator` is a v2 extension point that will generate
agent-specific payloads; for now it raises ``NotImplementedError``.
"""

from __future__ import annotations

from .models import AgentContext, AttackCategory, AttackPayload, Severity
from .payloads import ALL_PAYLOADS, get_payloads_for_context

__all__ = ["PayloadGenerator", "LLMPayloadGenerator"]

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class PayloadGenerator:
    """Base payload generator — uses the static payload library.

    Extension point for LLM-enhanced generation in v2.
    """

    def generate(
        self,
        context: AgentContext | None = None,
        categories: list[AttackCategory] | None = None,
    ) -> list[AttackPayload]:
        """Return payloads filtered and ordered for this context.

        With no context, every payload is returned (unfiltered). With a
        context, payloads are filtered to those relevant to the agent's
        tools. Ordering is CRITICAL first, then by relevance to the
        agent's tools.
        """
        if context is None:
            payloads = list(ALL_PAYLOADS)
        else:
            payloads = get_payloads_for_context(context)
        if categories:
            payloads = [p for p in payloads if p.category in categories]
        return self._prioritise(payloads, context)

    def _prioritise(
        self,
        payloads: list[AttackPayload],
        context: AgentContext | None,
    ) -> list[AttackPayload]:
        """Sort by severity (CRITICAL first), then tool relevance."""
        tool_set = set(context.tool_names) if context is not None else set()

        def relevance(payload: AttackPayload) -> int:
            # 0 = targets a tool the agent has (sorts first within a tier).
            if payload.requires_tools and any(t in tool_set for t in payload.requires_tools):
                return 0
            return 1

        return sorted(
            payloads,
            key=lambda p: (_SEVERITY_RANK.get(p.severity, 9), relevance(p)),
        )

    # Extension point — overridden in LLMPayloadGenerator.
    def generate_contextual(self, context: AgentContext) -> list[AttackPayload]:
        """v1: no contextual generation yet (returns an empty list)."""
        return []


class LLMPayloadGenerator(PayloadGenerator):
    """Stub for v2 LLM-enhanced generation."""

    def generate_contextual(self, context: AgentContext) -> list[AttackPayload]:
        raise NotImplementedError(
            "LLM-enhanced payload generation requires dscan attack --enhanced. "
            "Coming in v2. See https://deepscan.security/attack"
        )
