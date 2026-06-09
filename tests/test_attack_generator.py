"""Tests for dscan.attack.generator."""

import pytest

from dscan.attack.generator import LLMPayloadGenerator, PayloadGenerator
from dscan.attack.models import AgentContext, AgentTool, AttackCategory, Severity

_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


class TestGenerate:
    def test_no_context_returns_all(self):
        assert len(PayloadGenerator().generate()) == 61

    def test_category_filter(self):
        result = PayloadGenerator().generate(categories=[AttackCategory.JAILBREAK])
        assert result
        assert all(p.category == AttackCategory.JAILBREAK for p in result)

    def test_ordered_by_severity(self):
        result = PayloadGenerator().generate()
        ranks = [_RANK[p.severity] for p in result]
        assert ranks == sorted(ranks)  # CRITICAL before HIGH before ...

    def test_context_with_send_email_includes_tool_misuse(self):
        ctx = AgentContext(tools=[AgentTool("send_email", "sends", is_exfiltrating=True)])
        result = PayloadGenerator().generate(context=ctx)
        assert any(
            p.category == AttackCategory.TOOL_MISUSE and "send_email" in p.requires_tools
            for p in result
        )

    def test_context_with_no_tools_excludes_tool_requiring(self):
        result = PayloadGenerator().generate(context=AgentContext())
        assert result
        assert all(p.requires_tools == [] for p in result)

    def test_tool_relevant_payloads_sort_first_within_tier(self):
        # Within the CRITICAL tier, payloads matching the agent's tools
        # should come before equally-severe payloads that don't.
        ctx = AgentContext(tools=[AgentTool("send_email", "sends", is_exfiltrating=True)])
        result = PayloadGenerator().generate(context=ctx)
        criticals = [p for p in result if p.severity == Severity.CRITICAL]
        tool_relevant = [bool(p.requires_tools) for p in criticals]
        # Once we see a non-tool critical, no tool-requiring critical follows.
        seen_non_tool = False
        for is_tool in tool_relevant:
            if not is_tool:
                seen_non_tool = True
            elif seen_non_tool:
                pytest.fail("tool-relevant payload sorted after a non-tool one")


class TestContextualStub:
    def test_base_returns_empty(self):
        assert PayloadGenerator().generate_contextual(AgentContext()) == []

    def test_llm_generator_raises(self):
        with pytest.raises(NotImplementedError) as exc:
            LLMPayloadGenerator().generate_contextual(AgentContext())
        assert "deepscan.security/attack" in str(exc.value)
