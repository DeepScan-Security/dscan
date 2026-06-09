"""Tests for the dscan.attack payload library."""

import re

import pytest

from dscan.attack.models import AgentContext, AgentTool, AttackCategory, Severity
from dscan.attack.payloads import (
    ALL_PAYLOADS,
    GOAL_HIJACKING_PAYLOADS,
    INDIRECT_INJECTION_PAYLOADS,
    JAILBREAK_PAYLOADS,
    PRIVILEGE_ESCALATION_PAYLOADS,
    PROMPT_INJECTION_PAYLOADS,
    TOOL_MISUSE_PAYLOADS,
    get_payloads_by_category,
    get_payloads_by_severity,
    get_payloads_for_context,
)

_ID_RE = re.compile(r"^[A-Z]{2}-\d{3}$")


class TestCounts:
    def test_counts(self):
        assert len(PROMPT_INJECTION_PAYLOADS) == 15
        assert len(JAILBREAK_PAYLOADS) == 10
        assert len(TOOL_MISUSE_PAYLOADS) == 10
        assert len(INDIRECT_INJECTION_PAYLOADS) == 10
        assert len(GOAL_HIJACKING_PAYLOADS) == 8
        assert len(PRIVILEGE_ESCALATION_PAYLOADS) == 8

    def test_total(self):
        assert len(ALL_PAYLOADS) == 61


class TestIds:
    def test_id_format(self):
        for p in ALL_PAYLOADS:
            assert _ID_RE.match(p.id), f"bad id: {p.id}"

    def test_ids_unique(self):
        ids = [p.id for p in ALL_PAYLOADS]
        assert len(ids) == len(set(ids))


class TestRequiredFields:
    @pytest.mark.parametrize("p", ALL_PAYLOADS, ids=lambda p: p.id)
    def test_non_empty_fields(self, p):
        assert p.id and p.name and p.description and p.payload
        assert p.expected_safe_behavior
        assert len(p.success_indicators) >= 1
        assert len(p.failure_indicators) >= 1
        assert isinstance(p.severity, Severity)


class TestCategoryConsistency:
    @pytest.mark.parametrize(
        "payloads,category",
        [
            (PROMPT_INJECTION_PAYLOADS, AttackCategory.PROMPT_INJECTION),
            (JAILBREAK_PAYLOADS, AttackCategory.JAILBREAK),
            (TOOL_MISUSE_PAYLOADS, AttackCategory.TOOL_MISUSE),
            (INDIRECT_INJECTION_PAYLOADS, AttackCategory.INDIRECT_INJECTION),
            (GOAL_HIJACKING_PAYLOADS, AttackCategory.GOAL_HIJACKING),
            (PRIVILEGE_ESCALATION_PAYLOADS, AttackCategory.PRIVILEGE_ESCALATION),
        ],
    )
    def test_category_matches(self, payloads, category):
        assert all(p.category == category for p in payloads)


class TestFiltering:
    def test_by_category(self):
        assert len(get_payloads_by_category(AttackCategory.JAILBREAK)) == 10

    def test_by_severity(self):
        crit = get_payloads_by_severity(Severity.CRITICAL)
        assert crit
        assert all(p.severity == Severity.CRITICAL for p in crit)

    def test_context_with_no_tools(self):
        result = get_payloads_for_context(AgentContext())
        assert result
        assert all(p.requires_tools == [] for p in result)

    def test_context_with_send_email(self):
        ctx = AgentContext(tools=[AgentTool("send_email", "sends mail", is_exfiltrating=True)])
        result = get_payloads_for_context(ctx)
        # Includes the no-tool payloads...
        assert any(p.requires_tools == [] for p in result)
        # ...and the ones that require send_email.
        assert any("send_email" in p.requires_tools for p in result)
        # But not payloads requiring tools the agent lacks.
        assert all(
            not p.requires_tools or "send_email" in p.requires_tools
            for p in result
        )
