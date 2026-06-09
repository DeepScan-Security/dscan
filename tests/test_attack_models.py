"""Tests for dscan.attack.models — enums and dataclasses."""

from dataclasses import fields

from dscan.attack.models import (
    AgentContext,
    AgentTool,
    AttackCategory,
    AttackFinding,
    AttackPayload,
    AttackReport,
    Severity,
)


def _payload(severity):
    return AttackPayload(
        id="PI-001",
        category=AttackCategory.PROMPT_INJECTION,
        name="x",
        description="x",
        payload="x",
        expected_safe_behavior="x",
        success_indicators=["a"],
        failure_indicators=["b"],
        severity=severity,
    )


def _finding(severity, succeeded):
    return AttackFinding(
        payload=_payload(severity),
        succeeded=succeeded,
        confidence=0.9,
        evidence="e",
        agent_response="r",
        tool_calls_made=[],
        baseline_tool_calls=[],
        detection_method="response",
        recommendation="fix it",
    )


def _report(findings):
    return AttackReport(
        target="agent.py",
        context=AgentContext(),
        findings=findings,
        total_payloads=len(findings),
        duration_seconds=1.0,
        timestamp="2026-06-09T00:00:00Z",
    )


class TestEnums:
    def test_attack_category_values(self):
        assert {c.value for c in AttackCategory} == {
            "prompt_injection",
            "jailbreak",
            "tool_misuse",
            "indirect_injection",
            "goal_hijacking",
            "privilege_escalation",
        }

    def test_severity_values(self):
        assert {s.value for s in Severity} == {"critical", "high", "medium", "low"}


class TestAgentContext:
    def _ctx(self):
        return AgentContext(
            tools=[
                AgentTool("read_file", "reads files"),
                AgentTool("delete", "deletes", is_destructive=True),
                AgentTool("send_email", "sends", is_exfiltrating=True),
            ]
        )

    def test_tool_names(self):
        assert self._ctx().tool_names == ["read_file", "delete", "send_email"]

    def test_destructive_tools(self):
        ctx = self._ctx()
        assert [t.name for t in ctx.destructive_tools] == ["delete"]

    def test_exfiltrating_tools(self):
        ctx = self._ctx()
        assert [t.name for t in ctx.exfiltrating_tools] == ["send_email"]

    def test_has_dangerous_tools_true(self):
        assert self._ctx().has_dangerous_tools is True

    def test_has_dangerous_tools_false(self):
        ctx = AgentContext(tools=[AgentTool("read_file", "reads")])
        assert ctx.has_dangerous_tools is False


class TestAttackReport:
    def test_critical_count(self):
        report = _report([
            _finding(Severity.CRITICAL, True),
            _finding(Severity.CRITICAL, False),  # not succeeded -> not counted
            _finding(Severity.HIGH, True),
        ])
        assert report.critical_count == 1

    def test_high_count(self):
        report = _report([
            _finding(Severity.HIGH, True),
            _finding(Severity.HIGH, True),
            _finding(Severity.HIGH, False),
        ])
        assert report.high_count == 2

    def test_passed_false_with_critical(self):
        report = _report([_finding(Severity.CRITICAL, True)])
        assert report.passed is False

    def test_passed_false_with_high(self):
        report = _report([_finding(Severity.HIGH, True)])
        assert report.passed is False

    def test_passed_true_when_clean(self):
        report = _report([
            _finding(Severity.CRITICAL, False),
            _finding(Severity.HIGH, False),
        ])
        assert report.passed is True


class TestNoMutableDefaults:
    def test_default_factories(self):
        # Two fresh instances must not share mutable defaults.
        a, b = AgentContext(), AgentContext()
        a.tools.append(AgentTool("x", "y"))
        assert b.tools == []

        t1, t2 = AgentTool("a", "b"), AgentTool("c", "d")
        t1.parameters["k"] = 1
        assert t2.parameters == {}

    def test_list_fields_use_default_factory(self):
        # No dataclass field should have a mutable default *value*.
        for cls in (AgentTool, AgentContext, AttackPayload):
            for f in fields(cls):
                assert not isinstance(f.default, (list, dict))
