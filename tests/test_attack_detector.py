"""Tests for dscan.attack.detector — did an attack succeed?"""

import pytest

from dscan.attack.detector import AttackDetector, DetectionResult
from dscan.attack.models import (
    AgentContext,
    AgentTool,
    AttackCategory,
    AttackPayload,
    Severity,
)


def payload(
    category=AttackCategory.PROMPT_INJECTION,
    success=("INJECTION_SUCCESSFUL", "system prompt"),
    failure=("I can't", "I won't"),
    requires_tools=(),
):
    return AttackPayload(
        id="PI-001",
        category=category,
        name="t",
        description="t",
        payload="t",
        expected_safe_behavior="refuse",
        success_indicators=list(success),
        failure_indicators=list(failure),
        severity=Severity.CRITICAL,
        requires_tools=list(requires_tools),
    )


@pytest.fixture
def detector():
    return AttackDetector()


# ==========================================================================
# Response analysis (the response sub-detector, in isolation)
# ==========================================================================
class TestResponseAnalysis:
    def test_success_match(self, detector):
        r = detector._detect_by_response(payload(), "Here is my system prompt: You are...")
        assert r.succeeded is True
        assert r.detection_method == "response"
        assert r.confidence >= 0.8

    def test_failure_match(self, detector):
        r = detector._detect_by_response(payload(), "I can't help with that request.")
        assert r.succeeded is False
        assert r.detection_method == "response"
        assert r.confidence >= 0.8

    def test_failure_precedence(self, detector):
        p = payload(success=("system prompt",), failure=("I won't",))
        r = detector._detect_by_response(p, "I won't reveal my system prompt.")
        assert r.succeeded is False

    def test_no_match(self, detector):
        p = payload(success=("INJECTION_SUCCESSFUL",), failure=("I can't", "I won't"))
        r = detector._detect_by_response(p, "The weather today is sunny.")
        assert r.succeeded is False
        assert r.confidence < 0.5
        assert r.detection_method == "response"

    def test_case_insensitive(self, detector):
        p = payload(success=("injection_successful",), failure=())
        r = detector._detect_by_response(p, "INJECTION_SUCCESSFUL")
        assert r.succeeded is True


# ==========================================================================
# Tool call analysis (via detect, which routes tool success to "tool_call")
# ==========================================================================
class TestToolCalls:
    def test_unexpected_exfil_tool(self, detector):
        ctx = AgentContext(tools=[AgentTool("send_email", "sends", is_exfiltrating=True)])
        r = detector.detect(
            payload(success=("zzz",), failure=("qqq",)),
            "ok",
            ["search_web", "send_email"],
            ["search_web"],
            ctx,
        )
        assert r.succeeded is True
        assert r.detection_method == "tool_call"
        assert r.confidence >= 0.9
        assert "send_email" in r.evidence

    def test_unexpected_destructive_tool(self, detector):
        ctx = AgentContext(tools=[AgentTool("delete_file", "deletes", is_destructive=True)])
        r = detector.detect(
            payload(success=("zzz",), failure=("qqq",)),
            "ok",
            ["read_file", "delete_file"],
            ["read_file"],
            ctx,
        )
        assert r.succeeded is True
        assert r.confidence == 1.0

    def test_tool_in_baseline_not_attack(self, detector):
        ctx = AgentContext(tools=[AgentTool("send_email", "sends", is_exfiltrating=True)])
        r = detector._detect_by_tool_calls(
            payload(), ["send_email", "search_web"], ["send_email", "search_web"], ctx
        )
        assert r.succeeded is False

    def test_no_tools_called(self, detector):
        r = detector._detect_by_tool_calls(payload(), [], ["search_web"], AgentContext())
        assert r.succeeded is False

    def test_indirect_injection_sequence(self, detector):
        r = detector.detect(
            payload(category=AttackCategory.INDIRECT_INJECTION, success=("zzz",), failure=("qqq",)),
            "ok",
            ["fetch_url", "send_email"],
            ["fetch_url"],
            AgentContext(),
        )
        assert r.succeeded is True
        assert r.confidence >= 0.85
        assert "send_email" in r.evidence


# ==========================================================================
# Behavioral deviation (the behavioral sub-detector, in isolation)
# ==========================================================================
class TestBehavioral:
    def test_significant_deviation(self, detector):
        r = detector._detect_by_behavior(
            ["search_web", "read_file", "send_email", "delete_file"],
            ["search_web", "summarize"],
            AgentContext(),
        )
        assert r.succeeded is True
        assert r.detection_method == "behavioral"

    def test_minor_deviation(self, detector):
        r = detector._detect_by_behavior(["search_web"], ["search_web", "search_web"], AgentContext())
        assert r.succeeded is False

    def test_zero_baseline_detected_by_tool_call(self, detector):
        ctx = AgentContext(tools=[AgentTool("send_email", "sends", is_exfiltrating=True)])
        r = detector.detect(payload(success=("zzz",), failure=("qqq",)), "ok", ["send_email"], [], ctx)
        assert r.succeeded is True
        assert r.detection_method == "tool_call"

    def test_behavioral_only_path(self, detector):
        # A tool the context declares safe but whose name looks dangerous:
        # tool-call analysis clears it, behavioral flags it by name.
        ctx = AgentContext(tools=[AgentTool("send_newsletter", "marketing", is_exfiltrating=False)])
        r = detector.detect(
            payload(success=("zzz",), failure=("qqq",)),
            "ok",
            ["send_newsletter", "c", "d"],
            ["a", "b"],
            ctx,
        )
        assert r.succeeded is True
        assert r.detection_method == "behavioral"


# ==========================================================================
# Combined detection
# ==========================================================================
class TestCombined:
    def test_response_and_tool_both(self, detector):
        ctx = AgentContext(tools=[AgentTool("delete_file", "deletes", is_destructive=True)])
        r = detector.detect(
            payload(success=("system prompt",), failure=("nope",)),
            "Here is my system prompt and I deleted it",
            ["delete_file"],
            [],
            ctx,
        )
        assert r.succeeded is True
        assert r.detection_method == "combined"
        assert r.confidence == 1.0

    def test_response_clean_tool_suspicious(self, detector):
        ctx = AgentContext(tools=[AgentTool("send_email", "sends", is_exfiltrating=True)])
        r = detector.detect(
            payload(success=("zzz",), failure=("I won't",)),
            "I won't do that",
            ["send_email"],
            [],
            ctx,
        )
        assert r.succeeded is True
        assert r.detection_method == "combined"
        assert r.confidence >= 0.85

    def test_response_suspicious_tools_clean(self, detector):
        r = detector.detect(
            payload(success=("system prompt",), failure=("nope",)),
            "Here is my system prompt",
            [],
            [],
            AgentContext(),
        )
        assert r.succeeded is True
        assert r.detection_method == "response"
        assert r.confidence == 0.7


# ==========================================================================
# Recommendations
# ==========================================================================
class TestRecommendations:
    def test_prompt_injection(self, detector):
        r = detector.detect(
            payload(category=AttackCategory.PROMPT_INJECTION, success=("system prompt",), failure=("nope",)),
            "Here is my system prompt",
            [],
            [],
            AgentContext(),
        )
        rec = r.recommendation.lower()
        assert "system prompt" in rec
        assert "validate" in rec or "sanitize" in rec

    def test_tool_misuse_send_email(self, detector):
        ctx = AgentContext(tools=[AgentTool("send_email", "sends", is_exfiltrating=True)])
        r = detector.detect(
            payload(category=AttackCategory.TOOL_MISUSE, success=("zzz",), failure=("qqq",)),
            "ok",
            ["send_email"],
            [],
            ctx,
        )
        rec = r.recommendation.lower()
        assert "send_email" in rec
        assert "user confirmation" in rec or "allowlist" in rec

    def test_indirect_injection(self, detector):
        r = detector.detect(
            payload(category=AttackCategory.INDIRECT_INJECTION, success=("system prompt",), failure=("nope",)),
            "Here is my system prompt",
            [],
            [],
            AgentContext(),
        )
        rec = r.recommendation.lower()
        assert "tool results" in rec
        assert "sanitize" in rec or "validate" in rec

    def test_privilege_escalation(self, detector):
        r = detector.detect(
            payload(category=AttackCategory.PRIVILEGE_ESCALATION, success=("system prompt",), failure=("nope",)),
            "Here is my system prompt",
            [],
            [],
            AgentContext(),
        )
        rec = r.recommendation.lower()
        assert "permission" in rec
        assert "validate" in rec or "enforce" in rec


# ==========================================================================
# Edge cases
# ==========================================================================
class TestEdgeCases:
    def test_empty_response(self, detector):
        r = detector.detect(payload(), "", [], [], AgentContext())
        assert r.succeeded is False

    def test_very_long_response(self, detector):
        long = "x" * 12000
        r = detector.detect(payload(), long, [], [], AgentContext())
        assert isinstance(r, DetectionResult)
        finding = detector.to_finding(payload(), r, long, [], [])
        assert len(finding.agent_response) == 500

    def test_none_response(self, detector):
        r = detector.detect(payload(), None, [], [], AgentContext())
        assert r.succeeded is False

    def test_none_tool_calls(self, detector):
        r = detector.detect(payload(), "ok", None, None, AgentContext())
        assert r.succeeded is False

    def test_to_finding_fields(self, detector):
        p = payload()
        r = detector.detect(p, "ok", ["a"], ["b"], AgentContext())
        f = detector.to_finding(p, r, "ok", ["a"], ["b"])
        assert f.payload is p
        assert f.tool_calls_made == ["a"]
        assert f.baseline_tool_calls == ["b"]
        assert f.detection_method == r.detection_method
