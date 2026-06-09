"""Tests for dscan.attack.report — report formatting."""

import json
from io import StringIO

import pytest
from rich.console import Console

from dscan.attack.models import (
    AgentContext,
    AttackCategory,
    AttackFinding,
    AttackPayload,
    AttackReport,
    Severity,
)
from dscan.attack.report import AttackReporter


def _payload(id, category, severity, name="n"):
    return AttackPayload(
        id=id,
        category=category,
        name=name,
        description="d",
        payload="p",
        expected_safe_behavior="refuse",
        success_indicators=["x"],
        failure_indicators=["y"],
        severity=severity,
    )


def _finding(payload, succeeded, confidence, recommendation=""):
    return AttackFinding(
        payload=payload,
        succeeded=succeeded,
        confidence=confidence,
        evidence=f"evidence for {payload.id}",
        agent_response="agent said something",
        tool_calls_made=[],
        baseline_tool_calls=[],
        detection_method="response",
        recommendation=recommendation,
    )


@pytest.fixture
def report():
    findings = [
        _finding(
            _payload("PI-001", AttackCategory.PROMPT_INJECTION, Severity.CRITICAL, "Classic override"),
            True, 0.95, "Sanitize inputs. Add dscan shield to block injection attempts.",
        ),
        _finding(
            _payload("TM-001", AttackCategory.TOOL_MISUSE, Severity.HIGH, "Email exfil"),
            True, 0.9, "Require user confirmation before send_email.",
        ),
        _finding(
            _payload("II-001", AttackCategory.INDIRECT_INJECTION, Severity.HIGH, "Web inject"),
            True, 0.85, "Sanitize tool results before use.",
        ),
        _finding(_payload("JB-001", AttackCategory.JAILBREAK, Severity.HIGH, "DAN"), False, 0.4),
        _finding(_payload("GH-001", AttackCategory.GOAL_HIJACKING, Severity.MEDIUM, "Drift1"), False, 0.3),
        _finding(_payload("GH-002", AttackCategory.GOAL_HIJACKING, Severity.MEDIUM, "Drift2"), False, 0.3),
        _finding(_payload("GH-003", AttackCategory.GOAL_HIJACKING, Severity.MEDIUM, "Drift3"), False, 0.3),
    ]
    return AttackReport(
        target="agent.py",
        context=AgentContext(),
        findings=findings,
        total_payloads=61,
        duration_seconds=12.3,
        timestamp="2026-06-09T11:00:00Z",
    )


def _reporter(report, width=120):
    buf = StringIO()
    return AttackReporter(report, console=Console(file=buf, width=width)), buf


# ==========================================================================
# Content / data access
# ==========================================================================
class TestContent:
    def test_summary_stats(self, report):
        assert report.critical_count == 1
        assert report.high_count == 2
        assert report.passed is False
        assert len(report.findings) == 7
        assert sum(1 for f in report.findings if f.succeeded) == 3

    def test_findings_by_severity(self, report):
        grouped = AttackReporter(report).findings_by_severity()
        assert len(grouped["critical"]) == 1
        assert len(grouped["high"]) == 3  # 2 succeeded + 1 not
        assert len(grouped["medium"]) == 3
        assert grouped["low"] == []  # present, not KeyError

    def test_findings_by_category(self, report):
        grouped = AttackReporter(report).findings_by_category()
        assert len(grouped["prompt_injection"]) == 1
        assert all(isinstance(k, str) for k in grouped)

    def test_succeeded_findings(self, report):
        succeeded = AttackReporter(report).succeeded_findings()
        assert len(succeeded) == 3
        assert all(f.succeeded for f in succeeded)


# ==========================================================================
# Serialisation
# ==========================================================================
class TestSerialisation:
    def test_to_dict(self, report):
        d = AttackReporter(report).to_dict()
        json.dumps(d)  # must not raise
        assert d["summary"]["critical_count"] == 1
        assert d["summary"]["high_count"] == 2
        assert d["summary"]["passed"] is False
        assert d["summary"]["total_payloads"] == report.total_payloads
        assert d["summary"]["duration_seconds"] == report.duration_seconds
        assert isinstance(d["summary"]["timestamp"], str)
        assert d["target"] == report.target
        assert isinstance(d["findings"], list)
        required = {
            "id", "category", "name", "severity", "succeeded", "confidence",
            "evidence", "recommendation", "tool_calls_made", "detection_method",
        }
        for f in d["findings"]:
            assert required <= set(f)

    def test_to_json_pretty(self, report):
        s = AttackReporter(report).to_json()
        assert json.loads(s) == AttackReporter(report).to_dict()
        assert "\n" in s  # indented

    def test_to_json_compact(self, report):
        s = AttackReporter(report).to_json(indent=None)
        json.loads(s)
        assert "\n" not in s


# ==========================================================================
# Rich console output
# ==========================================================================
class TestConsole:
    def test_print_summary(self, report):
        reporter, buf = _reporter(report)
        reporter.print_summary()
        out = buf.getvalue()
        low = out.lower()
        assert "1" in out and "critical" in low
        assert "2" in out and "high" in low
        assert "fail" in low  # FAILED, not passed
        assert "agent.py" in out

    def test_print_findings(self, report):
        reporter, buf = _reporter(report)
        reporter.print_findings()
        out = buf.getvalue()
        assert "PI-001" in out
        assert "CRITICAL" in out
        assert "95%" in out
        assert out.index("CRITICAL") < out.index("HIGH")

    def test_print_findings_succeeded_only(self, report):
        reporter, buf = _reporter(report)
        reporter.print_findings(succeeded_only=True)
        out = buf.getvalue()
        for id in ("PI-001", "TM-001", "II-001"):
            assert id in out
        for id in ("JB-001", "GH-001", "GH-002", "GH-003"):
            assert id not in out

    def test_print_recommendations(self, report):
        reporter, buf = _reporter(report)
        reporter.print_recommendations()
        out = buf.getvalue()
        assert "Sanitize" in out
        assert "dscan shield" in out  # from the PI recommendation

    def test_print_full_report(self, report):
        reporter, buf = _reporter(report)
        reporter.print_full_report()
        out = buf.getvalue()
        assert "fail" in out.lower()  # summary
        assert "PI-001" in out  # findings table
        assert "dscan shield" in out  # recommendations


# ==========================================================================
# Passed reports
# ==========================================================================
class TestPassed:
    def test_empty_report(self):
        empty = AttackReport(
            target="agent.py", context=AgentContext(), findings=[],
            total_payloads=61, duration_seconds=12.3, timestamp="2026-06-09T11:00:00Z",
        )
        reporter, buf = _reporter(empty)
        reporter.print_summary()
        out = buf.getvalue()
        assert "pass" in out.lower() or "✓" in out
        assert "0 critical" in out.lower()

    def test_print_findings_empty(self):
        empty = AttackReport(
            target="a", context=AgentContext(), findings=[],
            total_payloads=0, duration_seconds=0.1, timestamp="2026-06-09T11:00:00Z",
        )
        reporter, buf = _reporter(empty)
        reporter.print_findings()
        assert "No findings" in buf.getvalue()

    def test_print_recommendations_when_clean(self, report):
        clean = AttackReport(
            target="a", context=AgentContext(),
            findings=[f for f in report.findings if not f.succeeded],
            total_payloads=4, duration_seconds=0.1, timestamp="2026-06-09T11:00:00Z",
        )
        reporter, buf = _reporter(clean)
        reporter.print_recommendations()
        assert "No vulnerabilities" in buf.getvalue()

    def test_findings_but_none_succeeded(self, report):
        clean = AttackReport(
            target="agent.py", context=AgentContext(),
            findings=[f for f in report.findings if not f.succeeded],
            total_payloads=61, duration_seconds=1.0, timestamp="2026-06-09T11:00:00Z",
        )
        assert clean.passed is True
        reporter, buf = _reporter(clean)
        reporter.print_summary()
        assert "pass" in buf.getvalue().lower()


# ==========================================================================
# File output
# ==========================================================================
class TestFileOutput:
    def test_save_json(self, report, tmp_path):
        path = tmp_path / "report.json"
        reporter = AttackReporter(report)
        reporter.save_json(path)
        assert path.exists()
        assert json.loads(path.read_text()) == reporter.to_dict()

    def test_save_json_creates_dirs(self, report, tmp_path):
        path = tmp_path / "reports" / "run1" / "report.json"
        AttackReporter(report).save_json(path)
        assert path.exists()
