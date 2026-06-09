"""Tests for dscan.audit.checks.versioning."""

from dscan.audit.checks.versioning import VersioningCheck
from dscan.audit.models import CheckId, McpServer, RiskLevel


def run(**kw):
    return VersioningCheck().check(McpServer(**kw))


def levels(findings, check=CheckId.NO_VERSION_PIN):
    return [f.risk_level for f in findings if f.check_id == check]


class TestPositive:
    def test_unpinned_unofficial(self):
        f = run(name="s", command="npx", args=["some-mcp-server"])
        assert RiskLevel.HIGH in levels(f)

    def test_unpinned_official(self):
        f = run(name="s", command="npx", args=["@modelcontextprotocol/server-fs"])
        assert RiskLevel.MEDIUM in levels(f)
        assert RiskLevel.HIGH not in levels(f)

    def test_auto_accept_flag(self):
        f = run(name="s", command="npx", args=["-y", "@modelcontextprotocol/server-fs"])
        assert any(
            x.risk_level == RiskLevel.LOW and "-y" in x.title for x in f
        )


class TestNegative:
    def test_pinned(self):
        assert run(name="s", command="npx", args=["@pkg/server@1.2.3"]) == []

    def test_non_npm(self):
        assert run(name="s", command="python", args=["server.py"]) == []

    def test_no_package(self):
        assert run(name="s", command="npx", args=[]) == []
