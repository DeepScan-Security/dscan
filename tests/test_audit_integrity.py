"""Tests for dscan.audit.checks.integrity."""

from dscan.audit.checks.integrity import IntegrityCheck
from dscan.audit.models import CheckId, McpServer, RiskLevel


def run(args):
    return IntegrityCheck().check(McpServer(name="s", command="npx", args=args))


class TestPositive:
    def test_inspector_cve(self):
        f = run(["@modelcontextprotocol/inspector"])
        cve = [x for x in f if x.check_id == CheckId.KNOWN_CVE]
        assert cve and cve[0].cve_id == "CVE-2025-6514"
        assert cve[0].risk_level == RiskLevel.CRITICAL

    def test_figma_cve(self):
        f = run(["figma-mcp"])
        cve = [x for x in f if x.check_id == CheckId.KNOWN_CVE]
        assert cve and cve[0].cve_id == "CVE-2025-53967"

    def test_unscoped_unverified(self):
        f = run(["some-mcp-server"])
        assert any(x.check_id == CheckId.UNVERIFIED_SOURCE and x.risk_level == RiskLevel.HIGH for x in f)


class TestNegative:
    def test_official_scoped_no_cve(self):
        f = run(["@modelcontextprotocol/server-fs"])
        assert not [x for x in f if x.check_id == CheckId.KNOWN_CVE]
        assert not [x for x in f if x.check_id == CheckId.UNVERIFIED_SOURCE]

    def test_scoped_unofficial_no_unverified(self):
        f = run(["@myorg/my-server"])
        assert not [x for x in f if x.check_id == CheckId.UNVERIFIED_SOURCE]

    def test_python_server(self):
        assert IntegrityCheck().check(McpServer(name="s", command="python", args=["x.py"])) == []
