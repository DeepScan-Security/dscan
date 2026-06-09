"""Tests for dscan.audit.models."""

from dscan.audit.models import (
    AuditFinding,
    AuditReport,
    CheckId,
    McpServer,
    McpTool,
    RiskLevel,
    ServerAudit,
)


def _finding(level):
    return AuditFinding(
        check_id=CheckId.OVER_PRIVILEGED, risk_level=level, server_name="s",
        title="t", detail="d", recommendation="r", score_contribution=10,
    )


def _server(name="s"):
    return McpServer(name=name, command="npx", args=["x"])


def _audit(level, findings=()):
    return ServerAudit(server=_server(), findings=list(findings), risk_level=level)


class TestMcpServer:
    def test_package_name_scoped(self):
        s = McpServer(name="fs", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem"])
        assert s.package_name == "@modelcontextprotocol/server-filesystem"

    def test_package_name_plain(self):
        s = McpServer(name="b", command="npx", args=["server-brave-search"])
        assert s.package_name == "server-brave-search"

    def test_is_pinned_true(self):
        s = McpServer(name="fs", command="npx", args=["@modelcontextprotocol/server-fs@1.2.3"])
        assert s.is_pinned is True

    def test_is_pinned_false(self):
        s = McpServer(name="fs", command="npx", args=["@modelcontextprotocol/server-fs"])
        assert s.is_pinned is False

    def test_is_http_true(self):
        assert McpServer(name="h", command="", url="http://x/mcp").is_http is True

    def test_is_http_false(self):
        assert McpServer(name="h", command="npx").is_http is False


class TestServerAudit:
    def test_passed_when_low(self):
        assert _audit(RiskLevel.LOW).passed is True

    def test_not_passed_when_high(self):
        assert _audit(RiskLevel.HIGH).passed is False

    def test_critical_findings(self):
        a = _audit(RiskLevel.CRITICAL, [_finding(RiskLevel.CRITICAL), _finding(RiskLevel.HIGH)])
        assert len(a.critical_findings) == 1

    def test_high_findings(self):
        a = _audit(RiskLevel.HIGH, [_finding(RiskLevel.HIGH), _finding(RiskLevel.HIGH), _finding(RiskLevel.LOW)])
        assert len(a.high_findings) == 2


class TestAuditReport:
    def _report(self, levels):
        servers = [_audit(lvl) for lvl in levels]
        return AuditReport(servers=servers, source_files=["mcp.json"], timestamp="2026-06-09T00:00:00Z")

    def test_critical_servers(self):
        r = self._report([RiskLevel.CRITICAL, RiskLevel.LOW, RiskLevel.CRITICAL])
        assert len(r.critical_servers) == 2

    def test_high_servers(self):
        r = self._report([RiskLevel.HIGH, RiskLevel.MEDIUM])
        assert len(r.high_servers) == 1

    def test_passed_false_with_critical(self):
        assert self._report([RiskLevel.CRITICAL, RiskLevel.LOW]).passed is False

    def test_passed_true_when_low_medium(self):
        assert self._report([RiskLevel.LOW, RiskLevel.MEDIUM]).passed is True

    def test_total_findings(self):
        a1 = _audit(RiskLevel.HIGH, [_finding(RiskLevel.HIGH), _finding(RiskLevel.LOW)])
        a2 = _audit(RiskLevel.MEDIUM, [_finding(RiskLevel.MEDIUM)])
        r = AuditReport(servers=[a1, a2], source_files=["m"], timestamp="t")
        assert r.total_findings == 3
