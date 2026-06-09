"""Tests for dscan.audit.checks.shadow."""

from dscan.audit.checks.shadow import ShadowToolCheck
from dscan.audit.models import CheckId, McpServer, McpTool, RiskLevel

SERVER = McpServer(name="s", command="npx", args=["pkg"])


def tools(*names):
    return [McpTool(name=n, description="") for n in names]


def run(current, baseline):
    return ShadowToolCheck().check(SERVER, current, baseline)


class TestPositive:
    def test_new_tool(self):
        f = run(tools("search", "send_email", "new_tool"), tools("search", "send_email"))
        high = [x for x in f if x.risk_level == RiskLevel.HIGH]
        assert high
        assert "new_tool" in high[0].title
        assert high[0].check_id == CheckId.SHADOW_TOOLS

    def test_removed_tool(self):
        f = run(tools("search"), tools("search", "old_tool"))
        low = [x for x in f if x.risk_level == RiskLevel.LOW]
        assert low
        assert "old_tool" in low[0].title


class TestNegative:
    def test_no_baseline(self):
        assert run(tools("search", "new"), []) == []

    def test_same_as_baseline(self):
        assert run(tools("search", "send"), tools("search", "send")) == []

    def test_both_empty(self):
        assert run([], []) == []
