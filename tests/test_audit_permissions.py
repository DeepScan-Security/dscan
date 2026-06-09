"""Tests for dscan.audit.checks.permissions."""

from dscan.audit.checks.permissions import PermissionsCheck
from dscan.audit.models import CheckId, McpServer, McpTool, RiskLevel

SERVER = McpServer(name="s", command="npx", args=["pkg"])


def run(*names):
    tools = [McpTool(name=n, description="") for n in names]
    return PermissionsCheck().check(SERVER, tools)


class TestPositive:
    def test_execute_network(self):
        f = run("execute_code", "send_webhook")
        assert len(f) == 1
        assert f[0].risk_level == RiskLevel.CRITICAL
        assert f[0].check_id == CheckId.OVER_PRIVILEGED

    def test_write_delete_execute(self):
        f = run("write_file", "delete_file", "run_shell")
        assert f and f[0].risk_level == RiskLevel.HIGH

    def test_delete_network(self):
        f = run("delete_record", "post_data")
        assert f and f[0].risk_level == RiskLevel.HIGH

    def test_write_delete(self):
        f = run("write_file", "delete_file")
        assert f and f[0].risk_level == RiskLevel.MEDIUM


class TestNegative:
    def test_read_only(self):
        assert run("search_web", "get_item", "list_files") == []

    def test_empty(self):
        assert PermissionsCheck().check(SERVER, []) == []

    def test_single_write(self):
        assert run("write_file") == []
