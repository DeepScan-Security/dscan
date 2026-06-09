"""Tests for the ``dscan audit`` CLI command.

AuditScanner is mocked at the boundary (except the not-found test, which
exercises the real FileNotFoundError path).
"""

import json

import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock

import dscan.cli
from dscan.cli import main
from dscan.audit.models import (
    AuditFinding,
    AuditReport,
    CheckId,
    McpServer,
    RiskLevel,
    ServerAudit,
)


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("DSCAN_AUDIT_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("COLUMNS", "200")


def _server_audit(name, level, findings=()):
    return ServerAudit(
        server=McpServer(name=name, command="npx", args=["pkg"]),
        findings=list(findings),
        risk_level=level,
        risk_score={"low": 5, "medium": 25, "high": 50, "critical": 90}[level.value],
    )


def _finding(level, check=CheckId.KNOWN_CVE, cve="CVE-x"):
    return AuditFinding(
        check_id=check, risk_level=level, server_name="s", title=f"{check.value} finding",
        detail="d", recommendation="fix", score_contribution=20, cve_id=cve,
    )


def make_report(servers, source="mcp.json"):
    return AuditReport(servers=list(servers), source_files=[source], timestamp="2026-06-09T11:00:00Z")


_UNSET = object()


def patch_scanner(monkeypatch, *, directory=_UNSET, config=_UNSET):
    instance = MagicMock()
    if directory is not _UNSET:
        instance.audit_directory = MagicMock(return_value=directory)
    if config is not _UNSET:
        instance.audit_config = MagicMock(return_value=config)
    cls = MagicMock(return_value=instance)
    monkeypatch.setattr(dscan.cli, "AuditScanner", cls)
    return cls, instance


def run(args):
    return CliRunner().invoke(main, args)


class TestBasic:
    def test_no_args_auto_discover(self, monkeypatch):
        report = make_report([_server_audit("filesystem", RiskLevel.LOW), _server_audit("search", RiskLevel.LOW)])
        patch_scanner(monkeypatch, directory=report)
        result = run(["audit"])
        assert result.exit_code == 0
        assert "PASSED" in result.output
        assert "filesystem" in result.output and "search" in result.output

    def test_config_file_high(self, monkeypatch):
        report = make_report([_server_audit("srv", RiskLevel.HIGH, [_finding(RiskLevel.HIGH, CheckId.UNVERIFIED_SOURCE, "")])])
        patch_scanner(monkeypatch, config=report)
        result = run(["audit", ".cursor/mcp.json"])
        assert result.exit_code == 1
        assert "FAILED" in result.output
        assert "HIGH" in result.output

    def test_nonexistent_config(self):
        result = run(["audit", "nonexistent_config_xyz.json"])
        assert result.exit_code == 2
        assert "not found" in result.output.lower()

    def test_directory_no_config(self, monkeypatch):
        patch_scanner(monkeypatch, directory=None)
        result = run(["audit", "."])
        assert result.exit_code == 2
        assert "No MCP config found" in result.output


class TestFailOn:
    def test_fail_on_critical_with_high(self, monkeypatch):
        report = make_report([_server_audit("srv", RiskLevel.HIGH)])
        patch_scanner(monkeypatch, config=report)
        result = run(["audit", ".cursor/mcp.json", "--fail-on", "critical"])
        assert result.exit_code == 0

    def test_fail_on_medium(self, monkeypatch):
        report = make_report([_server_audit("srv", RiskLevel.MEDIUM)])
        patch_scanner(monkeypatch, config=report)
        result = run(["audit", ".cursor/mcp.json", "--fail-on", "medium"])
        assert result.exit_code == 1


class TestOutput:
    def test_ci_mode(self, monkeypatch):
        report = make_report([_server_audit("srv", RiskLevel.CRITICAL, [_finding(RiskLevel.CRITICAL)])])
        patch_scanner(monkeypatch, config=report)
        result = run(["audit", ".cursor/mcp.json", "--ci"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["passed"] is False
        assert data["servers"][0]["name"] == "srv"
        assert data["servers"][0]["findings"][0]["cve_id"] == "CVE-x"

    def test_output_file(self, monkeypatch, tmp_path):
        report = make_report([_server_audit("srv", RiskLevel.LOW)])
        patch_scanner(monkeypatch, config=report)
        out = tmp_path / "report.json"
        run(["audit", ".cursor/mcp.json", "--output", str(out)])
        assert out.exists()
        assert json.loads(out.read_text())["servers"][0]["name"] == "srv"

    def test_auto_save(self, monkeypatch, tmp_path):
        report = make_report([_server_audit("srv", RiskLevel.LOW)])
        patch_scanner(monkeypatch, config=report)
        run(["audit", ".cursor/mcp.json"])
        assert list((tmp_path / "reports").glob("*.json"))

    def test_server_filter(self, monkeypatch):
        report = make_report([
            _server_audit("filesystem", RiskLevel.LOW),
            _server_audit("inspector", RiskLevel.CRITICAL, [_finding(RiskLevel.CRITICAL)]),
        ])
        patch_scanner(monkeypatch, config=report)
        result = run(["audit", ".cursor/mcp.json", "--server", "filesystem"])
        assert "filesystem" in result.output
        assert "inspector" not in result.output
