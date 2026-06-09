"""Tests for dscan.audit.scanner."""

import json
from datetime import datetime

import pytest

from dscan.audit.models import (
    AuditFinding,
    AuditReport,
    CheckId,
    McpServer,
    McpTool,
    RiskLevel,
)
from dscan.audit.scanner import AuditScanner


@pytest.fixture(autouse=True)
def audit_dir(monkeypatch, tmp_path):
    # Isolate baseline storage from the real home directory.
    monkeypatch.setenv("DSCAN_AUDIT_DIR", str(tmp_path / "baselines"))


@pytest.fixture
def scanner():
    return AuditScanner()


def _finding(score, check=CheckId.NO_VERSION_PIN, level=RiskLevel.LOW, cve=""):
    return AuditFinding(
        check_id=check, risk_level=level, server_name="s", title="t", detail="d",
        recommendation="r", score_contribution=score, cve_id=cve,
    )


def write_config(tmp_path, servers, name="mcp.json"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


class TestParseConfig:
    def test_parses_servers(self, scanner, tmp_path):
        path = write_config(tmp_path, {
            "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-fs"], "env": {"A": "1"}},
            "web": {"command": "npx", "args": ["server-x"]},  # no env key
        })
        servers = scanner.parse_mcp_config(str(path))
        assert {s.name for s in servers} == {"fs", "web"}
        fs = next(s for s in servers if s.name == "fs")
        assert fs.command == "npx" and fs.env == {"A": "1"}
        web = next(s for s in servers if s.name == "web")
        assert web.env == {}  # missing env handled

    def test_missing_file(self, scanner):
        with pytest.raises(FileNotFoundError):
            scanner.parse_mcp_config("/no/such/mcp.json")


class TestScore:
    def test_empty(self, scanner):
        assert scanner.calculate_score([]) == (0, RiskLevel.LOW)

    def test_low(self, scanner):
        score, level = scanner.calculate_score([_finding(15)])
        assert score == 15 and level == RiskLevel.LOW

    def test_medium(self, scanner):
        _, level = scanner.calculate_score([_finding(25)])
        assert level == RiskLevel.MEDIUM

    def test_high(self, scanner):
        _, level = scanner.calculate_score([_finding(50)])
        assert level == RiskLevel.HIGH

    def test_cve_critical(self, scanner):
        score, level = scanner.calculate_score([_finding(50, check=CheckId.KNOWN_CVE, level=RiskLevel.CRITICAL, cve="CVE-x")])
        assert score >= 71 and level == RiskLevel.CRITICAL

    def test_capped_at_100(self, scanner):
        score, _ = scanner.calculate_score([_finding(60), _finding(60), _finding(60)])
        assert score == 100


class TestBaseline:
    def test_save_and_load(self, scanner):
        server = McpServer(name="srv", command="npx", args=["pkg"])
        tools = [McpTool("search", "Search"), McpTool("send", "Send")]
        scanner.save_baseline(server, tools)
        loaded = scanner.load_baseline(server)
        assert {t.name for t in loaded} == {"search", "send"}

    def test_load_missing(self, scanner):
        assert scanner.load_baseline(McpServer(name="nope", command="npx")) == []


class TestAuditServer:
    def test_full_pipeline(self, scanner):
        server = McpServer(name="s", command="npx", args=["some-mcp-server"])
        audit = scanner.audit_server(server, tools=[], save_baseline=False)
        assert audit.server is server
        assert any(f.check_id == CheckId.NO_VERSION_PIN for f in audit.findings)
        assert audit.risk_score > 0


class TestAuditConfig:
    def test_two_servers(self, scanner, tmp_path):
        path = write_config(tmp_path, {
            "a": {"command": "npx", "args": ["some-mcp-server"]},
            "b": {"command": "npx", "args": ["@modelcontextprotocol/server-fs"]},
        })
        report = scanner.audit_config(str(path))
        assert isinstance(report, AuditReport)
        assert len(report.servers) == 2
        assert str(path) in report.source_files
        datetime.fromisoformat(report.timestamp)  # valid ISO8601


class TestAuditDirectory:
    def test_finds_cursor_config(self, scanner, tmp_path):
        write_config(tmp_path, {"a": {"command": "npx", "args": ["x"]}}, name=".cursor/mcp.json")
        report = scanner.audit_directory(str(tmp_path))
        assert isinstance(report, AuditReport)

    def test_none_when_no_config(self, scanner, tmp_path):
        assert scanner.audit_directory(str(tmp_path)) is None
