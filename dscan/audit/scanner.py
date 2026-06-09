"""AuditScanner — the MCP supply-chain audit engine.

Parses MCP config files into :class:`~dscan.audit.models.McpServer`
objects, runs the five checks (poisoning, permissions, versioning,
integrity, shadow) against each, scores the result, and assembles an
:class:`~dscan.audit.models.AuditReport`. Tool baselines (for shadow-tool
detection) are persisted under ``~/.dscan/audit/baselines`` (override with
``DSCAN_AUDIT_DIR``).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .checks.integrity import IntegrityCheck
from .checks.permissions import PermissionsCheck
from .checks.poisoning import PoisoningCheck
from .checks.shadow import ShadowToolCheck
from .checks.versioning import VersioningCheck
from .models import AuditFinding, AuditReport, McpServer, McpTool, RiskLevel, ServerAudit

__all__ = ["AuditScanner", "BASELINE_DIR"]

BASELINE_DIR = Path.home() / ".dscan" / "audit" / "baselines"


def _baseline_dir() -> Path:
    env = os.environ.get("DSCAN_AUDIT_DIR")
    return Path(env) if env else BASELINE_DIR


class AuditScanner:
    def __init__(self) -> None:
        self.poisoning = PoisoningCheck()
        self.permissions = PermissionsCheck()
        self.versioning = VersioningCheck()
        self.integrity = IntegrityCheck()
        self.shadow = ShadowToolCheck()

    # ── Config parsing ────────────────────────────────────────────────
    def parse_mcp_config(self, config_path: str) -> list[McpServer]:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")
        config = json.loads(path.read_text(encoding="utf-8"))
        servers = []
        for name, cfg in (config.get("mcpServers") or {}).items():
            servers.append(McpServer(
                name=name,
                command=cfg.get("command", ""),
                args=cfg.get("args", []),
                env=cfg.get("env", {}),
                url=cfg.get("url", ""),
                source_file=config_path,
            ))
        return servers

    def parse_tools_from_config(self, server: McpServer) -> list[McpTool]:
        """Static config rarely declares tool schemas; live enumeration is v2."""
        return []

    # ── Scoring ───────────────────────────────────────────────────────
    def calculate_score(self, findings: list[AuditFinding]) -> tuple[int, RiskLevel]:
        has_cve = any(f.check_id.value == "AU006" for f in findings)
        score = 50 if has_cve else 0
        score += sum(f.score_contribution for f in findings)
        score = min(score, 100)

        if score >= 71 or has_cve:
            level = RiskLevel.CRITICAL
        elif score >= 41:
            level = RiskLevel.HIGH
        elif score >= 21:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        return score, level

    # ── Baseline management ───────────────────────────────────────────
    def save_baseline(self, server: McpServer, tools: list[McpTool]) -> None:
        directory = _baseline_dir()
        directory.mkdir(parents=True, exist_ok=True)
        data = {
            "server_name": server.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": t.name, "description": t.description} for t in tools],
        }
        (directory / f"{server.name}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_baseline(self, server: McpServer) -> list[McpTool]:
        path = _baseline_dir() / f"{server.name}.json"
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return [McpTool(name=t["name"], description=t.get("description", "")) for t in data.get("tools", [])]

    # ── Main audit ────────────────────────────────────────────────────
    def audit_server(
        self,
        server: McpServer,
        tools: Optional[list[McpTool]] = None,
        save_baseline: bool = True,
    ) -> ServerAudit:
        if tools is None:
            tools = self.parse_tools_from_config(server)

        baseline_tools = self.load_baseline(server)
        findings: list[AuditFinding] = []
        findings += self.poisoning.check(server, tools)
        findings += self.permissions.check(server, tools)
        findings += self.versioning.check(server)
        findings += self.integrity.check(server)
        findings += self.shadow.check(server, tools, baseline_tools)

        score, level = self.calculate_score(findings)

        if save_baseline and tools:
            self.save_baseline(server, tools)

        return ServerAudit(
            server=server,
            findings=findings,
            tools_discovered=tools,
            risk_score=score,
            risk_level=level,
        )

    def audit_config(
        self,
        config_path: str,
        tools_map: Optional[dict[str, list[McpTool]]] = None,
        save_baseline: bool = True,
    ) -> AuditReport:
        servers = self.parse_mcp_config(config_path)
        audits = []
        for server in servers:
            tools = tools_map.get(server.name) if tools_map else None
            audits.append(self.audit_server(server, tools=tools, save_baseline=save_baseline))
        return AuditReport(
            servers=audits,
            source_files=[config_path],
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def audit_directory(self, directory: str) -> Optional[AuditReport]:
        for path in (
            Path(directory) / ".cursor" / "mcp.json",
            Path(directory) / "claude_desktop_config.json",
            Path(directory) / "mcp.json",
        ):
            if path.exists():
                return self.audit_config(str(path))
        return None
