"""Data structures for dscan audit — MCP supply-chain analysis.

Defines the risk/check enums, the MCP server/tool representations, and the
finding/audit/report dataclasses shared across the audit package. Pure
data — no scanning, I/O, or CLI lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "RiskLevel",
    "CheckId",
    "McpServer",
    "McpTool",
    "AuditFinding",
    "ServerAudit",
    "AuditReport",
]


class RiskLevel(str, Enum):
    CRITICAL = "critical"  # score 71-100 or known CVE
    HIGH = "high"  # score 41-70
    MEDIUM = "medium"  # score 21-40
    LOW = "low"  # score 0-20


class CheckId(str, Enum):
    TOOL_POISONING = "AU001"
    OVER_PRIVILEGED = "AU002"
    NO_VERSION_PIN = "AU003"
    UNVERIFIED_SOURCE = "AU004"
    SHADOW_TOOLS = "AU005"
    KNOWN_CVE = "AU006"


@dataclass
class McpServer:
    """One MCP server entry from a config file."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict = field(default_factory=dict)
    url: str = ""
    source_file: str = ""

    @property
    def package_name(self) -> str:
        """Extract the npm package name from args (e.g. @org/server)."""
        for arg in self.args:
            if arg.startswith("@") or (not arg.startswith("-") and "/" in arg):
                return arg
        for arg in self.args:
            if not arg.startswith("-") and arg not in ("npx", "node", "python", "-y"):
                return arg
        return ""

    @property
    def is_pinned(self) -> bool:
        """True if the package carries an explicit version (``pkg@1.2.3``)."""
        pkg = self.package_name
        return "@" in pkg[1:] if len(pkg) > 1 else False

    @property
    def is_http(self) -> bool:
        return bool(self.url) or self.command in ("http", "https")


@dataclass
class McpTool:
    name: str
    description: str
    input_schema: dict = field(default_factory=dict)


@dataclass
class AuditFinding:
    check_id: CheckId
    risk_level: RiskLevel
    server_name: str
    title: str
    detail: str
    recommendation: str
    score_contribution: int
    cve_id: str = ""


@dataclass
class ServerAudit:
    server: McpServer
    findings: list[AuditFinding] = field(default_factory=list)
    tools_discovered: list[McpTool] = field(default_factory=list)
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.LOW
    error: str = ""

    @property
    def passed(self) -> bool:
        return self.risk_level in (RiskLevel.LOW,)

    @property
    def critical_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.risk_level == RiskLevel.CRITICAL]

    @property
    def high_findings(self) -> list[AuditFinding]:
        return [f for f in self.findings if f.risk_level == RiskLevel.HIGH]


@dataclass
class AuditReport:
    servers: list[ServerAudit]
    source_files: list[str]
    timestamp: str

    @property
    def critical_servers(self) -> list[ServerAudit]:
        return [s for s in self.servers if s.risk_level == RiskLevel.CRITICAL]

    @property
    def high_servers(self) -> list[ServerAudit]:
        return [s for s in self.servers if s.risk_level == RiskLevel.HIGH]

    @property
    def passed(self) -> bool:
        return len(self.critical_servers) == 0 and len(self.high_servers) == 0

    @property
    def total_findings(self) -> int:
        return sum(len(s.findings) for s in self.servers)
