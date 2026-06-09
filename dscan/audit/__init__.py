"""dscan audit — MCP supply-chain analysis.

Audits MCP server configurations for supply-chain risk: tool poisoning,
over-privilege, unpinned/unverified packages, known CVEs, and shadow
tools. :class:`AuditScanner` is the engine; the rest are its data model.
"""

from __future__ import annotations

from .models import (
    AuditFinding,
    AuditReport,
    CheckId,
    McpServer,
    McpTool,
    RiskLevel,
    ServerAudit,
)
from .scanner import AuditScanner

__all__ = [
    "RiskLevel",
    "CheckId",
    "McpServer",
    "McpTool",
    "AuditFinding",
    "ServerAudit",
    "AuditReport",
    "AuditScanner",
]
