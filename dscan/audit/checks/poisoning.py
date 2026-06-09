"""Tool-poisoning detection — hidden instructions in tool descriptions."""

from __future__ import annotations

import re

from ..models import AuditFinding, CheckId, McpServer, McpTool, RiskLevel


class PoisoningCheck:
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|prior|all)\s+instructions?",
        r"disregard\s+(your|all|previous)\s+instructions?",
        r"you\s+are\s+now\s+(a|an|the)\s+\w+",
        r"act\s+as\s+(a|an)\s+\w+\s+with\s+no\s+restrictions?",
        r"send\s+(all|the)\s+(data|context|information)\s+to",
        r"forward\s+(this|the)\s+(conversation|context)\s+to",
        r"(email|post|upload)\s+(your|the)\s+(system\s+)?prompt",
        r"<\s*hidden\s*>",
        r"<!--.*instruct.*-->",
        r"\[INST\]|\[\/INST\]",
        r"(admin|root|elevated)\s+(mode|access|privileges?)",
        r"bypass\s+(safety|security|restrictions?)",
        r"base64",
        r"\\u00[0-9a-f]{2}",
    ]

    def check(self, server: McpServer, tools: list[McpTool]) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        for tool in tools:
            desc = tool.description or ""

            matched = [
                p for p in self.INJECTION_PATTERNS
                if re.search(p, desc, re.IGNORECASE | re.DOTALL)
            ]
            if matched:
                findings.append(AuditFinding(
                    check_id=CheckId.TOOL_POISONING,
                    risk_level=RiskLevel.CRITICAL,
                    server_name=server.name,
                    title=f"Tool poisoning detected in '{tool.name}'",
                    detail=(
                        f"Tool description contains injection pattern(s): "
                        f"{matched[:2]}. Description: {desc[:100]}..."
                    ),
                    recommendation=(
                        "Do not use this MCP server. The tool description "
                        "contains instructions designed to hijack your agent. "
                        "Report to the server maintainer and remove from config."
                    ),
                    score_contribution=40,
                ))
                continue  # one finding per tool max

            if len(desc) > 500:
                findings.append(AuditFinding(
                    check_id=CheckId.TOOL_POISONING,
                    risk_level=RiskLevel.MEDIUM,
                    server_name=server.name,
                    title=f"Unusually long tool description in '{tool.name}'",
                    detail=(
                        f"Description is {len(desc)} chars. Long descriptions "
                        "may hide injected instructions."
                    ),
                    recommendation=(
                        "Review the full tool description carefully before "
                        "using this server."
                    ),
                    score_contribution=10,
                ))

            if "\n" in desc and len(desc) > 100:
                findings.append(AuditFinding(
                    check_id=CheckId.TOOL_POISONING,
                    risk_level=RiskLevel.LOW,
                    server_name=server.name,
                    title=f"Multi-line tool description in '{tool.name}'",
                    detail=(
                        "Tool descriptions should be single-line. Multi-line "
                        "descriptions may contain hidden instructions after a newline."
                    ),
                    recommendation=(
                        "Verify the tool description is legitimate and contains "
                        "no hidden text."
                    ),
                    score_contribution=5,
                ))
        return findings
