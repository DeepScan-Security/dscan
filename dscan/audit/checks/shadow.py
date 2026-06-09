"""Shadow-tool detection — tools that appeared (or vanished) since baseline."""

from __future__ import annotations

from ..models import AuditFinding, CheckId, McpServer, McpTool, RiskLevel


class ShadowToolCheck:
    def check(
        self,
        server: McpServer,
        current_tools: list[McpTool],
        baseline_tools: list[McpTool],
    ) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        if not baseline_tools:
            return findings  # no baseline to compare against

        current_names = {t.name for t in current_tools}
        baseline_names = {t.name for t in baseline_tools}
        new_tools = current_names - baseline_names
        removed_tools = baseline_names - current_names

        if new_tools:
            findings.append(AuditFinding(
                check_id=CheckId.SHADOW_TOOLS,
                risk_level=RiskLevel.HIGH,
                server_name=server.name,
                title=f"Shadow tools detected: {', '.join(sorted(new_tools))}",
                detail=(
                    f"{len(new_tools)} new tool(s) appeared since last audit: "
                    f"{sorted(new_tools)}. These were not present when you first "
                    "trusted this server."
                ),
                recommendation=(
                    "Review the new tools carefully. If unexpected, the server may have "
                    "been compromised or updated maliciously. Contact the server maintainer."
                ),
                score_contribution=10,
            ))

        if removed_tools:
            findings.append(AuditFinding(
                check_id=CheckId.SHADOW_TOOLS,
                risk_level=RiskLevel.LOW,
                server_name=server.name,
                title=f"Tools removed since last audit: {', '.join(sorted(removed_tools))}",
                detail=f"{len(removed_tools)} tool(s) removed: {sorted(removed_tools)}.",
                recommendation="Verify this is an expected update. Re-run audit after reviewing changelog.",
                score_contribution=2,
            ))
        return findings
