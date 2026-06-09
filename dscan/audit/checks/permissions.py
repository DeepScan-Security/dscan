"""Over-privilege detection — dangerous capability combinations."""

from __future__ import annotations

from ..models import AuditFinding, CheckId, McpServer, McpTool, RiskLevel


class PermissionsCheck:
    WRITE_PATTERNS = ["write", "create", "update", "insert", "save", "put", "set", "store", "modify", "edit"]
    DELETE_PATTERNS = ["delete", "remove", "drop", "destroy", "truncate", "clear", "purge", "erase"]
    EXECUTE_PATTERNS = ["exec", "run", "eval", "shell", "command", "script", "invoke", "spawn", "subprocess"]
    NETWORK_PATTERNS = ["http", "fetch", "request", "download", "upload", "send", "post", "webhook"]
    READ_PATTERNS = ["read", "get", "fetch", "list", "search", "query", "find", "load", "retrieve", "describe"]

    def check(self, server: McpServer, tools: list[McpTool]) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        if not tools:
            return findings

        has_write = has_delete = has_execute = has_network = False
        for tool in tools:
            combined = (tool.name + " " + tool.description).lower()
            if any(p in combined for p in self.WRITE_PATTERNS):
                has_write = True
            if any(p in combined for p in self.DELETE_PATTERNS):
                has_delete = True
            if any(p in combined for p in self.EXECUTE_PATTERNS):
                has_execute = True
            if any(p in combined for p in self.NETWORK_PATTERNS):
                has_network = True

        if has_execute and has_network:
            findings.append(AuditFinding(
                check_id=CheckId.OVER_PRIVILEGED,
                risk_level=RiskLevel.CRITICAL,
                server_name=server.name,
                title="Execute + Network access combination",
                detail=(
                    "Server has both code execution and network access tools. "
                    "This combination enables remote code execution and data exfiltration."
                ),
                recommendation=(
                    "Use separate servers for execution and network operations. "
                    "If combined access is required, add explicit user confirmation "
                    "before any execution + network sequence."
                ),
                score_contribution=20,
            ))
        elif has_write and has_delete and has_execute:
            findings.append(AuditFinding(
                check_id=CheckId.OVER_PRIVILEGED,
                risk_level=RiskLevel.HIGH,
                server_name=server.name,
                title="Write + Delete + Execute combination",
                detail=(
                    "Server has write, delete, and execute capabilities. This is a "
                    "highly privileged server that can modify and destroy data and run "
                    "arbitrary code."
                ),
                recommendation=(
                    "Restrict to minimum required capabilities. If all three are needed, "
                    "add confirmation prompts before destructive operations."
                ),
                score_contribution=15,
            ))
        elif has_delete and has_network:
            findings.append(AuditFinding(
                check_id=CheckId.OVER_PRIVILEGED,
                risk_level=RiskLevel.HIGH,
                server_name=server.name,
                title="Delete + Network access combination",
                detail=(
                    "Server can both delete data and make network requests — enables "
                    "exfiltration before deletion."
                ),
                recommendation="Separate network and deletion operations into distinct servers.",
                score_contribution=12,
            ))
        elif has_write and has_delete:
            findings.append(AuditFinding(
                check_id=CheckId.OVER_PRIVILEGED,
                risk_level=RiskLevel.MEDIUM,
                server_name=server.name,
                title="Write + Delete capabilities",
                detail=(
                    "Server can both create and destroy data. Consider whether delete "
                    "is necessary."
                ),
                recommendation=(
                    "If delete is not required for your use case, use a read-only or "
                    "write-only server."
                ),
                score_contribution=8,
            ))
        return findings
