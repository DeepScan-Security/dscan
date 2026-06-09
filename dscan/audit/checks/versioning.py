"""Version-pinning checks for MCP npm packages."""

from __future__ import annotations

from ..models import AuditFinding, CheckId, McpServer, RiskLevel


class VersioningCheck:
    KNOWN_OFFICIAL_PREFIXES = [
        "@modelcontextprotocol/",
        "@anthropic/",
        "@openai/",
    ]

    def check(self, server: McpServer) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        if server.command not in ("npx", "node", "npm"):
            return findings

        pkg = server.package_name
        if not pkg:
            return findings

        if not server.is_pinned:
            is_official = any(pkg.startswith(p) for p in self.KNOWN_OFFICIAL_PREFIXES)
            findings.append(AuditFinding(
                check_id=CheckId.NO_VERSION_PIN,
                risk_level=RiskLevel.MEDIUM if is_official else RiskLevel.HIGH,
                server_name=server.name,
                title=f"Unpinned MCP server: {pkg}",
                detail=(
                    f"Package '{pkg}' has no version pinned. Any update could change "
                    "tool behavior or introduce malicious code (rug pull risk)."
                ),
                recommendation=(
                    f"Pin to a specific version: {pkg}@<version>. Run "
                    f"'npm view {pkg} version' to find the current stable version."
                ),
                score_contribution=8 if is_official else 15,
            ))

        if "-y" in server.args or "--yes" in server.args:
            findings.append(AuditFinding(
                check_id=CheckId.NO_VERSION_PIN,
                risk_level=RiskLevel.LOW,
                server_name=server.name,
                title=f"Auto-accept flag (-y) in {server.name}",
                detail=(
                    "The -y/--yes flag skips npm's integrity prompts. Combined with an "
                    "unpinned version, this runs whatever the registry serves."
                ),
                recommendation="Remove -y flag and pin the version. Review package before accepting.",
                score_contribution=5,
            ))
        return findings
