"""Source verification + known-CVE checks for MCP packages."""

from __future__ import annotations

from ..models import AuditFinding, CheckId, McpServer, RiskLevel

# Known vulnerable MCP packages — hardcoded. A live database replaces this in v2.
KNOWN_CVES = {
    "@modelcontextprotocol/inspector": {
        "cve_id": "CVE-2025-6514",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Remote code execution via command injection. No auth required.",
        "affected_versions": "< 0.14.0",
        "fixed_version": "0.14.0",
    },
    "figma-mcp": {
        "cve_id": "CVE-2025-53967",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Remote code execution via command injection in Figma MCP server.",
        "affected_versions": "< 0.3.0",
        "fixed_version": "0.3.0",
    },
}

_OFFICIAL_PREFIXES = ("@modelcontextprotocol/", "@anthropic/", "@openai/")


class IntegrityCheck:
    def check(self, server: McpServer) -> list[AuditFinding]:
        findings: list[AuditFinding] = []
        pkg = server.package_name
        if not pkg:
            return findings

        # Strip a trailing @version only when actually pinned (preserves the
        # leading @ of scoped package names).
        base_pkg = pkg.rsplit("@", 1)[0] if server.is_pinned else pkg

        for cve_pkg, info in KNOWN_CVES.items():
            if base_pkg == cve_pkg or base_pkg.endswith(cve_pkg.split("/")[-1]):
                findings.append(AuditFinding(
                    check_id=CheckId.KNOWN_CVE,
                    risk_level=RiskLevel.CRITICAL,
                    server_name=server.name,
                    title=f"{info['cve_id']} — {base_pkg}",
                    detail=(
                        f"{info['description']} CVSS: {info['cvss']}. "
                        f"Affected: {info['affected_versions']}. Fixed in: {info['fixed_version']}."
                    ),
                    recommendation=(
                        f"Update to {info['fixed_version']} or later immediately. "
                        f"This is a {info['severity']} severity vulnerability."
                    ),
                    score_contribution=50,
                    cve_id=info["cve_id"],
                ))

        if server.command in ("npx", "node", "npm"):
            is_official = base_pkg.startswith(_OFFICIAL_PREFIXES)
            is_scoped = base_pkg.startswith("@")
            if not is_official and not is_scoped:
                findings.append(AuditFinding(
                    check_id=CheckId.UNVERIFIED_SOURCE,
                    risk_level=RiskLevel.HIGH,
                    server_name=server.name,
                    title=f"Unscoped package: {base_pkg}",
                    detail=(
                        f"'{base_pkg}' is an unscoped npm package. Unscoped packages have "
                        "no namespace protection and are easier to typosquat."
                    ),
                    recommendation=(
                        "Prefer scoped packages (@org/package). Verify the package "
                        "maintainer's identity before use."
                    ),
                    score_contribution=10,
                ))
        return findings
