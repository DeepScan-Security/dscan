# Changelog

All notable changes to dscan are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-06-09

### Added
- dscan audit — MCP supply chain analysis (AU1+AU2)
  - 5 checks: tool poisoning, over-privilege,
    version pinning, integrity/CVE, shadow tools
  - Built-in CVE database: CVE-2025-6514 (MCP Inspector,
    CVSS 10.0), CVE-2025-53967 (figma-mcp, CVSS 9.8)
  - Risk scoring 0-100 → LOW/MEDIUM/HIGH/CRITICAL
  - Baseline tracking for shadow tool detection
  - dscan audit [config] --ci --fail-on --server
  - Auto-save audit reports to ~/.dscan/audit/
- Dashboard: Audit tab (third tab)
  - Per-server risk table with colour-coded severity
  - Expandable findings with CVE IDs and fix guidance
- Dashboard: Attack Reports tab
  - Per-run PASSED/FAILED summary
  - Expandable findings table

## [0.2.0] - 2026-06-09

### Added
- dscan attack — real-environment adversarial testing
  - 61 payloads across 6 categories:
    prompt injection (15), jailbreak (10),
    tool misuse (10), indirect injection (10),
    goal hijacking (8), privilege escalation (8)
  - 5 auto-discovery methods (zero code changes needed):
    MCP config, source file AST, HTTP introspection,
    module import, observation mode
  - Three-layer detection: response + tool call +
    behavioral baseline comparison
  - HTTP target mode for deployed agents
  - attack_suite() for pytest integration
  - dscan attack [target] --url --categories
    --max-payloads --concurrency --fail-on --ci --output
  - LLMPayloadGenerator stub (v2 extension point)
- dscan shield — prompt injection firewall
  - Offline regex mode (always active, no model needed)
  - LlamaFirewall integration (pip install dscan-security[shield])
  - Scan modes: input / output / both / tool_results
  - Custom regex rules
  - dscan shield check / setup / status
  - @watch(shield=ShieldMiddleware()) integration
- dscan trail — call chain sequence detection (CWAT)
  - 5 pattern classes: EXFIL_SEQUENCE, RECON_WALK,
    INJECTION_RELAY, GOAL_DRIFT, DATA_STAGING
  - Real-time incremental detection
  - @watch(trail=TrailAnalyzer()) integration
  - dscan trail <path> --min-severity --json
- PyPI: published as dscan-security

## [0.1.1] - 2026-06-09

### Fixed
- Dashboard screenshot now renders on the PyPI project page (the README
  uses an absolute image URL instead of a repo-relative path).

## [0.1.0] - 2026-06-09

### Added
- `dscan watch` — MCP runtime interception with the `@watch` decorator.
- `dscan secrets` — automatic PII and credential redaction in traces.
- `dscan scan` — static analysis of system prompts and MCP configs.
- `dscan trail` — call chain sequence detection (CWAT) with 5 pattern
  classes: EXFIL_SEQUENCE, RECON_WALK, INJECTION_RELAY, DATA_STAGING,
  GOAL_DRIFT.
- `dscan dashboard` — local web UI at localhost:4321, with trail finding
  visualisation (severity borders, inline labels, critical count).
- 215 tests, 97% coverage.
