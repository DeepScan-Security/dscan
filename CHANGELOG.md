# Changelog

All notable changes to dscan are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-09

### Added
- `dscan shield` — prompt-injection firewall. `@watch(shield=...)` screens
  every tool call before execution (offline regex layer + optional
  LlamaFirewall models); blocked calls are recorded and refused. CLI:
  `dscan shield check/--setup/status`. Dashboard shows blocked calls in red.
- `dscan attack` — adversarial testing suite for agents:
  - Automatic tool discovery from Python source, MCP configs, modules, and
    HTTP endpoints (`ToolDiscovery`).
  - A 61-payload library across six categories (prompt injection, jailbreak,
    tool misuse, indirect injection, goal hijacking, privilege escalation).
  - Concurrent runner with baseline collection, a combined
    response/tool-call/behavioral detector, and rich/JSON reporting.
  - HTTP target mode and an `attack_suite()` pytest helper.
  - CLI `dscan attack <target>` with progress bar, `--ci` JSON mode,
    `--fail-on` exit codes, and auto-saved reports.
  - Dashboard "Attack Reports" tab.

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
