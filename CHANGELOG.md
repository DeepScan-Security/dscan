# Changelog

All notable changes to dscan are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
