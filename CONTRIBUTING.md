# Contributing to dscan

## Setup

```bash
git clone https://github.com/DeepScan-Security/dscan
cd dscan
pip install -e ".[dev]"
pytest
```

Requires Python 3.11+.

## Rules

- TDD: write tests alongside every feature, never after.
- Coverage must stay ≥ 80%.
- Run `pytest tests/` before every PR.
- One feature per PR.

## What we need help with

- Additional pattern detectors for `dscan trail`.
- Framework integrations (LangChain, CrewAI, LangGraph).
- A TypeScript wrapper for `@watch`.
- Additional redaction patterns for `dscan secrets`.

## Do not

- Add dependencies without discussion.
- Break existing tests.
- Change the trace schema without a migration plan.

## Reporting security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
