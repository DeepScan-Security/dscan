# dscan

An open source agent security suite. Trace, redact, and scan AI agents.

```bash
pip install dscan
```

```python
from dscan import watch

@watch
async def my_agent(task: str):
    ...  # your agent code unchanged
```

```bash
dscan dashboard   # http://localhost:4321
```

![dscan dashboard](docs/dashboard.png)

## Install

```bash
pip install dscan
```

Requires Python 3.11+.

## Quick start

```python
from dscan import watch

@watch
async def my_agent(task: str):
    ...  # your agent code unchanged
```

Run your agent, then open the dashboard:

```bash
dscan dashboard
```

Tool calls are written as redacted NDJSON to `~/.dscan/traces/`.

## What it detects

| Module | What it catches |
| --- | --- |
| `redactor` | AWS keys, API tokens, JWTs, emails, phone numbers, SSNs, Luhn-valid credit cards, high-entropy secrets |
| `@watch` | every tool call's name, params, result, and duration; flags calls whose params contain secrets |
| `dscan scan` | permissive prompts (SP001), injection vectors (SP002), hardcoded secrets (SP003), excessive scope (SP004); unverified MCP servers (MC001), overprivileged servers (MC002), hardcoded MCP credentials (MC003) |
| dashboard | sessions, per-call timeline, redacted params/results, flagged calls |

## Commands

```bash
dscan scan ./                     # scan prompts and MCP configs in a directory
dscan scan --prompt prompt.txt    # scan a single system-prompt file
dscan watch                       # how to instrument an agent (it's a decorator)
dscan dashboard                   # start the dashboard at localhost:4321
dscan dashboard --port 4322       # use a custom port
dscan dashboard --no-open         # do not open a browser
```

`dscan scan` exits `1` if it finds any high-severity issue, `0` otherwise.

## How it works

`@watch` wraps your async agent and records every tool call — from the Anthropic SDK or any `@watch.tool` function — as redacted NDJSON under `~/.dscan/traces/`. `dscan scan` statically analyzes system prompts and MCP config files for risky patterns and hardcoded secrets. `dscan dashboard` serves a local web UI to inspect sessions and flagged calls.

## Contributing

```bash
git clone https://github.com/DeepScan-Security/dscan
cd dscan
pip install -e ".[dev]"
pytest
```

Tests are written test-first; coverage stays at or above 80%.

## License

MIT
