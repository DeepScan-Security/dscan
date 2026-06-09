# dscan

Security observability for AI agents. Wrap your agent in one decorator and
every tool call is traced, with secrets redacted before they ever touch disk.
Statically scan your prompts and MCP configs for risky patterns. Inspect it all
in a local dashboard.

```python
from dscan import watch

@watch
async def my_agent(task: str):
    ...  # your agent code, unchanged
```

```bash
dscan dashboard   # http://localhost:4321
```

![dscan dashboard](docs/dashboard.png)

---

## Why

Agents call tools with real arguments — file paths, API keys, database URLs,
customer emails. Most of that flows through logs and traces in plaintext. dscan
sits between your agent and its tools: it records what happened, redacts the
sensitive parts, and flags the calls worth looking at — without changing a
single byte of what your agent actually sends or receives.

## Install

dscan targets **Python 3.11+**.

```bash
pip install dscan            # once published to PyPI
```

Or from source:

```bash
git clone https://github.com/DeepScan-Security/dscan
cd dscan
pip install -e .
```

## Quick start

Decorate your async agent with `@watch`, and any tool with `@watch.tool`:

```python
from dscan import watch

@watch.tool
async def query_db(sql: str, connection: str) -> dict:
    ...

@watch
async def my_agent(task: str):
    return await query_db(
        sql="SELECT * FROM users",
        connection="postgresql://admin:s3cr3t@db/prod",
    )
```

Run it, then explore the traces:

```bash
dscan dashboard
```

That's it. Tool calls are written as redacted NDJSON to `~/.dscan/traces/`.
If you use the Anthropic SDK, `@watch` also intercepts `messages.create()` and
traces every `tool_use` block the model emits — no extra wiring.

## What a trace looks like

One JSON object per line. Secrets are replaced with typed placeholders, and the
call is flagged when its parameters contained anything sensitive:

```json
{"ts":"2026-06-09T03:16:57Z","session_id":"36f9a8bc-…","agent":"my_agent",
 "tool":"store_data","params":{"key":"api_key","value":"[REDACTED:API_KEY]"},
 "result":{"stored":true},"duration_ms":4,"flagged":true,
 "flag_reason":"secrets_in_params"}
```

The agent still received the real value — only the **trace** is redacted.

## What it detects

| Component | What it catches |
| --- | --- |
| **Redactor** | AWS keys, Anthropic/OpenAI/GitHub/Stripe tokens, JWTs, emails, phone numbers, SSNs, Luhn-valid credit cards, and arbitrary high-entropy secrets |
| **`@watch`** | every tool call's name, params, result, and duration; flags any call whose params contain a secret |
| **`dscan scan`** | risky system prompts and misconfigured MCP servers (see rules below) |
| **Dashboard** | sessions, per-call timeline, redacted params/results, flagged calls |

### Scan rules

```bash
dscan scan ./
```

| Rule | Severity | Detects |
| --- | --- | --- |
| `SP001` | high | Overly permissive prompt ("do anything", "no restrictions", "ignore previous") |
| `SP002` | high | Reads from an untrusted source (email, web, user input) with no sanitization |
| `SP003` | high | Hardcoded API key / token in the prompt |
| `SP004` | medium | Grants access to more than five tool categories |
| `MC001` | medium | MCP server on an unverified host with no pinned version |
| `MC002` | high | MCP server granting write + delete + execute together |
| `MC003` | high | Hardcoded credentials in an MCP config |

`dscan scan` reads `mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`,
and any `.txt` / `.md` prompt files in the target directory. It prints findings
grouped by severity (highest first) and **exits `1` if any high-severity issue
is found** — drop it into CI as a gate.

## Commands

```bash
dscan scan ./                   # scan prompts and MCP configs in a directory
dscan scan --prompt prompt.txt  # scan a single system-prompt file
dscan watch                     # reminder: @watch is a decorator, not a command
dscan dashboard                 # start the dashboard at localhost:4321
dscan dashboard --port 4322     # custom port
dscan dashboard --no-open       # don't open a browser
dscan --version
```

## How it works

`@watch` wraps your async agent and records every tool call — whether it comes
from the Anthropic SDK's `tool_use` blocks or a `@watch.tool`-wrapped function —
redacting params and results on a deep copy so the agent's real data is never
mutated. Traces are appended as NDJSON to `~/.dscan/traces/` (override with
`DSCAN_TRACES_DIR`), one file per agent per day. `dscan scan` is a separate
static pass over prompts and MCP configs, and `dscan dashboard` is a dependency-
free local web UI that reads the same trace files.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DSCAN_TRACES_DIR` | `~/.dscan/traces` | Where traces are read/written |
| `DSCAN_AGENT_NAME` | function name | Overrides the agent name in traces |

`@watch(name="custom")` overrides the agent name explicitly and takes precedence
over `DSCAN_AGENT_NAME`.

## Try the demo

```bash
python examples/demo_agent.py --mock
```

Runs an agent through five tool calls — two carrying fake secrets — and prints a
summary of what was traced and flagged. No API key required.

## Development

```bash
git clone https://github.com/DeepScan-Security/dscan
cd dscan
pip install -e ".[dev]"
pytest
```

Built test-first throughout; coverage stays at or above 80% (currently ~95%).
CI runs the suite on Python 3.11–3.14.

## Security

dscan is a security tool, so we hold it to that bar. To report a vulnerability,
see [SECURITY.md](SECURITY.md) — please don't open a public issue.

## License

MIT
