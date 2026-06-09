# dscan

[![CI](https://github.com/DeepScan-Security/dscan/actions/workflows/ci.yml/badge.svg)](https://github.com/DeepScan-Security/dscan/actions/workflows/ci.yml)
![coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)
[![PyPI](https://img.shields.io/pypi/v/dscan-security)](https://pypi.org/project/dscan-security/)
[![Python](https://img.shields.io/pypi/pyversions/dscan-security)](https://pypi.org/project/dscan-security/)
![license](https://img.shields.io/badge/license-MIT-green)

Security suite for AI agents.

```bash
pip install dscan-security
```

---

## Quick start

```python
from dscan import watch

@watch
async def my_agent(task: str):
    # your agent code unchanged
    ...
```


```bash
dscan dashboard    # localhost:4321 — see every tool call
dscan scan .       # check before you ship
dscan audit .      # check your MCP servers
dscan attack agent.py  # test like an attacker would
```

---

## What dscan catches

| Module | What it detects | How |
|--------|----------------|-----|
| `dscan watch` | Every MCP tool call — params, results, timing, secrets in params | Runtime decorator |
| `dscan secrets` | API keys, PII, credentials in traces before they're logged | Regex + entropy |
| `dscan scan` | Dangerous patterns in system prompts and MCP configs | Static analysis |
| `dscan shield` | Prompt injection and jailbreak attempts in real time | LlamaFirewall + regex |
| `dscan trail` | Multi-step attacks invisible at the single-call level | Sequence analysis |
| `dscan attack` | Vulnerabilities in your live agent — 61 adversarial payloads | Active testing |
| `dscan audit` | Poisoned, over-privileged, or CVE-affected MCP servers | Supply chain scan |

---

## Commands

### dscan watch

```python
from dscan import watch, TrailAnalyzer, ShieldMiddleware

@watch  # minimal — just intercept and log
async def my_agent(task: str): ...

@watch(trail=TrailAnalyzer(), shield=ShieldMiddleware())
async def my_agent(task: str): ...  # full protection
```

### dscan scan

```bash
dscan scan .                          # scan current directory
dscan scan ./agent.py                 # scan one file
dscan scan --prompt system_prompt.txt # scan a system prompt
```

Finds: over-broad permissions, injection vectors, hardcoded
secrets, dangerous MCP config patterns.
Exit 1 if HIGH findings.

### dscan audit

```bash
dscan audit                           # auto-discovers mcp.json
dscan audit .cursor/mcp.json         # explicit config
dscan audit . --fail-on critical      # CI mode
dscan audit . --server filesystem     # one server only
```

Checks: tool poisoning, over-privilege, unpinned versions,
known CVEs (CVE-2025-6514, CVE-2025-53967), shadow tools.
Exit 1 if findings at or above --fail-on threshold.

### dscan trail

```bash
dscan trail ~/.dscan/traces/          # analyse existing traces
dscan trail traces/ --min-severity high
dscan trail traces/ --json            # machine-readable output
```

Detects: EXFIL_SEQUENCE, RECON_WALK, INJECTION_RELAY,
DATA_STAGING, GOAL_DRIFT.

### dscan shield

```bash
dscan shield --setup                  # download models
dscan shield check "some input text"  # test a string
dscan shield check "text" --offline   # regex only, no model
dscan shield status                   # show configuration
```

Requires: pip install dscan-security[shield]

### dscan attack

```bash
dscan attack agent.py                 # auto-discovers tools
dscan attack --url http://localhost:8080/chat
dscan attack agent.py --categories prompt_injection,jailbreak
dscan attack agent.py --max-payloads 10 --ci
```

**pytest integration:**

```python
from dscan.attack import attack_suite

def test_agent_security():
    report = attack_suite(target=my_agent)
    assert report.critical_count == 0
    assert report.high_count == 0
```

Attack categories: prompt_injection, jailbreak, tool_misuse,
indirect_injection, goal_hijacking, privilege_escalation.
Exit 1 if findings at or above --fail-on (default: high).

### dscan dashboard

```bash
dscan dashboard                       # opens localhost:4321
dscan dashboard --port 4322           # custom port
dscan dashboard --no-open             # don't open browser
```

Three tabs: Traces (live tool calls), Attack Reports,
Audit Reports.

---

## CI/CD integration

```yaml
# .github/workflows/security.yml
- name: Install dscan
  run: pip install dscan-security

- name: Audit MCP servers
  run: dscan audit . --fail-on high --ci

- name: Attack test agent
  run: |
    python agent.py &
    sleep 2
    dscan attack --url http://localhost:8080 \
      --categories prompt_injection,jailbreak \
      --fail-on high \
      --ci
```

---

## How it works

dscan intercepts MCP tool calls at the decorator layer,
analyses them for security patterns, and stores traces
locally at ~/.dscan/. Nothing leaves your machine unless
you opt in to cloud traces (Team tier).

---

## Installation

```bash
pip install dscan-security           # core (all 7 modules)
pip install dscan-security[shield]   # + LlamaFirewall models
```

Requires Python 3.11+.

---

## Contributing

See CONTRIBUTING.md. Run tests: pytest tests/ -v

---

## License

MIT — built by DeepScan (deepscan.security)
