"""Scanner — static analysis of agent configs and system prompts.

Public API:

- :func:`scan_system_prompt` — analyze a system-prompt string (SP* rules).
- :func:`scan_file` — analyze a single file (dispatches prompt vs MCP config).
- :func:`scan_directory` — walk a directory and analyze prompts + MCP configs.

Each detection yields a :class:`Finding`.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dscan.redactor import redact

__all__ = [
    "Finding",
    "scan_system_prompt",
    "scan_file",
    "scan_directory",
]

_SNIPPET_MAX = 80

# Markers the redactor emits for credential-class secrets (not PII).
_SECRET_MARKERS = ("[REDACTED:AWS_KEY]", "[REDACTED:API_KEY]", "[REDACTED:SECRET]")

# MCP config filenames we recognize.
_MCP_FILENAMES = {"mcp.json", "claude_desktop_config.json"}

# Hosts considered trusted for MCP servers.
_KNOWN_GOOD_HOSTS = {"localhost", "127.0.0.1", "mcp.anthropic.com", "api.anthropic.com"}

# Names that indicate a credential value.
_CREDENTIAL_KEYS = {
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "secret",
    "password",
}

# Tool categories for excessive-scope detection (SP004).
_TOOL_CATEGORIES: dict[str, list[str]] = {
    "filesystem": ["file", "files", "filesystem", "directory", "read_file", "write_file"],
    "network": ["http", "https", "network", "fetch", "url", "request", "requests"],
    "shell": ["shell", "bash", "exec", "execute", "command", "commands", "subprocess"],
    "database": ["database", "sql", "postgres", "mysql", "sqlite", "query"],
    "email": ["email", "smtp", "mail"],
    "browser": ["browser", "selenium", "playwright", "puppeteer", "scrape"],
    "cloud": ["aws", "s3", "gcp", "azure"],
    "payment": ["payment", "stripe", "billing"],
    "calendar": ["calendar"],
    "code": ["git", "github", "repository"],
}

_UNTRUSTED_SOURCES = [
    "email",
    "web",
    "internet",
    "url",
    "user input",
    "user-provided",
    "untrusted",
    "webpage",
]


@dataclass(frozen=True)
class Finding:
    """A single static-analysis finding."""

    rule: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _snippet(text: str) -> str:
    return text.strip()[:_SNIPPET_MAX]


def _has_word(text: str, word: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


def _line_of(raw: str, needle: str) -> int:
    """1-based line number of the first line containing ``needle`` (else 1)."""
    for i, line in enumerate(raw.splitlines(), start=1):
        if needle in line:
            return i
    return 1


# --------------------------------------------------------------------------
# System prompt checks
# --------------------------------------------------------------------------
_SP001_PATTERNS = [
    r"do anything",
    r"no restrictions",
    r"ignore (?:all )?previous",
]


def scan_system_prompt(text: str, filename: str = "<system_prompt>") -> list[Finding]:
    """Run all SP* checks against a system-prompt string."""
    findings: list[Finding] = []
    lines = text.splitlines() or [text]

    sanitized = re.search(r"saniti|validat|escap", text, re.IGNORECASE) is not None

    for idx, line in enumerate(lines, start=1):
        lower = line.lower()

        # SP001 — overly permissive
        for pat in _SP001_PATTERNS:
            if re.search(pat, lower):
                findings.append(
                    Finding(
                        rule="SP001",
                        severity="high",
                        file=filename,
                        line=idx,
                        message="System prompt grants unrestricted behavior",
                        snippet=_snippet(line),
                    )
                )
                break

        # SP002 — injection vector
        if re.search(r"read(?:s|ing)?\s+from", lower) and not sanitized:
            if any(_has_word(line, src) or src in lower for src in _UNTRUSTED_SOURCES):
                findings.append(
                    Finding(
                        rule="SP002",
                        severity="high",
                        file=filename,
                        line=idx,
                        message="Reads from an untrusted source without sanitization",
                        snippet=_snippet(line),
                    )
                )

        # SP003 — hardcoded secret
        if any(marker in redact(line) for marker in _SECRET_MARKERS):
            findings.append(
                Finding(
                    rule="SP003",
                    severity="high",
                    file=filename,
                    line=idx,
                    message="Hardcoded secret found in system prompt",
                    snippet=_snippet(line),
                )
            )

    # SP004 — excessive scope (document-level)
    categories = [
        cat
        for cat, words in _TOOL_CATEGORIES.items()
        if any(_has_word(text, w) for w in words)
    ]
    if len(categories) > 5:
        findings.append(
            Finding(
                rule="SP004",
                severity="medium",
                file=filename,
                line=1,
                message=f"System prompt grants access to {len(categories)} tool categories (>5)",
                snippet=_snippet("tools: " + ", ".join(categories)),
            )
        )

    return findings


# --------------------------------------------------------------------------
# MCP config checks
# --------------------------------------------------------------------------
def _iter_servers(config: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict):
        return []
    return [(name, cfg) for name, cfg in servers.items() if isinstance(cfg, dict)]


def _is_version_pinned(server: dict[str, Any]) -> bool:
    if "version" in server:
        return True
    args = server.get("args") or []
    return any(isinstance(a, str) and re.search(r"@\d+\.\d", a) for a in args)


def _is_env_reference(value: str) -> bool:
    return re.fullmatch(r"\$\{?\w+\}?", value.strip()) is not None


def _walk_strings(obj: Any, key: str | None = None):
    """Yield (key, value) pairs for every string leaf in ``obj``."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, k)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_strings(item, key)
    elif isinstance(obj, str):
        yield key, obj


def scan_mcp_config(raw: str, filename: str) -> list[Finding]:
    """Run all MC* checks against the raw text of an MCP config file."""
    try:
        config = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(config, dict):
        return []

    findings: list[Finding] = []

    for name, server in _iter_servers(config):
        # MC001 — unverified server
        url = server.get("url")
        if isinstance(url, str) and url:
            host = (urlparse(url).hostname or "").lower()
            if host not in _KNOWN_GOOD_HOSTS and not _is_version_pinned(server):
                findings.append(
                    Finding(
                        rule="MC001",
                        severity="medium",
                        file=filename,
                        line=_line_of(raw, url),
                        message=f"MCP server '{name}' uses an unverified URL with no pinned version",
                        snippet=_snippet(url),
                    )
                )

        # MC002 — overprivileged
        perms = {
            str(p).lower()
            for p in (server.get("permissions") or server.get("scopes") or [])
        }
        if {"write", "delete", "execute"} <= perms:
            findings.append(
                Finding(
                    rule="MC002",
                    severity="high",
                    file=filename,
                    line=_line_of(raw, f'"{name}"'),
                    message=f"MCP server '{name}' grants write, delete, and execute together",
                    snippet=_snippet(", ".join(sorted(perms))),
                )
            )

    # MC003 — hardcoded credentials (anywhere in the config)
    seen_lines: set[int] = set()
    for key, value in _walk_strings(config):
        if not value or _is_env_reference(value):
            continue
        is_cred_key = key is not None and key.lower() in _CREDENTIAL_KEYS
        is_secret_value = any(m in redact(value) for m in _SECRET_MARKERS)
        if is_cred_key or is_secret_value:
            line = _line_of(raw, value)
            if line in seen_lines:
                continue
            seen_lines.add(line)
            findings.append(
                Finding(
                    rule="MC003",
                    severity="high",
                    file=filename,
                    line=line,
                    message="Hardcoded credential found in MCP config",
                    snippet=_snippet(f"{key}: {value}"),
                )
            )

    return findings


# --------------------------------------------------------------------------
# File / directory dispatch
# --------------------------------------------------------------------------
def _is_mcp_config(path: Path) -> bool:
    return path.name in _MCP_FILENAMES


def scan_file(path: str) -> list[Finding]:
    """Scan a single file, dispatching on whether it is an MCP config."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    if _is_mcp_config(p):
        return scan_mcp_config(raw, filename=str(p))
    return scan_system_prompt(raw, filename=str(p))


_SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", ".pytest_cache", ".mypy_cache"}
_PROMPT_SUFFIXES = {".txt", ".md"}


def scan_directory(path: str) -> list[Finding]:
    """Walk ``path`` and scan prompt files and MCP configs."""
    root = Path(path)
    findings: list[Finding] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if _is_mcp_config(p) or p.suffix.lower() in _PROMPT_SUFFIXES:
            findings.extend(scan_file(str(p)))
    return findings
