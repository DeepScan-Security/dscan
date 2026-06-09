"""dscan trail — the CWAT (Call Watch) engine.

Where the redactor and scanner look at single calls in isolation, the
trail engine looks at *sequences* of tool calls and flags suspicious
call chains: data exfiltration, reconnaissance walks, prompt-injection
relays, data staging, and goal drift.

The public surface is :class:`TrailAnalyzer`. It can analyze a complete
trace list in one shot (:meth:`TrailAnalyzer.analyze`) or incrementally,
one call at a time, returning only newly-discovered findings
(:meth:`TrailAnalyzer.analyze_incremental`).

Each detector is conservative about *which* calls it considers but
deliberately structural about *what* it flags — the goal is to surface
chains a human should review, with a confidence score attached rather
than a hard yes/no.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

__all__ = ["Finding", "TrailAnalyzer"]

Severity = Literal["critical", "high", "medium", "low"]

# Category precedence. The first category whose substrings match the
# (lower-cased) tool name wins. Order matters: more specific / more
# dangerous categories are checked first so that, e.g., "get_permissions"
# is recon (not read) and "truncate_table" is delete (not execute, via
# the "run" inside "truncate").
_CATEGORY_ORDER: list[tuple[str, tuple[str, ...]]] = [
    ("recon", ("permission", "role", "policy", "whoami", "describe",
               "enumerate", "scope", "privile", "identity", "audit")),
    ("delete", ("delete", "remove", "drop", "destroy", "truncate",
                "clear", "purge", "unlink", "erase", "wipe")),
    ("execute", ("exec", "run", "eval", "shell", "code", "script",
                 "command", "invoke", "subprocess", "spawn")),
    ("send", ("send", "post", "publish", "upload", "email", "notify",
              "webhook", "push", "transmit", "dispatch", "share", "emit")),
    ("write", ("write", "save", "store", "create", "update", "insert",
               "put", "set", "append", "modify", "persist")),
    ("read", ("read", "get", "fetch", "list", "search", "query", "find",
              "load", "retrieve", "scan", "view", "open", "browse")),
]

# Hints that a read pulls in *untrusted external* content (web, email,
# inbound messages). Used by the injection-relay detector and to exclude
# such reads from data-staging.
_UNTRUSTED_HINTS = (
    "web", "url", "http", "browse", "scrape", "crawl", "fetch", "search",
    "internet", "email", "message", "page", "rss", "feed", "download",
    "external", "remote", "inbox",
)

# Keys, in priority order, used to identify the "target" of a call.
_TARGET_KEYS = (
    "path", "file", "filepath", "url", "endpoint", "uri", "resource",
    "table", "to", "address", "recipient", "host", "bucket", "object",
    "query", "sql", "key",
)

# Goal-intent keyword groups, for goal-drift.
_GOAL_INTENTS: dict[str, tuple[str, ...]] = {
    "read": ("summarize", "summarise", "read", "analyze", "analyse",
             "review", "check", "find", "search", "inspect", "examine"),
    "write": ("write", "create", "generate", "draft", "compose", "build"),
    "send": ("send", "email", "notify", "post", "publish", "share",
             "report", "deliver", "forward"),
    "delete": ("delete", "remove", "clean", "clear", "purge", "wipe"),
}


@dataclass
class Finding:
    """A single call-chain finding."""

    pattern: str
    severity: str
    calls_involved: list[str]
    call_indices: list[int]
    message: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def _key(self) -> tuple[str, tuple[int, ...]]:
        return (self.pattern, tuple(sorted(self.call_indices)))


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class TrailAnalyzer:
    """Detects suspicious call-chain patterns across a trace sequence."""

    def __init__(
        self,
        declared_tools: list[str] | None = None,
        tool_categories: dict[str, str] | None = None,
        goal: str | None = None,
        window: int = 10,
    ) -> None:
        self.declared_tools = list(declared_tools) if declared_tools else None
        self.tool_categories = dict(tool_categories) if tool_categories else None
        self.goal = goal
        self.window = window
        self._goal_intents = self._parse_goal(goal) if goal else set()
        self._buffer: list[dict[str, Any]] = []
        self._emitted: set[tuple[str, tuple[int, ...]]] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @property
    def buffer(self) -> list[dict[str, Any]]:
        """A copy of the accumulated incremental trace buffer."""
        return list(self._buffer)

    def analyze(self, traces: list[dict[str, Any]]) -> list[Finding]:
        """Run all five detectors over ``traces`` and return findings."""
        findings: list[Finding] = []
        findings += self._detect_exfil_sequence(traces, self.window)
        findings += self._detect_recon_walk(traces)
        findings += self._detect_injection_relay(traces)
        findings += self._detect_data_staging(traces, self.window)
        findings += self._detect_goal_drift(traces, self.goal)

        seen: set[tuple[str, tuple[int, ...]]] = set()
        deduped: list[Finding] = []
        for f in findings:
            k = f._key()
            if k in seen:
                continue
            seen.add(k)
            deduped.append(f)

        deduped.sort(
            key=lambda f: (
                min(f.call_indices) if f.call_indices else 0,
                _SEVERITY_RANK.get(f.severity, 9),
            )
        )
        return deduped

    def analyze_incremental(self, trace: dict[str, Any]) -> list[Finding]:
        """Append ``trace`` to the buffer and return only *new* findings."""
        self._buffer.append(trace)
        new: list[Finding] = []
        for f in self.analyze(self._buffer):
            k = f._key()
            if k in self._emitted:
                continue
            self._emitted.add(k)
            new.append(f)
        return new

    def reset(self) -> None:
        """Clear the incremental buffer and finding history."""
        self._buffer = []
        self._emitted = set()

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------
    def _category(self, tool: str | None) -> str | None:
        if self.tool_categories and tool in self.tool_categories:
            return self.tool_categories[tool]
        name = (tool or "").lower()
        if not name:
            return None
        for category, subs in _CATEGORY_ORDER:
            if any(sub in name for sub in subs):
                return category
        return None

    def _is_untrusted_read(self, tool: str | None) -> bool:
        category = self._category(tool)
        if category in ("send", "delete", "execute", "write"):
            return False
        name = (tool or "").lower()
        return any(hint in name for hint in _UNTRUSTED_HINTS)

    def _is_data_read(self, tool: str | None) -> bool:
        """A read of a concrete data source (not an untrusted web read)."""
        return self._category(tool) == "read" and not self._is_untrusted_read(tool)

    def _target(self, call: dict[str, Any]) -> str:
        params = call.get("params") or {}
        if not isinstance(params, dict):
            return str(params)
        for key in _TARGET_KEYS:
            value = params.get(key)
            if value:
                text = str(value).strip()
                if key in ("sql", "query"):
                    match = re.search(r"\bfrom\s+([A-Za-z0-9_.]+)", text, re.IGNORECASE)
                    return f"table:{match.group(1).lower()}" if match else text.lower()
                return text.lower()
        return json.dumps(params, sort_keys=True) if params else "<none>"

    def _parse_goal(self, goal: str) -> set[str]:
        text = goal.lower()
        intents: set[str] = set()
        for intent, keywords in _GOAL_INTENTS.items():
            if any(re.search(r"\b" + re.escape(k), text) for k in keywords):
                intents.add(intent)
        return intents

    def _name(self, call: dict[str, Any]) -> str:
        return str(call.get("tool") or "")

    # ------------------------------------------------------------------
    # Detectors
    # ------------------------------------------------------------------
    def _detect_exfil_sequence(
        self, traces: list[dict[str, Any]], window: int = 10
    ) -> list[Finding]:
        findings: list[Finding] = []
        for s in range(len(traces)):
            if self._category(self._name(traces[s])) != "send":
                continue
            send_target = self._target(traces[s])
            lo = max(0, s - window + 1)
            read_indices = [
                r
                for r in range(lo, s)
                if self._category(self._name(traces[r])) == "read"
                and self._target(traces[r]) != send_target
            ]
            if not read_indices:
                continue
            indices = read_indices + [s]
            names = [self._name(traces[i]) for i in indices]
            findings.append(
                Finding(
                    pattern="EXFIL_SEQUENCE",
                    severity="high",
                    calls_involved=names,
                    call_indices=indices,
                    message=(
                        f"Read then external send across different targets: "
                        f"{names[0]} -> {self._name(traces[s])}"
                    ),
                    confidence=0.8,
                )
            )
        return findings

    def _detect_recon_walk(self, traces: list[dict[str, Any]]) -> list[Finding]:
        if not self.declared_tools:
            return []
        declared = set(self.declared_tools)
        recon_indices = [
            i for i in range(len(traces))
            if self._category(self._name(traces[i])) == "recon"
        ]
        if not recon_indices:
            return []
        first_recon = recon_indices[0]
        for j in range(first_recon + 1, len(traces)):
            name = self._name(traces[j])
            if name and name not in declared:
                priors = [r for r in recon_indices if r < j]
                r = priors[-1] if priors else first_recon
                return [
                    Finding(
                        pattern="RECON_WALK",
                        severity="high",
                        calls_involved=[self._name(traces[r]), name],
                        call_indices=[r, j],
                        message=(
                            f"Recon call '{self._name(traces[r])}' followed by "
                            f"undeclared tool '{name}'"
                        ),
                        confidence=0.9,
                    )
                ]
        return []

    def _detect_injection_relay(
        self, traces: list[dict[str, Any]], relay_window: int = 3
    ) -> list[Finding]:
        findings: list[Finding] = []
        n = len(traces)
        for u in range(n):
            if not self._is_untrusted_read(self._name(traces[u])):
                continue
            hi = min(n, u + 1 + relay_window)
            for j in range(u + 1, hi):
                category = self._category(self._name(traces[j]))
                if category in ("send", "execute"):
                    findings.append(
                        Finding(
                            pattern="INJECTION_RELAY",
                            severity="critical",
                            calls_involved=[self._name(traces[u]), self._name(traces[j])],
                            call_indices=[u, j],
                            message=(
                                f"Untrusted read '{self._name(traces[u])}' relayed to "
                                f"{category} '{self._name(traces[j])}'"
                            ),
                            confidence=0.85,
                        )
                    )
                    break
        return findings

    def _detect_data_staging(
        self, traces: list[dict[str, Any]], window: int = 10
    ) -> list[Finding]:
        findings: list[Finding] = []

        def scan_segment(lo: int, hi: int) -> None:
            reads = [
                (i, self._target(traces[i]))
                for i in range(lo, hi)
                if self._is_data_read(self._name(traces[i]))
            ]
            left = 0
            for right in range(len(reads)):
                while reads[right][0] - reads[left][0] >= window:
                    left += 1
                distinct: dict[str, int] = {}
                for k in range(left, right + 1):
                    idx, target = reads[k]
                    distinct.setdefault(target, idx)
                if len(distinct) >= 3:
                    indices = sorted(distinct.values())
                    findings.append(
                        Finding(
                            pattern="DATA_STAGING",
                            severity="medium",
                            calls_involved=[self._name(traces[i]) for i in indices],
                            call_indices=indices,
                            message=(
                                f"{len(distinct)} reads on distinct sources staged "
                                "without an intervening send"
                            ),
                            confidence=0.75,
                        )
                    )
                    return

        segment_start = 0
        for i in range(len(traces)):
            if self._category(self._name(traces[i])) == "send":
                scan_segment(segment_start, i)
                segment_start = i + 1
        scan_segment(segment_start, len(traces))
        return findings

    def _detect_goal_drift(
        self, traces: list[dict[str, Any]], goal: str | None = None
    ) -> list[Finding]:
        if not (goal or self.goal):
            return []
        intents = self._goal_intents if goal is None else self._parse_goal(goal)
        # Only fires for a strictly read-only goal.
        if not intents or (intents - {"read"}):
            return []
        for i in range(len(traces)):
            category = self._category(self._name(traces[i]))
            if category in ("send", "delete"):
                read_before = any(
                    self._category(self._name(traces[j])) == "read"
                    for j in range(i)
                )
                if not read_before:
                    return [
                        Finding(
                            pattern="GOAL_DRIFT",
                            severity="medium",
                            calls_involved=[self._name(traces[i])],
                            call_indices=[i],
                            message=(
                                f"{category} action '{self._name(traces[i])}' diverges "
                                "from a read-only goal with no prior read"
                            ),
                            confidence=0.7,
                        )
                    ]
                return []
        return []
