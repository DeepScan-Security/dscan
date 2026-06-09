"""Tracer — record agent events as NDJSON trace files.

A :class:`Tracer` represents a single ``@watch`` session. Each call to
:meth:`Tracer.record` appends one JSON object, on its own line, to
``<traces_dir>/YYYY-MM-DD_<agent>.ndjson``.

Writes are non-blocking (via ``aiofiles``) and serialized per file by an
``asyncio.Lock`` so concurrent coroutines can never interleave a
half-written line.

The traces directory is resolved at write time, in priority order:

1. the ``traces_dir`` argument passed to the constructor;
2. the ``DSCAN_TRACES_DIR`` environment variable;
3. ``~/.dscan/traces`` (the default).
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
import aiofiles.os

__all__ = ["Tracer"]

# One lock per resolved file path. The event loop is single-threaded, so
# plain dict access here is safe.
_file_locks: dict[str, asyncio.Lock] = {}


def _lock_for(path: Path) -> asyncio.Lock:
    key = str(path)
    lock = _file_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _file_locks[key] = lock
    return lock


def _utc_now_iso() -> str:
    """Current UTC time as an ISO8601 string with a trailing ``Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class Tracer:
    """Writes NDJSON trace entries for one agent session."""

    def __init__(
        self,
        agent: str,
        *,
        session_id: str | None = None,
        traces_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        self.agent = agent
        self.session_id = session_id or str(uuid.uuid4())
        self._traces_dir = Path(traces_dir) if traces_dir is not None else None

    @property
    def traces_dir(self) -> Path:
        """The directory trace files are written to (resolved on access)."""
        if self._traces_dir is not None:
            return self._traces_dir
        env = os.environ.get("DSCAN_TRACES_DIR")
        if env:
            return Path(env)
        return Path.home() / ".dscan" / "traces"

    def _trace_path(self) -> Path:
        return self.traces_dir / f"{_utc_date()}_{self.agent}.ndjson"

    async def record(
        self,
        *,
        tool: str,
        params: Any,
        result: Any,
        duration_ms: float,
        flagged: bool = False,
        flag_reason: str | None = None,
        ts: str | None = None,
        trail_findings: list[Any] | None = None,
        blocked: bool | None = None,
        block_reason: str | None = None,
    ) -> dict[str, Any]:
        """Append one trace entry and return it.

        ``params`` and ``result`` are expected to be already redacted by
        the caller. The returned dict is exactly what was written.

        ``trail_findings`` is included only when not ``None``; this keeps
        the default schema unchanged for callers that don't use the trail
        engine.
        """
        entry: dict[str, Any] = {
            "ts": ts or _utc_now_iso(),
            "session_id": self.session_id,
            "agent": self.agent,
            "tool": tool,
            "params": params,
            "result": result,
            "duration_ms": int(duration_ms),
            "flagged": bool(flagged),
            "flag_reason": flag_reason,
        }
        if trail_findings is not None:
            entry["trail_findings"] = trail_findings
        if blocked is not None:
            entry["blocked"] = bool(blocked)
        if block_reason is not None:
            entry["block_reason"] = block_reason
        await self._append(entry)
        return entry

    async def _append(self, entry: dict[str, Any]) -> None:
        path = self._trace_path()
        await aiofiles.os.makedirs(path.parent, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        async with _lock_for(path):
            async with aiofiles.open(path, mode="a", encoding="utf-8") as f:
                await f.write(line)
