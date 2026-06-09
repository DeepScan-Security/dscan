"""Watcher — the ``@watch`` decorator that instruments an agent.

``@watch`` wraps an async agent function and traces the tool calls it
makes, redacting sensitive data first. It is transparent: the agent's
arguments, return value, the data sent to the LLM, and the values
returned from tools are never modified — only the *trace* is redacted.

Two interception points are supported:

1. **Anthropic SDK** — while the agent runs, ``Messages.create`` and
   ``AsyncMessages.create`` are patched. When a response contains
   ``tool_use`` blocks, each is traced (tool name + redacted input).

2. **Generic / MCP tools** — wrap any tool function with ``@watch.tool``.
   Each call is traced with redacted params and redacted result.

Usage::

    from dscan import watch

    @watch                       # or @watch(name="custom")
    async def my_agent(task): ...

    @watch.tool
    async def read_file(path): ...
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import functools
import inspect
import os
import time
from typing import Any, Callable

from dscan.redactor import redact
from dscan.tracer import Tracer

__all__ = ["watch"]


# The session active in the current async context, if any.
_current_session: contextvars.ContextVar["_Session | None"] = contextvars.ContextVar(
    "dscan_session", default=None
)


class _Session:
    """Per-``@watch``-invocation state."""

    def __init__(
        self,
        tracer: Tracer,
        trail: Any | None = None,
        shield: Any | None = None,
    ) -> None:
        self.tracer = tracer
        # Optional TrailAnalyzer; when set, each recorded tool call is fed
        # to it and any findings are attached to the trace.
        self.trail = trail
        # Optional ShieldMiddleware; when set, each tool call is screened
        # for prompt injection before it executes.
        self.shield = shield
        # Tasks for traces scheduled from synchronous call sites; awaited
        # before the agent wrapper returns.
        self.pending: list[asyncio.Task[Any]] = []


# --------------------------------------------------------------------------
# Redaction helpers (always operate on copies — never mutate caller data)
# --------------------------------------------------------------------------
def _redact_copy(value: Any) -> Any:
    return redact(copy.deepcopy(value))


def _redact_and_flag(value: Any) -> tuple[Any, bool]:
    """Return (redacted_copy, changed?) without touching ``value``."""
    redacted = _redact_copy(value)
    return redacted, redacted != value


async def _emit(
    session: _Session,
    *,
    tool: str,
    params: Any,
    result: Any,
    duration_ms: float,
) -> None:
    red_params, flagged = _redact_and_flag(params)
    red_result = _redact_copy(result)
    flag_reason = "secrets_in_params" if flagged else None
    await _finalize(
        session,
        tool=tool,
        red_params=red_params,
        red_result=red_result,
        duration_ms=duration_ms,
        flagged=flagged,
        flag_reason=flag_reason,
    )


async def _finalize(
    session: _Session,
    *,
    tool: str,
    red_params: Any,
    red_result: Any,
    duration_ms: float,
    flagged: bool,
    flag_reason: str | None,
) -> None:
    """Run trail analysis (if enabled) on the redacted entry, then record.

    A CRITICAL trail finding overrides the flag: ``flagged`` becomes True
    and ``flag_reason`` becomes ``"trail:<PATTERN>"``.
    """
    trail_findings: list[Any] | None = None
    if session.trail is not None:
        new = session.trail.analyze_incremental(
            {"tool": tool, "params": red_params, "result": red_result}
        )
        trail_findings = [f.to_dict() for f in new]
        critical = next((f for f in new if f.severity == "critical"), None)
        if critical is not None:
            flagged = True
            flag_reason = f"trail:{critical.pattern}"

    # When a shield is active, every executed call is explicitly marked as
    # not blocked (blocked calls are recorded separately by _emit_blocked).
    blocked = False if session.shield is not None else None

    await session.tracer.record(
        tool=tool,
        params=red_params,
        result=red_result,
        duration_ms=duration_ms,
        flagged=flagged,
        flag_reason=flag_reason,
        trail_findings=trail_findings,
        blocked=blocked,
    )


async def _emit_blocked(
    session: _Session, *, tool: str, params: Any, shield_result: Any
) -> None:
    """Record a tool call that the shield blocked (the tool did not run)."""
    red_params, _ = _redact_and_flag(params)
    scanner = getattr(shield_result, "scanner", None)
    category = getattr(shield_result, "category", None) or "block"
    await session.tracer.record(
        tool=tool,
        params=red_params,
        result=None,
        duration_ms=0,
        flagged=True,
        flag_reason=f"shield:{scanner}",
        blocked=True,
        block_reason=f"{category}:{scanner}",
    )


# --------------------------------------------------------------------------
# Anthropic SDK response handling
# --------------------------------------------------------------------------
async def _trace_response(session: _Session, response: Any, duration_ms: float) -> None:
    """Trace every ``tool_use`` block in an Anthropic ``Message`` response."""
    for block in getattr(response, "content", None) or []:
        if getattr(block, "type", None) != "tool_use":
            continue
        tool_input = getattr(block, "input", {}) or {}
        red_params, flagged = _redact_and_flag(tool_input)
        await _finalize(
            session,
            tool=getattr(block, "name", "unknown"),
            red_params=red_params,
            red_result=None,  # the tool has not executed at request time
            duration_ms=duration_ms,
            flagged=flagged,
            flag_reason="secrets_in_params" if flagged else None,
        )


def _schedule_response_trace(
    session: _Session, response: Any, duration_ms: float
) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return  # no event loop -> cannot trace from a pure sync context
    session.pending.append(
        loop.create_task(_trace_response(session, response, duration_ms))
    )


# --------------------------------------------------------------------------
# Anthropic SDK patching (refcounted so concurrent @watch agents compose)
# --------------------------------------------------------------------------
_sdk = {"count": 0, "orig_async": None, "orig_sync": None}


def _make_async_create(orig: Callable[..., Any]) -> Callable[..., Any]:
    async def create(self: Any, *args: Any, **kwargs: Any) -> Any:
        session = _current_session.get(None)
        start = time.perf_counter()
        response = await orig(self, *args, **kwargs)
        if session is not None:
            await _trace_response(
                session, response, int((time.perf_counter() - start) * 1000)
            )
        return response

    return create


def _make_sync_create(orig: Callable[..., Any]) -> Callable[..., Any]:
    def create(self: Any, *args: Any, **kwargs: Any) -> Any:
        session = _current_session.get(None)
        start = time.perf_counter()
        response = orig(self, *args, **kwargs)
        if session is not None:
            _schedule_response_trace(
                session, response, int((time.perf_counter() - start) * 1000)
            )
        return response

    return create


def _activate_sdk_patch() -> None:
    if _sdk["count"] == 0:
        try:
            from anthropic.resources.messages import AsyncMessages, Messages
        except Exception:
            _sdk["count"] += 1  # nothing to patch, but keep the refcount balanced
            return
        _sdk["orig_async"] = AsyncMessages.create
        _sdk["orig_sync"] = Messages.create
        AsyncMessages.create = _make_async_create(_sdk["orig_async"])
        Messages.create = _make_sync_create(_sdk["orig_sync"])
    _sdk["count"] += 1


def _deactivate_sdk_patch() -> None:
    _sdk["count"] -= 1
    if _sdk["count"] == 0 and _sdk["orig_async"] is not None:
        from anthropic.resources.messages import AsyncMessages, Messages

        AsyncMessages.create = _sdk["orig_async"]
        Messages.create = _sdk["orig_sync"]
        _sdk["orig_async"] = None
        _sdk["orig_sync"] = None


# --------------------------------------------------------------------------
# Generic / MCP tool wrapping
# --------------------------------------------------------------------------
def _bind_params(func: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
    """Best-effort mapping of a call's args to named parameters."""
    try:
        bound = inspect.signature(func).bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        return {"args": list(args), "kwargs": dict(kwargs)}


def _watch_tool(func: Callable[..., Any]) -> Callable[..., Any]:
    """Trace calls to a tool function while a ``@watch`` session is active."""
    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_tool(*args: Any, **kwargs: Any) -> Any:
            session = _current_session.get(None)
            if session is None:
                return await func(*args, **kwargs)
            params = _bind_params(func, args, kwargs)
            if session.shield is not None:
                blocked = session.shield.shield_check(func.__name__, params)
                if blocked.blocked:
                    await _emit_blocked(
                        session, tool=func.__name__, params=params, shield_result=blocked
                    )
                    from dscan.shield import ShieldBlockedError

                    raise ShieldBlockedError(
                        f"Tool call blocked by dscan shield: {blocked.reason}"
                    )
            start = time.perf_counter()
            result = await func(*args, **kwargs)
            await _emit(
                session,
                tool=func.__name__,
                params=params,
                result=result,
                duration_ms=int((time.perf_counter() - start) * 1000),
            )
            return result

        return async_tool

    @functools.wraps(func)
    def sync_tool(*args: Any, **kwargs: Any) -> Any:
        session = _current_session.get(None)
        if session is None:
            return func(*args, **kwargs)
        params = _bind_params(func, args, kwargs)
        if session.shield is not None:
            blocked = session.shield.shield_check(func.__name__, params)
            if blocked.blocked:
                try:
                    loop = asyncio.get_running_loop()
                    session.pending.append(
                        loop.create_task(
                            _emit_blocked(
                                session,
                                tool=func.__name__,
                                params=params,
                                shield_result=blocked,
                            )
                        )
                    )
                except RuntimeError:
                    pass
                from dscan.shield import ShieldBlockedError

                raise ShieldBlockedError(
                    f"Tool call blocked by dscan shield: {blocked.reason}"
                )
        start = time.perf_counter()
        result = func(*args, **kwargs)
        duration_ms = int((time.perf_counter() - start) * 1000)
        try:
            loop = asyncio.get_running_loop()
            session.pending.append(
                loop.create_task(
                    _emit(
                        session,
                        tool=func.__name__,
                        params=params,
                        result=result,
                        duration_ms=duration_ms,
                    )
                )
            )
        except RuntimeError:
            pass
        return result

    return sync_tool


# --------------------------------------------------------------------------
# The @watch decorator
# --------------------------------------------------------------------------
def watch(
    func: Callable[..., Any] | None = None,
    *,
    name: str | None = None,
    trail: Any | None = None,
    shield: Any | None = None,
) -> Callable[..., Any]:
    """Instrument an async agent function.

    Use as ``@watch`` or ``@watch(name="custom")``. The agent name is
    resolved as ``name`` > ``$DSCAN_AGENT_NAME`` > the function's
    ``__name__``.

    Pass ``trail=TrailAnalyzer(...)`` to additionally run call-chain
    analysis: each traced call is fed to the analyzer, findings are
    attached to the trace under ``trail_findings``, and a CRITICAL
    finding flags the entry with ``flag_reason="trail:<PATTERN>"``.

    Pass ``shield=ShieldMiddleware(...)`` to screen each tool call for
    prompt injection before it runs. A blocked call is not executed; its
    trace records ``blocked=True`` and the agent receives a
    ``ShieldBlockedError``.
    """
    if func is None:
        return functools.partial(watch, name=name, trail=trail, shield=shield)

    if not inspect.iscoroutinefunction(func):
        raise TypeError(
            f"@watch only supports async functions; "
            f"'{func.__name__}' must be defined with 'async def'"
        )

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        agent_name = name or os.environ.get("DSCAN_AGENT_NAME") or func.__name__
        session = _Session(Tracer(agent_name), trail=trail, shield=shield)
        token = _current_session.set(session)
        _activate_sdk_patch()
        try:
            return await func(*args, **kwargs)
        finally:
            if session.pending:
                await asyncio.gather(*session.pending)
            _deactivate_sdk_patch()
            _current_session.reset(token)

    return wrapper


watch.tool = _watch_tool  # type: ignore[attr-defined]
