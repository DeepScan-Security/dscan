"""Watcher — the ``@watch`` decorator that instruments an agent.

This module is a scaffold placeholder. For now ``watch`` is a
transparent decorator so that user code importing it runs unchanged.
Tracing, redaction, and scanning are wired in test-first in later
iterations.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def watch(func: F) -> F:
    """Instrument an agent function.

    Currently a transparent pass-through decorator: it returns a wrapper
    that calls ``func`` unchanged. This keeps user code working while the
    instrumentation internals are built out test-first.
    """

    @functools.wraps(func)
    async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
        return await func(*args, **kwargs)

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    import asyncio

    wrapper = async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return wrapper  # type: ignore[return-value]
