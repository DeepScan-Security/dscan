"""HTTP target mode for dscan attack.

:class:`HttpTarget` drives an agent exposed over HTTP. It sends each
payload as a JSON request (configurable input/output field names, dot
notation for nested outputs, custom headers, timeout), and exposes a
:meth:`HttpTarget.send` coroutine matching the ``agent_fn`` signature
the :class:`~dscan.attack.runner.AttackRunner` expects. Errors (timeouts,
connection failures, HTTP 4xx/5xx) are captured into
:class:`HttpResponse`, never raised.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

import aiohttp

__all__ = ["HttpResponse", "HttpTarget"]


@dataclass
class HttpResponse:
    response_text: str
    status_code: int
    duration_ms: float
    error: Optional[str] = None


class HttpTarget:
    DEFAULT_PROBE_INPUT = (
        "Hello, this is a connectivity test. "
        "Please respond with a brief acknowledgment."
    )

    def __init__(
        self,
        url: str,
        input_field: str = "message",
        output_field: str = "response",
        method: str = "POST",
        headers: Optional[dict] = None,
        timeout: float = 30.0,
        extra_body: Optional[dict] = None,
    ) -> None:
        self.url = url
        self.input_field = input_field
        self.output_field = output_field
        self.method = method.upper()
        self.headers = headers or {}
        self.timeout = timeout
        self.extra_body = extra_body or {}

    async def send_payload(self, payload_text: str) -> HttpResponse:
        """Send one payload and return the captured :class:`HttpResponse`."""
        body = {self.input_field: payload_text}
        body.update(self.extra_body)

        start = time.perf_counter()
        try:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.request(
                    self.method, self.url, json=body, timeout=timeout_obj
                ) as resp:
                    duration_ms = (time.perf_counter() - start) * 1000
                    if resp.status >= 400:
                        return HttpResponse("", resp.status, duration_ms, f"HTTP {resp.status}")

                    content_type = resp.headers.get("Content-Type", "")
                    if "json" in content_type:
                        text = self._extract_field(await resp.json(), self.output_field)
                    else:
                        text = await resp.text()
                    return HttpResponse(text, resp.status, duration_ms)

        except asyncio.TimeoutError:
            return HttpResponse("", 0, (time.perf_counter() - start) * 1000, "timeout")
        except aiohttp.ClientConnectorError as exc:
            return HttpResponse("", 0, (time.perf_counter() - start) * 1000, str(exc))
        except Exception as exc:  # noqa: BLE001 — capture, never propagate
            return HttpResponse(
                "", 0, (time.perf_counter() - start) * 1000, f"{type(exc).__name__}: {exc}"
            )

    def _extract_field(self, data, field: str) -> str:
        """Extract a field from a dict, supporting ``a.b.c`` dot notation."""
        if not isinstance(data, dict):
            return str(data)
        current = data
        for part in field.split("."):
            if isinstance(current, dict):
                current = current.get(part, "")
            else:
                return ""
        return str(current) if current is not None else ""

    async def probe(self) -> bool:
        """Return True if the agent endpoint responds to a benign request."""
        result = await self.send_payload(self.DEFAULT_PROBE_INPUT)
        return result.error is None and result.status_code < 400

    async def send(self, payload_text: str) -> str:
        """``agent_fn``-compatible interface for the runner (text, "" on error)."""
        return (await self.send_payload(payload_text)).response_text
