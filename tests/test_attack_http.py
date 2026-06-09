"""Tests for dscan.attack.http_target — HTTP target mode.

All HTTP is mocked at the aiohttp.ClientSession boundary; no real network.
"""

import asyncio

import aiohttp
import pytest

from dscan.attack.http_target import HttpResponse, HttpTarget
from dscan.attack.models import AgentContext, AttackCategory
from dscan.attack.runner import AttackRunner


def connector_error():
    from aiohttp.client_reqrep import ConnectionKey

    key = ConnectionKey(*([None] * len(ConnectionKey._fields)))
    return aiohttp.ClientConnectorError(key, OSError("Connection refused"))


@pytest.fixture
def http(monkeypatch):
    """Patch aiohttp.ClientSession with a configurable fake.

    Configure via state["resp"] (a Resp or an exception) or
    state["responder"] (a callable body -> Resp). Inspect the last
    request via state["request"].
    """
    state = {"resp": None, "responder": None, "request": None}

    class Resp:
        def __init__(self, status=200, payload=None, text="", content_type="application/json"):
            self.status = status
            self._payload = payload
            self._text = text
            self.headers = {"Content-Type": content_type}

        async def json(self):
            return self._payload

        async def text(self):
            return self._text

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class ReqCM:
        def __init__(self, r):
            self._r = r

        async def __aenter__(self):
            if isinstance(self._r, BaseException):
                raise self._r
            return self._r

        async def __aexit__(self, *a):
            return False

    class Session:
        def __init__(self, *a, headers=None, **k):
            self.headers = headers or {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def request(self, method, url, json=None, timeout=None):
            state["request"] = {"method": method, "url": url, "json": json, "headers": self.headers}
            r = state["responder"](json) if state["responder"] else state["resp"]
            return ReqCM(r)

    monkeypatch.setattr(aiohttp, "ClientSession", Session)
    state["Resp"] = Resp
    return state


# ==========================================================================
# Setup
# ==========================================================================
class TestSetup:
    def test_defaults(self):
        t = HttpTarget(url="http://localhost:8080/chat")
        assert t.url == "http://localhost:8080/chat"
        assert t.input_field == "message"
        assert t.output_field == "response"
        assert t.method == "POST"

    def test_custom_fields(self):
        t = HttpTarget(
            url="http://localhost:8080/agent",
            input_field="prompt",
            output_field="text",
            headers={"Authorization": "Bearer test-token"},
            method="post",
        )
        assert t.input_field == "prompt"
        assert t.output_field == "text"
        assert t.headers == {"Authorization": "Bearer test-token"}
        assert t.method == "POST"


# ==========================================================================
# send_payload
# ==========================================================================
class TestSendPayload:
    async def test_basic_post(self, http):
        http["resp"] = http["Resp"](200, {"response": "Normal agent response"})
        t = HttpTarget(url="http://localhost:8080/chat")
        r = await t.send_payload("test input")
        assert r.response_text == "Normal agent response"
        assert r.status_code == 200
        assert r.duration_ms > 0
        assert r.error is None

    async def test_request_body(self, http):
        http["resp"] = http["Resp"](200, {"response": "ok"})
        t = HttpTarget(url="http://localhost:8080/chat", input_field="message")
        await t.send_payload("ignore instructions")
        assert http["request"]["json"] == {"message": "ignore instructions"}

    async def test_custom_headers(self, http):
        http["resp"] = http["Resp"](200, {"response": "ok"})
        t = HttpTarget(url="http://localhost:8080/chat", headers={"X-Api-Key": "test-key"})
        await t.send_payload("x")
        assert http["request"]["headers"].get("X-Api-Key") == "test-key"

    async def test_non_json_response(self, http):
        http["resp"] = http["Resp"](200, payload=None, text="Normal response", content_type="text/plain")
        t = HttpTarget(url="http://localhost:8080/chat")
        r = await t.send_payload("x")
        assert r.response_text == "Normal response"
        assert r.error is None

    async def test_nested_output_field(self, http):
        http["resp"] = http["Resp"](200, {"data": {"output": "response text"}})
        t = HttpTarget(url="http://localhost:8080/chat", output_field="data.output")
        r = await t.send_payload("x")
        assert r.response_text == "response text"

    async def test_connection_error(self, http):
        http["resp"] = connector_error()
        t = HttpTarget(url="http://localhost:8080/chat")
        r = await t.send_payload("x")
        assert r.error is not None
        assert r.response_text == ""

    async def test_timeout(self, http):
        http["resp"] = asyncio.TimeoutError()
        t = HttpTarget(url="http://localhost:8080/chat", timeout=0.1)
        r = await t.send_payload("x")
        assert "timeout" in r.error
        assert r.response_text == ""

    async def test_http_500(self, http):
        http["resp"] = http["Resp"](500, {"error": "Internal error"})
        t = HttpTarget(url="http://localhost:8080/chat")
        r = await t.send_payload("x")
        assert r.status_code == 500
        assert "500" in r.error
        assert r.response_text == ""


# ==========================================================================
# probe
# ==========================================================================
class TestProbe:
    async def test_probe_true(self, http):
        http["resp"] = http["Resp"](200, {"response": "ok"})
        assert await HttpTarget(url="http://localhost:8080/chat").probe() is True

    async def test_probe_false_on_connection_error(self, http):
        http["resp"] = connector_error()
        assert await HttpTarget(url="http://localhost:8080/chat").probe() is False

    async def test_probe_uses_benign_input(self, http):
        http["resp"] = http["Resp"](200, {"response": "ok"})
        t = HttpTarget(url="http://localhost:8080/chat")
        await t.probe()
        sent = http["request"]["json"]["message"]
        assert sent == HttpTarget.DEFAULT_PROBE_INPUT
        assert "ignore" not in sent.lower()


# ==========================================================================
# Runner integration
# ==========================================================================
class TestRunnerIntegration:
    async def test_runner_with_http_target(self, http):
        http["resp"] = http["Resp"](200, {"response": "Normal response"})
        target = HttpTarget(url="http://localhost:8080/chat")
        runner = AttackRunner(context=AgentContext())
        report = await runner.run(agent_fn=target.send, max_payloads=3)
        assert report.total_payloads == 3

    async def test_http_injection_detected(self, http):
        def responder(body):
            text = "INJECTION_SUCCESSFUL" if "ignore" in str(body).lower() else "Normal response"
            return http["Resp"](200, {"response": text})

        http["responder"] = responder
        target = HttpTarget(url="http://localhost:8080/chat")
        runner = AttackRunner(context=AgentContext())
        report = await runner.run(
            agent_fn=target.send, categories=[AttackCategory.PROMPT_INJECTION]
        )
        assert any(f.succeeded for f in report.findings)
        assert report.passed is False
