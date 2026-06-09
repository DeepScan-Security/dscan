"""Tests for dscan.watcher (the @watch decorator).

The Anthropic client is never called for real: we patch
``AsyncMessages.create`` / ``Messages.create`` at the SDK boundary so a
canned ``Message`` (with ``tool_use`` blocks) is returned.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from anthropic.resources.messages import AsyncMessages, Messages
from anthropic.types import Message, TextBlock, ToolUseBlock, Usage

from dscan import watch


# --------------------------------------------------------------------------
# Helpers / fixtures
# --------------------------------------------------------------------------
def make_message(blocks, stop_reason="tool_use"):
    return Message(
        id="msg_1",
        type="message",
        role="assistant",
        model="claude-test",
        content=blocks,
        stop_reason=stop_reason,
        stop_sequence=None,
        usage=Usage(input_tokens=1, output_tokens=1),
    )


def tool_use(name, input, id="toolu_1"):
    return ToolUseBlock(id=id, name=name, input=input, type="tool_use")


@pytest.fixture
def traces_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
    monkeypatch.delenv("DSCAN_AGENT_NAME", raising=False)
    return tmp_path


def read_entries(traces_dir, agent):
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = Path(traces_dir) / f"{date}_{agent}.ndjson"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def trace_files(traces_dir):
    return sorted(p.name for p in Path(traces_dir).iterdir())


# --------------------------------------------------------------------------
# Transparent wrapping
# --------------------------------------------------------------------------
class TestTransparentWrapping:
    async def test_return_value_unchanged(self, traces_dir):
        @watch
        async def add(a, b):
            return a + b

        assert await add(2, 3) == 5

    async def test_args_and_kwargs_passed_through(self, traces_dir):
        @watch
        async def greet(name, *, greeting="hi"):
            return f"{greeting}, {name}"

        assert await greet("ada", greeting="hello") == "hello, ada"

    async def test_no_tools_writes_no_trace(self, traces_dir):
        @watch
        async def noop():
            return 1

        await noop()
        assert trace_files(traces_dir) == []

    def test_sync_function_raises_typeerror(self):
        with pytest.raises(TypeError, match="async"):

            @watch
            def sync_agent():
                return 1

    def test_sync_function_raises_with_name(self):
        with pytest.raises(TypeError, match="async"):

            @watch(name="x")
            def sync_agent():
                return 1


# --------------------------------------------------------------------------
# Anthropic SDK interception
# --------------------------------------------------------------------------
class TestAnthropicInterception:
    async def test_traces_tool_use_block(self, traces_dir):
        import anthropic

        canned = make_message([tool_use("read_file", {"path": "/etc/hosts"})])
        with patch.object(AsyncMessages, "create", AsyncMock(return_value=canned)):
            client = anthropic.AsyncAnthropic(api_key="test")

            @watch
            async def my_agent(task):
                return await client.messages.create(
                    model="claude-test",
                    max_tokens=16,
                    messages=[{"role": "user", "content": task}],
                )

            await my_agent("read the file")

        entries = read_entries(traces_dir, "my_agent")
        assert len(entries) == 1
        assert entries[0]["tool"] == "read_file"
        assert entries[0]["params"] == {"path": "/etc/hosts"}
        assert entries[0]["agent"] == "my_agent"

    async def test_traces_every_tool_use_block(self, traces_dir):
        import anthropic

        canned = make_message(
            [
                TextBlock(type="text", text="working"),
                tool_use("read_file", {"path": "/a"}, id="t1"),
                tool_use("write_file", {"path": "/b"}, id="t2"),
            ]
        )
        with patch.object(AsyncMessages, "create", AsyncMock(return_value=canned)):
            client = anthropic.AsyncAnthropic(api_key="test")

            @watch
            async def my_agent():
                return await client.messages.create(
                    model="m", max_tokens=16, messages=[]
                )

            await my_agent()

        entries = read_entries(traces_dir, "my_agent")
        assert [e["tool"] for e in entries] == ["read_file", "write_file"]

    async def test_redacts_params_from_tool_use(self, traces_dir):
        import anthropic

        secret_input = {"path": "/x", "api_key": "sk-ant-api03-supersecret"}
        canned = make_message([tool_use("call_api", secret_input)])
        with patch.object(AsyncMessages, "create", AsyncMock(return_value=canned)):
            client = anthropic.AsyncAnthropic(api_key="test")

            @watch
            async def my_agent():
                return await client.messages.create(
                    model="m", max_tokens=16, messages=[]
                )

            response = await my_agent()

        entries = read_entries(traces_dir, "my_agent")
        assert entries[0]["params"] == {
            "path": "/x",
            "api_key": "[REDACTED:API_KEY]",
        }
        # Flagged because a secret was found in params.
        assert entries[0]["flagged"] is True
        assert entries[0]["flag_reason"] == "secrets_in_params"
        # Transparency: the response the agent received is NOT redacted.
        assert response.content[0].input["api_key"] == "sk-ant-api03-supersecret"
        # And the original block input dict is untouched.
        assert secret_input["api_key"] == "sk-ant-api03-supersecret"

    async def test_clean_params_not_flagged(self, traces_dir):
        import anthropic

        canned = make_message([tool_use("read_file", {"path": "/safe"})])
        with patch.object(AsyncMessages, "create", AsyncMock(return_value=canned)):
            client = anthropic.AsyncAnthropic(api_key="test")

            @watch
            async def my_agent():
                return await client.messages.create(
                    model="m", max_tokens=16, messages=[]
                )

            await my_agent()

        entries = read_entries(traces_dir, "my_agent")
        assert entries[0]["flagged"] is False
        assert entries[0]["flag_reason"] is None

    async def test_no_tool_use_no_trace(self, traces_dir):
        import anthropic

        canned = make_message([TextBlock(type="text", text="just text")], stop_reason="end_turn")
        with patch.object(AsyncMessages, "create", AsyncMock(return_value=canned)):
            client = anthropic.AsyncAnthropic(api_key="test")

            @watch
            async def my_agent():
                return await client.messages.create(
                    model="m", max_tokens=16, messages=[]
                )

            await my_agent()

        assert read_entries(traces_dir, "my_agent") == []

    async def test_sync_client_is_intercepted(self, traces_dir):
        import anthropic

        canned = make_message([tool_use("read_file", {"path": "/sync"})])
        with patch.object(Messages, "create", MagicMock(return_value=canned)):
            client = anthropic.Anthropic(api_key="test")

            @watch
            async def my_agent():
                # Synchronous client call from within an async agent.
                return client.messages.create(model="m", max_tokens=16, messages=[])

            await my_agent()

        entries = read_entries(traces_dir, "my_agent")
        assert len(entries) == 1
        assert entries[0]["tool"] == "read_file"


# --------------------------------------------------------------------------
# Generic MCP-style tool wrapping (params + result)
# --------------------------------------------------------------------------
class TestToolWrapping:
    async def test_traces_tool_call_with_params_and_result(self, traces_dir):
        @watch.tool
        async def fetch(path):
            return {"path": path, "body": "ok"}

        @watch
        async def agent():
            return await fetch("/data")

        result = await agent()
        # Transparent: caller gets the real result.
        assert result == {"path": "/data", "body": "ok"}

        entries = read_entries(traces_dir, "agent")
        assert len(entries) == 1
        assert entries[0]["tool"] == "fetch"
        assert entries[0]["params"] == {"path": "/data"}
        assert entries[0]["result"] == {"path": "/data", "body": "ok"}

    async def test_redacts_result(self, traces_dir):
        @watch.tool
        async def get_token(path):
            return {"token": "sk-ant-api03-zzz", "path": path}

        @watch
        async def agent():
            return await get_token("/creds")

        result = await agent()
        # Transparency: real (unredacted) result returned to the agent.
        assert result["token"] == "sk-ant-api03-zzz"

        entries = read_entries(traces_dir, "agent")
        assert entries[0]["result"] == {
            "token": "[REDACTED:API_KEY]",
            "path": "/creds",
        }

    async def test_flags_secret_in_params(self, traces_dir):
        @watch.tool
        async def send(api_key, msg):
            return {"sent": True}

        @watch
        async def agent():
            return await send(api_key="sk-ant-api03-secret", msg="hi")

        await agent()
        entries = read_entries(traces_dir, "agent")
        assert entries[0]["params"] == {
            "api_key": "[REDACTED:API_KEY]",
            "msg": "hi",
        }
        assert entries[0]["flagged"] is True
        assert entries[0]["flag_reason"] == "secrets_in_params"

    async def test_tool_does_not_mutate_caller_params(self, traces_dir):
        @watch.tool
        async def use(payload):
            return "done"

        original = {"api_key": "sk-ant-api03-secret"}

        @watch
        async def agent():
            return await use(original)

        await agent()
        # The dict the caller passed in must be untouched.
        assert original == {"api_key": "sk-ant-api03-secret"}

    async def test_traces_sync_tool(self, traces_dir):
        # A plain (non-async) tool function called from within an async
        # agent: tracing is scheduled on the loop and drained on exit.
        @watch.tool
        def compute(x, y):
            return {"sum": x + y, "secret": "sk-ant-api03-zzz"}

        @watch
        async def agent():
            return compute(2, 3)

        result = await agent()
        # Transparency: caller gets the real, unredacted result.
        assert result == {"sum": 5, "secret": "sk-ant-api03-zzz"}

        entries = read_entries(traces_dir, "agent")
        assert len(entries) == 1
        assert entries[0]["tool"] == "compute"
        assert entries[0]["params"] == {"x": 2, "y": 3}
        assert entries[0]["result"] == {"sum": 5, "secret": "[REDACTED:API_KEY]"}
        assert entries[0]["flagged"] is False

    async def test_sync_tool_flags_secret_in_params(self, traces_dir):
        @watch.tool
        def store(api_key):
            return "stored"

        @watch
        async def agent():
            return store(api_key="sk-ant-api03-secret")

        await agent()
        entries = read_entries(traces_dir, "agent")
        assert entries[0]["params"] == {"api_key": "[REDACTED:API_KEY]"}
        assert entries[0]["flagged"] is True
        assert entries[0]["flag_reason"] == "secrets_in_params"

    async def test_sync_tool_outside_session_runs_without_tracing(self, traces_dir):
        @watch.tool
        def doubler(x):
            return x * 2

        assert doubler(21) == 42
        assert trace_files(traces_dir) == []

    async def test_tool_outside_session_runs_without_tracing(self, traces_dir):
        @watch.tool
        async def standalone(x):
            return x * 2

        # No @watch agent active -> just runs, writes nothing.
        assert await standalone(21) == 42
        assert trace_files(traces_dir) == []


# --------------------------------------------------------------------------
# Agent name resolution + zero config
# --------------------------------------------------------------------------
class TestAgentName:
    async def test_defaults_to_function_name(self, traces_dir):
        @watch.tool
        async def t():
            return 1

        @watch
        async def some_agent():
            return await t()

        await some_agent()
        assert read_entries(traces_dir, "some_agent")

    async def test_custom_name_argument(self, traces_dir):
        @watch.tool
        async def t():
            return 1

        @watch(name="custom")
        async def some_agent():
            return await t()

        await some_agent()
        assert read_entries(traces_dir, "custom")

    async def test_env_var_overrides_function_name(self, traces_dir, monkeypatch):
        monkeypatch.setenv("DSCAN_AGENT_NAME", "from_env")

        @watch.tool
        async def t():
            return 1

        @watch
        async def some_agent():
            return await t()

        await some_agent()
        assert read_entries(traces_dir, "from_env")

    async def test_explicit_name_beats_env_var(self, traces_dir, monkeypatch):
        monkeypatch.setenv("DSCAN_AGENT_NAME", "from_env")

        @watch.tool
        async def t():
            return 1

        @watch(name="explicit")
        async def some_agent():
            return await t()

        await some_agent()
        assert read_entries(traces_dir, "explicit")
        assert read_entries(traces_dir, "from_env") == []
