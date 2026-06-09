"""Tests for dscan.attack.discovery — automatic tool detection.

HTTP probing is mocked at the aiohttp boundary; no real network calls.
Module imports use temp files added to sys.path and cleaned up after.
"""

import json
import sys

import aiohttp
import pytest

from dscan.attack.discovery import DiscoveryError, ToolDiscovery
from dscan.attack.models import AgentContext


def write(tmp_path, content, name="agent.py"):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return str(p)


# ==========================================================================
# Source file analysis
# ==========================================================================
class TestSourceFile:
    def test_anthropic(self, tmp_path):
        src = (
            "import anthropic\n"
            "client = anthropic.Anthropic()\n"
            "tools = [\n"
            '    {"name": "search_web", "description": "Search the web"},\n'
            '    {"name": "send_email", "description": "Send an email"},\n'
            "]\n"
            "response = client.messages.create(model='claude-3-5-sonnet', tools=tools)\n"
        )
        ctx = ToolDiscovery.from_source_file(write(tmp_path, src))
        assert set(ctx.tool_names) == {"search_web", "send_email"}
        assert ctx.framework == "anthropic"

    def test_langchain(self, tmp_path):
        src = (
            "from langchain_core.tools import tool\n\n"
            "@tool\n"
            "def search_web(query: str) -> str:\n"
            '    """Search the web for information"""\n'
            "    return ''\n\n"
            "@tool\n"
            "def send_email(to: str, body: str) -> str:\n"
            '    """Send an email to the specified address"""\n'
            "    return ''\n"
        )
        ctx = ToolDiscovery.from_source_file(write(tmp_path, src))
        assert set(ctx.tool_names) == {"search_web", "send_email"}
        assert ctx.framework == "langchain"
        send = next(t for t in ctx.tools if t.name == "send_email")
        assert send.is_exfiltrating is True

    def test_crewai(self, tmp_path):
        src = (
            "from crewai import Agent\n\n"
            "class MyAgent(Agent):\n"
            "    tools = [SearchTool(), EmailTool()]\n"
        )
        ctx = ToolDiscovery.from_source_file(write(tmp_path, src))
        assert set(ctx.tool_names) == {"SearchTool", "EmailTool"}
        assert ctx.framework == "crewai"

    def test_mcp(self, tmp_path):
        src = (
            "from mcp.server.fastmcp import FastMCP\n"
            "mcp = FastMCP('demo')\n\n"
            "@mcp.tool()\n"
            "def read_file(path: str) -> str:\n"
            '    """Read a file from the filesystem"""\n'
            "    return ''\n"
        )
        ctx = ToolDiscovery.from_source_file(write(tmp_path, src))
        assert ctx.tool_names == ["read_file"]
        assert ctx.framework == "mcp"

    def test_system_prompt(self, tmp_path):
        src = (
            'SYSTEM_PROMPT = """You are a helpful assistant\n'
            'that searches the web and sends email reports."""\n'
        )
        ctx = ToolDiscovery.from_source_file(write(tmp_path, src))
        assert "helpful assistant" in ctx.system_prompt

    def test_goal_detection(self, tmp_path):
        src = 'SYSTEM_PROMPT = "Your goal is to summarize documents."\n'
        ctx = ToolDiscovery.from_source_file(write(tmp_path, src))
        assert ctx.goal == "summarize documents"

    def test_no_tools(self, tmp_path):
        src = "x = 1\n\ndef foo():\n    return 2\n"
        ctx = ToolDiscovery.from_source_file(write(tmp_path, src))
        assert ctx.tools == []
        assert ctx.framework == "unknown"

    def test_file_not_found(self):
        with pytest.raises(DiscoveryError, match="File not found"):
            ToolDiscovery.from_source_file("/no/such/file_xyz.py")


# ==========================================================================
# MCP config
# ==========================================================================
_MCP_CONFIG = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem"],
            "env": {},
        },
        "search": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-brave-search"],
        },
    }
}


class TestMcpConfig:
    def test_cursor_mcp_json(self, tmp_path):
        path = write(tmp_path, json.dumps(_MCP_CONFIG), name="mcp.json")
        ctx = ToolDiscovery.from_mcp_config(path)
        assert set(ctx.tool_names) == {"filesystem", "search"}
        assert ctx.framework == "mcp"

    def test_claude_desktop_config(self, tmp_path):
        path = write(tmp_path, json.dumps(_MCP_CONFIG), name="claude_desktop_config.json")
        ctx = ToolDiscovery.from_mcp_config(path)
        assert set(ctx.tool_names) == {"filesystem", "search"}
        assert ctx.framework == "mcp"

    def test_no_servers_key(self, tmp_path):
        path = write(tmp_path, json.dumps({"other": 1}), name="mcp.json")
        ctx = ToolDiscovery.from_mcp_config(path)
        assert ctx.tools == []

    def test_not_found(self):
        with pytest.raises(DiscoveryError, match="MCP config not found"):
            ToolDiscovery.from_mcp_config("/no/such/mcp.json")

    def test_invalid_json(self, tmp_path):
        path = write(tmp_path, "{not valid json", name="mcp.json")
        with pytest.raises(DiscoveryError, match="Invalid JSON"):
            ToolDiscovery.from_mcp_config(path)


# ==========================================================================
# HTTP introspection (mocked aiohttp)
# ==========================================================================
class _FakeResp:
    def __init__(self, status, payload):
        self.status = status
        self._payload = payload

    async def json(self):
        return self._payload


class _FakeReqCM:
    def __init__(self, entry):
        self._entry = entry

    async def __aenter__(self):
        if isinstance(self._entry, BaseException):
            raise self._entry
        status, payload = self._entry
        return _FakeResp(status, payload)

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    routes: dict = {}

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, timeout=None):
        return _FakeReqCM(_FakeSession.routes.get(url, (404, {})))


@pytest.fixture
def http_routes(monkeypatch):
    _FakeSession.routes = {}
    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)
    return _FakeSession


class TestHttp:
    BASE = "http://localhost:8080"

    def test_tools_endpoint(self, http_routes):
        http_routes.routes = {
            f"{self.BASE}/tools": (
                200,
                {
                    "tools": [
                        {"name": "search", "description": "Search web",
                         "parameters": {"query": {"type": "string"}}},
                        {"name": "send_email", "description": "Send email",
                         "parameters": {"to": {"type": "string"}}},
                    ]
                },
            )
        }
        ctx = ToolDiscovery.from_http(self.BASE)
        assert set(ctx.tool_names) == {"search", "send_email"}
        assert ctx.framework == "openai_compatible"

    def test_openapi(self, http_routes):
        http_routes.routes = {
            f"{self.BASE}/openapi.json": (
                200,
                {
                    "openapi": "3.0.0",
                    "info": {"title": "agent", "version": "1"},
                    "paths": {"/chat": {"post": {"summary": "Chat"}}},
                },
            )
        }
        ctx = ToolDiscovery.from_http(self.BASE)
        assert ctx.framework == "openapi"

    def test_no_endpoint(self, http_routes):
        http_routes.routes = {}  # everything 404
        ctx = ToolDiscovery.from_http(self.BASE)
        assert ctx.tools == []
        assert ctx.framework == "unknown"

    def test_connection_refused(self, http_routes):
        err = aiohttp.ClientConnectorError.__new__(aiohttp.ClientConnectorError)
        http_routes.routes = {f"{self.BASE}/tools": err}
        with pytest.raises(DiscoveryError, match="Is the agent running"):
            ToolDiscovery.from_http(self.BASE)


# ==========================================================================
# Module introspection
# ==========================================================================
_MODULE_SRC = (
    "class _Tool:\n"
    "    def __init__(self, name, description):\n"
    "        self.name = name\n"
    "        self.description = description\n"
    "    def __call__(self, *a, **k):\n"
    "        return None\n\n"
    "search_web = _Tool('search_web', 'Search the web')\n"
    "send_email = _Tool('send_email', 'Send an email')\n"
)


class TestModule:
    def test_from_module(self, tmp_path):
        mod_name = "dscan_test_agent_mod"
        (tmp_path / f"{mod_name}.py").write_text(_MODULE_SRC, encoding="utf-8")
        sys.path.insert(0, str(tmp_path))
        try:
            ctx = ToolDiscovery.from_module(mod_name)
            assert set(ctx.tool_names) == {"search_web", "send_email"}
        finally:
            sys.path.remove(str(tmp_path))
            sys.modules.pop(mod_name, None)

    def test_module_not_found(self):
        with pytest.raises(DiscoveryError, match="Cannot import module"):
            ToolDiscovery.from_module("myapp.agents.missing_xyz_123")


# ==========================================================================
# Auto discovery
# ==========================================================================
class TestAuto:
    def test_python_file(self, tmp_path, monkeypatch):
        from unittest.mock import MagicMock

        spy = MagicMock(return_value=AgentContext())
        monkeypatch.setattr(ToolDiscovery, "from_source_file", spy)
        path = write(tmp_path, "x = 1\n")
        ToolDiscovery.auto(path)
        spy.assert_called_once_with(path)

    def test_url(self, monkeypatch):
        from unittest.mock import MagicMock

        spy = MagicMock(return_value=AgentContext())
        monkeypatch.setattr(ToolDiscovery, "from_http", spy)
        ToolDiscovery.auto("http://localhost:9000")
        spy.assert_called_once_with("http://localhost:9000")

    def test_module(self, monkeypatch):
        from unittest.mock import MagicMock

        spy = MagicMock(return_value=AgentContext())
        monkeypatch.setattr(ToolDiscovery, "from_module", spy)
        ToolDiscovery.auto("myapp.agents.search")
        spy.assert_called_once_with("myapp.agents.search")

    def test_mcp_config(self, monkeypatch):
        from unittest.mock import MagicMock

        spy = MagicMock(return_value=AgentContext())
        monkeypatch.setattr(ToolDiscovery, "from_mcp_config", spy)
        ToolDiscovery.auto("config.json")
        spy.assert_called_once_with("config.json")

    def test_directory(self, tmp_path):
        write(tmp_path, "x = 1\n", name="agent.py")
        ctx = ToolDiscovery.auto(str(tmp_path))
        assert isinstance(ctx, AgentContext)

    def test_empty_directory(self, tmp_path):
        with pytest.raises(DiscoveryError, match="No agent files found"):
            ToolDiscovery.auto(str(tmp_path))

    def test_unknown_target(self):
        with pytest.raises(DiscoveryError, match="Supported formats"):
            ToolDiscovery.auto("not_a_valid_target")


# ==========================================================================
# Tool classification
# ==========================================================================
class TestClassification:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("delete_file", True),
            ("remove_user", True),
            ("drop_table", True),
            ("search_web", False),
            ("read_file", False),
        ],
    )
    def test_is_destructive(self, name, expected):
        assert ToolDiscovery.classify_tool(name)[0] is expected

    @pytest.mark.parametrize(
        "name,expected",
        [
            ("send_email", True),
            ("post_webhook", True),
            ("upload_file", True),
            ("read_file", False),
            ("search_web", False),
        ],
    )
    def test_is_exfiltrating(self, name, expected):
        assert ToolDiscovery.classify_tool(name)[1] is expected
