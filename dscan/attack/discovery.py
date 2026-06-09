"""Automatic agent tool discovery for dscan attack.

:class:`ToolDiscovery` builds an :class:`~dscan.attack.models.AgentContext`
from a target — a Python source file (static AST analysis, never executed),
an MCP config, an importable module, or an HTTP endpoint (introspection
probes). :meth:`ToolDiscovery.auto` picks the right strategy from the
target string. Tools are classified as destructive/exfiltrating by name
and description heuristics. No runner, detector, or CLI lives here.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import json
import re
from pathlib import Path
from typing import Optional

import aiohttp

from .models import AgentContext, AgentTool

__all__ = ["DiscoveryError", "ToolDiscovery"]


class DiscoveryError(Exception):
    pass


class ToolDiscovery:
    # ── Tool classification ───────────────────────────────────────────
    DESTRUCTIVE_PATTERNS = [
        "delete", "remove", "drop", "destroy", "truncate", "clear",
        "purge", "wipe", "erase",
    ]

    EXFILTRATING_PATTERNS = [
        "send", "post", "publish", "upload", "email", "notify", "webhook",
        "push", "export", "share", "transmit", "forward", "relay",
    ]

    @classmethod
    def classify_tool(cls, name: str, description: str = "") -> tuple[bool, bool]:
        """Return (is_destructive, is_exfiltrating)."""
        combined = (name + " " + description).lower()
        is_destructive = any(p in combined for p in cls.DESTRUCTIVE_PATTERNS)
        is_exfiltrating = any(p in combined for p in cls.EXFILTRATING_PATTERNS)
        return is_destructive, is_exfiltrating

    # ── Source file analysis ──────────────────────────────────────────
    @classmethod
    def from_source_file(cls, filepath: str) -> AgentContext:
        """Parse a Python source file with AST. Never executes the code."""
        path = Path(filepath)
        if not path.exists():
            raise DiscoveryError(f"File not found: {filepath}")

        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        context = AgentContext(source_file=filepath)
        context.framework = cls._detect_framework(source, tree)

        if context.framework == "anthropic":
            tools = cls._extract_anthropic_tools(tree)
        elif context.framework == "langchain":
            tools = cls._extract_langchain_tools(tree)
        elif context.framework == "crewai":
            tools = cls._extract_crewai_tools(tree)
        elif context.framework == "mcp":
            tools = cls._extract_mcp_tools(tree)
        else:
            tools = (
                cls._extract_anthropic_tools(tree)
                or cls._extract_langchain_tools(tree)
                or cls._extract_mcp_tools(tree)
            )

        context.tools = tools
        context.system_prompt = cls._extract_system_prompt(tree, source)
        if context.system_prompt:
            context.goal = cls._extract_goal(context.system_prompt)
        return context

    @classmethod
    def _detect_framework(cls, source: str, tree: ast.AST) -> str:
        lower = source.lower()
        if "client.messages.create" in source or "anthropic" in lower:
            return "anthropic"
        if "@tool" in source and ("langchain" in lower or "from langchain" in source):
            return "langchain"
        if "crewai" in lower or ("class" in source and "Agent" in source and "tools" in source):
            return "crewai"
        if "@mcp.tool" in source or "mcp.tool()" in source:
            return "mcp"
        return "unknown"

    @classmethod
    def _extract_anthropic_tools(cls, tree: ast.AST) -> list[AgentTool]:
        """Find tools defined as ``tools=[{...}]`` (keyword) or ``tools = [{...}]``."""
        tools: list[AgentTool] = []
        seen: set[str] = set()
        for node in ast.walk(tree):
            list_node: Optional[ast.List] = None
            if (
                isinstance(node, ast.keyword)
                and node.arg == "tools"
                and isinstance(node.value, ast.List)
            ):
                list_node = node.value
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.List):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "tools":
                        list_node = node.value
            if list_node is None:
                continue
            for elt in list_node.elts:
                if isinstance(elt, ast.Dict):
                    tool = cls._dict_to_tool(elt)
                    if tool and tool.name not in seen:
                        seen.add(tool.name)
                        tools.append(tool)
        return tools

    @classmethod
    def _extract_langchain_tools(cls, tree: ast.AST) -> list[AgentTool]:
        """Find ``@tool`` decorated functions, using name + docstring."""
        tools: list[AgentTool] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                name = ""
                if isinstance(decorator, ast.Name):
                    name = decorator.id
                elif isinstance(decorator, ast.Attribute):
                    name = decorator.attr
                if name == "tool":
                    docstring = ast.get_docstring(node) or ""
                    is_dest, is_exfil = cls.classify_tool(node.name, docstring)
                    tools.append(
                        AgentTool(node.name, docstring, is_destructive=is_dest, is_exfiltrating=is_exfil)
                    )
        return tools

    @classmethod
    def _extract_mcp_tools(cls, tree: ast.AST) -> list[AgentTool]:
        """Find ``@mcp.tool()`` decorated functions."""
        tools: list[AgentTool] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                func = decorator.func
                is_mcp_tool = (
                    isinstance(func, ast.Attribute) and func.attr == "tool"
                ) or (isinstance(func, ast.Name) and func.id == "tool")
                if is_mcp_tool:
                    docstring = ast.get_docstring(node) or ""
                    is_dest, is_exfil = cls.classify_tool(node.name, docstring)
                    tools.append(
                        AgentTool(node.name, docstring, is_destructive=is_dest, is_exfiltrating=is_exfil)
                    )
        return tools

    @classmethod
    def _extract_crewai_tools(cls, tree: ast.AST) -> list[AgentTool]:
        """Find ``tools = [ToolClass()]`` in class bodies."""
        tools: list[AgentTool] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                for target in item.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "tools"
                        and isinstance(item.value, ast.List)
                    ):
                        for elt in item.value.elts:
                            name = cls._get_call_name(elt)
                            if name:
                                is_dest, is_exfil = cls.classify_tool(name)
                                tools.append(
                                    AgentTool(name, "", is_destructive=is_dest, is_exfiltrating=is_exfil)
                                )
        return tools

    @classmethod
    def _extract_system_prompt(cls, tree: ast.AST, source: str) -> str:
        """Find ``SYSTEM_PROMPT = "..."`` (or similar) and return the string."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and "system" in target.id.lower()
                    and "prompt" in target.id.lower()
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    return node.value.value
        return ""

    @classmethod
    def _extract_goal(cls, system_prompt: str) -> str:
        """Extract a goal phrase from the system prompt, if present."""
        patterns = [
            r"[Yy]our goal is to (.+?)[\.\n]",
            r"[Yy]our task is to (.+?)[\.\n]",
            r"[Yy]ou are (?:a|an) .+? that (.+?)[\.\n]",
            r"[Yy]ou help (?:users?|people) (.+?)[\.\n]",
        ]
        for pattern in patterns:
            match = re.search(pattern, system_prompt)
            if match:
                return match.group(1).strip()
        return ""

    @classmethod
    def _dict_to_tool(cls, node: ast.Dict) -> Optional[AgentTool]:
        name = ""
        description = ""
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(value, ast.Constant):
                if key.value == "name":
                    name = value.value
                elif key.value == "description":
                    description = value.value
        if name:
            is_dest, is_exfil = cls.classify_tool(name, description)
            return AgentTool(name, description, is_destructive=is_dest, is_exfiltrating=is_exfil)
        return None

    @classmethod
    def _get_call_name(cls, node: ast.expr) -> str:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                return node.func.id
            if isinstance(node.func, ast.Attribute):
                return node.func.attr
        return ""

    # ── MCP config parsing ────────────────────────────────────────────
    @classmethod
    def from_mcp_config(cls, config_path: str) -> AgentContext:
        path = Path(config_path)
        if not path.exists():
            raise DiscoveryError(f"MCP config not found: {config_path}")
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise DiscoveryError(f"Invalid JSON in MCP config: {config_path}: {exc}") from exc

        context = AgentContext(source_file=config_path, framework="mcp")
        tools: list[AgentTool] = []
        for server_name, server_config in (config.get("mcpServers") or {}).items():
            args = server_config.get("args", []) if isinstance(server_config, dict) else []
            description = " ".join(str(a) for a in args)
            is_dest, is_exfil = cls.classify_tool(server_name, description)
            tools.append(
                AgentTool(server_name, description, is_destructive=is_dest, is_exfiltrating=is_exfil)
            )
        context.tools = tools
        return context

    # ── HTTP introspection ────────────────────────────────────────────
    @classmethod
    async def from_http_async(cls, url: str) -> AgentContext:
        """Probe common introspection endpoints for tool definitions."""
        rest = url.split("://", 1)[-1]
        base = url.rstrip("/").rsplit("/", 1)[0] if "/" in rest else url.rstrip("/")
        probe_urls = [
            f"{base}/tools",
            f"{base}/.well-known/agent.json",
            f"{base}/openapi.json",
            f"{base}/api/tools",
        ]
        context = AgentContext(framework="unknown")
        try:
            async with aiohttp.ClientSession() as session:
                for probe_url in probe_urls:
                    try:
                        async with session.get(
                            probe_url, timeout=aiohttp.ClientTimeout(total=5)
                        ) as resp:
                            if resp.status != 200:
                                continue
                            data = await resp.json()
                            tools = cls._parse_http_tools(data, probe_url)
                            framework = cls._detect_http_framework(probe_url, data)
                            if tools or framework != "unknown":
                                context.tools = tools
                                context.framework = framework
                                return context
                    except aiohttp.ClientConnectorError:
                        raise  # unreachable host -> handled below
                    except aiohttp.ClientError:
                        continue
        except aiohttp.ClientConnectorError as exc:
            raise DiscoveryError(
                f"Cannot connect to agent at {url}. Is the agent running?"
            ) from exc
        return context

    @classmethod
    def from_http(cls, url: str) -> AgentContext:
        """Synchronous wrapper for :meth:`from_http_async`."""
        return asyncio.run(cls.from_http_async(url))

    @classmethod
    def _parse_http_tools(cls, data: dict, probe_url: str) -> list[AgentTool]:
        raw_tools: list = []
        if isinstance(data, dict) and "tools" in data:
            raw_tools = data["tools"]
        elif isinstance(data, dict) and "paths" in data:
            for path, methods in (data.get("paths") or {}).items():
                if not isinstance(methods, dict):
                    continue
                for method, spec in methods.items():
                    if method in ("post", "put") and isinstance(spec, dict):
                        raw_tools.append(
                            {"name": spec.get("operationId", path), "description": spec.get("summary", "")}
                        )

        tools: list[AgentTool] = []
        for tool_def in raw_tools:
            if isinstance(tool_def, dict) and "name" in tool_def:
                name = tool_def["name"]
                desc = tool_def.get("description", "")
                params = tool_def.get("parameters", {})
                is_dest, is_exfil = cls.classify_tool(name, desc)
                tools.append(
                    AgentTool(name, desc, parameters=params, is_destructive=is_dest, is_exfiltrating=is_exfil)
                )
        return tools

    @classmethod
    def _detect_http_framework(cls, probe_url: str, data: dict) -> str:
        if "openapi" in probe_url:
            return "openapi"
        if isinstance(data, dict) and "tools" in data:
            return "openai_compatible"
        return "unknown"

    # ── Module introspection ──────────────────────────────────────────
    @classmethod
    def from_module(cls, module_path: str) -> AgentContext:
        """Import a module and introspect its tool registries (import-time only)."""
        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise DiscoveryError(
                f"Cannot import module '{module_path}'. Check the module path and "
                f"ensure dependencies are installed. Error: {exc}"
            ) from exc

        context = AgentContext()
        tools: list[AgentTool] = []
        for attr_name in dir(module):
            attr = getattr(module, attr_name, None)
            if attr is None:
                continue
            if hasattr(attr, "name") and hasattr(attr, "description") and callable(attr):
                is_dest, is_exfil = cls.classify_tool(str(attr.name), str(attr.description))
                tools.append(
                    AgentTool(str(attr.name), str(attr.description), is_destructive=is_dest, is_exfiltrating=is_exfil)
                )
            elif isinstance(attr, list) and attr_name == "tools":
                for item in attr:
                    if hasattr(item, "name"):
                        desc = str(getattr(item, "description", ""))
                        is_dest, is_exfil = cls.classify_tool(str(item.name), desc)
                        tools.append(
                            AgentTool(str(item.name), desc, is_destructive=is_dest, is_exfiltrating=is_exfil)
                        )
        context.tools = tools
        return context

    # ── Auto discovery ────────────────────────────────────────────────
    @classmethod
    def auto(cls, target: str) -> AgentContext:
        """Detect the target type and run the appropriate discovery method."""
        target = target.strip()
        if target.startswith(("http://", "https://")):
            return cls.from_http(target)

        path = Path(target)
        if path.suffix == ".json":
            return cls.from_mcp_config(target)
        if path.suffix == ".py":
            for mcp_name in (".cursor/mcp.json", "claude_desktop_config.json", "mcp.json"):
                if (path.parent / mcp_name).exists():
                    return cls.from_mcp_config(str(path.parent / mcp_name))
            return cls.from_source_file(target)
        if path.is_dir():
            for candidate in (
                path / ".cursor" / "mcp.json",
                path / "mcp.json",
                path / "claude_desktop_config.json",
                path / "agent.py",
                path / "main.py",
            ):
                if candidate.exists():
                    return cls.auto(str(candidate))
            raise DiscoveryError(
                f"No agent files found in {target}. Expected: agent.py, main.py, or mcp.json"
            )
        if "." in target and not path.exists():
            return cls.from_module(target)

        raise DiscoveryError(
            f"Cannot determine target type for: {target}\n"
            "Supported formats:\n"
            "  dscan attack ./agent.py        (Python file)\n"
            "  dscan attack --url http://...  (HTTP endpoint)\n"
            "  dscan attack .cursor/mcp.json  (MCP config)\n"
            "  dscan attack myapp.agent       (Python module)"
        )
