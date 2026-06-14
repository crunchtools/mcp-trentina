"""Tests for gateway/internal.py — airlock's own tools as an in-process backend."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.types import TextContent, ToolAnnotations
from mcp.types import Tool as McpTool

from mcp_airlock_crunchtools.gateway import internal
from mcp_airlock_crunchtools.gateway.errors import BackendCallError


class _FakeFunctionTool:
    """Stands in for a FastMCP FunctionTool: only to_mcp_tool() is exercised."""

    def __init__(self, mcp_tool: McpTool) -> None:
        self._mcp_tool = mcp_tool

    def to_mcp_tool(self) -> McpTool:
        return self._mcp_tool


class _FakeResult:
    """Stands in for a FastMCP ToolResult."""

    def __init__(
        self,
        content: list[Any],
        structured_content: dict[str, Any] | None = None,
        is_error: bool = False,
    ) -> None:
        self.content = content
        self.structured_content = structured_content
        self.is_error = is_error


class _FakeServer:
    """Minimal FastMCP stand-in: list_tools() + call_tool()."""

    name = "fake-airlock"

    def __init__(
        self,
        tools: list[_FakeFunctionTool],
        call_result: _FakeResult | None = None,
        raise_on_list: Exception | None = None,
        raise_on_call: Exception | None = None,
    ) -> None:
        self._tools = tools
        self._call_result = call_result
        self._raise_on_list = raise_on_list
        self._raise_on_call = raise_on_call
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[_FakeFunctionTool]:
        if self._raise_on_list is not None:
            raise self._raise_on_list
        return self._tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> _FakeResult:
        self.calls.append((name, arguments))
        if self._raise_on_call is not None:
            raise self._raise_on_call
        assert self._call_result is not None
        return self._call_result


def _tool(name: str) -> _FakeFunctionTool:
    return _FakeFunctionTool(
        McpTool(
            name=name,
            description=f"{name} description",
            inputSchema={"type": "object", "properties": {}},
        )
    )


@pytest.fixture(autouse=True)
def _restore_server() -> Iterator[None]:
    """Save and restore the module-level singleton around every test."""
    saved = internal._server
    try:
        yield
    finally:
        internal._server = saved


@pytest.mark.asyncio
class TestInternalBackend:
    """list/call dispatch against the bound FastMCP server."""

    async def test_not_registered_raises(self) -> None:
        internal._server = None
        assert internal.internal_server_registered() is False
        with pytest.raises(BackendCallError, match="not registered"):
            await internal.list_internal_tools()
        with pytest.raises(BackendCallError, match="not registered"):
            await internal.call_internal_tool("safe_fetch_tool", {})

    async def test_register_then_listed(self) -> None:
        server = _FakeServer([_tool("safe_fetch_tool"), _tool("quarantine_stats_tool")])
        internal.register_internal_server(server)
        assert internal.internal_server_registered() is True

        tools = await internal.list_internal_tools()
        names = sorted(t["name"] for t in tools)
        assert names == ["quarantine_stats_tool", "safe_fetch_tool"]
        sample = tools[0]
        assert "description" in sample
        assert sample["inputSchema"] == {"type": "object", "properties": {}}

    async def test_tools_with_annotations_serialize_to_json(self) -> None:
        """Regression: a tool whose annotations is a pydantic ToolAnnotations
        model must serialize to a JSON-able dict, not blow up json.dumps."""
        annotated = _FakeFunctionTool(
            McpTool(
                name="safe_fetch_tool",
                description="d",
                inputSchema={"type": "object", "properties": {}},
                annotations=ToolAnnotations(title="Safe Fetch", readOnlyHint=True),
            )
        )
        internal.register_internal_server(_FakeServer([annotated]))
        tools = await internal.list_internal_tools()
        assert isinstance(tools[0]["annotations"], dict)
        assert tools[0]["annotations"]["title"] == "Safe Fetch"
        json.dumps(tools)  # must not raise

    async def test_call_returns_backendcall(self) -> None:
        result = _FakeResult(
            content=[TextContent(type="text", text="hello")],
            structured_content={"answer": 42},
            is_error=False,
        )
        server = _FakeServer([_tool("safe_fetch_tool")], call_result=result)
        internal.register_internal_server(server)
        call = await internal.call_internal_tool("safe_fetch_tool", {"url": "http://x"})
        assert server.calls == [("safe_fetch_tool", {"url": "http://x"})]
        assert call.content == [{"type": "text", "text": "hello"}]
        assert call.is_error is False
        assert call.structured_content == {"answer": 42}

    async def test_call_propagates_is_error(self) -> None:
        result = _FakeResult(
            content=[TextContent(type="text", text="boom")], is_error=True
        )
        server = _FakeServer([_tool("safe_fetch_tool")], call_result=result)
        internal.register_internal_server(server)
        call = await internal.call_internal_tool("safe_fetch_tool", {})
        assert call.is_error is True

    async def test_list_wraps_failure_in_backendcallerror(self) -> None:
        server = _FakeServer([], raise_on_list=RuntimeError("walk failed"))
        internal.register_internal_server(server)
        with pytest.raises(BackendCallError, match="internal list_tools failed"):
            await internal.list_internal_tools()

    async def test_call_wraps_failure_in_backendcallerror(self) -> None:
        server = _FakeServer([], raise_on_call=KeyError("no such tool"))
        internal.register_internal_server(server)
        with pytest.raises(BackendCallError, match="call failed"):
            await internal.call_internal_tool("nope", {})


@pytest.mark.asyncio
async def test_real_airlock_server_lists_its_tools() -> None:
    """Integration smoke test: the real FastMCP server's tools serialize cleanly.

    Metadata only — no tool is executed, so this stays offline and DB-free. It
    guards the to_mcp_tool() path against the installed FastMCP version.
    """
    from mcp_airlock_crunchtools.server import mcp

    saved = internal._server
    try:
        internal.register_internal_server(mcp)
        tools = await internal.list_internal_tools()
    finally:
        internal._server = saved

    names = {t["name"] for t in tools}
    assert "safe_fetch_tool" in names
    assert "quarantine_stats_tool" in names
    for t in tools:
        assert isinstance(t["name"], str) and t["name"]
        assert "inputSchema" in t
