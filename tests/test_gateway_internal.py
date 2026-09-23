"""Tests for gateway/internal.py — trentina's own tools as an in-process backend."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.types import TextContent, ToolAnnotations
from mcp.types import Tool as McpTool

from mcp_trentina_crunchtools.gateway import internal
from mcp_trentina_crunchtools.gateway.errors import BackendCallError


class _FakeFunctionTool:
    """Stands in for a FastMCP FunctionTool: to_mcp_tool() and run()."""

    def __init__(self, mcp_tool: McpTool) -> None:
        self._mcp_tool = mcp_tool
        self.name = mcp_tool.name
        self._result: _FakeResult | None = None
        self._raise: Exception | None = None
        self.calls: list[dict[str, Any]] = []

    def to_mcp_tool(self) -> McpTool:
        return self._mcp_tool

    async def run(self, arguments: dict[str, Any]) -> _FakeResult:
        self.calls.append(arguments)
        if self._raise is not None:
            raise self._raise
        assert self._result is not None
        return self._result


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
    """Minimal FastMCP stand-in mirroring the real 4.x surface.

    FastMCP has no ``call_tool``; a caller resolves the tool with ``get_tool``
    and invokes ``Tool.run``. This fake must not grow methods the real class
    lacks, nor keep ones it has dropped -- ``TestFakeMatchesRealFastMcp``
    enforces both directions.

    Tool enumeration is ``list_tools()`` returning a list: fastmcp 4 removed
    the 2.x ``get_tools()`` dict. ``_FakeLegacyServer`` below covers the old
    shape, which ``internal._walk_server_tools`` still accepts.
    """

    name = "fake-trentina"

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

    async def list_tools(self) -> list[_FakeFunctionTool]:
        if self._raise_on_list is not None:
            raise self._raise_on_list
        return list(self._tools)

    async def get_tool(self, name: str) -> _FakeFunctionTool:
        for tool in self._tools:
            if tool.name == name:
                tool._result = self._call_result
                tool._raise = self._raise_on_call
                return tool
        raise KeyError(f"unknown tool: {name}")

    @property
    def calls(self) -> list[tuple[str, dict[str, Any]]]:
        """Every (tool name, arguments) pair run through this server."""
        return [(t.name, args) for t in self._tools for args in t.calls]


class _FakeLegacyServer:
    """A fastmcp 2.x-shaped server: ``get_tools()`` returning a name->tool dict.

    Not a drift risk -- it deliberately models a framework generation trentina
    no longer installs, to prove ``_walk_server_tools`` still accepts a backend
    running the older shape.
    """

    name = "fake-legacy-trentina"

    def __init__(self, tools: list[_FakeFunctionTool]) -> None:
        self._tools = tools

    async def get_tools(self) -> dict[str, _FakeFunctionTool]:
        return {t.name: t for t in self._tools}


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
            await internal.call_internal_tool("block_fetch_tool", {})

    async def test_register_then_listed(self) -> None:
        server = _FakeServer([_tool("block_fetch_tool"), _tool("quarantine_stats_tool")])
        internal.register_internal_server(server)
        assert internal.internal_server_registered() is True

        tools = await internal.list_internal_tools()
        names = sorted(t["name"] for t in tools)
        assert names == ["block_fetch_tool", "quarantine_stats_tool"]
        sample = tools[0]
        assert "description" in sample
        assert sample["inputSchema"] == {"type": "object", "properties": {}}

    async def test_tools_with_annotations_serialize_to_json(self) -> None:
        """Regression: a tool whose annotations is a pydantic ToolAnnotations
        model must serialize to a JSON-able dict, not blow up json.dumps."""
        annotated = _FakeFunctionTool(
            McpTool(
                name="block_fetch_tool",
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
        server = _FakeServer([_tool("block_fetch_tool")], call_result=result)
        internal.register_internal_server(server)
        call = await internal.call_internal_tool("block_fetch_tool", {"url": "http://x"})
        assert server.calls == [("block_fetch_tool", {"url": "http://x"})]
        assert call.content == [{"type": "text", "text": "hello"}]
        assert call.is_error is False
        assert call.structured_content == {"answer": 42}

    async def test_call_propagates_is_error(self) -> None:
        result = _FakeResult(
            content=[TextContent(type="text", text="boom")], is_error=True
        )
        server = _FakeServer([_tool("block_fetch_tool")], call_result=result)
        internal.register_internal_server(server)
        call = await internal.call_internal_tool("block_fetch_tool", {})
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
async def test_real_trentina_server_lists_its_tools() -> None:
    """Integration smoke test: the real FastMCP server's tools serialize cleanly.

    Metadata only — no tool is executed, so this stays offline and DB-free. It
    guards the to_mcp_tool() path against the installed FastMCP version.
    """
    from mcp_trentina_crunchtools.server import mcp

    saved = internal._server
    try:
        internal.register_internal_server(mcp)
        tools = await internal.list_internal_tools()
    finally:
        internal._server = saved

    names = {t["name"] for t in tools}
    assert "block_fetch_tool" in names
    assert "quarantine_stats_tool" in names
    for t in tools:
        assert isinstance(t["name"], str) and t["name"]
        assert "inputSchema" in t


class TestFakeMatchesRealFastMcp:
    """Guards against the fake drifting from the real FastMCP surface.

    The internal dispatch path broke because ``_FakeServer`` implemented a
    ``call_tool`` method that FastMCP 2.x does not have, so every test
    passed while production raised AttributeError on every internal tool.

    That guard was one-directional and so missed the mirror-image failure:
    fastmcp 4 *removed* ``get_tools()``, and a fake still implementing it kept
    passing while production raised AttributeError on every internal tool for
    the second time. Both directions are checked now.
    """

    def test_fake_only_implements_methods_the_real_class_has(self) -> None:
        from fastmcp import FastMCP

        fake_methods = {
            name
            for name in dir(_FakeServer)
            if not name.startswith("_") and callable(getattr(_FakeServer, name))
        }
        missing = {m for m in fake_methods if not hasattr(FastMCP, m)}
        assert not missing, (
            f"_FakeServer implements methods FastMCP lacks: {sorted(missing)}. "
            "The fake has drifted from the real API."
        )

    async def test_legacy_get_tools_dict_still_accepted(self) -> None:
        """A fastmcp 2.x-shaped server still enumerates.

        The gateway must not be pinned to one framework generation by its own
        internal backend, so the dict-returning ``get_tools()`` shape stays
        supported even though trentina now installs fastmcp 4.
        """
        internal.register_internal_server(_FakeLegacyServer([_tool("legacy_tool")]))

        tools = await internal.list_internal_tools()

        assert [t["name"] for t in tools] == ["legacy_tool"]

    async def test_server_with_neither_enumeration_method_fails_loudly(self) -> None:
        class _Bare:
            name = "bare"

        internal.register_internal_server(_Bare())

        with pytest.raises(BackendCallError, match="internal list_tools failed"):
            await internal.list_internal_tools()

    def test_methods_the_gateway_calls_still_exist_on_real_fastmcp(self) -> None:
        """The other direction: the real class dropping something we call.

        ``_walk_server_tools`` tries ``list_tools`` then ``get_tools``; at
        least one must be real, or the internal backend is dead in production
        while every fake-backed test still passes.
        """
        from fastmcp import FastMCP

        assert any(
            hasattr(FastMCP, m) for m in ("list_tools", "get_tools")
        ), "FastMCP exposes neither list_tools nor get_tools"

        for method in ("get_tool", "custom_route"):
            assert hasattr(FastMCP, method), (
                f"FastMCP no longer exposes {method!r}, which the gateway calls."
            )

    async def test_real_fastmcp_dispatch_round_trip(self) -> None:
        """call_internal_tool against a genuine FastMCP instance."""
        from fastmcp import FastMCP

        server: FastMCP = FastMCP("test-trentina")

        @server.tool()
        def echo_tool(value: str) -> str:
            """Echo the supplied value."""
            return f"echoed:{value}"

        internal.register_internal_server(server)

        tools = await internal.list_internal_tools()
        assert [t["name"] for t in tools] == ["echo_tool"]

        call = await internal.call_internal_tool("echo_tool", {"value": "hi"})
        assert call.is_error is False
        assert any("echoed:hi" in block.get("text", "") for block in call.content)

    async def test_real_fastmcp_unknown_tool_raises_backendcallerror(self) -> None:
        from fastmcp import FastMCP

        server: FastMCP = FastMCP("test-trentina")
        internal.register_internal_server(server)
        with pytest.raises(BackendCallError, match="call failed"):
            await internal.call_internal_tool("nope_tool", {})
