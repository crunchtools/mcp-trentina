"""Tests for gateway/filter.py — tools/list allowlist filter."""

from __future__ import annotations

from typing import Any

from mcp_trentina_crunchtools.gateway.filter import filter_tools
from mcp_trentina_crunchtools.gateway.profile import Backend


def _tool(name: str) -> dict[str, Any]:
    """Build a minimal MCP tool dict for testing."""
    return {"name": name, "description": f"tool {name}", "inputSchema": {}}


def _backend(allow: list[str], deny: list[str] | None = None) -> Backend:
    """Build a Backend with the given allow/deny patterns for testing."""
    return Backend(url="http://x/mcp", tools_allow=allow, tools_deny=deny or [])


def _names(tools: list[dict[str, Any]]) -> list[str]:
    """Pull out tool names as a list of plain strings for stable sorting."""
    return sorted(str(t["name"]) for t in tools)


class TestFilter:
    """Filter behaviour across allowlist, denylist, and glob patterns."""

    def test_wildcard_allow_keeps_all(self) -> None:
        tools = [_tool("a"), _tool("b"), _tool("c")]
        out = filter_tools(tools, _backend(["*"]))
        assert _names(out) == ["a", "b", "c"]

    def test_exact_allow_only(self) -> None:
        tools = [_tool("a"), _tool("b"), _tool("c")]
        out = filter_tools(tools, _backend(["a", "c"]))
        assert _names(out) == ["a", "c"]

    def test_prefix_glob_allow(self) -> None:
        tools = [_tool("get_x"), _tool("get_y"), _tool("delete_z")]
        out = filter_tools(tools, _backend(["get_*"]))
        assert _names(out) == ["get_x", "get_y"]

    def test_deny_wins_over_allow(self) -> None:
        tools = [_tool("delete_post"), _tool("delete_page"), _tool("get_post")]
        out = filter_tools(tools, _backend(["*"], deny=["delete_*"]))
        assert _names(out) == ["get_post"]

    def test_specific_deny_with_wildcard_allow(self) -> None:
        tools = [
            _tool("send_gmail_message"),
            _tool("draft_gmail_message"),
            _tool("list_gmail_labels"),
        ]
        out = filter_tools(tools, _backend(["*"], deny=["send_gmail_message"]))
        assert _names(out) == ["draft_gmail_message", "list_gmail_labels"]

    def test_empty_allow_keeps_nothing(self) -> None:
        tools = [_tool("a"), _tool("b")]
        out = filter_tools(tools, _backend([]))
        assert out == []

    def test_unnamed_tools_dropped(self) -> None:
        tools: list[dict[str, Any]] = [{"description": "no name"}, _tool("ok")]
        out = filter_tools(tools, _backend(["*"]))
        assert _names(out) == ["ok"]

    def test_combined_patterns(self) -> None:
        tools = [
            _tool("wordpress_get_post"),
            _tool("wordpress_create_post"),
            _tool("wordpress_update_post"),
            _tool("wordpress_delete_post"),
            _tool("wordpress_delete_page"),
        ]
        out = filter_tools(
            tools,
            _backend(allow=["wordpress_*"], deny=["wordpress_delete_*"]),
        )
        assert _names(out) == [
            "wordpress_create_post",
            "wordpress_get_post",
            "wordpress_update_post",
        ]
