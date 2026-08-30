"""Tests for MCP server registration."""

from __future__ import annotations

import asyncio

from mcp_airlock_crunchtools.server import mcp


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    def test_tool_count(self) -> None:
        """Verify exactly 6 tools are registered."""
        tools = asyncio.run(mcp.list_tools())
        assert len(tools) == 6, f"Expected 6 tools, got {len(tools)}"

    def test_expected_tools_registered(self) -> None:
        """Verify all expected tool names are present."""
        tools = asyncio.run(mcp.list_tools())
        tool_names = {t.name for t in tools}
        expected = {
            "fetch_tool",
            "read_tool",
            "search_tool",
            "scan_tool",
            "blocklist_tool",
            "stats_tool",
        }
        assert tool_names == expected

    def test_server_name(self) -> None:
        assert mcp.name == "mcp-airlock-crunchtools"
