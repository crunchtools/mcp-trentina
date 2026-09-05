"""Tests for MCP server registration."""

from __future__ import annotations

import asyncio

from mcp_trentina_crunchtools.server import mcp


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    async def test_tool_count(self) -> None:
        """Verify exactly 16 tools are registered."""
        tools = await mcp.get_tools()
        assert len(tools) == 16, f"Expected 16 tools, got {len(tools)}"

    async def test_expected_tools_registered(self) -> None:
        """Verify all expected tool names are present."""
        tools = await mcp.get_tools()
        tool_names = set(tools.keys())
        expected = {
            "safe_fetch_tool",
            "quarantine_fetch_tool",
            "safe_read_tool",
            "quarantine_read_tool",
            "quarantine_scan_tool",
            "quarantine_scan_dir_tool",
            "deep_quarantine_scan_tool",
            "safe_content_tool",
            "quarantine_content_tool",
            "scan_content_tool",
            "deep_scan_content_tool",
            "safe_search_tool",
            "quarantine_search_tool",
            "quarantine_stats_tool",
            "cache_flush_tool",
            "reconnect_backend_tool",
        }
        assert tool_names == expected

    def test_server_name(self) -> None:
        assert mcp.name == "mcp-trentina-crunchtools"
