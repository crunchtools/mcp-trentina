"""Tests for MCP server registration."""

from __future__ import annotations

import asyncio

from mcp_trentina_crunchtools.server import mcp


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    def test_tool_count(self) -> None:
        """Verify exactly 14 tools are registered."""
        tools = asyncio.run(mcp._list_tools())
        assert len(tools) == 14, f"Expected 14 tools, got {len(tools)}"

    def test_expected_tools_registered(self) -> None:
        """Verify all expected tool names are present."""
        tools = asyncio.run(mcp._list_tools())
        tool_names = {t.name for t in tools}
        expected = {
            "safe_fetch_tool",
            "quarantine_fetch_tool",
            "safe_read_tool",
            "quarantine_read_tool",
            "quarantine_scan_tool",
            "deep_quarantine_scan_tool",
            "safe_content_tool",
            "quarantine_content_tool",
            "scan_content_tool",
            "deep_scan_content_tool",
            "safe_search_tool",
            "quarantine_search_tool",
            "quarantine_stats_tool",
            "cache_flush_tool",
        }
        assert tool_names == expected

    def test_server_name(self) -> None:
        assert mcp.name == "mcp-trentina-crunchtools"
