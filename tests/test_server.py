"""Tests for MCP server registration."""

from __future__ import annotations

from mcp_trentina_crunchtools.server import mcp


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    async def test_tool_count(self) -> None:
        """21: block_*/warn_*/clean_* plus the diagnostics. The alias

        The count is asserted because twenty-one tool definitions sit in
        every agent's context on every call. Adding one should be a decision
        somebody made, not something that happened.
        """
        tools = await mcp.list_tools()
        assert len(tools) == 21, f"Expected 21 tools, got {len(tools)}"

    async def test_every_family_offers_all_three_modes(self) -> None:
        """The point of 0.26.0: the AGENT picks the mode, per call.

        A family missing a mode silently removes a choice — and the one that
        would go missing is `warn`, because it is the only one that had no
        predecessor to be renamed from.
        """
        tools = await mcp.list_tools()
        names = {t.name for t in tools}
        missing = [
            f"{mode}_{family}_tool"
            for family in ("fetch", "read", "content", "search")
            for mode in ("block", "warn", "clean")
            if f"{mode}_{family}_tool" not in names
        ]
        assert not missing, f"families missing a mode: {missing}"

    async def test_expected_tools_registered(self) -> None:
        """Verify all expected tool names are present."""
        tools = await mcp.list_tools()
        tool_names = {t.name for t in tools}
        modes = {
            f"{mode}_{family}_tool"
            for family in ("fetch", "read", "content", "search")
            for mode in ("block", "warn", "clean")
        }
        # The pre-0.26.0 spellings. Still registered and still routed; this
        # set and the registrations it names go in 0.29.0 together.
        deprecated = {
            "block_fetch_tool",
            "clean_fetch_tool",
            "block_read_tool",
            "clean_read_tool",
            "block_content_tool",
            "clean_content_tool",
            "block_search_tool",
            "clean_search_tool",
        }
        diagnostics = {
            "quarantine_scan_tool",
            "quarantine_scan_dir_tool",
            "deep_quarantine_scan_tool",
            "scan_content_tool",
            "deep_scan_content_tool",
            "quarantine_stats_tool",
            "cache_flush_tool",
            "reconnect_backend_tool",
            "reload_profiles_tool",
        }
        assert tool_names == modes | deprecated | diagnostics

    def test_server_name(self) -> None:
        assert mcp.name == "mcp-trentina-crunchtools"
