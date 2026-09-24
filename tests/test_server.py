"""Tests for MCP server registration."""

from __future__ import annotations

from mcp_trentina_crunchtools.server import mcp

FAMILIES = ("fetch", "read", "dir", "content", "search")


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    async def test_tool_count(self) -> None:
        """19: five families in three modes, plus four that deliver no content.

        The count is asserted because every tool definition sits in every
        agent's context on every call. Adding one should be a decision
        somebody made, not something that happened.
        """
        tools = await mcp.list_tools()
        assert len(tools) == 19, f"Expected 19 tools, got {len(tools)}"

    async def test_every_family_offers_all_three_modes(self) -> None:
        """The agent picks the mode, per call, and a family missing one
        silently removes a choice."""
        tools = await mcp.list_tools()
        names = {t.name for t in tools}
        missing = [
            f"{mode}_{family}_tool"
            for family in FAMILIES
            for mode in ("block", "warn", "clean")
            if f"{mode}_{family}_tool" not in names
        ]
        assert not missing, f"families missing a mode: {missing}"

    async def test_expected_tools_registered(self) -> None:
        """Nothing delivers content except a (family, mode) tool (#187).

        The diagnostic scans (quarantine_scan, deep_*, scan_content,
        quarantine_scan_dir) were a second mental model beside the three
        modes, and went in 0.31.0; quarantine_scan_dir became the dir family.
        """
        tools = await mcp.list_tools()
        tool_names = {t.name for t in tools}
        modes = {
            f"{mode}_{family}_tool" for family in FAMILIES for mode in ("block", "warn", "clean")
        }
        admin = {
            "quarantine_stats_tool",
            "cache_flush_tool",
            "reconnect_backend_tool",
            "reload_profiles_tool",
        }
        assert tool_names == modes | admin

    def test_server_name(self) -> None:
        assert mcp.name == "mcp-trentina-crunchtools"
