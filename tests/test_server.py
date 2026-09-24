"""Tests for MCP server registration."""

from __future__ import annotations

from mcp_trentina_crunchtools.server import mcp

FAMILIES = ("fetch", "read", "dir", "content", "search")


class TestServerRegistration:
    """Test that all tools are registered correctly."""

    async def test_tool_count(self) -> None:
        """9: one tool per family, plus four that deliver no content.

        The count is asserted because every tool definition sits in every
        agent's context on every call. Adding one should be a decision
        somebody made, not something that happened. It was 19 until 0.32.0,
        when the mode moved from the tool NAME to an argument (#193).
        """
        tools = await mcp.list_tools()
        assert len(tools) == 9, f"Expected 9 tools, got {len(tools)}"

    async def test_every_family_takes_a_mode(self) -> None:
        """The mode is an argument the policy checks, not a name the agent picks."""
        tools = {t.name: t for t in await mcp.list_tools()}
        for family in FAMILIES:
            props = tools[f"{family}_tool"].parameters["properties"]
            assert "trentina_mode" in props, family
            assert "trentina_prompt" in props, family
            assert "trentina_mode" not in tools[f"{family}_tool"].parameters.get("required", [])

    async def test_expected_tools_registered(self) -> None:
        """Nothing delivers content except a family tool (#187, #193)."""
        tools = await mcp.list_tools()
        tool_names = {t.name for t in tools}
        families = {f"{family}_tool" for family in FAMILIES}
        admin = {
            "quarantine_stats_tool",
            "cache_flush_tool",
            "reconnect_backend_tool",
            "reload_profiles_tool",
        }
        assert tool_names == families | admin

    def test_server_name(self) -> None:
        assert mcp.name == "mcp-trentina-crunchtools"
