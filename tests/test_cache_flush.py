"""Tests for tools/cache.py — flushing within the caller's role.

This tool had no behavioral test at all, which is how it kept a substring
match over every cached URL in the process: `cache_flush("gw")` evicted
gw-work and gw-personal together, in whatever profile they lived.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from mcp_trentina_crunchtools.gateway import compress
from mcp_trentina_crunchtools.gateway.backend import _tool_list_cache
from mcp_trentina_crunchtools.gateway.compress import set_profiles
from mcp_trentina_crunchtools.gateway.context import profile_context
from mcp_trentina_crunchtools.gateway.loader import (
    load_profiles,
    register_active_config,
)
from mcp_trentina_crunchtools.gateway.router import _profile_tools_cache
from mcp_trentina_crunchtools.tools.cache import cache_flush

pytestmark = pytest.mark.asyncio

WORK_URL = "http://gw-work:1/mcp"
PERSONAL_URL = "http://gw-personal:1/mcp"
WIKI_URL = "http://wiki:1/mcp"

YAML = f"""\
profiles:
  alpha:
    role: operator
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      gw-work:
        url: {WORK_URL}
      wiki:
        url: {WIKI_URL}
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    backends:
      gw-personal:
        url: {PERSONAL_URL}
      wiki:
        url: {WIKI_URL}
"""


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    """Two profiles, all three backends cached, both aggregates warm."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "a")
    monkeypatch.setenv("TEST_BETA_TOKEN", "b")
    path = tmp_path / "profiles.yaml"
    path.write_text(YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    for url in (WORK_URL, PERSONAL_URL, WIKI_URL):
        _tool_list_cache[url] = [{"name": "a_tool"}]
    _profile_tools_cache["alpha"] = [{"name": "x"}]
    _profile_tools_cache["beta"] = [{"name": "y"}]
    yield config.profiles
    compress._profiles = None


class TestAgentScope:
    async def test_no_argument_flushes_only_the_callers_backends(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            result = await cache_flush()

        assert result["backends_flushed"] == ["gw-personal", "wiki"]
        assert PERSONAL_URL not in _tool_list_cache
        assert WORK_URL in _tool_list_cache
        assert "beta" not in _profile_tools_cache

    async def test_a_backend_in_another_profile_is_refused(self, gateway: dict) -> None:
        """The substring bug, as the caller would have hit it."""
        with profile_context(gateway["beta"]):
            result = await cache_flush("gw-work")

        assert result["flushed"] == "nothing"
        assert "not in this profile" in result["error"]
        assert WORK_URL in _tool_list_cache

    async def test_a_prefix_flushes_nothing(self, gateway: dict) -> None:
        with profile_context(gateway["beta"]):
            result = await cache_flush("gw")

        assert result["flushed"] == "nothing"
        assert PERSONAL_URL in _tool_list_cache

    async def test_no_other_profile_is_named_or_counted(self, gateway: dict) -> None:
        """It used to report how many other profiles were still warm."""
        with profile_context(gateway["beta"]):
            result = await cache_flush()

        assert "alpha" not in str(result)
        assert "gw-work" not in str(result)

    async def test_the_callers_aggregate_goes_but_the_others_stays(self, gateway: dict) -> None:
        """A shared backend's eviction is felt; another profile's cache is not
        cleared by the caller's own flush of a backend it alone holds."""
        with profile_context(gateway["beta"]):
            await cache_flush("gw-personal")

        assert "beta" not in _profile_tools_cache
        assert "alpha" in _profile_tools_cache


class TestOperatorScope:
    async def test_no_argument_flushes_the_gateway(self, gateway: dict) -> None:
        with profile_context(gateway["alpha"]):
            result = await cache_flush()

        assert result["scope"] == "gateway"
        assert result["backend_caches_evicted"] == 3
        assert not _tool_list_cache
        assert not _profile_tools_cache

    async def test_a_name_resolves_through_the_registry_not_the_cache_keys(
        self, gateway: dict
    ) -> None:
        """'gw' is a substring of two cached URLs and the name of neither."""
        with profile_context(gateway["alpha"]):
            result = await cache_flush("gw")

        assert result["evicted"] == 0
        assert len(_tool_list_cache) == 3

    async def test_a_name_in_another_profile_is_reachable(self, gateway: dict) -> None:
        with profile_context(gateway["alpha"]):
            result = await cache_flush("gw-personal")

        assert result["evicted"] == 1
        assert PERSONAL_URL not in _tool_list_cache


class TestUnknownCaller:
    async def test_a_live_gateway_with_no_caller_flushes_nothing(self, gateway: dict) -> None:
        result = await cache_flush()

        assert result["flushed"] == "nothing"
        assert len(_tool_list_cache) == 3
