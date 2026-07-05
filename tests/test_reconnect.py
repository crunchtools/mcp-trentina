"""Tests for tools/reconnect.py — per-backend circuit reset and re-probe.

Patches the transport layer (_do_list_tools) so the real reconnect_backend
runs its breaker reset, cache eviction, fresh fetch, and profile-cache
invalidation end to end. Profiles are registered via set_profiles and reset
to None after each test (the autouse conftest fixture does not manage them).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest

from mcp_trentina_crunchtools.gateway import compress
from mcp_trentina_crunchtools.gateway.backend import _tool_list_cache
from mcp_trentina_crunchtools.gateway.circuit import State, breaker
from mcp_trentina_crunchtools.gateway.compress import set_profiles
from mcp_trentina_crunchtools.gateway.profile import AuthConfig, Backend, Profile
from mcp_trentina_crunchtools.gateway.router import (
    _profile_backend_urls,
    _profile_tools_cache,
)
from mcp_trentina_crunchtools.tools.reconnect import _safe_endpoint, reconnect_backend

POSTIZ_URL = "http://mcp-postiz:5000/api/mcp/token-a"


def _unset_profiles() -> None:
    """Clear the profile registry to simulate an un-started gateway."""
    compress._profiles = None


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name
        self.description = ""
        self.inputSchema: dict[str, Any] = {}


class _FakeToolsResult:
    def __init__(self, names: list[str]) -> None:
        self.tools = [_FakeTool(n) for n in names]


def _profile(name: str, backends: dict[str, Backend]) -> Profile:
    return Profile(name=name, auth=AuthConfig(bearer_token_env="TEST"), backends=backends)


@pytest.fixture(autouse=True)
def _clear_profiles() -> Iterator[None]:
    """Reset the profile registry around each test (conftest does not)."""
    yield
    _unset_profiles()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://mcp-postiz:5000/api/mcp/token-a", "http://mcp-postiz:5000"),
        ("http://mcp-rotv:8080/mcp?token=secret", "http://mcp-rotv:8080"),
        ("https://example.com", "https://example.com"),
        ("internal://web", "internal://web"),
        ("garbage-no-scheme", "(redacted)"),
        ("", "(redacted)"),
    ],
)
def test_safe_endpoint_strips_path_and_query(url: str, expected: str) -> None:
    """host:port survives; any path/query (where tokens hide) is dropped."""
    result = _safe_endpoint(url)
    assert result == expected
    assert "token" not in result
    assert "secret" not in result


@pytest.mark.asyncio
class TestReconnectBackend:
    async def test_reset_closes_open_circuit_and_rewarms_cache(self) -> None:
        """An open circuit is forced closed and the tool cache is re-warmed."""
        set_profiles(
            {"josui": _profile("josui", {"postiz": Backend(url=POSTIZ_URL)})}
        )
        for _ in range(3):
            breaker.record_failure(POSTIZ_URL)
        assert breaker.get_state(POSTIZ_URL) is State.OPEN

        async def ok(_url: str, _headers: Any) -> _FakeToolsResult:
            return _FakeToolsResult(["integrationList", "listPostsTool"])

        with patch(
            "mcp_trentina_crunchtools.gateway.backend._do_list_tools", side_effect=ok
        ):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is True
        assert result["targets"][0]["tool_count"] == 2
        assert result["targets"][0]["circuit"] == "closed"
        assert result["targets"][0]["endpoint"] == "http://mcp-postiz:5000"
        assert "token-a" not in str(result)
        assert breaker.get_state(POSTIZ_URL) is State.CLOSED
        assert _tool_list_cache[POSTIZ_URL]

    async def test_unknown_backend_reports_available(self) -> None:
        """A name in no profile returns reconnected False with the known names."""
        set_profiles(
            {"josui": _profile("josui", {"postiz": Backend(url=POSTIZ_URL)})}
        )
        result = await reconnect_backend("nope")

        assert result["reconnected"] is False
        assert result["error"] == "backend not found in any profile"
        assert result["available"] == ["postiz"]

    async def test_failing_backend_reports_failure(self) -> None:
        """A backend that still can't be reached reports reconnected False."""
        set_profiles(
            {"josui": _profile("josui", {"postiz": Backend(url=POSTIZ_URL)})}
        )

        async def boom(_url: str, _headers: Any) -> Any:
            raise ConnectionRefusedError("still down")

        with patch(
            "mcp_trentina_crunchtools.gateway.backend._do_list_tools", side_effect=boom
        ):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is False
        assert "error" in result["targets"][0]
        assert POSTIZ_URL not in _tool_list_cache

    async def test_internal_backend_is_noop(self) -> None:
        """An internal:// backend needs no transport reconnect."""
        set_profiles(
            {"josui": _profile("josui", {"web": Backend(url="internal://web")})}
        )
        result = await reconnect_backend("web")

        assert result["reconnected"] is True
        assert result["targets"][0]["internal"] is True

    async def test_distinct_urls_across_profiles_all_reset(self) -> None:
        """The same name with different URLs across profiles resets each URL."""
        url_b = "http://mcp-postiz:5000/api/mcp/token-b"
        set_profiles(
            {
                "josui": _profile("josui", {"postiz": Backend(url=POSTIZ_URL)}),
                "takeda": _profile("takeda", {"postiz": Backend(url=url_b)}),
            }
        )

        async def ok(_url: str, _headers: Any) -> _FakeToolsResult:
            return _FakeToolsResult(["integrationList"])

        with patch(
            "mcp_trentina_crunchtools.gateway.backend._do_list_tools", side_effect=ok
        ):
            result = await reconnect_backend("postiz")

        assert result["reconnected"] is True
        assert len(result["targets"]) == 2
        profiles_seen = {frozenset(t["profiles"]) for t in result["targets"]}
        assert profiles_seen == {frozenset({"josui"}), frozenset({"takeda"})}
        assert "token-" not in str(result)

    async def test_reconnect_invalidates_stale_profile_cache(self) -> None:
        """A profile aggregate that omitted the backend is dropped on reconnect."""
        set_profiles(
            {"josui": _profile("josui", {"postiz": Backend(url=POSTIZ_URL)})}
        )
        _profile_tools_cache["josui"] = [{"name": "other__tool"}]
        _profile_backend_urls["josui"] = {POSTIZ_URL}

        async def ok(_url: str, _headers: Any) -> _FakeToolsResult:
            return _FakeToolsResult(["integrationList"])

        with patch(
            "mcp_trentina_crunchtools.gateway.backend._do_list_tools", side_effect=ok
        ):
            await reconnect_backend("postiz")

        assert "josui" not in _profile_tools_cache

    async def test_gateway_not_initialized(self) -> None:
        """With no profiles loaded, reconnect reports the gateway is down."""
        _unset_profiles()
        result = await reconnect_backend("postiz")

        assert result["reconnected"] is False
        assert result["error"] == "gateway not initialized"
