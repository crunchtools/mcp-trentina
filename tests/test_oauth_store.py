"""Registrations expire, used ones are promoted, and expired files get swept.

Before #156 a DCR registration was written with no TTL and nothing ever called
``cull()``, so a gateway accumulated one permanent file per registration and
one immortal file per abandoned OAuth flow. These tests pin all three halves of
the fix: the lifetimes actually reach the store, promotion actually re-stamps,
and housekeeping failure never propagates into a login.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from mcp_trentina_crunchtools.gateway.oauth_store import (
    DEFAULT_CULL_INTERVAL_SECONDS,
    DEFAULT_PROMOTED_TTL_DAYS,
    PROVISIONAL_TTL_SECONDS,
    PromoteOnExchange,
    SweeperTrigger,
    cull_interval_seconds,
    cull_once,
    mark_provisional,
    promote_registration,
    promoted_ttl_seconds,
    reset_cull_task,
    resolve_cullable,
)


class _FakeClientStore:
    """Stands in for the proxy's PydanticAdapter over the encrypted store."""

    def __init__(self, records: dict[str, Any] | None = None) -> None:
        self.records = records or {}
        self.puts: list[tuple[str, Any, float | None]] = []

    async def get(self, *, key: str) -> Any:
        return self.records.get(key)

    async def put(self, *, key: str, value: Any, ttl: float | None = None) -> None:
        self.records[key] = value
        self.puts.append((key, value, ttl))


class _Cullable:
    def __init__(self, fail: bool = False) -> None:
        self.culled = 0
        self.fail = fail

    async def cull(self) -> None:
        self.culled += 1
        if self.fail:
            raise OSError("disk went away")


class _Wrapper:
    """Mirrors key_value's wrapper shape: the wrapped store is `key_value`."""

    def __init__(self, inner: Any) -> None:
        self.key_value = inner


@pytest.fixture(autouse=True)
def _no_leaked_sweeper() -> Any:
    reset_cull_task()
    yield
    reset_cull_task()


class TestLifetimes:
    def test_provisional_lifetime_is_short(self) -> None:
        """A client that registers and never logs in is litter within the hour.
        Real clients register and exchange within seconds, so an hour is
        already generous."""
        assert PROVISIONAL_TTL_SECONDS == 3600

    def test_promoted_lifetime_defaults_to_ninety_days(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TRENTINA_REGISTRATION_TTL_DAYS", raising=False)
        assert promoted_ttl_seconds() == DEFAULT_PROMOTED_TTL_DAYS * 24 * 3600

    def test_promoted_lifetime_is_configurable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_REGISTRATION_TTL_DAYS", "7")
        assert promoted_ttl_seconds() == 7 * 24 * 3600

    def test_unparseable_lifetime_falls_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_REGISTRATION_TTL_DAYS", "ninety")
        assert promoted_ttl_seconds() == DEFAULT_PROMOTED_TTL_DAYS * 24 * 3600

    def test_promoted_lifetime_outlives_the_provisional_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If these ever inverted, a successful login would SHORTEN the record
        it was supposed to keep."""
        monkeypatch.delenv("TRENTINA_REGISTRATION_TTL_DAYS", raising=False)
        assert promoted_ttl_seconds() > PROVISIONAL_TTL_SECONDS


class TestProvisionalMarking:
    async def test_a_new_registration_gets_the_short_lifetime(self) -> None:
        """The SDK writes the record with no TTL, which is what made every
        registration permanent."""
        store = _FakeClientStore({"fresh": {"client_id": "fresh"}})

        await mark_provisional(store, "fresh")

        assert store.puts == [
            ("fresh", {"client_id": "fresh"}, PROVISIONAL_TTL_SECONDS)
        ]

    async def test_an_unknown_registration_is_a_silent_no_op(self) -> None:
        store = _FakeClientStore()

        await mark_provisional(store, "missing")

        assert store.puts == []

    async def test_a_broken_store_never_fails_the_registration(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """One record that will not expire on its own beats refusing a client
        that asked to register."""

        class _Broken:
            async def get(self, *, key: str) -> Any:
                raise OSError("store is gone")

        with caplog.at_level(logging.WARNING):
            await mark_provisional(_Broken(), "c")

        assert "will not expire on its own" in caplog.text


class TestPromotion:
    async def test_promotion_restamps_with_the_long_ttl(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TRENTINA_REGISTRATION_TTL_DAYS", raising=False)
        store = _FakeClientStore({"client-abc": {"client_id": "client-abc"}})

        await promote_registration(store, "client-abc")

        assert len(store.puts) == 1
        key, value, ttl = store.puts[0]
        assert key == "client-abc"
        assert value == {"client_id": "client-abc"}
        assert ttl == DEFAULT_PROMOTED_TTL_DAYS * 24 * 3600

    async def test_every_use_restamps_again(self) -> None:
        """Re-putting IS the 'last used' stamp — a client refreshing for years
        must never age out from under itself."""
        store = _FakeClientStore({"c": {"client_id": "c"}})

        await promote_registration(store, "c")
        await promote_registration(store, "c")
        await promote_registration(store, "c")

        assert len(store.puts) == 3
        assert all(ttl == promoted_ttl_seconds() for _, _, ttl in store.puts)

    async def test_unknown_client_is_a_silent_no_op(self) -> None:
        """Normal for a CIMD client and for the synthesized upstream client —
        neither is a DCR registration."""
        store = _FakeClientStore()

        await promote_registration(store, "never-registered")

        assert store.puts == []

    async def test_store_failure_never_propagates(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Housekeeping must not fail a login. The worst case is a record that
        keeps its provisional hour, which every DCR client re-registers."""

        class _Broken:
            async def get(self, *, key: str) -> Any:
                raise OSError("store is gone")

        with caplog.at_level(logging.WARNING):
            await promote_registration(_Broken(), "c")

        assert "could not promote registration" in caplog.text


class TestSweeping:
    def test_cullable_is_found_through_the_wrapper_chain(self) -> None:
        """The proxy hands its collections a Fernet wrapper around the file
        store; cull() lives on the innermost one."""
        store = _Cullable()
        assert resolve_cullable(_Wrapper(_Wrapper(store))) is store

    def test_a_store_that_cannot_cull_returns_none(self) -> None:
        assert resolve_cullable(_Wrapper(object())) is None

    def test_a_cyclic_chain_terminates(self) -> None:
        """A wrapper that wraps itself must not hang the sweeper."""
        loop = _Wrapper(None)
        loop.key_value = loop
        assert resolve_cullable(loop) is None

    async def test_sweep_reaches_the_store(self) -> None:
        store = _Cullable()
        assert await cull_once(_Wrapper(store)) is True
        assert store.culled == 1

    async def test_sweep_failure_is_swallowed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        store = _Cullable(fail=True)
        with caplog.at_level(logging.WARNING):
            assert await cull_once(_Wrapper(store)) is False
        assert "sweep failed" in caplog.text

    async def test_sweep_on_an_uncullable_store_is_a_no_op(self) -> None:
        assert await cull_once(object()) is False

    def test_interval_defaults_and_has_a_floor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TRENTINA_OAUTH_CULL_INTERVAL", raising=False)
        assert cull_interval_seconds() == DEFAULT_CULL_INTERVAL_SECONDS
        # A one-second sweep would walk the whole tree in a hot loop.
        monkeypatch.setenv("TRENTINA_OAUTH_CULL_INTERVAL", "1")
        assert cull_interval_seconds() == 60

    async def test_first_request_starts_the_sweeper(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Records accumulate as a consequence of traffic, so the routes that
        cause them are what start the task that removes them."""
        monkeypatch.setenv("TRENTINA_OAUTH_CULL_INTERVAL", "60")
        store = _Cullable()
        served = 0

        async def inner(_scope: Any, _receive: Any, _send: Any) -> None:
            nonlocal served
            served += 1

        app = SweeperTrigger(inner, _Wrapper(store))
        await app({"type": "http"}, None, None)
        # Let the freshly created task reach its first cull.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        assert served == 1
        assert store.culled >= 1

    async def test_the_sweeper_is_started_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_OAUTH_CULL_INTERVAL", "3600")
        store = _Cullable()

        async def inner(_scope: Any, _receive: Any, _send: Any) -> None:
            return

        app = SweeperTrigger(inner, _Wrapper(store))
        for _ in range(5):
            await app({"type": "http"}, None, None)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # One sweep from the single task, not five tasks racing each other.
        assert store.culled == 1


class _StubProvider:
    """The provider half of the MRO: records the exchange, returns a token."""

    def __init__(self, client_store: Any) -> None:
        self._client_store = client_store
        self.exchanges: list[str] = []

    async def exchange_authorization_code(
        self, client: Any, authorization_code: Any
    ) -> str:
        self.exchanges.append("code")
        return "access-token"

    async def exchange_refresh_token(
        self, client: Any, refresh_token: Any, scopes: list[str]
    ) -> str:
        self.exchanges.append("refresh")
        return "refreshed-token"


class _Client:
    def __init__(self, client_id: str) -> None:
        self.client_id = client_id


class TestPromoteOnExchangeMixin:
    """The mixin is what connects 'a token was issued' to 'keep this record'.

    Mixed into the real provider it is never constructed directly, so it is
    exercised here against a stub that stands in for the fastmcp half.
    """

    @staticmethod
    def _provider(store: Any) -> Any:
        class _Provider(PromoteOnExchange, _StubProvider):
            pass

        return _Provider(store)

    async def test_code_exchange_promotes_and_returns_the_token(self) -> None:
        store = _FakeClientStore({"c": {"client_id": "c"}})
        provider = self._provider(store)

        token = await provider.exchange_authorization_code(_Client("c"), object())

        assert token == "access-token"
        assert provider.exchanges == ["code"]
        assert store.puts[0][2] == promoted_ttl_seconds()

    async def test_refresh_promotes_and_returns_the_token(self) -> None:
        store = _FakeClientStore({"c": {"client_id": "c"}})
        provider = self._provider(store)

        token = await provider.exchange_refresh_token(_Client("c"), object(), [])

        assert token == "refreshed-token"
        assert provider.exchanges == ["refresh"]
        assert store.puts[0][2] == promoted_ttl_seconds()

    async def test_promotion_never_swallows_the_token(self) -> None:
        """Housekeeping runs after the exchange, so a broken store must cost a
        TTL refresh and not the login it was refreshing for."""

        class _Broken:
            async def get(self, *, key: str) -> Any:
                raise OSError("store is gone")

        provider = self._provider(_Broken())

        assert await provider.exchange_authorization_code(
            _Client("c"), object()
        ) == "access-token"
