"""The unauthenticated OAuth write paths are limited, and the limits BIND.

Every test here asserts a request was actually refused, not that a code path
exists. #156 asked for exactly that distinction, and for one more thing the
rest of these could pass without: that several source addresses are tracked
independently, so the shared-NAT case is pinned rather than assumed.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_trentina_crunchtools.gateway.ratelimit import (
    RateLimiter,
    UnauthenticatedWriteGuard,
    client_address,
    describe_limits,
    enabled,
    max_registration_bytes,
)


class _Recorder:
    """Minimal ASGI app that records what reached it and returns 200."""

    def __init__(self) -> None:
        self.calls = 0
        self.bodies: list[bytes] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.calls += 1
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        self.bodies.append(b"".join(chunks))
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b"{}"})


def _scope(
    *, method: str = "POST", address: str = "198.51.100.7", headers: Any = None
) -> dict[str, Any]:
    return {
        "type": "http",
        "method": method,
        "path": "/register",
        "client": (address, 54321),
        "headers": headers or [],
    }


async def _drive(
    app: Any, scope: dict[str, Any], body: bytes = b"{}"
) -> tuple[int, bytes, dict[bytes, bytes]]:
    """Run one request through an ASGI app and return (status, body, headers)."""
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    status = 0
    headers: dict[bytes, bytes] = {}
    chunks: list[bytes] = []

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
            headers.update({k.lower(): v for k, v in message.get("headers", [])})
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    return status, b"".join(chunks), headers


class TestRateLimiter:
    def test_burst_is_allowed_then_refused(self) -> None:
        """The capacity'th request passes and the next one does not."""
        limiter = RateLimiter(3, 3, name="/register")
        assert [limiter.allow("a", now=0.0) for _ in range(3)] == [True] * 3
        assert limiter.allow("a", now=0.0) is False

    def test_refusal_is_not_permanent(self) -> None:
        """Enough elapsed time buys back exactly one request, not the burst."""
        limiter = RateLimiter(2, 3600, name="/register")  # one per second
        assert limiter.allow("a", now=0.0)
        assert limiter.allow("a", now=0.0)
        assert limiter.allow("a", now=0.0) is False
        assert limiter.allow("a", now=1.0) is True
        assert limiter.allow("a", now=1.0) is False

    def test_refill_is_capped_at_capacity(self) -> None:
        """An address quiet for a week does not bank a week of requests."""
        limiter = RateLimiter(2, 3600, name="/register")
        assert limiter.allow("a", now=0.0)
        assert [limiter.allow("a", now=604_800.0) for _ in range(2)] == [True, True]
        assert limiter.allow("a", now=604_800.0) is False

    def test_addresses_are_tracked_independently(self) -> None:
        """THE shared-NAT guard rail: exhausting one address does not touch
        another. If this ever regresses, one noisy client locks out everybody
        the limiter can see."""
        limiter = RateLimiter(2, 2, name="/register")
        assert limiter.allow("198.51.100.1", now=0.0)
        assert limiter.allow("198.51.100.1", now=0.0)
        assert limiter.allow("198.51.100.1", now=0.0) is False

        assert limiter.allow("198.51.100.2", now=0.0) is True
        assert limiter.allow("203.0.113.9", now=0.0) is True

    def test_tracked_addresses_are_bounded(self) -> None:
        """The limiter must not become the memory exhaustion it prevents."""
        limiter = RateLimiter(5, 5, name="/register", max_tracked=10)
        for index in range(500):
            limiter.allow(f"10.0.0.{index}", now=0.0)
        assert limiter.tracked() <= 10

    def test_eviction_only_ever_grants(self) -> None:
        """An evicted address gets a fresh bucket — never a stuck refusal."""
        limiter = RateLimiter(1, 1, name="/register", max_tracked=2)
        assert limiter.allow("first", now=0.0)
        assert limiter.allow("first", now=0.0) is False
        limiter.allow("second", now=0.0)
        limiter.allow("third", now=0.0)
        assert limiter.allow("first", now=0.0) is True


class TestGuardRateLimiting:
    async def test_guard_refuses_with_429_and_retry_after(self) -> None:
        inner = _Recorder()
        guard = UnauthenticatedWriteGuard(
            inner,
            limiter=RateLimiter(1, 1, name="/register"),
        )

        status, _, _ = await _drive(guard, _scope())
        assert status == 200

        status, body, headers = await _drive(guard, _scope())
        assert status == 429
        assert headers[b"retry-after"] == b"60"
        assert b"Too Many Requests" in body
        # The refused request never reached the handler, which is the point.
        assert inner.calls == 1

    async def test_guard_limits_per_address(self) -> None:
        inner = _Recorder()
        guard = UnauthenticatedWriteGuard(
            inner,
            limiter=RateLimiter(1, 1, name="/register"),
        )
        assert (await _drive(guard, _scope(address="198.51.100.1")))[0] == 200
        assert (await _drive(guard, _scope(address="198.51.100.1")))[0] == 429
        assert (await _drive(guard, _scope(address="198.51.100.2")))[0] == 200

    async def test_options_preflight_is_never_limited(self) -> None:
        """A CORS preflight writes nothing and costs nothing; limiting it would
        break the browser flow the real request depends on."""
        inner = _Recorder()
        guard = UnauthenticatedWriteGuard(
            inner,
            limiter=RateLimiter(1, 1, name="/register"),
        )
        for _ in range(20):
            status, _, _ = await _drive(guard, _scope(method="OPTIONS"))
            assert status == 200
        assert inner.calls == 20


class TestGuardBodyCap:
    async def test_oversized_declared_body_is_refused_unparsed(self) -> None:
        inner = _Recorder()
        guard = UnauthenticatedWriteGuard(
            inner,
            limiter=RateLimiter(100, 100, name="/register"),
            max_body_bytes=64,
        )
        scope = _scope(headers=[(b"content-length", b"999999")])

        status, body, _ = await _drive(guard, scope, body=b"x" * 999_999)
        assert status == 413
        assert b"invalid_client_metadata" in body
        assert inner.calls == 0

    async def test_oversized_undeclared_body_is_still_refused(self) -> None:
        """A chunked request declares no content-length, so the drained bytes
        have to be counted as well — a cap that trusts the header only is not
        a cap."""
        inner = _Recorder()
        guard = UnauthenticatedWriteGuard(
            inner,
            limiter=RateLimiter(100, 100, name="/register"),
            max_body_bytes=64,
        )

        status, _, _ = await _drive(guard, _scope(), body=b"y" * 5000)
        assert status == 413
        assert inner.calls == 0

    async def test_lying_content_length_is_still_refused(self) -> None:
        """Declaring 10 bytes and sending 5000 must not buy a pass."""
        inner = _Recorder()
        guard = UnauthenticatedWriteGuard(
            inner,
            limiter=RateLimiter(100, 100, name="/register"),
            max_body_bytes=64,
        )
        scope = _scope(headers=[(b"content-length", b"10")])

        status, _, _ = await _drive(guard, scope, body=b"y" * 5000)
        assert status == 413
        assert inner.calls == 0

    async def test_body_under_the_cap_reaches_the_handler_intact(self) -> None:
        """The guard drains the body to measure it, so it has to hand the same
        bytes on — a cap that silently ate the registration would 'pass' every
        test above and break every real client."""
        inner = _Recorder()
        guard = UnauthenticatedWriteGuard(
            inner,
            limiter=RateLimiter(100, 100, name="/register"),
            max_body_bytes=4096,
        )
        payload = b'{"client_name":"trentina-test","redirect_uris":["http://x"]}'

        status, _, _ = await _drive(guard, _scope(), body=payload)
        assert status == 200
        assert inner.bodies == [payload]

    async def test_cap_is_checked_before_the_limiter(self) -> None:
        """An oversized body must not also spend a token: a caller sending junk
        would otherwise exhaust its own bucket and get a 429 that misdescribes
        what happened."""
        limiter = RateLimiter(1, 1, name="/register")
        guard = UnauthenticatedWriteGuard(
            _Recorder(),
            limiter=limiter,
            max_body_bytes=8,
        )

        assert (await _drive(guard, _scope(), body=b"z" * 100))[0] == 413
        assert limiter.allow("198.51.100.7", now=0.0) is True


class TestConfiguration:
    def test_rate_limiting_is_on_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_RATE_LIMIT", raising=False)
        assert enabled() is True

    @pytest.mark.parametrize("value", ["0", "off", "false", "no", "OFF"])
    def test_rate_limiting_can_be_turned_off(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """An operator locked out during an incident needs an off switch that
        does not require a rebuild."""
        monkeypatch.setenv("TRENTINA_RATE_LIMIT", value)
        assert enabled() is False

    def test_registration_cap_defaults_and_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRENTINA_MAX_REGISTRATION_BYTES", raising=False)
        assert max_registration_bytes() == 8192
        monkeypatch.setenv("TRENTINA_MAX_REGISTRATION_BYTES", "1024")
        assert max_registration_bytes() == 1024

    def test_unparseable_cap_falls_back_rather_than_crashing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_MAX_REGISTRATION_BYTES", "eight kilobytes")
        assert max_registration_bytes() == 8192

    def test_client_address_reads_only_the_scope(self) -> None:
        """Never the header. uvicorn has already applied X-Forwarded-For if and
        only if the peer is trusted; re-reading it here would hand an attacker
        a fresh bucket per request by sending their own."""
        scope = {
            "type": "http",
            "client": ("192.0.2.5", 1234),
            "headers": [(b"x-forwarded-for", b"203.0.113.1")],
        }
        assert client_address(scope) == "192.0.2.5"

    def test_client_address_survives_a_missing_peer(self) -> None:
        assert client_address({"type": "http"}) == "unknown"
        assert client_address({"type": "http", "client": None}) == "unknown"

    def test_startup_line_names_the_trust_boundary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The one question after a refused login is 'what address is this
        keyed on'. That answer has to be in the journal before anyone asks."""
        monkeypatch.delenv("TRENTINA_RATE_LIMIT", raising=False)
        monkeypatch.setenv("TRENTINA_FORWARDED_ALLOW_IPS", "10.88.0.1")
        line = describe_limits()
        assert "10.88.0.1" in line
        assert "ONE bucket" in line

    def test_startup_line_says_so_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_RATE_LIMIT", "off")
        assert "DISABLED" in describe_limits()


class TestRouteWiring:
    """`_harden` decides which routes get a limiter. Getting that wrong is
    silent: an unlimited `/register` looks exactly like a limited one until
    someone abuses it."""

    @staticmethod
    def _layers(path: str, *, methods: list[str] | None = None) -> list[str]:
        """Names of the wrappers `_harden` puts around one route's endpoint,
        outermost first."""
        from starlette.routing import Route

        from mcp_trentina_crunchtools import _harden

        async def endpoint(_scope: Any, _receive: Any, _send: Any) -> None:
            return

        route = Route(path, endpoint=endpoint, methods=methods or ["POST"])
        current: Any = _harden(route, storage=object()).app
        names: list[str] = []
        for _ in range(10):
            names.append(type(current).__name__)
            current = getattr(current, "_inner", None)
            if current is None:
                break
        return names

    @pytest.mark.parametrize("path", ["/register", "/authorize", "/consent"])
    def test_the_unauthenticated_write_paths_are_limited(
        self, path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TRENTINA_RATE_LIMIT", raising=False)
        assert "UnauthenticatedWriteGuard" in self._layers(path)

    def test_the_token_endpoint_is_not_limited(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`/token` is reached with a code or refresh token this gateway
        itself issued, so it is not an unauthenticated write path — limiting
        it would throttle a legitimate client's refresh for no gain."""
        monkeypatch.delenv("TRENTINA_RATE_LIMIT", raising=False)
        assert "UnauthenticatedWriteGuard" not in self._layers("/token")

    def test_every_route_still_gets_the_sweeper_trigger(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unlimited route still leaves transaction records behind, and the
        sweep is what removes them."""
        monkeypatch.delenv("TRENTINA_RATE_LIMIT", raising=False)
        for path in ("/register", "/token", "/consent"):
            assert "SweeperTrigger" in self._layers(path)

    def test_turning_the_limiter_off_leaves_the_sweeper_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_RATE_LIMIT", "off")
        layers = self._layers("/register")
        assert "UnauthenticatedWriteGuard" not in layers
        assert "SweeperTrigger" in layers

    def test_the_consent_page_patch_sits_inside_the_limiter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It has to see the consent handler's own response — a 429 from the
        limiter is not a consent page and has nothing to patch."""
        monkeypatch.delenv("TRENTINA_RATE_LIMIT", raising=False)
        layers = self._layers("/consent", methods=["GET", "POST"])
        assert layers.index("UnauthenticatedWriteGuard") < layers.index("ConsentUsability")

    def test_the_route_keeps_its_path_and_methods(self) -> None:
        """Rebuilding a Route is how the wrapper is attached; dropping a method
        while doing it would 405 the real traffic."""
        from starlette.routing import Route

        from mcp_trentina_crunchtools import _harden

        async def endpoint(_scope: Any, _receive: Any, _send: Any) -> None:
            return

        route = _harden(
            Route("/consent", endpoint=endpoint, methods=["GET", "POST"]),
            storage=object(),
        )
        assert route.path == "/consent"
        assert {"GET", "POST"} <= set(route.methods or ())

    def test_a_limiter_is_shared_across_route_rebuilds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rebuilding the routes must not hand a caller a fresh allowance —
        that would make the limit resettable by anything that re-reads them."""
        monkeypatch.delenv("TRENTINA_RATE_LIMIT", raising=False)
        from mcp_trentina_crunchtools import _limiter

        assert _limiter("/register") is _limiter("/register")
