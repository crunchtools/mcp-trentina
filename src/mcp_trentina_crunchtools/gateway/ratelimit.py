"""Rate limiting and a body cap for the unauthenticated OAuth write paths.

``/register``, ``/authorize`` and ``/consent`` are unauthenticated by design —
that is what Dynamic Client Registration and a browser login mean. Nothing in
this codebase limited how often any of them could be called, at any layer,
which left "put a proxy in front of it" as the only answer and made it an
answer most operators would never know they needed. See #156.

Two constraints shaped this more than the algorithm did.

**It must not lock out a shared address.** A household, an office or a CGNAT
pool is one address to this process, and refusing all of them because one of
them logged in ten times is worse than the abuse being unlimited. So the
buckets are per ROUTE CLASS rather than one global bucket, the allowances are
sized for a burst of real people rather than for one, and a refusal is logged
at WARNING naming the address — an operator diagnosing "login is broken" reads
the cause out of the journal instead of inferring it.

**It stays in-process.** No redis, no shared state, no new dependency. Each
replica limits what it serves; with one replica, which is the shape Trentina
runs in, that is the whole story.

The address comes from ``scope["client"]``, which is uvicorn's — and therefore
already ``X-Forwarded-For``-resolved when the immediate peer is trusted (see
``TRENTINA_FORWARDED_ALLOW_IPS``). When it is not, every caller behind the
proxy collapses onto the proxy's own address and shares one bucket. That is a
real failure mode rather than a theoretical one, so :func:`describe_limits`
says which of the two is in effect at startup instead of leaving it to be
found during an outage.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import OrderedDict
from typing import Any

from ..config import int_env

logger = logging.getLogger(__name__)

#: Allowances as (burst, per_hour), per source address, per route class.
#:
#: A real client registers ONCE and logs in a handful of times, so these are
#: already an order of magnitude above honest use by a single caller — the
#: headroom is there for the shared-address case, not for the individual.
#: `/register` is the tightest because it is the only one of the three that
#: writes a permanent record, which is what made it worth limiting first.
REGISTER_LIMIT = (10, 10)
AUTHORIZE_LIMIT = (20, 60)
CONSENT_LIMIT = (20, 60)

#: Largest `POST /register` body accepted, before it is parsed. A Dynamic
#: Client Registration request is a few hundred bytes; 8 KiB is room for a
#: client with many redirect URIs and a long client_name, and still small
#: enough that filling a disk through this endpoint is not worth anyone's
#: bandwidth.
DEFAULT_MAX_REGISTRATION_BYTES = 8192

#: How many source addresses each limiter tracks before evicting the least
#: recently seen. Without a bound the limiter is itself the memory leak it
#: exists to prevent: one bucket per spoofed address, forever. Eviction can
#: only ever GRANT a request that would have been refused, never refuse one
#: that would have been granted, so the failure direction is the safe one.
MAX_TRACKED_ADDRESSES = 10_000

#: 413 Content Too Large for an oversized registration, 429 Too Many Requests
#: for an exhausted bucket. Named so the two refusals are told apart at their
#: call sites rather than by remembering which number is which.
STATUS_TOO_LARGE = 413
STATUS_TOO_MANY = 429

_FALSY = {"0", "false", "no", "off"}


class RateLimiter:
    """A token bucket per source address, bounded in how many it keeps.

    ``capacity`` is the burst — how many requests an address that has been
    quiet can make at once. ``per_hour`` is the sustained refill. Both are
    per address, and an address is only created when it is first seen, so an
    idle gateway holds nothing.

    Time is injectable because the alternative is a test that sleeps, and a
    test that sleeps for an hour to prove an hourly refill does not get
    written.
    """

    __slots__ = ("_buckets", "_capacity", "_max_tracked", "_name", "_refill_per_second")

    def __init__(
        self,
        capacity: int,
        per_hour: int,
        *,
        name: str,
        max_tracked: int = MAX_TRACKED_ADDRESSES,
    ) -> None:
        self._capacity = float(capacity)
        self._refill_per_second = per_hour / 3600.0
        self._name = name
        self._max_tracked = max_tracked
        #: address -> (tokens, last updated). Ordered so eviction is LRU.
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    @property
    def name(self) -> str:
        return self._name

    def allow(self, address: str, *, now: float | None = None) -> bool:
        """Spend one token for ``address``; False when it has none left."""
        moment = time.monotonic() if now is None else now

        tokens, updated = self._buckets.get(address, (self._capacity, moment))
        tokens = min(
            self._capacity,
            tokens + max(0.0, moment - updated) * self._refill_per_second,
        )

        if tokens < 1.0:
            # Re-stamp rather than leaving `updated` stale: a refused caller
            # still ages toward its next token, and writing the refusal back
            # is what keeps the bucket warm in the LRU.
            self._buckets[address] = (tokens, moment)
            self._buckets.move_to_end(address)
            return False

        self._buckets[address] = (tokens - 1.0, moment)
        self._buckets.move_to_end(address)
        while len(self._buckets) > self._max_tracked:
            self._buckets.popitem(last=False)
        return True

    def tracked(self) -> int:
        """How many addresses currently hold a bucket (for tests and stats)."""
        return len(self._buckets)

    def reset(self) -> None:
        """Forget every bucket. Used by tests, and by nothing else."""
        self._buckets.clear()


def enabled() -> bool:
    """Whether rate limiting is on. Default on; ``TRENTINA_RATE_LIMIT`` opts out.

    An off switch exists because a limiter that locks out a legitimate operator
    during an incident must be removable without a code change or a rebuild.
    Documented in README.md's environment table.
    """
    raw = os.environ.get("TRENTINA_RATE_LIMIT", "").strip().lower()
    return raw not in _FALSY


def max_registration_bytes() -> int:
    """Body cap for ``POST /register``; 0 or negative disables the cap.

    Documented in README.md's environment table.
    """
    return int_env("TRENTINA_MAX_REGISTRATION_BYTES", DEFAULT_MAX_REGISTRATION_BYTES)


def client_address(scope: dict[str, Any]) -> str:
    """The source address a limiter keys on, or ``"unknown"``.

    Deliberately reads only ``scope["client"]`` and never a forwarding header
    directly. uvicorn's ProxyHeadersMiddleware has already applied
    ``X-Forwarded-For`` **if and only if** the immediate peer is in its trusted
    set, and reading the header here as well would re-add the spoofing it
    exists to prevent: an attacker sending their own ``X-Forwarded-For`` would
    get a fresh bucket per request and no limit at all.
    """
    client = scope.get("client")
    if not client:
        return "unknown"
    return str(client[0])


def describe_limits() -> str:
    """One line for the startup log saying what is actually in force.

    Reports the peer addresses whose ``X-Forwarded-For`` is trusted, from
    ``TRENTINA_FORWARDED_ALLOW_IPS`` or uvicorn's own ``FORWARDED_ALLOW_IPS``.
    Both are documented in README.md's environment table; the first is the one
    Trentina forwards to uvicorn at startup.
    """
    if not enabled():
        return (
            "ratelimit: DISABLED (TRENTINA_RATE_LIMIT) — /register, /authorize "
            "and /consent are unlimited"
        )
    forwarded = (
        os.environ.get("TRENTINA_FORWARDED_ALLOW_IPS", "").strip()
        or os.environ.get("FORWARDED_ALLOW_IPS", "").strip()
        or "127.0.0.1 (uvicorn default)"
    )
    return (
        f"ratelimit: /register {REGISTER_LIMIT[0]} burst + {REGISTER_LIMIT[1]}/h, "
        f"/authorize {AUTHORIZE_LIMIT[0]} burst + {AUTHORIZE_LIMIT[1]}/h, "
        f"/consent {CONSENT_LIMIT[0]} burst + {CONSENT_LIMIT[1]}/h, per source "
        f"address; registration body capped at {max_registration_bytes()} bytes; "
        f"source address trusted from X-Forwarded-For only when the peer is in "
        f"{forwarded} — if your proxy is not in that set every caller shares "
        f"ONE bucket"
    )


class _BufferedBody:
    """An ASGI ``receive`` that replays an already-drained request body once.

    The guard has to read the body to measure it, which consumes the real
    ``receive``. The inner app still expects to read its own body, so it is
    handed this instead.
    """

    __slots__ = ("_body", "_sent")

    def __init__(self, body: bytes) -> None:
        self._body = body
        self._sent = False

    async def __call__(self) -> dict[str, Any]:
        if self._sent:
            return {"type": "http.disconnect"}
        self._sent = True
        return {"type": "http.request", "body": self._body, "more_body": False}


class UnauthenticatedWriteGuard:
    """ASGI wrapper: cap the body, then rate-limit, then delegate.

    Wraps ONE route's app, so the bucket is per route class by construction
    rather than by a path comparison made on every request.

    Order matters. The body is read and measured first, because the point of
    the cap is to refuse a large registration *before it is parsed*; a limiter
    that ran first would still let a capped-but-enormous body through on the
    requests it allowed. Buffering is safe at these sizes — the cap is 8 KiB
    and nothing on these routes streams.

    ``OPTIONS`` passes through untouched. FastMCP wraps `/register` and
    `/token` in CORS middleware, and rate-limiting a preflight would break the
    browser flow that the real request depends on while limiting nothing: a
    preflight writes no record and costs nothing to serve.
    """

    __slots__ = ("_inner", "_limiter", "_max_body_bytes")

    def __init__(
        self,
        inner: Any,
        *,
        limiter: RateLimiter,
        max_body_bytes: int | None = None,
    ) -> None:
        self._inner = inner
        self._limiter = limiter
        self._max_body_bytes = max_body_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method") == "OPTIONS":
            await self._inner(scope, receive, send)
            return

        if self._max_body_bytes is not None and self._max_body_bytes > 0:
            body, overflowed = await self._read_capped(scope, receive)
            if overflowed:
                address = client_address(scope)
                logger.warning(
                    "ratelimit: refused oversized %s body from %s (cap %d bytes)",
                    self._limiter.name, address, self._max_body_bytes,
                )
                await _send_json(
                    send, STATUS_TOO_LARGE,
                    {
                        "error": "invalid_client_metadata",
                        "error_description": (
                            "Registration request body exceeds "
                            f"{self._max_body_bytes} bytes."
                        ),
                    },
                )
                return
            receive = _BufferedBody(body)

        address = client_address(scope)
        if not self._limiter.allow(address):
            logger.warning(
                "ratelimit: refused %s from %s — bucket empty; if this is a "
                "shared address or your reverse proxy, see "
                "TRENTINA_FORWARDED_ALLOW_IPS and TRENTINA_RATE_LIMIT",
                self._limiter.name, address,
            )
            await _send_text(
                send, STATUS_TOO_MANY,
                "Too Many Requests: slow down and retry shortly.\n",
                headers=[(b"retry-after", b"60")],
            )
            return

        await self._inner(scope, receive, send)

    async def _read_capped(
        self, scope: Any, receive: Any
    ) -> tuple[bytes, bool]:
        """Drain the request body, stopping one byte past the cap.

        A declared ``content-length`` is checked first so an oversized body is
        refused without being transferred at all. It is not TRUSTED, because a
        chunked request declares none and a lying one declares whatever it
        likes, so the drained bytes are counted regardless.
        """
        cap = self._max_body_bytes or 0

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    if int(value) > cap:
                        return b"", True
                except ValueError:
                    return b"", True
                break

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > cap:
                return b"", True
            chunks.append(chunk)
            if not message.get("more_body"):
                break
        return b"".join(chunks), False


async def _send_text(
    send: Any, status: int, text: str, *, headers: list[tuple[bytes, bytes]] | None = None
) -> None:
    body = text.encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(body)).encode()),
            *(headers or []),
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def _send_json(send: Any, status: int, document: dict[str, Any]) -> None:
    body = json.dumps(document).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})
