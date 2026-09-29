"""The one egress guard for every gateway-side fetch (#260).

Trentina sits on the container network beside backends with no auth of their
own, so a URL an agent (or a page it fetched) chooses must never reach them.
Three rules, each closing a way round the one before:

- ``check_url`` resolves the host and refuses unless EVERY answer is a global
  address. Deciding on the resolved address, not the spelling, is what
  catches ``2130706433``, ``0x7f.1`` and a single-label container name.
- ``PinnedBackend`` connects to the address that was checked. Resolving again
  at connect time would let a DNS answer that changes in between (rebinding)
  swap the target after the check passed. TLS still verifies the hostname:
  httpcore passes the URL's host as ``server_hostname``, not the pinned IP.
- ``open_guarded`` follows redirects itself and checks every hop, because a
  public page that redirects inward is the same attack by other means.

``TRENTINA_FETCH_ALLOW_PRIVATE`` lifts the address rule only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpcore
import httpx

from .config import get_config
from .errors import EgressRefusedError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterable

log = logging.getLogger(__name__)

DEFAULT_PORTS = {"http": 80, "https": 443}
ALLOWED_SCHEMES = frozenset(DEFAULT_PORTS)
ALLOWED_PORTS = frozenset({80, 443})
MAX_REDIRECTS = 5
RESOLVE_TIMEOUT = 10.0
MAX_LOOKUPS = 16
"""Lookups in flight at once, counting ones whose caller already timed out.

``getaddrinfo`` cannot be cancelled, so a stalled resolver keeps its thread
after ``RESOLVE_TIMEOUT``. The executor has exactly this many workers and a
lookup takes a slot before it is submitted, so nothing ever queues behind a
stalled one; past the limit a fetch is refused as ``unresolvable``."""

_RESOLVER = ThreadPoolExecutor(max_workers=MAX_LOOKUPS, thread_name_prefix="egress-dns")
_lookup_slots = threading.BoundedSemaphore(MAX_LOOKUPS)

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Neither is in ipaddress's non-global table, and both carry an IPv4 address
# a host with the matching tunnel or translator would reach.
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_V4_COMPATIBLE = ipaddress.IPv6Network("::/96")


@dataclass(frozen=True)
class ResolvedTarget:
    """A host that passed the check, and the address its connection is pinned to."""

    host: str
    port: int
    address: str


def _embedded_v4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses an IPv6 answer carries: mapped, 6to4 and NAT64."""
    embedded = [v4 for v4 in (ip.ipv4_mapped, ip.sixtofour) if v4 is not None]
    if ip in _NAT64:
        embedded.append(ipaddress.IPv4Address(ip.packed[-4:]))
    return embedded


def is_global_address(ip: _IPAddress) -> bool:
    """True only for an address on the public internet.

    ``is_global`` alone already excludes loopback, RFC 1918, link-local
    (169.254.169.254, fe80::/10), CGNAT and ULA. The explicit terms are there
    so a change to Python's table cannot quietly readmit one.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _V4_COMPATIBLE:
            return False
        if any(not is_global_address(v4) for v4 in _embedded_v4(ip)):
            return False
    return ip.is_global and not (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _lookup(host: str, port: int) -> list[str]:
    """Every address the resolver returns for ``host``. Blocking; run in a thread."""
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(sockaddr[0]) for *_, sockaddr in answers]


async def _resolve(host: str, port: int) -> list[str]:
    slots = _lookup_slots
    if not slots.acquire(blocking=False):
        log.warning("egress: every resolver slot is busy; refusing")
        raise EgressRefusedError("unresolvable")
    job = _RESOLVER.submit(_lookup, host, port)
    # On the executor's future, not asyncio's: it fires when the thread
    # finishes, however long after the caller timed out.
    job.add_done_callback(lambda _job: slots.release())
    try:
        return await asyncio.wait_for(asyncio.wrap_future(job), RESOLVE_TIMEOUT)
    except (OSError, UnicodeError, TimeoutError) as exc:
        raise EgressRefusedError("unresolvable") from exc


async def check_url(url: str | httpx.URL) -> ResolvedTarget:
    """Refuse a URL the gateway must not fetch; otherwise the address to pin.

    Raises:
        EgressRefusedError: with the reason only, never the host or address.
    """
    # Parsed by httpx, so the check and the connection read the same host.
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError) as exc:
        raise EgressRefusedError("unresolvable") from exc
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise EgressRefusedError("scheme")
    port = DEFAULT_PORTS[parsed.scheme] if parsed.port is None else parsed.port
    if port not in ALLOWED_PORTS:
        raise EgressRefusedError("port")
    host = parsed.raw_host.decode("ascii")
    if not host:
        raise EgressRefusedError("unresolvable")

    addresses = await _resolve(host, port)
    if not addresses:
        raise EgressRefusedError("unresolvable")
    if not get_config().fetch_allow_private:
        for answer in addresses:
            try:
                ip = ipaddress.ip_address(answer)
            except ValueError:
                raise EgressRefusedError("non_global_address") from None
            if not is_global_address(ip):
                log.warning("egress: refused a non-global address")
                raise EgressRefusedError("non_global_address")
    return ResolvedTarget(host=host, port=port, address=addresses[0])


def _socket_backend() -> httpcore.AsyncNetworkBackend:
    """The real network backend. Tests replace it to watch what is dialled."""
    return httpcore.AnyIOBackend()


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Dials the checked address for each (host, port), and nothing unchecked.

    ``connect_unix_socket`` is left as the base class's NotImplementedError:
    the pool is never given a socket path.
    """

    def __init__(self) -> None:
        self._inner = _socket_backend()
        self._pins: dict[tuple[str, int], str] = {}

    def pin(self, target: ResolvedTarget) -> None:
        self._pins[(target.host, target.port)] = target.address

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        address = self._pins.get((host, port))
        if address is None:
            # Only reachable if something sent a request the loop never
            # checked. Fail closed rather than resolve it here.
            raise EgressRefusedError("unresolvable")
        return await self._inner.connect_tcp(
            address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx's transport over a connection pool that dials through ``PinnedBackend``.

    ``AsyncHTTPTransport`` takes no network backend, so the pool it builds is
    replaced with one that does. Everything else — request and response
    mapping, exception mapping — is httpx's own. Tests replace the class
    with an ``httpx.MockTransport``.
    """

    def __init__(self, backend: PinnedBackend) -> None:
        ssl_context = httpx.create_ssl_context()
        super().__init__(verify=ssl_context, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(ssl_context=ssl_context, network_backend=backend)


@asynccontextmanager
async def open_guarded(
    method: str,
    url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> AsyncIterator[httpx.Response]:
    """Send ``method`` to ``url`` and follow up to five redirects, checking every hop.

    Args:
        method: HTTP method, sent unchanged except where a 303 makes it GET.
        url: the URL to fetch; checked like every hop after it.
        timeout: seconds for each connect, read and write, per hop.
        headers: sent on every hop, as httpx sends a client's headers.

    Yields the final ``httpx.Response``, still streaming, with ``history``
    holding the redirects that led to it, as httpx's own redirect handling
    would. It is closed, with its client, when the context exits.
    ``trust_env`` is off: an environment proxy is mounted beside the
    transport, not through it, and would route round the pin.

    Raises:
        EgressRefusedError: a hop failed the check, dropped to http, or there
            were more than five.
    """
    backend = PinnedBackend()
    transport = PinnedTransport(backend)
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        headers=headers,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        request = client.build_request(method, url)
        history: list[httpx.Response] = []
        while True:
            backend.pin(await check_url(request.url))
            resp = await client.send(request, stream=True)
            # httpx builds next_request only for a 3xx with a usable Location;
            # a 304, or a 300 without one, is the final response.
            hop = resp.next_request
            if hop is None:
                break
            await resp.aclose()
            history.append(resp)
            if len(history) > MAX_REDIRECTS:
                raise EgressRefusedError("too_many_redirects")
            if request.url.scheme == "https" and hop.url.scheme == "http":
                raise EgressRefusedError("downgrade")
            request = hop
        resp.history = history
        try:
            yield resp
        finally:
            await resp.aclose()
