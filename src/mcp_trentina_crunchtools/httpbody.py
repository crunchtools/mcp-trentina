"""Reading an untrusted HTTP body: capped while it streams, and validation
errors reported by location, never by value.

Shared by the gateway's bridge endpoints and the bridge process's own API, so
it lives here rather than in either: the bridge process must not import the
gateway's defense stack just to read a request.

``RequestBodyCap`` applies the same rule as ASGI middleware, for routes whose
handler (or whose SDK) reads the body with an unbounded ``request.body()``
(#267).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .config import int_env

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydantic import ValidationError
    from starlette.requests import Request

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 1_048_576

DEFAULT_MAX_REQUEST_BYTES = MAX_BODY_BYTES
"""``TRENTINA_MAX_REQUEST_BYTES``' default, 1 MiB. A JSON-RPC tool call is a
few KiB; the largest honest one is a document an agent writes back through a
tool, and 1 MiB leaves room for that without letting one request push the
container toward its memory limit."""

MIN_REQUEST_BYTES = 1024
"""A floor, not an off switch: a cap below an ``initialize`` refuses everything."""

STATUS_TOO_LARGE = 413

#: Methods whose body is capped. GET and DELETE carry none, and leaving their
#: ``receive`` alone keeps a long-lived SSE GET's disconnect detection exactly
#: as Starlette wrote it.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class TooLargeError(ValueError):
    """The body passed the cap while it was still arriving."""


def max_request_bytes() -> int:
    """``TRENTINA_MAX_REQUEST_BYTES``, floored at ``MIN_REQUEST_BYTES``."""
    return int_env(
        "TRENTINA_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES, minimum=MIN_REQUEST_BYTES
    )


async def read_capped(request: Request, limit: int = MAX_BODY_BYTES) -> bytes:
    """The request body, refused as soon as it passes ``limit``, never after
    buffering all of it. A declared ``content-length`` over the limit is
    refused before a byte is read."""
    if declared_length_over(request.scope, limit):
        raise TooLargeError(f"body over {limit} bytes")
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > limit:
            raise TooLargeError(f"body over {limit} bytes")
    return bytes(received)


def declared_length_over(scope: Any, cap: int) -> bool:
    """True when ``content-length`` says the body is over ``cap``, or is not a number.

    Lets an oversized body be refused before any of it is transferred. It is
    never TRUSTED: a chunked request declares nothing and a lying one declares
    what it likes, so callers still count what actually arrives.
    """
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                return int(value) > cap
            except ValueError:
                return True
    return False


async def drain_capped(scope: Any, receive: Any, cap: int) -> tuple[bytes | None, bool]:
    """Drain an ASGI request body, stopping as soon as it passes ``cap``.

    Returns ``(body, overflowed)``. On overflow the body is empty and the rest
    of it is never read. ``body`` is None when the client disconnected before
    the body ended: a partial body is not a request, and must not be handed on
    as if it were one.
    """
    if declared_length_over(scope, cap):
        return b"", True
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None, False
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > cap:
            return b"", True
        chunks.append(chunk)
        if not message.get("more_body"):
            break
    return b"".join(chunks), False


class CappedReceive:
    """An ASGI ``receive`` that counts body bytes as the handler pulls them.

    Raises ``TooLargeError`` from the handler's own read once the total passes
    ``cap``, so nothing is buffered on the handler's behalf and a handler that
    refuses before reading (the gateway authenticates first) reads nothing.
    Every other message passes through untouched, disconnects included.
    """

    __slots__ = ("_cap", "_receive", "_total")

    def __init__(self, receive: Any, cap: int) -> None:
        self._receive = receive
        self._cap = cap
        self._total = 0

    async def __call__(self) -> dict[str, Any]:
        message: dict[str, Any] = await self._receive()
        if message["type"] == "http.request":
            self._total += len(message.get("body", b""))
            if self._total > self._cap:
                raise TooLargeError(f"body over {self._cap} bytes")
        return message


class BufferedReceive:
    """An ASGI ``receive`` that replays an already-drained body once, then
    passes every later call to the real ``receive``.

    Passing through afterwards, rather than inventing an ``http.disconnect``,
    is what keeps a streamed reply alive: Starlette's ``StreamingResponse``
    listens on ``receive`` for the client going away, and a fake disconnect
    would end an SSE response the moment it began.
    """

    __slots__ = ("_body", "_receive", "_sent")

    def __init__(self, body: bytes, receive: Any) -> None:
        self._body = body
        self._receive = receive
        self._sent = False

    async def __call__(self) -> dict[str, Any]:
        if self._sent:
            message: dict[str, Any] = await self._receive()
            return message
        self._sent = True
        return {"type": "http.request", "body": self._body, "more_body": False}


def mcp_path_matcher(*mcp_paths: str) -> Callable[[str], bool]:
    """A predicate for the gateway's ``/gateway/<profile>/mcp`` routes plus
    FastMCP's own MCP mount(s), ``mcp_paths``."""
    own = frozenset(p.rstrip("/") or "/" for p in mcp_paths)

    def applies(path: str) -> bool:
        trimmed = path.rstrip("/") or "/"
        if trimmed in own:
            return True
        parts = trimmed.split("/")
        return len(parts) == 4 and parts[1] == "gateway" and parts[3] == "mcp" and bool(parts[2])

    return applies


class RequestBodyCap:
    """ASGI middleware: refuse a request body over ``cap`` with 413, unread.

    Wraps the whole app but acts only where ``applies(path)`` holds, so the
    LLM and Matrix proxies, which stream bodies they never hold, keep their
    own behaviour.

    Nothing is buffered here. A declared ``Content-Length`` over the cap is
    refused before the app runs; otherwise the app reads through
    ``CappedReceive``, which stops the read at the cap. The gateway handler
    authenticates before it reads, so an unauthenticated caller costs no body
    memory at all, and a refusal from a handler that has not started its
    response still becomes a 413 here.
    """

    __slots__ = ("_app", "_applies", "_cap")

    def __init__(
        self,
        app: Any,
        *,
        cap: int | None = None,
        applies: Callable[[str], bool] | None = None,
    ) -> None:
        self._app = app
        self._cap = cap if cap is not None else max_request_bytes()
        self._applies = applies or mcp_path_matcher("/mcp")

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") not in _BODY_METHODS
            or not self._applies(scope.get("path", ""))
        ):
            await self._app(scope, receive, send)
            return
        if declared_length_over(scope, self._cap):
            await self._refuse(send)
            return
        started = False

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self._app(scope, CappedReceive(receive, self._cap), tracked_send)
        except TooLargeError:
            if started:
                raise
            await self._refuse(send)

    async def _refuse(self, send: Any) -> None:
        # The cap, never the path: the path carries a caller-chosen profile
        # name, and the journal is readable by agents (#262).
        logger.warning("http: refused a request body over %d bytes", self._cap)
        await send_text(send, STATUS_TOO_LARGE, f"Request body exceeds {self._cap} bytes.\n")


async def send_text(
    send: Any, status: int, text: str, *, headers: list[tuple[bytes, bytes]] | None = None
) -> None:
    """A complete plain-text ASGI response."""
    body = text.encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
                *(headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def where_invalid(exc: ValidationError) -> list[str]:
    """Where validation failed, never the values that failed it: a rejected
    event's content is exactly what must not reach a log. Nor a key the model
    forbids: an extra key's name is the sender's text (#262)."""
    return [
        ".".join(
            "<extra>" if e["type"] == "extra_forbidden" and i == len(e["loc"]) - 1 else str(part)
            for i, part in enumerate(e["loc"])
        )
        for e in exc.errors(include_input=False)
    ]
