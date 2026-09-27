"""Reading an untrusted HTTP body: capped while it streams, and validation
errors reported by location, never by value.

Shared by the gateway's bridge endpoints and the bridge process's own API, so
it lives here rather than in either: the bridge process must not import the
gateway's defense stack just to read a request.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import ValidationError
    from starlette.requests import Request

MAX_BODY_BYTES = 1_048_576


class TooLargeError(ValueError):
    """The body passed the cap while it was still arriving."""


async def read_capped(request: Request, limit: int = MAX_BODY_BYTES) -> bytes:
    """The request body, refused as soon as it passes ``limit``, never after
    buffering all of it."""
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > limit:
            raise TooLargeError(f"body over {limit} bytes")
    return bytes(received)


def where_invalid(exc: ValidationError) -> list[str]:
    """Where validation failed, never the values that failed it: a rejected
    event's content is exactly what must not reach a log."""
    return [".".join(str(part) for part in e["loc"]) for e in exc.errors(include_input=False)]
