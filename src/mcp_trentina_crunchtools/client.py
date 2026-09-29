"""HTTP client for fetching web content."""

from __future__ import annotations

import logging

import httpx

from .egress import open_guarded
from .errors import FetchError, UnsupportedContentTypeError

log = logging.getLogger(__name__)

FETCH_TIMEOUT = 30.0
MAX_RESPONSE_SIZE = 5_000_000  # 5 MB
MAX_ERROR_BODY = 2048
USER_AGENT = "mcp-trentina-crunchtools/0.1.0 (security-scanner)"

TEXT_CONTENT_TYPES = frozenset(
    {
        "application/atom+xml",
        "application/ecmascript",
        "application/javascript",
        "application/json",
        "application/ld+json",
        "application/rss+xml",
        "application/x-ndjson",
        "application/xhtml+xml",
        "application/xml",
        "application/yaml",
    }
)
"""Media types the defense pipeline can read as text.

Anything outside this set — PDF, images, archives, office documents —
decodes into replacement characters that tokenize into hundreds of
thousands of meaningless tokens."""

TEXT_CONTENT_SUFFIXES = ("+json", "+xml")
"""Structured-syntax suffixes (RFC 6839) that imply a text body."""


def _is_text_content_type(content_type: str) -> bool:
    """True if the media type is text the defense pipeline can handle.

    An absent content-type is common on plain files, so it counts as text;
    the size cap and L1 handle whatever actually turns up.
    """
    media_type = content_type.split(";", 1)[0].strip().lower()

    if not media_type:
        return True
    if media_type.startswith("text/"):
        return True
    if media_type in TEXT_CONTENT_TYPES:
        return True
    return media_type.endswith(TEXT_CONTENT_SUFFIXES)


def _build_redirect_chain(resp: httpx.Response) -> list[dict[str, object]] | None:
    """Extract the redirect chain from an httpx response, if any."""
    if not resp.history:
        return None
    chain = []
    for hop in resp.history:
        chain.append(
            {
                "url": str(hop.url),
                "status": hop.status_code,
                "content_type": hop.headers.get("content-type", ""),
            }
        )
    chain.append(
        {
            "url": str(resp.url),
            "status": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
        }
    )
    return chain


async def _error_body(resp: httpx.Response) -> str | None:
    """The first ``MAX_ERROR_BODY`` bytes of a 4xx body, read while the stream is open.

    Reading it after the ``stream`` block closed, as this used to, always
    failed, so no 4xx body ever reached the advisory scan. A body that breaks
    off mid-read still leaves the status to report.
    """
    buf = bytearray()
    try:
        # open_guarded refused an encoded body before this, so these are the
        # bytes that crossed the wire, not a decompressor's output (#276).
        async for chunk in resp.aiter_bytes():
            buf += chunk
            if len(buf) >= MAX_ERROR_BODY:
                break
    except httpx.HTTPError as exc:
        log.debug("could not read a %d error body: %s", resp.status_code, type(exc).__name__)
        return None
    return bytes(buf[:MAX_ERROR_BODY]).decode("utf-8", errors="replace")


async def fetch_url(url: str) -> tuple[str, str]:
    """Fetch a URL and return (content, content_type).

    Every hop passes the egress guard (``egress.open_guarded``). The response
    is streamed so the content-type and size can be rejected from headers
    alone, before a large or binary body is pulled over the wire and decoded.
    Servers lie about or omit content-length, so the cap is re-checked
    against bytes actually received. Those are wire bytes: the guard asks for
    ``identity`` and refuses an encoded body (#276), so nothing is inflated.

    Raises FetchError on failure, UnsupportedContentTypeError on non-text,
    EgressRefusedError when the guard refuses a hop.
    """
    try:
        async with open_guarded(
            "GET", url, timeout=FETCH_TIMEOUT, headers={"User-Agent": USER_AGENT}
        ) as resp:
            status = resp.status_code
            # Not only >= 400: a 3xx the guard did not follow (304, a 300
            # with no Location) is no page either, as raise_for_status held.
            if not resp.is_success:
                error_body = await _error_body(resp) if 400 <= status < 500 else None
                raise FetchError(url, f"HTTP {status}", status_code=status, error_body=error_body)

            content_type = resp.headers.get("content-type", "text/html")
            if not _is_text_content_type(content_type):
                raise UnsupportedContentTypeError(
                    url, content_type, redirect_chain=_build_redirect_chain(resp)
                )

            declared = resp.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > MAX_RESPONSE_SIZE:
                raise FetchError(url, f"Response too large: {declared} bytes")

            buf = bytearray()
            # Identity only (open_guarded refuses anything else), so the cap
            # counts what crossed the wire, never a decompressor's output (#276).
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_RESPONSE_SIZE:
                    raise FetchError(url, f"Response too large: exceeds {MAX_RESPONSE_SIZE} bytes")

            return bytes(buf).decode(resp.encoding or "utf-8", errors="replace"), content_type

    except httpx.TimeoutException as exc:
        raise FetchError(url, "Request timed out") from exc
    except httpx.RequestError as exc:
        raise FetchError(url, str(exc)) from exc
