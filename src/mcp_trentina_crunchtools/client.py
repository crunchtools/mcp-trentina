"""HTTP client for fetching web content."""

from __future__ import annotations

import logging

import httpx

from .errors import FetchError, UnsupportedContentTypeError

log = logging.getLogger(__name__)

FETCH_TIMEOUT = 30.0
MAX_RESPONSE_SIZE = 5_000_000  # 5 MB
USER_AGENT = "mcp-trentina-crunchtools/0.1.0 (security-scanner)"

TEXT_CONTENT_TYPES = frozenset({
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
})
"""Media types the sanitization pipeline can read as text.

Anything outside this set — PDF, images, archives, office documents —
decodes into replacement characters that tokenize into hundreds of
thousands of meaningless tokens."""

TEXT_CONTENT_SUFFIXES = ("+json", "+xml")
"""Structured-syntax suffixes (RFC 6839) that imply a text body."""


def _is_text_content_type(content_type: str) -> bool:
    """True if the media type is text the sanitization pipeline can handle.

    An absent content-type is common on plain files, so it counts as text;
    the size cap and sanitizer handle whatever actually turns up.
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
        chain.append({
            "url": str(hop.url),
            "status": hop.status_code,
            "content_type": hop.headers.get("content-type", ""),
        })
    chain.append({
        "url": str(resp.url),
        "status": resp.status_code,
        "content_type": resp.headers.get("content-type", ""),
    })
    return chain


async def fetch_url(url: str) -> tuple[str, str]:
    """Fetch a URL and return (content, content_type).

    The response is streamed so the content-type and size can be rejected
    from headers alone, before a large or binary body is pulled over the
    wire and decoded.  Servers lie about or omit content-length, so the cap
    is re-checked against bytes actually received; those bytes accumulate
    here because resp.text is unavailable on a streamed response.

    Raises FetchError on failure, UnsupportedContentTypeError on non-text.
    """
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(FETCH_TIMEOUT),
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": USER_AGENT},
        ) as http_client, http_client.stream("GET", url) as resp:
            resp.raise_for_status()

            content_type = resp.headers.get("content-type", "text/html")
            if not _is_text_content_type(content_type):
                redirect_chain = _build_redirect_chain(resp)
                raise UnsupportedContentTypeError(
                    url, content_type, redirect_chain=redirect_chain
                )

            declared = resp.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > MAX_RESPONSE_SIZE:
                raise FetchError(url, f"Response too large: {declared} bytes")

            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_RESPONSE_SIZE:
                    raise FetchError(
                        url, f"Response too large: exceeds {MAX_RESPONSE_SIZE} bytes"
                    )

            return bytes(buf).decode(resp.encoding or "utf-8", errors="replace"), content_type

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        error_body = None
        if 400 <= status < 500:
            try:
                raw = exc.response.read()
                error_body = raw[:2048].decode("utf-8", errors="replace")
            except Exception:
                log.debug("Could not read error body for %s", url)
        raise FetchError(
            url,
            f"HTTP {status}",
            status_code=status,
            error_body=error_body,
        ) from exc
    except httpx.TimeoutException as exc:
        raise FetchError(url, "Request timed out") from exc
    except httpx.RequestError as exc:
        raise FetchError(url, str(exc)) from exc
