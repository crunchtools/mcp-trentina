"""fetch_url: the one HTTP GET behind fetch_tool.

The gateway runs on the container network beside backends that have no auth
of their own.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from mcp_trentina_crunchtools.errors import FetchError

FETCH_TIMEOUT = 30.0
MAX_RESPONSE_SIZE = 5_000_000
USER_AGENT = "mcp-trentina-crunchtools/0.1.0 (security-scanner)"
_BLOCKED_HOSTS = frozenset({"localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal"})


def _check(url: str) -> None:
    """Refuse non-web schemes and the obvious internal hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise FetchError(url, "scheme not allowed")
    if (parsed.hostname or "").lower() in _BLOCKED_HOSTS:
        raise FetchError(url, "host not allowed")


async def fetch_url(url: str) -> tuple[str, str]:
    """Fetch ``url`` (chosen by the agent) and return (content, content_type)."""
    _check(url)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(FETCH_TIMEOUT),
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": USER_AGENT},
        ) as client, client.stream("GET", url) as resp:
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "text/html")
            buf = bytearray()
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > MAX_RESPONSE_SIZE:
                    raise FetchError(url, "Response too large")
            return bytes(buf).decode(resp.encoding or "utf-8", errors="replace"), content_type
    except httpx.TimeoutException as exc:
        raise FetchError(url, "Request timed out") from exc
    except httpx.RequestError as exc:
        raise FetchError(url, str(exc)) from exc
