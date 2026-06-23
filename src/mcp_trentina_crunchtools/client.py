"""HTTP client for fetching web content."""

from __future__ import annotations

import httpx

from .errors import FetchError

FETCH_TIMEOUT = 30.0
MAX_RESPONSE_SIZE = 5_000_000  # 5 MB
USER_AGENT = "mcp-trentina-crunchtools/0.1.0 (security-scanner)"


async def fetch_url(url: str) -> tuple[str, str]:
    """Fetch a URL and return (content, content_type).

    Raises FetchError on failure.
    """
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(FETCH_TIMEOUT),
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": USER_AGENT},
        ) as http_client:
            resp = await http_client.get(url)
            resp.raise_for_status()

            content_length = len(resp.content)
            if content_length > MAX_RESPONSE_SIZE:
                raise FetchError(url, f"Response too large: {content_length} bytes")

            content_type = resp.headers.get("content-type", "text/html")
            return resp.text, content_type

    except httpx.HTTPStatusError as exc:
        raise FetchError(url, f"HTTP {exc.response.status_code}") from exc
    except httpx.TimeoutException as exc:
        raise FetchError(url, "Request timed out") from exc
    except httpx.RequestError as exc:
        raise FetchError(url, str(exc)) from exc
