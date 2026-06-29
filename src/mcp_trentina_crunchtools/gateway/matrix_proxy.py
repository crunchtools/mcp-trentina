"""Matrix Client-Server API reverse proxy.

Forwards requests from ``/matrix/{path}`` to the configured Matrix
homeserver.  Agents on the internal network point ``MATRIX_HOMESERVER``
at Trentina instead of directly at matrix.org.

Matrix handles its own auth via access tokens in request headers —
this proxy does not inject credentials.  It is a transparent
pass-through with timeout tuning for the long-poll ``/sync`` endpoint.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx
from starlette.responses import Response, StreamingResponse

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

logger = logging.getLogger(__name__)

_DEFAULT_UPSTREAM = "https://matrix-client.matrix.org"

_SYNC_TIMEOUT = httpx.Timeout(
    connect=10.0, read=120.0, write=10.0, pool=5.0,
)

_STRIP_REQUEST_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
})

_STRIP_RESPONSE_HEADERS = frozenset({
    "content-encoding", "content-length", "transfer-encoding", "connection",
})

_MATRIX_METHODS = [
    "GET", "POST", "PUT", "DELETE", "OPTIONS",
]

_PLAIN = "text/plain"

_matrix_client: httpx.AsyncClient | None = None


def _get_matrix_client() -> httpx.AsyncClient:
    global _matrix_client
    if _matrix_client is None:
        _matrix_client = httpx.AsyncClient(timeout=_SYNC_TIMEOUT)
    return _matrix_client


async def close_matrix_client() -> None:
    """Close the Matrix proxy httpx client. Called on application shutdown."""
    global _matrix_client
    if _matrix_client is not None:
        await _matrix_client.aclose()
        _matrix_client = None


def register_matrix_routes(
    mcp_server: Any, *, upstream: str = _DEFAULT_UPSTREAM,
) -> None:
    """Wire ``/matrix/{path:path}`` onto the FastMCP server."""
    if not upstream.startswith("https://"):
        raise ValueError(
            f"Matrix upstream must start with https://: {upstream!r}",
        )
    upstream = upstream.rstrip("/")

    async def matrix_proxy_endpoint(request: Request) -> Response:
        return await _proxy_matrix(request, upstream)

    mcp_server.custom_route(
        "/matrix/{path:path}", methods=_MATRIX_METHODS,
    )(matrix_proxy_endpoint)

    logger.info(
        "matrix_proxy: registered /matrix/{path} → %s", upstream,
    )


async def _proxy_matrix(request: Request, upstream: str) -> Response:
    """Forward one Matrix Client-Server API request."""
    from .proxy_utils import sanitize_proxy_path

    raw_path = request.path_params.get("path", "")
    path = sanitize_proxy_path(raw_path)
    if path is None:
        return Response(
            content="Path traversal rejected",
            status_code=400, media_type=_PLAIN,
        )

    upstream_url = f"{upstream}/{path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    fwd_headers: dict[str, str] = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _STRIP_REQUEST_HEADERS
    }

    body = await request.body()
    client = _get_matrix_client()

    try:
        resp = await client.send(
            client.build_request(
                request.method, upstream_url,
                headers=fwd_headers,
                content=body if body else None,
            ),
            stream=True,
        )
    except httpx.TimeoutException:
        return Response(
            content="Matrix upstream timeout",
            status_code=504, media_type=_PLAIN,
        )
    except httpx.ConnectError as exc:
        logger.warning("matrix_proxy: connect error: %s", exc)
        return Response(
            content="Matrix upstream unreachable",
            status_code=502, media_type=_PLAIN,
        )

    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in _STRIP_RESPONSE_HEADERS
    }

    async def stream_body() -> AsyncIterator[bytes]:
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()

    ct = resp.headers.get("content-type", "application/json")
    return StreamingResponse(
        stream_body(), status_code=resp.status_code,
        headers=resp_headers, media_type=ct,
    )
