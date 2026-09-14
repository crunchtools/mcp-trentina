"""Matrix Client-Server API reverse proxy — authenticated, scanned.

Forwards requests from ``/matrix/{token}/{path}`` to the configured Matrix
homeserver. Agents on the internal network point their homeserver URL at
``http://trentina:PORT/matrix/<token>`` instead of directly at matrix.org;
the Matrix client's own path segments (``_matrix/client/...``) follow the
prefix untouched, so the client needs no changes beyond the URL.

**Auth.** The token is the gateway's, not Matrix's: it resolves to a
profile (constant-time compare, mirroring the alert ingress) and requests
with no valid token get 401. Before this existed the proxy was an open
relay — anything that could reach the port could proxy to the homeserver
through Trentina, unauthenticated and unattributed. Matrix's OWN auth (the
access token in the Authorization header) still passes through untouched;
this proxy never injects or reads Matrix credentials.

**Scanning.** Message-bearing responses — ``/sync`` and room
``/messages`` — are long-poll JSON, so they are buffered whole and judged
by the shared pipeline (latency is noise against a 120s poll). Annotate
mode: the body forwards byte-identical, a flagged response gains a root
``_trentina_warning`` key (Matrix clients ignore unknown root keys), and
the flag is recorded as ``source_type="matrix_sync"``. Everything else
streams through untouched.

**E2EE honesty.** For encrypted rooms this proxy sees ciphertext;
plaintext materializes inside the agent's Matrix client, past the
perimeter. Scanning covers unencrypted rooms only, and no gateway can
claim otherwise.
"""

from __future__ import annotations

import hmac
import json
import logging
from typing import TYPE_CHECKING, Any

import httpx
from starlette.responses import Response, StreamingResponse

from ..defense import defend, defend_json
from .proxy_utils import (
    PLAIN_TEXT,
    filter_response_headers,
    forward_request_headers,
    sanitize_proxy_path,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

_DEFAULT_UPSTREAM = "https://matrix-client.matrix.org"

_SYNC_TIMEOUT = httpx.Timeout(
    connect=10.0, read=120.0, write=10.0, pool=5.0,
)

MATRIX_HTTP_METHODS = [
    "GET", "POST", "PUT", "DELETE", "OPTIONS",
]

# Endpoints whose responses carry room content the agent will read. Event
# and context fetches are exactly what reply-handling bots do; /search is a
# POST that returns message bodies.
_SCANNED_PATH_MARKERS = (
    "/sync", "/messages", "/event/", "/context/", "/relations",
    "/notifications", "/search",
)

# Only buffer-and-scan bodies up to this size; a larger one forwards
# unscanned WITH a logged warning rather than OOMing the gateway. /sync
# responses are typically tens of KB; 32MB is far past any honest one.
_MAX_SCAN_BYTES = 32 * 1024 * 1024

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


def _resolve_profile_by_matrix_token(
    token: str, profiles: dict[str, Profile],
) -> Profile | None:
    token_bytes = token.encode("utf-8")
    match: Profile | None = None
    for profile in profiles.values():
        ingress = profile.matrix_ingress
        if ingress is None or ingress.token is None:
            continue
        expected = ingress.token.get_secret_value().encode("utf-8")
        if hmac.compare_digest(token_bytes, expected) and match is None:
            match = profile
    return match


def register_matrix_routes(
    mcp_server: Any,
    profiles: dict[str, Profile],
    *,
    upstream: str = _DEFAULT_UPSTREAM,
) -> None:
    """Wire ``/matrix/{token}/{path:path}`` onto the FastMCP server.

    An old-style unauthenticated request (``/matrix/_matrix/client/...``)
    lands here with ``_matrix`` parsed as the token, resolves to no
    profile, and gets 401 — the open-relay shape fails closed by
    construction.
    """
    if not upstream.startswith("https://"):
        raise ValueError(
            f"Matrix upstream must start with https://: {upstream!r}",
        )
    upstream = upstream.rstrip("/")

    matrix_profiles = [
        name for name, p in profiles.items() if p.matrix_ingress is not None
    ]
    if not matrix_profiles:
        logger.warning(
            "matrix_proxy: matrix.enabled is set but no profile has a "
            "matrix_ingress token — every request will 401",
        )

    async def matrix_proxy_endpoint(request: Request) -> Response:
        token = request.path_params.get("token", "")
        profile = _resolve_profile_by_matrix_token(token, profiles)
        if profile is None:
            return Response(
                content="unauthorized", status_code=401, media_type=PLAIN_TEXT,
            )
        return await _proxy_matrix(request, upstream, profile)

    mcp_server.custom_route(
        "/matrix/{token}/{path:path}", methods=MATRIX_HTTP_METHODS,
    )(matrix_proxy_endpoint)

    logger.info(
        "matrix_proxy: registered /matrix/{token}/{path} → %s for %d profile(s): %s",
        upstream, len(matrix_profiles), ", ".join(matrix_profiles) or "(none)",
    )


def _should_scan(method: str, path: str) -> bool:
    return method in ("GET", "POST") and any(m in path for m in _SCANNED_PATH_MARKERS)


async def _proxy_matrix(
    request: Request, upstream: str, profile: Profile,
) -> Response:
    """Forward one Matrix Client-Server API request."""
    raw_path = request.path_params.get("path", "")
    path = sanitize_proxy_path(raw_path)
    if path is None:
        return Response(
            content="Path traversal rejected",
            status_code=400, media_type=PLAIN_TEXT,
        )

    upstream_url = f"{upstream}/{path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    fwd_headers = forward_request_headers(list(request.headers.items()))

    has_body = request.method in ("POST", "PUT", "PATCH")
    client = _get_matrix_client()

    try:
        resp = await client.send(
            client.build_request(
                request.method, upstream_url,
                headers=fwd_headers,
                content=request.stream() if has_body else None,
            ),
            stream=True,
        )
    except httpx.TimeoutException:
        return Response(
            content="Matrix upstream timeout",
            status_code=504, media_type=PLAIN_TEXT,
        )
    except httpx.ConnectError as exc:
        logger.warning("matrix_proxy: connect error: %s", exc)
        return Response(
            content="Matrix upstream unreachable",
            status_code=502, media_type=PLAIN_TEXT,
        )

    resp_headers = filter_response_headers(list(resp.headers.items()))
    ct = resp.headers.get("content-type", "application/json")

    if (
        resp.status_code == 200
        and _should_scan(request.method, path)
        and "json" in ct
    ):
        return await _scan_and_forward(resp, resp_headers, ct, profile, path)

    async def stream_body() -> AsyncIterator[bytes]:
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()

    return StreamingResponse(
        stream_body(), status_code=resp.status_code,
        headers=resp_headers, media_type=ct,
    )


async def _scan_and_forward(
    resp: httpx.Response,
    resp_headers: dict[str, str],
    content_type: str,
    profile: Profile,
    path: str,
) -> Response:
    """Buffer a message-bearing response, judge it, forward it annotated.

    The body always forwards intact; ``content-length`` is recomputed only
    when a warning key is added. On any parse or scan failure the original
    bytes forward unscanned with a logged warning — the proxy degrading to
    a relay is survivable, the proxy eating the agent's Matrix traffic is
    not.
    """
    headers = {k: v for k, v in resp_headers.items() if k.lower() != "content-length"}

    chunks: list[bytes] = []
    size = 0
    body_iter = resp.aiter_bytes()
    async for chunk in body_iter:
        size += len(chunk)
        chunks.append(chunk)
        if size > _MAX_SCAN_BYTES:
            # Too big to judge: stop BUFFERING (the old guard kept
            # accumulating and only skipped the scan — an OOM lever), stream
            # what we have plus the remainder, and say so loudly.
            logger.warning(
                "matrix_proxy: %s response exceeds %d bytes — forwarded unscanned",
                path, _MAX_SCAN_BYTES,
            )

            async def passthrough() -> AsyncIterator[bytes]:
                try:
                    for buffered in chunks:
                        yield buffered
                    async for rest in body_iter:
                        yield rest
                finally:
                    await resp.aclose()

            return StreamingResponse(
                passthrough(), status_code=200,
                headers=headers, media_type=content_type,
            )
    await resp.aclose()
    body = b"".join(chunks)

    try:
        payload = json.loads(body)
        result = await defend_json(
            payload,
            source=f"matrix:{profile.name}:{path}",
            source_type="matrix_sync",
            defense=profile.defense,
            record=True,
            attribution={
                "profile": profile.name,
                "backend": "matrix",
                "direction": "sync",
                "blocked": False,
            },
        )
    except Exception:
        # A parse failure here is attacker-reachable (any room member can
        # ship pathological JSON), so "scan failed" must not mean "clean":
        # fall back to judging the raw bytes as TEXT — L1/L2 still read a
        # plaintext payload buried beside the poison — and forward with the
        # failure on the record.
        logger.exception(
            "matrix_proxy: structured scan failed for %s — text-mode fallback",
            path,
        )
        await _text_fallback_scan(body, profile, path)
        return Response(content=body, status_code=200,
                        headers=headers, media_type=content_type)

    verdict = result.verdict
    if verdict.flagged and isinstance(payload, dict):
        payload["_trentina_warning"] = {
            "risk_level": verdict.risk_level,
            "flagged_by": verdict.flagged_by.value if verdict.flagged_by else None,
            "l1_detections": verdict.pipeline.stats.total_detections(),
        }
        logger.warning(
            "matrix_proxy: flagged %s for profile=%s risk=%s flagged_by=%s",
            path, profile.name, verdict.risk_level,
            verdict.flagged_by.value if verdict.flagged_by else None,
        )
        body = json.dumps(payload).encode("utf-8")

    return Response(content=body, status_code=200,
                    headers=headers, media_type=content_type)


async def _text_fallback_scan(body: bytes, profile: Profile, path: str) -> None:
    """Judge unparseable response bytes as plain text; record any flag.

    The annotation channel is gone (no JSON to attach a key to), so the flag
    lives in the detections table and the log — degraded, but never the
    silent clean the recursive-parse fail-open used to produce.
    """
    try:
        verdict = await defend(
            body.decode("utf-8", errors="replace"),
            source=f"matrix:{profile.name}:{path}",
            source_type="matrix_sync",
            defense=profile.defense,
            is_html=False,
            guarded=False,
        )
        if verdict.flagged:
            logger.error(
                "matrix_proxy: UNPARSEABLE response FLAGGED for profile=%s "
                "path=%s risk=%s — forwarded (no annotation channel); "
                "investigate the sender",
                profile.name, path, verdict.risk_level,
            )
    except Exception:
        logger.exception("matrix_proxy: text-mode fallback scan failed for %s", path)
