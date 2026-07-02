"""Starlette routes for the gateway endpoint family.

Phase 2: Streamable HTTP transport with session persistence.

``POST /gateway/{profile}/mcp`` handles JSON-RPC requests, optionally
returning an SSE stream when the ``Accept`` header includes
``text/event-stream``.  A new session is created on ``initialize`` and
tracked via the ``Mcp-Session-Id`` response header.

``GET /gateway/{profile}/mcp`` opens an SSE stream for server-initiated
notifications (e.g. ``tools/listChanged`` on circuit breaker state changes).

``DELETE /gateway/{profile}/mcp`` tears down a session.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .auth import verify_bearer
from .errors import (
    AuthError,
    BackendCallError,
    BackendNotInProfileError,
    GatewayError,
    ProfileNotFoundError,
)
from .router import route_jsonrpc
from .sessions import SessionRegistry, session_registry

if TYPE_CHECKING:
    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

MCP_SESSION_ID_HEADER = "mcp-session-id"


def gateway_app(
    registry: dict[str, Profile],
    sessions: SessionRegistry | None = None,
) -> Starlette:
    """Build the Starlette sub-app exposing ``/{profile}/mcp``.

    Used by tests with Starlette's ``TestClient``.  Production deployment
    wires the same handler via ``register_with_fastmcp`` to avoid
    mount-composition issues with FastMCP's own internal routing.
    """
    sr = sessions or session_registry

    async def handle_post(request: Request) -> Response:
        return await _handle_post(request, registry, sr)

    async def handle_get(request: Request) -> Response:
        return await _handle_get(request, registry, sr)

    async def handle_delete(request: Request) -> Response:
        return await _handle_delete(request, registry, sr)

    routes = [
        Route("/{profile}/mcp", endpoint=handle_post, methods=["POST"]),
        Route("/{profile}/mcp", endpoint=handle_get, methods=["GET"]),
        Route("/{profile}/mcp", endpoint=handle_delete, methods=["DELETE"]),
    ]
    return Starlette(routes=routes)


def register_with_fastmcp(
    mcp_server: Any,
    registry: dict[str, Profile],
    sessions: SessionRegistry | None = None,
) -> None:
    """Wire gateway routes onto a FastMCP server via its custom_route decorator."""
    sr = sessions or session_registry

    @mcp_server.custom_route("/gateway/{profile}/mcp", methods=["POST", "GET", "DELETE"])  # type: ignore[untyped-decorator]
    async def gateway_endpoint(request: Request) -> Response:
        if request.method == "GET":
            return await _handle_get(request, registry, sr)
        if request.method == "DELETE":
            return await _handle_delete(request, registry, sr)
        return await _handle_post(request, registry, sr)


async def _handle_get(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
) -> Response:
    """Open an SSE stream for server-push notifications.

    Requires a valid ``Mcp-Session-Id`` header.  The stream stays open
    until the client disconnects; ``tools/listChanged`` notifications
    are pushed when circuit breaker state affects this session's profile.

    Phase 2 implementation: validates the session exists and returns 200
    with an ``text/event-stream`` content type.  Actual long-lived SSE
    streaming requires an ASGI streaming response that will be connected
    to the session notification pipeline in a follow-up.
    """
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        return _plain(404, "Not Found")

    try:
        verify_bearer(request.headers.get("authorization"), profile)
    except AuthError:
        return _plain(401, "Unauthorized")

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if not session_id:
        return _plain(400, "Bad Request: missing Mcp-Session-Id header")

    session = sessions.get_session(session_id)
    if session is None:
        return _plain(404, "Session not found or expired")

    if session.profile_name != profile_name:
        return _plain(403, "Session does not belong to this profile")

    import asyncio
    from collections.abc import AsyncIterator  # noqa: TC003

    from starlette.responses import StreamingResponse

    async def event_stream() -> AsyncIterator[str]:
        yield f"event: endpoint\ndata: /gateway/{profile_name}/mcp\n\n"
        try:
            while True:
                await asyncio.sleep(30)
                yield ": keepalive\n\n"
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            MCP_SESSION_ID_HEADER: session_id,
            "Cache-Control": "no-cache",
        },
    )


async def _handle_delete(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
) -> Response:
    """Tear down an MCP session."""
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        return _plain(404, "Not Found")

    try:
        verify_bearer(request.headers.get("authorization"), profile)
    except AuthError:
        return _plain(401, "Unauthorized")

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if not session_id:
        return _plain(400, "Bad Request: missing Mcp-Session-Id header")

    session = sessions.get_session(session_id)
    if session is None:
        return _plain(404, "Session not found or expired")

    if session.profile_name != profile_name:
        return _plain(403, "Session does not belong to this profile")

    sessions.delete_session(session_id)
    logger.info("gateway: session %s deleted for profile=%s", session_id[:8], profile_name)
    return Response(status_code=204)


async def _handle_post(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
) -> Response:
    """Authenticate, parse, dispatch, and return one gateway JSON-RPC request.

    On ``initialize``, creates a new session and returns the
    ``Mcp-Session-Id`` header.  Subsequent requests may include the
    session header for tracking; omitting it falls back to stateless
    mode for backwards compatibility.
    """
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        logger.info("gateway: unknown profile %r", profile_name)
        return _plain(404, "Not Found")

    try:
        verify_bearer(request.headers.get("authorization"), profile)
    except AuthError as exc:
        logger.info("gateway: auth failed profile=%s reason=%s", profile_name, exc)
        return _plain(401, "Unauthorized")

    try:
        body_bytes = await request.body()
    except Exception:
        return _plain(400, "Bad Request: cannot read body")

    if not body_bytes:
        return _plain(400, "Bad Request: empty body")

    try:
        body: Any = json.loads(body_bytes)
    except json.JSONDecodeError:
        return _plain(400, "Bad Request: body is not valid JSON")

    if not isinstance(body, dict):
        return _plain(400, "Bad Request: JSON-RPC body must be an object")

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if session_id:
        session = sessions.get_session(session_id)
        if session is None:
            return _plain(404, "Session not found or expired")
        if session.profile_name != profile_name:
            return _plain(403, "Session does not belong to this profile")

    try:
        response = await route_jsonrpc(profile, body)
    except BackendNotInProfileError as exc:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": -32602, "message": str(exc)},
            }
        )
    except ProfileNotFoundError:
        return _plain(404, "Not Found")
    except BackendCallError as exc:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": -32603, "message": str(exc)},
            },
            status_code=502,
        )
    except GatewayError:
        logger.exception("gateway: unexpected gateway error profile=%s", profile_name)
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": -32603, "message": "Internal gateway error"},
            },
            status_code=500,
        )
    except Exception:
        logger.exception("gateway: unhandled error profile=%s", profile_name)
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": -32603, "message": "Internal error"},
            },
            status_code=500,
        )

    headers: dict[str, str] = {}
    method = body.get("method", "")
    if method == "initialize":
        new_session_id = sessions.create_session(profile_name)
        headers[MCP_SESSION_ID_HEADER] = new_session_id
    elif session_id:
        headers[MCP_SESSION_ID_HEADER] = session_id

    return JSONResponse(response, headers=headers)


def _plain(status: int, text: str) -> Response:
    """Build a plain-text response with the given status code."""
    return Response(content=text, media_type="text/plain", status_code=status)
