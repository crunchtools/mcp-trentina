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

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from ..quarantine.classifier import classifier_status
from .auth import verify_bearer, verify_oauth
from .errors import (
    AuthError,
    BackendCallError,
    BackendNotInProfileError,
    GatewayError,
    OAuthForbiddenError,
    ProfileNotFoundError,
)
from .router import JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS, route_jsonrpc
from .sessions import SessionRegistry, session_registry

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

MCP_SESSION_ID_HEADER = "mcp-session-id"

SSE_KEEPALIVE_SECONDS = 25.0
"""Idle gap between keepalive frames. Under common proxy/gateway idle
timeouts (~60s) so quiet connections don't hit 504 upstream-timeout drops."""

SSE_RETRY_MS = 15000
"""Reconnect hint (ms) sent on stream open. Standard SSE clients honour
``retry:`` and back off at the protocol layer, bypassing app-level retry caps."""


@dataclass(frozen=True)
class OAuthContext:
    """What the gateway needs to enforce and advertise Google-backed OAuth.

    ``provider`` is the FastMCP OAuth provider (a ``GoogleProvider``/
    ``OAuthProxy``) that validates presented tokens; ``base_url`` is the public
    origin (no trailing slash) used to build the RFC 9728 resource-metadata URL
    in the 401 challenge. ``issuer`` is the authorization-server identifier the
    provider advertises as ``issuer`` in its own ``/.well-known/oauth-authorization-server``
    document — captured byte-for-byte so our protected-resource metadata names
    the AS with the *exact* same string. FastMCP renders the issuer through a
    pydantic ``AnyHttpUrl``, which appends a trailing slash to a bare-authority
    origin (``https://host`` -> ``https://host/``); RFC 8414 §3.3 requires the
    client to find ``issuer`` identical to the AS identifier it discovered, so a
    protected-resource doc naming ``https://host`` (no slash) against an AS
    issuer of ``https://host/`` is rejected as non-conformant — which is what
    made gemini.google.com report "automatic registration failed" without ever
    POSTing to ``/register``. Built once at startup and threaded into the
    handlers; None on a gateway with no OAuth-enabled profile.

    ``scopes`` is the scope list the provider advertises as ``scopes_supported``
    in its own AS metadata — the *normalized* form (GoogleProvider expands the
    ``email``/``profile`` shorthands to their full ``googleapis.com`` URIs). Our
    protected-resource document must advertise the identical list: a client that
    reads short names here but sees full URIs at the AS (or vice versa) can
    request a scope the AS does not recognize and fail authorization. Captured
    from the provider so the two documents never drift.
    """

    provider: Any
    base_url: str
    issuer: str
    scopes: tuple[str, ...]


async def _authorize(
    request: Request,
    profile: Profile,
    oauth: OAuthContext | None,
) -> Response | None:
    """Authorize one request against a profile. Return None if allowed.

    Static bearer is tried first and, on success, nothing else runs — every
    existing profile behaves exactly as before. Only when the static token does
    not match AND the profile opted into OAuth does the OAuth path run, so an
    OAuth failure never masks a plain static-token typo for a static profile.

    On failure returns the response to send: a bare 401 for a static-only
    profile (unchanged), a 401 carrying a ``WWW-Authenticate`` challenge for an
    OAuth-enabled profile with no usable token, or a 403 when a valid Google
    identity is simply not on the allowlist.
    """
    auth_header = request.headers.get("authorization")
    if _static_bearer_ok(auth_header, profile):
        return None

    if profile.oauth is not None and profile.oauth.enabled:
        try:
            await verify_oauth(
                auth_header, profile, oauth.provider if oauth is not None else None
            )
        except OAuthForbiddenError as exc:
            logger.info(
                "gateway: oauth forbidden profile=%s reason=%s [%s]",
                profile.name, exc, _client_desc(request),
            )
            return _plain(403, "Forbidden")
        except AuthError as exc:
            logger.info(
                "gateway: oauth challenge profile=%s reason=%s [%s]",
                profile.name, exc, _client_desc(request),
            )
            return _oauth_challenge(profile.name, oauth)
        else:
            return None

    logger.info("gateway: auth failed profile=%s", profile.name)
    return _plain(401, "Unauthorized")


def _static_bearer_ok(authorization_header: str | None, profile: Profile) -> bool:
    """Return True iff the profile's static bearer token matches; never raises.

    A predicate over ``verify_bearer`` for the gateway's two-stage auth: a
    static-token miss is not an error here but the signal to try the OAuth path
    next, so the raised ``AuthError`` is converted to a plain False rather than
    swallowed — the decision to fall through is the recovery.
    """
    try:
        verify_bearer(authorization_header, profile)
    except AuthError:
        return False
    return True


def _oauth_challenge(profile_name: str, oauth: OAuthContext | None) -> Response:
    """401 that points an MCP client at this resource's RFC 9728 metadata.

    The ``resource_metadata`` URL is where the client learns which authorization
    server to use, which is how gemini.google.com bootstraps the whole flow from
    a single unauthenticated request.
    """
    headers: dict[str, str] = {}
    if oauth is not None:
        metadata_url = (
            f"{oauth.base_url}/.well-known/oauth-protected-resource"
            f"/gateway/{profile_name}/mcp"
        )
        headers["WWW-Authenticate"] = f'Bearer resource_metadata="{metadata_url}"'
    return Response(
        content="Unauthorized",
        media_type="text/plain",
        status_code=401,
        headers=headers,
    )


def _client_desc(request: Request) -> str:
    """Identify the caller for correlating a disconnect with one client.

    Source port distinguishes concurrent clients behind the same address,
    which is what separates one agent terminal from another over a tunnel.
    """
    client = request.client
    peer = f"{client.host}:{client.port}" if client is not None else "unknown"
    agent = request.headers.get("user-agent", "-")
    return f"peer={peer} ua={agent!r}"


def gateway_app(
    registry: dict[str, Profile],
    sessions: SessionRegistry | None = None,
    oauth: OAuthContext | None = None,
) -> Starlette:
    """Build the Starlette sub-app exposing ``/{profile}/mcp``.

    Used by tests with Starlette's ``TestClient``.  Production deployment
    wires the same handler via ``register_with_fastmcp`` to avoid
    mount-composition issues with FastMCP's own internal routing.
    """
    sr = sessions or session_registry

    async def handle_post(request: Request) -> Response:
        return await _handle_post(request, registry, sr, oauth)

    async def handle_get(request: Request) -> Response:
        return await _handle_get(request, registry, sr, oauth)

    async def handle_delete(request: Request) -> Response:
        return await _handle_delete(request, registry, sr, oauth)

    async def handle_health(_request: Request) -> Response:
        return _health_payload(registry)

    async def handle_resource_metadata(request: Request) -> Response:
        return _resource_metadata(request, registry, oauth)

    routes = [
        Route("/health", endpoint=handle_health, methods=["GET"]),
        Route(
            "/.well-known/oauth-protected-resource/gateway/{profile}/mcp",
            endpoint=handle_resource_metadata,
            methods=["GET"],
        ),
        Route("/{profile}/mcp", endpoint=handle_post, methods=["POST"]),
        Route("/{profile}/mcp", endpoint=handle_get, methods=["GET"]),
        Route("/{profile}/mcp", endpoint=handle_delete, methods=["DELETE"]),
    ]
    return Starlette(routes=routes)


def _resource_metadata(
    request: Request,
    registry: dict[str, Profile],
    oauth: OAuthContext | None,
) -> Response:
    """Serve RFC 9728 protected-resource metadata for one gateway profile.

    FastMCP registers this document only for its own MCP mount path, never for
    the gateway's ``/gateway/{profile}/mcp`` routes, so the gateway serves its
    own — naming itself as the authorization server the client should use. Only
    OAuth-enabled profiles have one; everything else is a 404.
    """
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if (
        oauth is None
        or profile is None
        or profile.oauth is None
        or not profile.oauth.enabled
    ):
        return _plain(404, "Not Found")
    return JSONResponse({
        "resource": f"{oauth.base_url}/gateway/{profile_name}/mcp",
        # oauth.issuer, not oauth.base_url: the AS identifier here must match the
        # `issuer` FastMCP advertises byte-for-byte (trailing slash included), or
        # RFC 8414 §3.3 makes a strict client reject the AS metadata — see the
        # OAuthContext docstring.
        "authorization_servers": [oauth.issuer],
        # The provider's own advertised scopes (normalized to full googleapis
        # URIs), not the shorthand — the two discovery documents must name the
        # same scope strings or a strict client requests a scope the AS rejects.
        # See the OAuthContext docstring.
        "scopes_supported": list(oauth.scopes),
        "bearer_methods_supported": ["header"],
    })


def _health_payload(registry: dict[str, Profile]) -> Response:
    """Build the liveness response.

    The value here is not the body but the fact that it is served at all:
    the handler runs on the event loop, so a timeout means the loop is
    blocked.  During the 2026-08-22 incident an unbounded classifier scan
    wedged the loop for 90 minutes with no way to detect it from outside.
    """
    return JSONResponse({
        "status": "ok",
        "classifier": classifier_status(),
        "profiles": len(registry),
    })


def register_with_fastmcp(
    mcp_server: Any,
    registry: dict[str, Profile],
    sessions: SessionRegistry | None = None,
    oauth: OAuthContext | None = None,
) -> None:
    """Wire gateway routes onto a FastMCP server via its custom_route decorator."""
    sr = sessions or session_registry

    @mcp_server.custom_route("/health", methods=["GET"])  # type: ignore[untyped-decorator]
    async def health_endpoint(_request: Request) -> Response:
        return _health_payload(registry)

    if oauth is not None:
        @mcp_server.custom_route(  # type: ignore[untyped-decorator]
            "/.well-known/oauth-protected-resource/gateway/{profile}/mcp",
            methods=["GET"],
        )
        async def resource_metadata_endpoint(request: Request) -> Response:
            return _resource_metadata(request, registry, oauth)

    @mcp_server.custom_route("/gateway/{profile}/mcp", methods=["POST", "GET", "DELETE"])  # type: ignore[untyped-decorator]
    async def gateway_endpoint(request: Request) -> Response:
        if request.method == "GET":
            return await _handle_get(request, registry, sr, oauth)
        if request.method == "DELETE":
            return await _handle_delete(request, registry, sr, oauth)
        return await _handle_post(request, registry, sr, oauth)


async def _handle_get(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
    oauth: OAuthContext | None = None,
) -> Response:
    """Open a long-lived SSE stream for server-push notifications.

    Requires a valid ``Mcp-Session-Id`` header.  The stream stays open
    until the client disconnects; ``notifications/tools/listChanged`` frames
    are delivered when circuit breaker state affects this session's profile
    (see :meth:`SessionRegistry.broadcast_tools_changed`).  Keepalive comment
    frames are interleaved during idle periods to hold the socket open.
    """
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        return _plain(404, "Not Found")

    auth_response = await _authorize(request, profile, oauth)
    if auth_response is not None:
        return auth_response

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if not session_id:
        return _plain(400, "Bad Request: missing Mcp-Session-Id header")

    session = sessions.get_session(session_id)
    if session is None:
        logger.warning(
            "gateway: SSE stream rejected — session=%s profile=%s not found: %s [%s]",
            session_id[:8],
            profile_name,
            sessions.explain_missing(session_id),
            _client_desc(request),
        )
        return _plain(404, "Session not found or expired")

    if session.profile_name != profile_name:
        return _plain(403, "Session does not belong to this profile")

    logger.info(
        "gateway: SSE stream opened session=%s profile=%s [%s]",
        session_id[:8],
        profile_name,
        _client_desc(request),
    )
    return StreamingResponse(
        _sse_event_stream(sessions, session_id),
        media_type="text/event-stream",
        headers={
            MCP_SESSION_ID_HEADER: session_id,
            "Cache-Control": "no-cache",
        },
    )


async def _sse_event_stream(
    sessions: SessionRegistry,
    session_id: str,
    keepalive_seconds: float = SSE_KEEPALIVE_SECONDS,
) -> AsyncIterator[str]:
    """Yield SSE frames for one server-push stream.

    Subscribes a notification queue for ``session_id`` and drains it as
    MCP-compliant ``event: message`` frames.  When no notification arrives
    within ``keepalive_seconds``, emits a comment keepalive instead.  Always
    deregisters the queue on disconnect (``CancelledError``) or exit.

    Each keepalive tick doubles as a liveness check: once the session is gone
    the stream closes rather than sending keepalives forever to a session the
    registry has already dropped.

    The ``retry:`` reconnect hint is emitted before any data so it is set
    even if the client reconnects immediately.
    """
    queue = sessions.subscribe(session_id)
    try:
        yield f"retry: {SSE_RETRY_MS}\n\n"
        while True:
            try:
                notification = await asyncio.wait_for(
                    queue.get(), timeout=keepalive_seconds
                )
            except TimeoutError:
                if not sessions.is_active(session_id):
                    return
                yield ": keepalive\n\n"
                continue
            yield f"event: message\ndata: {json.dumps(notification)}\n\n"
    except asyncio.CancelledError:
        return
    finally:
        sessions.unsubscribe(session_id, queue)


async def _handle_delete(
    request: Request,
    registry: dict[str, Profile],
    sessions: SessionRegistry,
    oauth: OAuthContext | None = None,
) -> Response:
    """Tear down an MCP session."""
    profile_name = request.path_params.get("profile", "")
    profile = registry.get(profile_name)
    if profile is None:
        return _plain(404, "Not Found")

    auth_response = await _authorize(request, profile, oauth)
    if auth_response is not None:
        return auth_response

    session_id = request.headers.get(MCP_SESSION_ID_HEADER, "")
    if not session_id:
        return _plain(400, "Bad Request: missing Mcp-Session-Id header")

    session = sessions.get_session(session_id)
    if session is None:
        logger.warning(
            "gateway: DELETE rejected — session=%s profile=%s not found: %s [%s]",
            session_id[:8],
            profile_name,
            sessions.explain_missing(session_id),
            _client_desc(request),
        )
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
    oauth: OAuthContext | None = None,
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

    auth_response = await _authorize(request, profile, oauth)
    if auth_response is not None:
        return auth_response

    try:
        body_bytes = await request.body()
    except Exception:
        # Same reasoning as alert_ingress: 400 is correct for every cause, but
        # discarding the cause loses the only signal that separates a flaky
        # client from someone probing the gateway.
        logger.warning(
            "gateway: could not read request body profile=%s", profile_name,
            exc_info=True,
        )
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
            logger.warning(
                "gateway: DISCONNECT — session=%s profile=%s rejected on "
                "method=%r: %s [%s] census=%s",
                session_id[:8],
                profile_name,
                body.get("method", ""),
                sessions.explain_missing(session_id),
                _client_desc(request),
                sessions.census(),
            )
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
                "error": {"code": JSONRPC_INVALID_PARAMS, "message": str(exc)},
            }
        )
    except ProfileNotFoundError:
        return _plain(404, "Not Found")
    except BackendCallError as exc:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": JSONRPC_INTERNAL_ERROR, "message": str(exc)},
            },
            status_code=502,
        )
    except GatewayError:
        logger.exception("gateway: unexpected gateway error profile=%s", profile_name)
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": JSONRPC_INTERNAL_ERROR, "message": "Internal gateway error"},
            },
            status_code=500,
        )
    except Exception:
        logger.exception("gateway: unhandled error profile=%s", profile_name)
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": JSONRPC_INTERNAL_ERROR, "message": "Internal error"},
            },
            status_code=500,
        )

    headers: dict[str, str] = {}
    method = body.get("method", "")
    if method == "initialize":
        new_session_id = sessions.create_session(profile_name)
        headers[MCP_SESSION_ID_HEADER] = new_session_id
        logger.info(
            "gateway: initialize session=%s profile=%s [%s]",
            new_session_id[:8],
            profile_name,
            _client_desc(request),
        )
    elif session_id:
        headers[MCP_SESSION_ID_HEADER] = session_id

    return JSONResponse(response, headers=headers)


def _plain(status: int, text: str) -> Response:
    """Build a plain-text response with the given status code."""
    return Response(content=text, media_type="text/plain", status_code=status)
