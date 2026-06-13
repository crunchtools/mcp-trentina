"""Starlette routes for the gateway endpoint family.

`POST /gateway/{profile}/mcp` is the only method served in Phase 1. `GET`
and `DELETE` (used for streamable-http session management) return 405;
Phase 1 is a stateless-per-call gateway with no session resumption support.
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

if TYPE_CHECKING:
    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)


def gateway_app(registry: dict[str, Profile]) -> Starlette:
    """Build the Starlette sub-app exposing /gateway/{profile}/mcp.

    Args:
        registry: Mapping from profile name to loaded `Profile` (returned by
            `loader.load_profiles`).

    Returns:
        A Starlette app with one route family. Mount under `/` in a parent.
    """

    async def handle_post(request: Request) -> Response:
        return await _handle_post(request, registry)

    async def handle_method_not_allowed(_request: Request) -> Response:
        return _plain(405, "Method Not Allowed (Phase 1 supports POST only)")

    routes = [
        Route(
            "/gateway/{profile}/mcp",
            endpoint=handle_post,
            methods=["POST"],
        ),
        Route(
            "/gateway/{profile}/mcp",
            endpoint=handle_method_not_allowed,
            methods=["GET", "DELETE"],
        ),
    ]
    return Starlette(routes=routes)


async def _handle_post(request: Request, registry: dict[str, Profile]) -> Response:
    """Authenticate, parse, dispatch, and return one gateway JSON-RPC request.

    Failure modes and their mappings:
        unknown profile        -> HTTP 404
        missing/bad auth       -> HTTP 401
        unreadable body        -> HTTP 400
        empty body             -> HTTP 400
        body is not JSON       -> HTTP 400
        body is not an object  -> HTTP 400
        backend in JSON-RPC error path -> HTTP 200 with JSON-RPC error body
        backend transport failure      -> HTTP 502 with JSON-RPC error body
        any other GatewayError -> HTTP 500 (logged with traceback)
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

    return JSONResponse(response)


def _plain(status: int, text: str) -> Response:
    """Build a plain-text response with the given status code."""
    return Response(content=text, media_type="text/plain", status_code=status)
