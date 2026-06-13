"""JSON-RPC dispatch for gateway endpoints.

Implements the MCP wire-protocol surface a consumer needs from the gateway:
`initialize`, `tools/list`, `tools/call`, `ping`, and the
`notifications/initialized` no-op. Other methods return JSON-RPC error
-32601 (method not found).

For `tools/list`, aggregates across all backends in the profile and applies
the allowlist filter. Tool names in the response are namespaced as
`<backend>__<tool>` to avoid collisions across backends.

For `tools/call`, parses the namespaced tool name back into (backend, tool),
verifies the backend is in the profile, re-checks the allowlist (defense in
depth), and forwards. Phase 1 returns the backend response verbatim; Phase 2
inserts the L1/L2/L3 defense pipeline here.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .. import __version__
from .backend import call_backend_tool, list_backend_tools
from .errors import BackendCallError, BackendNotInProfileError
from .filter import filter_tools
from .internal import call_internal_tool, list_internal_tools

if TYPE_CHECKING:
    from .profile import Profile

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
NAMESPACE_SEP = "__"


def _ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


async def route_jsonrpc(profile: Profile, request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one JSON-RPC request against a profile.

    The response is always a JSON-RPC 2.0 body. HTTP status is 200 for any
    well-formed JSON-RPC, including error responses — the caller never
    promotes a JSON-RPC error to an HTTP non-200.

    Args:
        profile: The authenticated profile (auth was checked before dispatch).
        request: Parsed JSON-RPC 2.0 request body.

    Returns:
        JSON-RPC 2.0 response body.

    Raises:
        BackendNotInProfileError: tools/call targets a backend not present in
            the profile. The caller maps this to a JSON-RPC error -32602.
    """
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return _ok(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": f"mcp-airlock-gateway:{profile.name}",
                    "version": __version__,
                },
                "instructions": (
                    f"airlock gateway, profile={profile.name}. Tool names are "
                    f"namespaced as <backend>{NAMESPACE_SEP}<tool>."
                ),
            },
        )

    if method == "ping":
        return _ok(req_id, {})

    if method == "notifications/initialized":
        return _ok(req_id, {})

    if method == "tools/list":
        return await _route_tools_list(profile, req_id)

    if method == "tools/call":
        return await _route_tools_call(profile, req_id, params)

    return _err(req_id, -32601, f"Method not found: {method}")


async def _route_tools_list(profile: Profile, req_id: Any) -> dict[str, Any]:
    """Aggregate tools/list across the profile's backends, filtered and namespaced.

    A failing backend (down, timing out, refusing) is logged and skipped so
    the rest of the fleet stays usable. The consumer still sees the union
    of healthy backends.
    """
    aggregated: list[dict[str, Any]] = []
    for backend_name, backend in profile.backends.items():
        try:
            if backend.is_internal:
                backend_tools = await list_internal_tools()
            else:
                backend_tools = await list_backend_tools(backend_name, backend)
        except BackendCallError as exc:
            logger.warning(
                "gateway: tools/list profile=%s backend=%s skipped: %s",
                profile.name,
                backend_name,
                exc,
            )
            continue
        filtered = filter_tools(backend_tools, backend)
        for tool in filtered:
            namespaced_tool = dict(tool)
            namespaced_tool["name"] = f"{backend_name}{NAMESPACE_SEP}{tool['name']}"
            aggregated.append(namespaced_tool)

    return _ok(req_id, {"tools": aggregated})


async def _route_tools_call(
    profile: Profile, req_id: Any, params: dict[str, Any]
) -> dict[str, Any]:
    """Parse the namespaced tool name, validate routing, forward to the backend.

    Re-applies the allowlist on call as defense in depth: even if a consumer
    somehow learned about a tool name, calling it must still match the filter
    that produced their tools/list view.
    """
    namespaced_name = params.get("name", "")
    arguments = params.get("arguments") or {}

    if NAMESPACE_SEP not in namespaced_name:
        return _err(
            req_id,
            -32602,
            f"Tool name {namespaced_name!r} must be <backend>{NAMESPACE_SEP}<tool>",
        )

    backend_name, _, tool_name = namespaced_name.partition(NAMESPACE_SEP)
    if not tool_name:
        return _err(req_id, -32602, f"Empty tool component in {namespaced_name!r}")

    backend = profile.backends.get(backend_name)
    if backend is None:
        raise BackendNotInProfileError(
            f"backend {backend_name!r} not in profile {profile.name!r}"
        )

    if not filter_tools([{"name": tool_name}], backend):
        return _err(
            req_id,
            -32602,
            f"Tool {tool_name!r} not permitted on backend {backend_name!r}",
        )

    try:
        if backend.is_internal:
            call_result = await call_internal_tool(tool_name, arguments)
        else:
            call_result = await call_backend_tool(
                backend_name, backend, tool_name, arguments
            )
    except BackendCallError as exc:
        return _err(req_id, -32603, str(exc))

    result: dict[str, Any] = {
        "content": call_result.content,
        "isError": call_result.is_error,
    }
    if call_result.structured_content is not None:
        result["structuredContent"] = call_result.structured_content
    return _ok(req_id, result)
