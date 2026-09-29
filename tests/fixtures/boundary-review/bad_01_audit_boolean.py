"""Gateway tools/call routing with an audit row per call.

Reduced from gateway/router.py as of 353f261 (before #87). Every call that
reaches a backend is recorded in gateway_calls, so docs/audit-log.md can
promise operators an ok/error count per tool.
"""

from __future__ import annotations

import time
from typing import Any

from mcp_trentina_crunchtools.database import record_gateway_call
from mcp_trentina_crunchtools.gateway.backend import call_backend_tool
from mcp_trentina_crunchtools.gateway.errors import BackendCallError
from mcp_trentina_crunchtools.gateway.internal import call_internal_tool


def _ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


async def route_tools_call(
    profile: Any, backend_name: str, backend: Any, tool_name: str, arguments: dict[str, Any],
    req_id: Any,
) -> dict[str, Any]:
    """Forward one call and record it.

    ``success`` is False when the call failed and True when it returned. The
    audit write is fire-and-forget and never breaks a tool call. The internal
    tools (fetch_tool, read_tool) raise BlockedSourceError when the defense
    refuses content; call_internal_tool wraps it in BackendCallError.
    """
    t0 = time.monotonic()
    try:
        if backend.is_internal:
            call_result = await call_internal_tool(tool_name, arguments)
        else:
            call_result = await call_backend_tool(backend_name, backend, tool_name, arguments)
    except BackendCallError as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        record_gateway_call(profile.name, backend_name, tool_name, False, duration_ms, str(exc))
        return _err(req_id, -32603, str(exc))

    duration_ms = int((time.monotonic() - t0) * 1000)
    record_gateway_call(profile.name, backend_name, tool_name, True, duration_ms)

    result: dict[str, Any] = {
        "content": call_result.content,
        "isError": call_result.is_error,
    }
    if call_result.structured_content is not None:
        result["structuredContent"] = call_result.structured_content
    return _ok(req_id, result)
