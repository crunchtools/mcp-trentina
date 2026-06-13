"""Internal-tool backend: airlock's own FastMCP tools as a gateway backend.

Option C folds airlock's native tool surface (safe_fetch, quarantine_*, scan,
stats, …) into the gateway alongside the remote http(s) MCP backends. A profile
backend whose URL uses the ``internal://<label>`` scheme routes here instead of
opening a streamable-http session: the whole airlock tool surface becomes one
backend, namespaced under whatever key the profile gives it (conventionally
``web``). The ``<label>`` after the scheme is cosmetic — there is exactly one
internal source, the airlock FastMCP server itself.

The bound server is a module-level singleton, populated once at startup from the
FastMCP instance (see ``__init__._run_with_gateway``). This mirrors backend.py's
module-function style so router.py can dispatch on URL scheme with a parallel
call shape (``list_*``/``call_*`` returning the same types as the http path).

Tool listing and result serialization reuse backend.py's helpers, so an
internal tool and a remote tool present identically to the consumer.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .backend import BackendCall, _serialize_content_block, _serialize_tool
from .errors import BackendCallError

if TYPE_CHECKING:
    from fastmcp import FastMCP

logger = logging.getLogger(__name__)

_server: FastMCP | None = None


def register_internal_server(mcp_server: FastMCP) -> None:
    """Bind the FastMCP server whose tools the internal backend exposes.

    Called once at startup. Idempotent — re-binding simply replaces the
    reference (useful in tests).
    """
    global _server
    _server = mcp_server
    logger.info(
        "gateway: internal tool backend bound to FastMCP server %r",
        getattr(mcp_server, "name", "?"),
    )


def internal_server_registered() -> bool:
    """Report whether an internal FastMCP server has been bound."""
    return _server is not None


async def list_internal_tools() -> list[dict[str, Any]]:
    """Fetch airlock's own tool list, serialized like a remote backend's.

    Returns the raw (un-namespaced, un-filtered) tool list — the router applies
    the profile allowlist and the ``<backend>__<tool>`` namespacing, exactly as
    it does for http backends.

    Raises:
        BackendCallError: no server bound, or the FastMCP tool walk failed.
    """
    if _server is None:
        raise BackendCallError("internal tool backend not registered")
    try:
        tools = await _server.list_tools()
    except Exception as exc:
        logger.warning("gateway: internal list_tools failed err=%s", exc)
        raise BackendCallError(
            f"internal list_tools failed: {type(exc).__name__}"
        ) from exc

    return [_serialize_tool(tool.to_mcp_tool()) for tool in tools]


async def call_internal_tool(tool_name: str, arguments: dict[str, Any]) -> BackendCall:
    """Invoke an airlock tool in-process, returning a BackendCall like the http path.

    Phase 1 returns the tool result verbatim. Phase 2 wraps it in the L1/L2/L3
    defense pipeline at the router, identically to remote backends.

    Raises:
        BackendCallError: no server bound, unknown tool, or tool execution error.
    """
    if _server is None:
        raise BackendCallError("internal tool backend not registered")
    try:
        result = await _server.call_tool(tool_name, arguments)
    except Exception as exc:
        logger.warning(
            "gateway: internal call_tool failed tool=%s err=%s", tool_name, exc
        )
        raise BackendCallError(
            f"internal tool {tool_name!r} call failed: {type(exc).__name__}"
        ) from exc

    content = [_serialize_content_block(block) for block in result.content]
    structured = getattr(result, "structured_content", None)
    return BackendCall(
        content=content,
        is_error=bool(getattr(result, "is_error", False)),
        structured_content=structured if isinstance(structured, dict) else None,
    )
