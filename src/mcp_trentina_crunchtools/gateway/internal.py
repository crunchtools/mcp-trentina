"""Internal-tool backend: trentina's own FastMCP tools as a gateway backend.

Option C folds trentina's native tool surface (fetch_tool, read_tool,
search_tool, stats, …) into the gateway alongside the remote http(s) MCP backends. A profile
backend whose URL uses the ``internal://<label>`` scheme routes here instead of
opening a streamable-http session: the whole trentina tool surface becomes one
backend, namespaced under whatever key the profile gives it (conventionally
``web``). The ``<label>`` after the scheme is cosmetic — there is exactly one
internal source, the trentina FastMCP server itself.

The bound server is a module-level singleton, populated once at startup from the
FastMCP instance (see ``__init__._run_with_gateway``). This mirrors backend.py's
module-function style so router.py can dispatch on URL scheme with a parallel
call shape (``list_*``/``call_*`` returning the same types as the http path).

Tool listing and result serialization reuse backend.py's helpers, so an
internal tool and a remote tool present identically to the consumer.
"""

from __future__ import annotations

import logging
from typing import Any

from .backend import (
    BackendCall,
    _field,
    _serialize_content_block,
    _serialize_tool,
)
from .errors import BackendCallError

logger = logging.getLogger(__name__)

_server: Any = None


def register_internal_server(mcp_server: Any) -> None:
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


async def _walk_server_tools(server: Any) -> list[Any]:
    """Enumerate a FastMCP server's tools across both framework generations.

    fastmcp 2.x exposed ``get_tools()`` returning a ``{name: Tool}`` dict;
    fastmcp 4.x removed it in favour of ``list_tools()`` returning a list.
    Accept either shape so the gateway is not pinned to one framework
    generation by its own internal backend.

    Raises:
        AttributeError: the server exposes neither enumeration method. Raised
            bare so the caller's existing handler wraps it in BackendCallError
            with the offending type name.
    """
    for method in ("list_tools", "get_tools"):
        walk = getattr(server, method, None)
        if walk is None:
            continue
        tools = await walk()
        # dict on fastmcp 2.x, list on 4.x.
        return list(tools.values()) if hasattr(tools, "values") else list(tools)

    raise AttributeError(f"{type(server).__name__} exposes neither list_tools() nor get_tools()")


async def list_internal_tools() -> list[dict[str, Any]]:
    """Fetch trentina's own tool list, serialized like a remote backend's.

    Returns the raw (un-namespaced, un-filtered) tool list — the router applies
    the profile allowlist and the ``<backend>__<tool>`` namespacing, exactly as
    it does for http backends.

    Raises:
        BackendCallError: no server bound, or the FastMCP tool walk failed.
    """
    if _server is None:
        raise BackendCallError("internal tool backend not registered")
    try:
        tools = await _walk_server_tools(_server)
    except Exception as exc:
        logger.warning("gateway: internal list_tools failed err=%s", exc)
        raise BackendCallError(f"internal list_tools failed: {type(exc).__name__}") from exc

    return [_serialize_tool(tool.to_mcp_tool()) for tool in tools]


async def call_internal_tool(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    modal_arguments: dict[str, Any] | None = None,
) -> BackendCall:
    """Invoke an trentina tool in-process, returning a BackendCall like the http path.

    ``modal_arguments`` are the gateway's RESOLVED ``trentina_mode`` and
    ``trentina_prompt``. They are merged only into a tool that declares them:
    the admin tools take neither, and passing an undeclared argument would
    fail the call.

    Raises:
        BackendCallError: no server bound, unknown tool, or tool execution error.
    """
    if _server is None:
        raise BackendCallError("internal tool backend not registered")
    try:
        tool = await _server.get_tool(tool_name)
        declared = (getattr(tool, "parameters", None) or {}).get("properties") or {}
        extra = {
            k: v for k, v in (modal_arguments or {}).items() if k in declared and v is not None
        }
        result = await tool.run({**arguments, **extra})
    except Exception as exc:
        logger.warning("gateway: internal call_tool failed tool=%s err=%s", tool_name, exc)
        raise BackendCallError(
            f"internal tool {tool_name!r} call failed: {type(exc).__name__}"
        ) from exc

    content = [_serialize_content_block(block) for block in result.content]
    structured = _field(result, "structured_content", "structuredContent")
    return BackendCall(
        content=content,
        is_error=bool(_field(result, "is_error", "isError", False)),
        structured_content=structured if isinstance(structured, dict) else None,
    )
