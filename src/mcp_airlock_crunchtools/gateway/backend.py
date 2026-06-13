"""Backend MCP connection management.

Phase 1 opens a fresh `streamablehttp_client` session per call. No connection
pooling — that arrives in Phase 2 as an optimization. Each call to a backend
establishes its own MCP session, performs the requested op, and tears down.

Simple lifecycle, visible chokepoint, easy to debug. Pool-sharing under load
is the next step once Phase 1 architecture is proven.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from .errors import BackendCallError

if TYPE_CHECKING:
    from .profile import Backend

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BackendCall:
    """Outcome of a backend tool invocation."""

    content: list[dict[str, Any]]
    is_error: bool
    structured_content: dict[str, Any] | None


async def list_backend_tools(backend_name: str, backend: Backend) -> list[dict[str, Any]]:
    """Fetch the tool list from one backend MCP server.

    Returns the raw tool list as the backend reported it (no allowlist filtering
    here — that's `filter.py`'s job). Tool names are NOT yet namespaced; the
    caller does the `<backend>__<tool>` rewrite.

    Raises:
        BackendCallError: connection failure, protocol error, or timeout.
    """
    headers = backend.headers or None
    try:
        tools_result = await asyncio.wait_for(
            _do_list_tools(backend.url, headers),
            timeout=backend.timeout_seconds,
        )
    except Exception as exc:
        logger.warning(
            "gateway: list_tools failed for backend=%s url=%s err=%s",
            backend_name,
            backend.url,
            exc,
        )
        raise BackendCallError(
            f"backend {backend_name!r} list_tools failed: {type(exc).__name__}"
        ) from exc

    return [_serialize_tool(tool) for tool in tools_result.tools]


async def call_backend_tool(
    backend_name: str,
    backend: Backend,
    tool_name: str,
    arguments: dict[str, Any],
) -> BackendCall:
    """Invoke a tool on a backend MCP server, returning the raw result.

    Phase 1 passes the response through verbatim. Phase 2 wraps it in the
    L1/L2/L3 defense pipeline before returning.

    Raises:
        BackendCallError: connection failure, protocol error, or timeout.
    """
    headers = backend.headers or None
    try:
        result = await asyncio.wait_for(
            _do_call_tool(backend.url, headers, tool_name, arguments),
            timeout=backend.timeout_seconds,
        )
    except Exception as exc:
        logger.warning(
            "gateway: call_tool failed backend=%s tool=%s err=%s",
            backend_name,
            tool_name,
            exc,
        )
        raise BackendCallError(
            f"backend {backend_name!r} call_tool failed: {type(exc).__name__}"
        ) from exc

    content: list[dict[str, Any]] = [_serialize_content_block(b) for b in result.content]
    structured = getattr(result, "structuredContent", None)
    return BackendCall(
        content=content,
        is_error=bool(result.isError),
        structured_content=structured if isinstance(structured, dict) else None,
    )


async def _do_list_tools(url: str, headers: dict[str, str] | None) -> Any:
    """Open a session and call list_tools.

    Extracted as a separate coroutine so `asyncio.wait_for` can wrap it
    cleanly (the connection setup and the protocol call both need the
    timeout, not just the call).
    """
    async with (
        streamablehttp_client(url, headers=headers) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        return await session.list_tools()


async def _do_call_tool(
    url: str,
    headers: dict[str, str] | None,
    tool_name: str,
    arguments: dict[str, Any],
) -> Any:
    """Open a session and call_tool, parallel to `_do_list_tools`.

    Separate coroutine so `asyncio.wait_for` covers the full lifecycle of
    the backend session, not just the protocol call.
    """
    async with (
        streamablehttp_client(url, headers=headers) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        return await session.call_tool(tool_name, arguments=arguments)


def _serialize_tool(tool: Any) -> dict[str, Any]:
    """Convert an MCP Tool dataclass to a JSON-serializable dict."""
    out: dict[str, Any] = {
        "name": tool.name,
        "description": tool.description or "",
        "inputSchema": tool.inputSchema,
    }
    for extra in ("title", "annotations", "outputSchema"):
        value = getattr(tool, extra, None)
        if value is None:
            continue
        # annotations (and sometimes outputSchema) come back as pydantic models
        # (e.g. ToolAnnotations), which are not directly JSON-serializable.
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
        out[extra] = value
    return out


def _serialize_content_block(block: Any) -> dict[str, Any]:
    """Convert an MCP content block (TextContent, ImageContent, etc.) to a dict."""
    kind = getattr(block, "type", None)
    if kind == "text":
        return {"type": "text", "text": getattr(block, "text", "")}
    if kind == "image":
        return {
            "type": "image",
            "data": getattr(block, "data", ""),
            "mimeType": getattr(block, "mimeType", ""),
        }
    if kind == "resource":
        return {"type": "resource", "resource": getattr(block, "resource", {})}
    return {"type": kind or "unknown", "_repr": repr(block)[:200]}
