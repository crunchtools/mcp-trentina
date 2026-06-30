"""Backend MCP connection management with tool list caching.

Opens a fresh MCP session per call (streamablehttp_client creates anyio
task groups that cannot cross task boundaries, so pooling is not viable).
Caches tool lists per URL with a configurable TTL to avoid redundant
backend round-trips.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from .circuit import breaker
from .errors import BackendCallError

if TYPE_CHECKING:
    from .profile import Backend

logger = logging.getLogger(__name__)

BACKEND_CACHE_TTL: float = float(
    os.environ.get("TRENTINA_BACKEND_CACHE_TTL", "600")
)


@dataclass(frozen=True)
class BackendCall:
    """Outcome of a backend tool invocation."""

    content: list[dict[str, Any]]
    is_error: bool
    structured_content: dict[str, Any] | None


@dataclass
class _CachedToolList:
    """Cached list_tools result for one backend URL."""

    tools: list[dict[str, Any]]
    cached_at: float


_tool_list_cache: dict[str, _CachedToolList] = {}


def reset_tool_list_cache() -> None:
    """Clear the backend tool list cache (for testing)."""
    _tool_list_cache.clear()


async def list_backend_tools(
    backend_name: str, backend: Backend,
) -> list[dict[str, Any]]:
    """Fetch the tool list from one backend MCP server.

    Checks the per-URL cache first. On miss, opens a fresh session.

    Raises:
        BackendCallError: connection failure, protocol error, timeout, or
            circuit open.
    """
    if not breaker.allow(backend.url):
        raise BackendCallError(
            f"backend {backend_name!r} circuit open — skipped"
        )

    cached = _tool_list_cache.get(backend.url)
    if cached is not None:
        age = time.monotonic() - cached.cached_at
        if age < BACKEND_CACHE_TTL:
            return cached.tools

    headers = backend.headers or None
    try:
        tools_result = await asyncio.wait_for(
            _do_list_tools(backend.url, headers),
            timeout=backend.list_timeout_seconds,
        )
    except Exception as exc:
        breaker.record_failure(backend.url)
        _tool_list_cache.pop(backend.url, None)
        logger.warning(
            "gateway: list_tools failed for backend=%s url=%s err=%s",
            backend_name,
            backend.url,
            exc,
        )
        raise BackendCallError(
            f"backend {backend_name!r} list_tools failed: {type(exc).__name__}"
        ) from exc

    breaker.record_success(backend.url)
    tools = [_serialize_tool(tool) for tool in tools_result.tools]
    _tool_list_cache[backend.url] = _CachedToolList(
        tools=tools, cached_at=time.monotonic(),
    )
    return tools


async def call_backend_tool(
    backend_name: str,
    backend: Backend,
    tool_name: str,
    arguments: dict[str, Any],
) -> BackendCall:
    """Invoke a tool on a backend MCP server, returning the raw result.

    Raises:
        BackendCallError: connection failure, protocol error, timeout, or
            circuit open.
    """
    if not breaker.allow(backend.url):
        raise BackendCallError(
            f"backend {backend_name!r} circuit open — skipped"
        )

    headers = backend.headers or None
    try:
        result = await asyncio.wait_for(
            _do_call_tool(backend.url, headers, tool_name, arguments),
            timeout=backend.timeout_seconds,
        )
    except Exception as exc:
        breaker.record_failure(backend.url)
        _tool_list_cache.pop(backend.url, None)
        logger.warning(
            "gateway: call_tool failed backend=%s tool=%s err=%s",
            backend_name,
            tool_name,
            exc,
        )
        raise BackendCallError(
            f"backend {backend_name!r} call_tool failed: {type(exc).__name__}"
        ) from exc

    breaker.record_success(backend.url)
    content: list[dict[str, Any]] = [
        _serialize_content_block(b) for b in result.content
    ]
    structured = getattr(result, "structuredContent", None)
    return BackendCall(
        content=content,
        is_error=bool(result.isError),
        structured_content=structured if isinstance(structured, dict) else None,
    )


async def _do_list_tools(url: str, headers: dict[str, str] | None) -> Any:
    """Open a fresh session and call list_tools."""
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
    """Open a fresh session and call_tool."""
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
        if hasattr(value, "model_dump"):
            value = value.model_dump(
                mode="json", by_alias=True, exclude_none=True,
            )
        out[extra] = value
    return out


def _serialize_content_block(block: Any) -> dict[str, Any]:
    """Convert an MCP content block to a dict."""
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
        return {
            "type": "resource",
            "resource": getattr(block, "resource", {}),
        }
    return {"type": kind or "unknown"}
