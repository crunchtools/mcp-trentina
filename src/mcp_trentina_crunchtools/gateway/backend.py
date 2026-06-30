"""Backend MCP connection management with persistent tool list caching.

Opens a fresh MCP session per call (streamablehttp_client creates anyio
task groups that cannot cross task boundaries, so pooling is not viable).
Caches tool lists per URL indefinitely — invalidated on backend failure
or explicit flush, persisted in SQLite across restarts.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from ..database import delete_all_tool_lists, delete_tool_list, save_tool_list
from .circuit import breaker
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


_tool_list_cache: dict[str, list[dict[str, Any]]] = {}

_on_evict_callbacks: list[Any] = []


def on_backend_cache_evict(callback: Any) -> None:
    """Register a callback(url) to fire when a backend cache entry is evicted."""
    _on_evict_callbacks.append(callback)


def _evict_backend_cache(url: str) -> None:
    """Remove a backend's cached tool list and notify listeners."""
    if _tool_list_cache.pop(url, None) is not None:
        delete_tool_list(url)
        for cb in _on_evict_callbacks:
            cb(url)
        logger.info("cache: evicted backend %s", url)


def evict_backend_cache_by_name(url: str) -> int:
    """Evict cache for a specific backend. Returns 1 if evicted, 0 if not found."""
    if url in _tool_list_cache:
        _evict_backend_cache(url)
        return 1
    return 0


def flush_all_caches() -> int:
    """Flush all backend caches + SQLite. Returns count evicted."""
    count = len(_tool_list_cache)
    urls = list(_tool_list_cache.keys())
    for url in urls:
        _tool_list_cache.pop(url, None)
        for cb in _on_evict_callbacks:
            cb(url)
    delete_all_tool_lists()
    logger.info("cache: flushed all %d backend caches", count)
    return count


def load_tool_list_cache() -> int:
    """Populate in-memory cache from SQLite at startup. Returns count loaded."""
    from ..database import get_all_tool_lists

    loaded = get_all_tool_lists()
    _tool_list_cache.update(loaded)
    logger.info("cache: loaded %d tool lists from database", len(loaded))
    return len(loaded)


def reset_tool_list_cache() -> None:
    """Clear the in-memory cache without touching SQLite (for testing)."""
    _tool_list_cache.clear()
    _on_evict_callbacks.clear()


async def list_backend_tools(
    backend_name: str, backend: Backend,
) -> list[dict[str, Any]]:
    """Fetch the tool list from one backend MCP server.

    Returns from in-memory cache if available. On miss, fetches from
    the backend and persists to SQLite.

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
        return cached

    headers = backend.headers or None
    try:
        tools_result = await asyncio.wait_for(
            _do_list_tools(backend.url, headers),
            timeout=backend.list_timeout_seconds,
        )
    except Exception as exc:
        breaker.record_failure(backend.url)
        _evict_backend_cache(backend.url)
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
    _tool_list_cache[backend.url] = tools
    save_tool_list(backend.url, tools)
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
        _evict_backend_cache(backend.url)
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
