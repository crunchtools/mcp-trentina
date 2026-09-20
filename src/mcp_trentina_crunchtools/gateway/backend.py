"""Backend MCP connection management with persistent tool list caching.

Opens a fresh MCP session per call (streamable_http_client creates anyio
task groups that cannot cross task boundaries, so pooling is not viable).
Caches tool lists per URL indefinitely — invalidated only on explicit flush
or reconnect, persisted in SQLite across restarts. Crucially, a fetch failure
never evicts: a cached backend keeps being served from cache through a transient
outage, so a backend blip can never wipe the cache (which previously triggered a
fan-out stampede). Concurrent misses for the same URL coalesce into a single
in-flight fetch.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from ..database import delete_all_tool_lists, delete_tool_list, save_tool_list
from .circuit import breaker
from .errors import BackendCallError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from .profile import Backend


@asynccontextmanager
async def _connect_streamable_http(
    url: str, headers: dict[str, str] | None,
) -> AsyncIterator[Any]:
    """Adapt this module's ``headers`` dict onto mcp's ``http_client=`` API.

    ``streamable_http_client`` only manages an ``httpx2.AsyncClient``'s
    lifecycle when it creates one itself -- passing a pre-configured client
    makes the caller responsible for closing it.

    The client is ``httpx2``, not ``httpx``: that is the fork the MCP SDK
    builds on and annotates for. The two are separate distributions with
    separate import names and coexist happily, so trentina's own ``httpx``
    use elsewhere (quarantine's Gemini REST calls) is untouched. Passing an
    ``httpx`` client here does work at runtime -- httpx2 is a fork with the
    same API -- but it is a type error, and relying on two HTTP stacks
    staying API-identical is not a bet worth carrying.

    Yields ``(read, write)``. The SDK has shipped the stream bundle as both a
    2-tuple and a 3-tuple (trailing session-id callback); that trailing element
    is unused here, so take the first two either way rather than unpacking a
    fixed width at the call sites.
    """
    if not headers:
        async with streamable_http_client(url) as streams:
            yield streams[0], streams[1]
        return

    async with (
        httpx2.AsyncClient(headers=headers) as http_client,
        streamable_http_client(url, http_client=http_client) as streams,
    ):
        yield streams[0], streams[1]

logger = logging.getLogger(__name__)

_MISSING = object()


def _field(obj: Any, snake: str, camel: str, default: Any = None) -> Any:
    """Read an MCP model field without depending on fastmcp's alias shim.

    SDK 2.x renamed every model field to snake_case (``input_schema``,
    ``is_error``, ``structured_content``); camelCase survives only as a
    pydantic *serialization* alias, so it is absent from objects deserialized
    off the wire.

    fastmcp re-attaches the camelCase spellings as deprecated properties when
    it is imported, which means reading ``tool.inputSchema`` appears to keep
    working -- but only as a side effect of importing fastmcp, and only until
    the shim is dropped (it already emits FastMCPDeprecationWarning). That is
    a trap, not compatibility: this module must be correct on a raw SDK object
    with fastmcp absent, which ``tests/test_backend_no_fastmcp.py`` enforces.

    Reads the real field name first and keeps camelCase only as a fallback for
    SDK 1.x objects, so the gateway stays correct against either SDK vintage.
    """
    value = getattr(obj, snake, _MISSING)
    if value is _MISSING:
        value = getattr(obj, camel, _MISSING)
    return default if value is _MISSING else value


@dataclass(frozen=True)
class BackendCall:
    """Outcome of a backend tool invocation."""

    content: list[dict[str, Any]]
    is_error: bool
    structured_content: dict[str, Any] | None


_tool_list_cache: dict[str, list[dict[str, Any]]] = {}

_inflight: dict[str, asyncio.Task[list[dict[str, Any]]]] = {}

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
    _inflight.clear()
    _on_evict_callbacks.clear()


async def list_backend_tools(
    backend_name: str, backend: Backend,
) -> list[dict[str, Any]]:
    """Fetch the tool list from one backend MCP server.

    A cached backend is always served from cache — the fast path never touches
    the transport or circuit breaker. Because the cache is never evicted on
    failure (only on explicit flush/reconnect), a transient backend outage can
    neither wipe nor bypass the last-known-good list: it keeps being served
    here. On a genuine miss, concurrent callers coalesce onto one in-flight
    fetch per URL.

    Raises:
        BackendCallError: connection failure, protocol error, timeout, or
            circuit open — only on a cold miss with nothing cached to serve.
    """
    cached = _tool_list_cache.get(backend.url)
    if cached is not None:
        return cached

    inflight = _inflight.get(backend.url)
    if inflight is None:
        inflight = asyncio.ensure_future(_single_flight_fetch(backend_name, backend))
        _inflight[backend.url] = inflight
    return await inflight


async def _single_flight_fetch(
    backend_name: str, backend: Backend,
) -> list[dict[str, Any]]:
    """Run one fetch and drop its in-flight slot when done."""
    try:
        return await _fetch_and_cache(backend_name, backend)
    finally:
        _inflight.pop(backend.url, None)


async def _fetch_and_cache(
    backend_name: str, backend: Backend,
) -> list[dict[str, Any]]:
    """Fetch one backend's tool list, cache it, and persist to SQLite.

    Only invoked on a cache miss (``list_backend_tools`` serves any cached list
    directly and never evicts on failure), so there is never a stale entry to
    fall back on here — a failure simply raises.
    """
    if not breaker.allow(backend.url):
        raise BackendCallError(
            f"backend {backend_name!r} circuit open — skipped"
        )

    headers = backend.headers or None
    try:
        tools_result = await asyncio.wait_for(
            _do_list_tools(backend.url, headers),
            timeout=backend.list_timeout_seconds,
        )
    except Exception as exc:
        breaker.record_failure(backend.url)
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

    A failed call records a circuit failure but deliberately does NOT evict the
    tool-list cache — a transient call error must not wipe the list and trigger a
    refetch storm on the next tools/list. The list refreshes only on flush.

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
            _do_call_tool(
                backend.url, headers, tool_name, arguments,
                validate_output=backend.validate_output_schema,
            ),
            timeout=backend.timeout_seconds,
        )
    except Exception as exc:
        breaker.record_failure(backend.url)
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
    # SDK 2.x widened call_tool's return to CallToolResult | InputRequiredResult
    # | Result. Only the first carries content/is_error; the others arrive when
    # a tool wants elicitation or hands back a bare result. The gateway does not
    # negotiate those capabilities, so anything without content is a protocol
    # surprise rather than a tool answer -- surface it instead of reporting an
    # empty success.
    raw_content = _field(result, "content", "content", _MISSING)
    if raw_content is _MISSING:
        raise BackendCallError(
            f"backend {backend_name!r} returned {type(result).__name__} "
            f"for tool {tool_name!r}, which carries no content"
        )
    content: list[dict[str, Any]] = [
        _serialize_content_block(b) for b in raw_content
    ]
    structured = _field(result, "structured_content", "structuredContent")
    return BackendCall(
        content=content,
        is_error=bool(_field(result, "is_error", "isError", False)),
        structured_content=structured if isinstance(structured, dict) else None,
    )


async def _do_list_tools(url: str, headers: dict[str, str] | None) -> Any:
    """Open a fresh session and call list_tools."""
    async with (
        _connect_streamable_http(url, headers) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        return await session.list_tools()


async def _do_call_tool(
    url: str,
    headers: dict[str, str] | None,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    validate_output: bool = True,
) -> Any:
    """Open a fresh session and call_tool.

    When ``validate_output`` is False, client-side output-schema validation is
    disabled for buggy backends: the cached schemas are cleared and the
    validator is replaced with a no-op. The SDK internals are reached through
    an ``Any`` alias so the method override type-checks without a suppression.

    SDK 2.x renamed the validator ``_validate_tool_result`` -> public
    ``validate_tool_result``. Assigning the old name would silently create a
    dead attribute, leaving validation switched ON for exactly the backends
    this flag exists to accommodate -- a misconfiguration that reports as a
    backend failure. So the override asserts it actually patched something.
    """
    async with (
        _connect_streamable_http(url, headers) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        if not validate_output:
            _disable_output_validation(session)
        return await session.call_tool(tool_name, arguments=arguments)


def _disable_output_validation(session: Any) -> None:
    """Neuter client-side output-schema validation on an open session.

    Raises:
        BackendCallError: the SDK exposes neither known validator name, so the
            override would be a no-op. Fail loudly rather than quietly honour
            the opposite of what the profile asked for.
    """
    schemas = getattr(session, "_tool_output_schemas", None)
    if schemas is not None:
        schemas.clear()

    for attr in ("validate_tool_result", "_validate_tool_result"):
        if hasattr(session, attr):
            setattr(session, attr, _noop_validate)
            return

    raise BackendCallError(
        "cannot disable output-schema validation: this MCP SDK exposes no "
        "known validator hook (tried validate_tool_result, "
        "_validate_tool_result)"
    )


async def _noop_validate(name: str, result: Any) -> None:
    """Skip client-side output schema validation."""


def _serialize_tool(tool: Any) -> dict[str, Any]:
    """Convert an MCP Tool dataclass to a JSON-serializable dict.

    Reads snake_case field names (see ``_field``) but **emits camelCase keys**:
    those are the MCP wire format, unchanged across every protocol revision,
    and the whole defense pipeline downstream keys off them. The rename was
    Python-side only.
    """
    out: dict[str, Any] = {
        "name": tool.name,
        "description": tool.description or "",
        "inputSchema": _field(tool, "input_schema", "inputSchema"),
    }
    for wire_key, snake, camel in (
        ("title", "title", "title"),
        ("annotations", "annotations", "annotations"),
        ("outputSchema", "output_schema", "outputSchema"),
    ):
        value = _field(tool, snake, camel)
        if value is None:
            continue
        if hasattr(value, "model_dump"):
            value = value.model_dump(
                mode="json", by_alias=True, exclude_none=True,
            )
        out[wire_key] = value
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
            "mimeType": _field(block, "mime_type", "mimeType", ""),
        }
    if kind == "resource":
        resource = getattr(block, "resource", None)
        if resource is not None and hasattr(resource, "model_dump"):
            # The SDK hands back a pydantic TextResourceContents, not a
            # dict. Passing the model through raw meant the perimeter's
            # isinstance(resource, dict) walk never saw its text (a scan
            # skip) and json.dumps crashed the response (a 500). Dump it.
            resource = resource.model_dump(mode="json", exclude_none=True)
        return {
            "type": "resource",
            "resource": resource if resource is not None else {},
        }
    return {"type": kind or "unknown"}
