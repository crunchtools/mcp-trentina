"""Cache management tool — flush backend and profile tool list caches."""

from __future__ import annotations

from typing import Any

from ..gateway.backend import (
    _tool_list_cache,
    evict_backend_cache_by_name,
    flush_all_caches,
)
from ..gateway.router import _profile_tools_cache


async def cache_flush(backend: str | None = None) -> dict[str, Any]:
    """Flush tool list caches.

    With no arguments, flushes all backend and profile caches.
    With a backend name, flushes just that backend (and any profile
    caches that included it).
    """
    if backend is not None:
        urls = [
            url for url in _tool_list_cache
            if backend in url
        ]
        evicted = 0
        for url in urls:
            evicted += evict_backend_cache_by_name(url)
        return {
            "flushed": "backend",
            "backend": backend,
            "urls_evicted": evicted,
            "profile_caches_remaining": len(_profile_tools_cache),
        }

    count = flush_all_caches()
    _profile_tools_cache.clear()
    return {
        "flushed": "all",
        "backend_caches_evicted": count,
        "profile_caches_cleared": True,
    }
