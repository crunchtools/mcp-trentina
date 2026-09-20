"""Cache management tool — flush backend and profile tool list caches.

Scoped by role. An agent profile flushes its own backends and its own
aggregate; the operator flushes the gateway. What an agent may name is
therefore exactly what it already holds, which also ends the old substring
match — ``cache_flush("gw")`` used to evict every cached URL containing "gw",
including backends in profiles the caller had never heard of.

The eviction itself is still felt gateway-wide when a backend is shared: the
tool list cache is keyed by URL, so dropping it drops it for everyone using
that URL, and their aggregates rebuild on next use. That is correctness — a
stale list is stale for every reader — and it discloses nothing.
"""

from __future__ import annotations

import logging
from typing import Any

from ..gateway.backend import evict_backend_cache_url, flush_all_caches
from ..gateway.compress import get_profiles
from ..gateway.errors import ScopeError
from ..gateway.router import _profile_tools_cache, invalidate_profile_cache
from ..gateway.scope import CallerScope, require_caller, resolve_backend

logger = logging.getLogger(__name__)


def _flush_own(scope: CallerScope, backend: str | None) -> dict[str, Any]:
    """Agent path: the caller's own backends, named or all of them."""
    if backend is not None:
        url, _cfg = resolve_backend(scope, backend)
        invalidate_profile_cache(scope.label)
        return {
            "flushed": "backend",
            "scope": scope.label,
            "backend": backend,
            "evicted": evict_backend_cache_url(url),
        }

    flushed = [
        name
        for name, cfg in sorted(scope.backends.items())
        if not cfg.is_internal and evict_backend_cache_url(cfg.url)
    ]
    invalidate_profile_cache(scope.label)
    return {
        "flushed": "profile",
        "scope": scope.label,
        "backends_flushed": flushed,
        "profile_cache_cleared": True,
    }


def _flush_named_gateway_wide(backend: str) -> dict[str, Any]:
    """Operator path for one name: flush it wherever it is configured.

    Resolves through the profile registry, not through the cache keys, so a
    name means a backend somebody configured — never any URL it happens to be
    a substring of.
    """
    profiles = get_profiles() or {}
    urls = {
        cfg.url
        for profile in profiles.values()
        if (cfg := profile.backends.get(backend)) is not None and not cfg.is_internal
    }
    return {
        "flushed": "backend",
        "scope": "gateway",
        "backend": backend,
        "evicted": sum(evict_backend_cache_url(url) for url in urls),
        "urls_matched": len(urls),
    }


async def cache_flush(backend: str | None = None) -> dict[str, Any]:
    """Flush tool list caches, within the caller's role.

    Args:
        backend: Backend name to flush. Omit to flush everything in scope —
            the caller's own backends, or every cache for an operator.

    Returns:
        What was flushed. An agent profile's result names only its own
        backends; a refusal names nothing at all.
    """
    try:
        scope = require_caller("cache_flush")
        if not scope.is_operator:
            return _flush_own(scope, backend)
    except ScopeError as exc:
        logger.warning("cache_flush refused: %s", exc)
        return {"flushed": "nothing", "error": str(exc)}

    if backend is not None:
        return _flush_named_gateway_wide(backend)

    count = flush_all_caches()
    _profile_tools_cache.clear()
    return {
        "flushed": "all",
        "scope": "gateway",
        "backend_caches_evicted": count,
        "profile_caches_cleared": True,
    }
