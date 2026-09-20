"""Reconnect tool — recover a single backend after it restarts.

There is no persistent MCP transport to a backend (backend.py opens a fresh
streamable-http session per call), so "reconnect" here means clearing the
recovery state that a backend restart leaves stale:

1. Reset the per-URL circuit breaker (``cache_flush`` never touches it, so an
   open circuit otherwise blocks calls until the 60s cooldown probe succeeds).
2. Evict the cached tool list so the next fetch is a real handshake.
3. Force a fresh probe/fetch that re-warms the cache and records breaker
   success/failure.
4. Invalidate any profile aggregate that omitted the backend while it failed.

This lets an operator recover one backend without restarting the whole gateway.

Scoped by role. An agent profile reconnects a backend it holds, and hears back
about that one: its endpoint, its circuit, and the tool count AS THAT PROFILE
SEES IT through its own allowlist. The operator reconnects a name wherever it
is configured and is told which profiles share it. A name the caller does not
hold is refused the same way whether or not it exists elsewhere, so a miss is
not a map of the rest of the gateway.

Resetting a circuit is felt by every profile on that URL — the breaker is keyed
by URL and healing it heals it for all of them. That is the point of the tool,
not a leak.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

from ..gateway.backend import evict_backend_cache_url, list_backend_tools
from ..gateway.circuit import breaker
from ..gateway.compress import get_profiles
from ..gateway.errors import BackendCallError, ScopeError
from ..gateway.filter import filter_tools
from ..gateway.router import invalidate_profile_cache_for_backend
from ..gateway.scope import (
    CallerScope,
    current_scope,
    require_caller,
    resolve_backend,
)

logger = logging.getLogger(__name__)


def _safe_endpoint(url: str) -> str:
    """Return scheme://host:port only — never the path/query.

    A backend URL can carry an auth token in its path (e.g. Postiz's
    ``/api/mcp/<token>``) or query string, so the full URL must never be
    echoed back to the caller. The host:port is a non-secret network alias.
    """
    parts = urlsplit(url)
    if not parts.netloc:
        return "(redacted)"
    return f"{parts.scheme}://{parts.netloc}"


async def _reset_one(
    backend: str, url: str, cfg: Any, base: dict[str, Any], scope: CallerScope
) -> dict[str, Any]:
    """Reset, re-probe and report one backend URL.

    ``tool_count`` is filtered through the caller's own allowlist, so the
    number is what that profile would actually see on the next tools/list —
    not the backend's raw surface, which for a shared backend is somebody
    else's view.
    """
    if cfg.is_internal:
        return {
            **base,
            "reconnected": True,
            "internal": True,
            "note": "in-process backend — nothing to reconnect",
        }

    breaker.reset(url)
    evict_backend_cache_url(url)
    try:
        tools = await list_backend_tools(backend, cfg)
    except BackendCallError as exc:
        return {
            **base,
            "reconnected": False,
            "error": str(exc),
            "circuit": breaker.get_state(url).value,
        }
    invalidate_profile_cache_for_backend(url)
    visible = tools if scope.is_operator else filter_tools(tools, cfg)
    return {
        **base,
        "reconnected": True,
        "tool_count": len(visible),
        "circuit": breaker.get_state(url).value,
    }


async def reconnect_backend(backend: str) -> dict[str, Any]:
    """Reset and re-probe a backend by name, within the caller's role.

    An agent profile reconnects the backend of that name in its own profile.
    An operator reconnects every distinct URL configured under the name — a
    name can resolve to more than one URL across profiles when the URL carries
    a per-profile token — and is told which profiles share each one.

    Args:
        backend: Backend name as it appears in the caller's profile (e.g.
            "postiz", "slack", "jira").

    Returns:
        Status dict with an overall ``reconnected`` flag and a ``targets`` list
        describing each URL that was reset. A refusal names nothing.
    """
    base: dict[str, Any]
    try:
        scope = require_caller("reconnect_backend")
        if not scope.is_operator:
            url, cfg = resolve_backend(scope, backend)
            base = {"endpoint": _safe_endpoint(url), "scope": scope.label}
            results = [await _reset_one(backend, url, cfg, base, scope)]
            return {
                "backend": backend,
                "scope": scope.label,
                "reconnected": all(r["reconnected"] for r in results),
                "targets": results,
            }
    except ScopeError as exc:
        # The caller's OWN backend names, which turns a typo into a usable
        # correction. Listing the gateway's, which is what this used to do,
        # turned every typo into a directory of every other agent's backends.
        refused = current_scope()
        logger.warning("reconnect_backend refused: %s", exc)
        return {
            "backend": backend,
            "reconnected": False,
            "error": str(exc),
            "available": sorted(refused.backends) if refused else [],
        }

    profiles = get_profiles()
    if profiles is None:
        return {
            "backend": backend,
            "reconnected": False,
            "error": "gateway not initialized",
        }

    targets: dict[str, dict[str, Any]] = {}
    for profile in profiles.values():
        found = profile.backends.get(backend)
        if found is not None:
            entry = targets.setdefault(found.url, {"cfg": found, "profiles": set()})
            entry["profiles"].add(profile.name)

    if not targets:
        return {
            "backend": backend,
            "reconnected": False,
            "error": "backend not found in any profile",
            "available": sorted(
                name for p in profiles.values() for name in p.backends
            ),
        }

    results = []
    for url, entry in targets.items():
        base = {
            "endpoint": _safe_endpoint(url),
            "profiles": sorted(entry["profiles"]),
        }
        results.append(await _reset_one(backend, url, entry["cfg"], base, scope))

    return {
        "backend": backend,
        "scope": "gateway",
        "reconnected": all(r["reconnected"] for r in results),
        "targets": results,
    }

