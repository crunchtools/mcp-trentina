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
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..gateway.backend import evict_backend_cache_by_name, list_backend_tools
from ..gateway.circuit import breaker
from ..gateway.compress import get_profiles
from ..gateway.errors import BackendCallError
from ..gateway.router import invalidate_profile_cache_for_backend


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


async def reconnect_backend(backend: str) -> dict[str, Any]:
    """Reset and re-probe a single backend by name.

    A backend name can resolve to more than one URL across profiles (e.g. a
    token carried in the URL path differs per profile), so every distinct URL
    for the name is reset and probed independently.

    Args:
        backend: Backend name as it appears in the profile config (e.g.
            "postiz", "slack", "jira").

    Returns:
        Status dict with an overall ``reconnected`` flag and a ``targets`` list
        describing each distinct URL that was reset.
    """
    profiles = get_profiles()
    if profiles is None:
        return {"backend": backend, "reconnected": False, "error": "gateway not initialized"}

    targets: dict[str, dict[str, Any]] = {}
    available: set[str] = set()
    for profile in profiles.values():
        available.update(profile.backends.keys())
        found = profile.backends.get(backend)
        if found is not None:
            entry = targets.setdefault(found.url, {"cfg": found, "profiles": set()})
            entry["profiles"].add(profile.name)

    if not targets:
        return {
            "backend": backend,
            "reconnected": False,
            "error": "backend not found in any profile",
            "available": sorted(available),
        }

    results: list[dict[str, Any]] = []
    for url, entry in targets.items():
        cfg = entry["cfg"]
        base = {"endpoint": _safe_endpoint(url), "profiles": sorted(entry["profiles"])}
        if cfg.is_internal:
            results.append(
                {**base, "reconnected": True, "internal": True,
                 "note": "in-process backend — nothing to reconnect"}
            )
            continue

        breaker.reset(url)
        evict_backend_cache_by_name(url)
        try:
            tools = await list_backend_tools(backend, cfg)
        except BackendCallError as exc:
            results.append(
                {**base, "reconnected": False, "error": str(exc),
                 "circuit": breaker.get_state(url).value}
            )
            continue
        invalidate_profile_cache_for_backend(url)
        results.append(
            {**base, "reconnected": True, "tool_count": len(tools),
             "circuit": breaker.get_state(url).value}
        )

    return {
        "backend": backend,
        "reconnected": all(r["reconnected"] for r in results),
        "targets": results,
    }
