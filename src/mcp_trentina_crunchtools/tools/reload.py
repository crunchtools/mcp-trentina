"""Profile reload tool — apply a profiles.yaml edit without a gateway restart.

Restarting to apply a profile edit is not cheap. On restart the gateway
re-judges every tool description in every profile through all three defense
layers before the first `tools/list` can answer; on the CrunchTools
deployment (~380 tools across two active profiles) that ran for over forty
minutes, during which clients time out on connect. A one-line allowlist
change cannot cost that, or it stops being made — and editing the file
without a reload did nothing at all, because `_build_profile_tools` rebuilds
its aggregate from the IN-MEMORY `Profile`. The file that decides which
destructive tools an agent may call is the worst possible place for an edit
that silently does nothing.

What makes the reload cheap is what it deliberately leaves alone:

* The perimeter verdict cache. Its key is (kind, defense thresholds,
  description text) — not the profile name, and nothing a `tools_allow` edit
  touches — so the rebuilt aggregate re-judges nothing. Editing a profile's
  `defense` thresholds DOES change that key and those descriptions are judged
  again, which is the honest cost of changing the policy they were judged
  under, and the only edit that pays it.
* The per-backend tool list cache, so no backend is re-probed and no circuit
  breaker is disturbed. Only the per-profile aggregate — the filtered,
  namespaced view — is dropped and rebuilt.

The swap is all-or-nothing: the new YAML is parsed, validated and its secrets
resolved in full BEFORE anything is mutated, so a bad edit leaves the running
gateway exactly as it was and returns the error. See `loader.ActiveConfig`
for why mutating the registry dict in place is the entire swap.

What a reload touches is decided by the caller's role (``gateway/scope.py``).

An OPERATOR reload is the one described above: the whole file, every profile,
the gateway-wide settings, and the full diff.

An AGENT reload validates the whole file — a bad edit anywhere still refuses,
because half a file is not a config — and then applies exactly one entry: the
caller's own. Other profiles keep serving what they were serving, and their
diffs are not reported, because another agent's backend names, allowlist deltas
and guarded parameter names are the shape of its permissions and nobody else's
business. The note the caller gets back is fixed text, so it says nothing about
whether anyone else moved.

One thing an agent reload will not do is apply a change to its OWN ``role``.
The file is the authority on who is the operator, and file write access is the
real trust boundary — but a profile promoting itself in a single call is a
worse shape than one that costs an operator reload or a restart.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ..gateway.compress import retrigger_compression
from ..gateway.errors import ScopeError
from ..gateway.llm_proxy import validate_profile_llm_keys
from ..gateway.loader import (
    get_active_config,
    load_profiles,
    replace_active_config,
)
from ..gateway.router import invalidate_profile_cache
from ..gateway.scope import CallerScope, require_caller
from ..gateway.sessions import session_registry

if TYPE_CHECKING:
    from ..gateway.loader import ActiveConfig, GatewayConfig
    from ..gateway.profile import Backend, Profile

logger = logging.getLogger(__name__)


def _glob_delta(before: list[str], after: list[str]) -> dict[str, list[str]] | None:
    """Set-style delta between two glob lists, or None if they match.

    Order within an allow/deny list carries no meaning (a name matches any
    pattern in it, and deny always wins over allow), so a reordering is
    correctly reported as no change.
    """
    added = [pat for pat in after if pat not in before]
    removed = [pat for pat in before if pat not in after]
    if not added and not removed:
        return None
    return {"added": added, "removed": removed}


def _guard_delta(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> dict[str, dict[str, list[str]]]:
    """Per-tool parameter-guard delta, by parameter NAME only.

    Guard patterns are operator-authored and not secrets, but they are also
    not what an operator needs read back — "the guard on `path` changed" is
    the fact, and the file is the authority on what it changed to.
    """
    delta: dict[str, dict[str, list[str]]] = {}
    for tool in sorted(set(before) | set(after)):
        old = before.get(tool, {})
        new = after.get(tool, {})
        entry = {
            "parameters_added": sorted(set(new) - set(old)),
            "parameters_removed": sorted(set(old) - set(new)),
            "parameters_changed": sorted(
                name for name in set(old) & set(new) if old[name] != new[name]
            ),
        }
        if any(entry.values()):
            delta[tool] = {k: v for k, v in entry.items() if v}
    return delta


def _backend_delta(before: Backend, after: Backend) -> dict[str, Any]:
    """What changed on one backend. Empty dict means nothing did."""
    candidate: dict[str, Any] = {
        "tools_allow": _glob_delta(before.tools_allow, after.tools_allow),
        "tools_deny": _glob_delta(before.tools_deny, after.tools_deny),
        "parameter_guards": _guard_delta(
            before.parameter_guards, after.parameter_guards
        ),
        "fields_changed": sorted(
            name
            for name in type(before).model_fields
            if name not in ("tools_allow", "tools_deny", "parameter_guards")
            and getattr(before, name) != getattr(after, name)
        ),
    }
    return {key: value for key, value in candidate.items() if value}


def _profile_delta(before: Profile, after: Profile) -> dict[str, Any]:
    """What changed on one profile. Empty dict means nothing did."""
    candidate: dict[str, Any] = {
        "backends_added": sorted(set(after.backends) - set(before.backends)),
        "backends_removed": sorted(set(before.backends) - set(after.backends)),
        "backends_changed": {
            name: delta
            for name in sorted(set(before.backends) & set(after.backends))
            if (delta := _backend_delta(before.backends[name], after.backends[name]))
        },
        "fields_changed": sorted(
            name
            for name in type(before).model_fields
            if name not in ("name", "backends")
            and getattr(before, name) != getattr(after, name)
        ),
    }
    return {key: value for key, value in candidate.items() if value}


def _compression_surface(profiles: dict[str, Profile]) -> set[tuple[str, bool]]:
    """The (url, compress_descriptions) pairs description compression walks.

    Re-arming compression is worth a fan-out only when this set moved.
    ``precompress_all`` deduplicates by URL and ``_find_uncached`` skips every
    description already cached, so a tools_deny edit would cost one tools/list
    per compressing backend and buy nothing.
    """
    return {
        (backend.url, backend.compress_descriptions)
        for profile in profiles.values()
        for backend in profile.backends.values()
        if not backend.is_internal
    }


def _unapplied(active: ActiveConfig, new_config: GatewayConfig) -> list[str]:
    """Name every edit in the new file that a reload cannot put into force.

    These are the sections bound into route closures at startup. Reporting
    success over one of them would recreate exactly the failure this tool
    exists to end: a validated edit that changed nothing, believed.
    """
    notes: list[str] = []
    current = active.config

    if new_config.llm_providers != current.llm_providers:
        notes.append(
            "llm_providers changed: the /llm proxy binds its provider set at "
            "startup — restart to apply (per-profile llm_keys DID reload)"
        )
    if new_config.matrix != current.matrix:
        notes.append(
            "matrix section changed: the upstream and the route are bound at "
            "startup — restart to apply"
        )
    if not active.alert_route_registered and any(
        p.alert_ingress is not None for p in new_config.profiles.values()
    ):
        notes.append(
            "alert_ingress added but /alert/{token} was not registered at "
            "startup (no profile had one) — restart to serve it"
        )
    if not active.matrix_route_registered and any(
        p.matrix_ingress is not None for p in new_config.profiles.values()
    ):
        notes.append(
            "matrix_ingress added but /matrix is off (matrix.enabled) — "
            "restart with it enabled to serve it"
        )
    return notes


AGENT_SCOPE_NOTE = (
    "agent scope — only this profile's section was applied; other profiles "
    "and gateway-wide settings need an operator-scope reload"
)


def _profile_compression_surface(profile: Profile) -> set[tuple[str, bool]]:
    """One profile's slice of the compression surface."""
    return {
        (backend.url, backend.compress_descriptions)
        for backend in profile.backends.values()
        if not backend.is_internal
    }


async def _apply_own_profile(
    scope: CallerScope,
    registry: dict[str, Profile],
    new_config: GatewayConfig,
) -> dict[str, Any]:
    """Agent path: put the caller's own section into force, and nothing else.

    Nothing here touches ``replace_active_config``, the session TTL or the
    session cap: those are gateway-wide, and an agent applying them would be
    changing the terms every other profile runs under.
    """
    name = scope.label
    before = registry.get(name)
    after = new_config.profiles.get(name)

    if before is None or after is None:
        return {
            "reloaded": False,
            "scope": name,
            "error": (
                "this profile is not in the file on disk — an operator reload "
                "or a restart applies a profile that was added or removed"
            ),
        }
    if before.role != after.role:
        return {
            "reloaded": False,
            "scope": name,
            "error": (
                "this profile's role changed on disk — a role change is "
                "applied by an operator reload or a restart, never by the "
                "profile it promotes"
            ),
        }

    delta = _profile_delta(before, after)
    registry[name] = after
    invalidated = invalidate_profile_cache(name)
    if _profile_compression_surface(before) != _profile_compression_surface(after):
        retrigger_compression()
    notified = await session_registry.broadcast_tools_changed(name)

    logger.warning(
        "gateway: profile %s reloaded its own section — %d field group(s) moved",
        name, len(delta),
    )
    return {
        "reloaded": True,
        "scope": name,
        "applied": [name],
        "changes": {name: delta} if delta else {},
        "caches_invalidated": [name] if invalidated else [],
        "sessions_notified": notified,
        "note": AGENT_SCOPE_NOTE,
    }


async def reload_profiles() -> dict[str, Any]:
    """Re-read profiles.yaml and put it into force without a restart.

    Returns:
        A result dict. On success ``scope`` says what was reloaded: the
        caller's profile name for an agent, which applied and reports only its
        own section, or "gateway" for an operator, which applied the whole
        file and reports every profile that moved.

        ``reloaded`` is False with an ``error`` when the caller is unknown, or
        when the file did not validate — in which case the running config is
        untouched. That refusal is itself scoped: an operator also gets the
        ``path`` it failed to load and the ``profiles`` currently serving,
        while an agent gets the parse error alone, because the file it cannot
        read and the roster it does not hold are not its business.
    """
    active = get_active_config()
    if active is None:
        return {"reloaded": False, "error": "gateway not initialized"}

    try:
        scope = require_caller("reload_profiles")
    except ScopeError as exc:
        logger.warning("reload_profiles refused: %s", exc)
        return {"reloaded": False, "error": str(exc)}

    path = active.path
    before = dict(active.config.profiles)

    try:
        new_config = load_profiles(path)
        # Startup runs this via register_llm_routes; a reload has to run it
        # itself or a profile could name a provider the proxy has never heard
        # of, and the dangling reference would surface as a runtime 502
        # instead of a refused reload.
        validate_profile_llm_keys(active.llm_providers, new_config.profiles)
    except Exception as exc:
        # Deliberately everything: whatever went wrong reading or validating
        # the file, the running config is the one that keeps serving. The
        # traceback goes to the journal because the returned message is
        # load_profiles' own for every expected cause, and an unexpected one
        # is exactly where an operator needs more than its str().
        logger.warning(
            "gateway: profile reload REFUSED from %s: %s", path, exc, exc_info=True,
        )
        refusal: dict[str, Any] = {
            "reloaded": False,
            "error": str(exc),
            "note": "running configuration left unchanged",
        }
        if scope.is_operator:
            refusal["path"] = str(path)
            refusal["profiles"] = sorted(before)
        return refusal

    if not scope.is_operator:
        return await _apply_own_profile(scope, active.config.profiles, new_config)

    after = new_config.profiles
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = {
        name: delta
        for name in sorted(set(before) & set(after))
        if (delta := _profile_delta(before[name], after[name]))
    }

    # Read the startup wiring facts before the swap replaces the holder.
    not_applied = _unapplied(active, new_config)

    # The swap. Every route handler, the compression module and the
    # circuit-breaker wiring hold THIS dict object and read it per request, so
    # refilling it in place is what makes the new config live everywhere at
    # once. Binding the name to a fresh dict would reach none of them.
    registry = active.config.profiles
    registry.clear()
    registry.update(new_config.profiles)
    session_registry.session_ttl = new_config.session_ttl_seconds
    session_registry.max_sessions_per_profile = new_config.max_sessions_per_profile
    replace_active_config(replace(new_config, profiles=registry))

    invalidated = [
        name for name in (*added, *removed, *changed) if invalidate_profile_cache(name)
    ]
    if _compression_surface(before) != _compression_surface(after):
        retrigger_compression()

    dropped_sessions = sum(
        session_registry.delete_session(session.session_id)
        for name in removed
        for session in session_registry.get_sessions_for_profile(name)
    )
    notified = {
        name: await session_registry.broadcast_tools_changed(name)
        for name in [*added, *changed]
    }

    logger.warning(
        "gateway: profiles reloaded from %s by %s — %d added, %d removed, %d changed",
        path, scope.label, len(added), len(removed), len(changed),
    )
    return {
        "reloaded": True,
        "scope": "gateway",
        "path": str(path),
        "profiles": {
            "added": added,
            "removed": removed,
            "changed": sorted(changed),
            "unchanged": sorted((set(before) & set(after)) - set(changed)),
        },
        "changes": changed,
        "caches_invalidated": invalidated,
        "sessions_notified": {k: v for k, v in notified.items() if v},
        "sessions_dropped": dropped_sessions,
        "not_applied": not_applied,
    }
