"""Stats tool — quarantine_stats for session and blocklist information.

Scoped by role, because "stats" over a shared database is the widest of the
admin tools. Unfiltered, the 30-day audit lists every backend and tool any
profile called, with volumes, and a detection's ``source`` is written as
``profile:backend:tool`` — so the recent-detections list hands the reader other
agents' names and the URLs they fetched.

An agent profile therefore gets its own rows and its own effective settings.
The operator gets the gateway. Nobody gets a host filesystem path they cannot
act on: ``classifier_model_path`` is an operator field.
"""

from __future__ import annotations

from typing import Any

from ..config import get_config
from ..database import get_blocklist_stats, get_compression_stats, get_gateway_call_stats
from ..gateway.errors import ScopeError
from ..gateway.scope import CallerScope, require_caller
from ..quarantine.classifier import is_classifier_available

GATEWAY_AUDIT_LOOKBACK_DAYS = 30

# Shipped inline with the audit block. Without it the columns invite the same
# misreading the outcome taxonomy was built to prevent: "blocked" is the
# defense doing its job, and only "failed" indicates something needs fixing.
COLUMN_MEANINGS = {
    "ok": "Call returned content.",
    "blocked": (
        "Policy stopped the call: defense pipeline block, allowlist denial, "
        "or parameter guard. Working as designed — a security metric, not an "
        "error rate."
    ),
    "failed": (
        "Something broke: tool-reported error, upstream failure, or a gateway "
        "bug. This is the health signal."
    ),
    "unknown": "Row predates the outcome taxonomy.",
}


def _agent_stats(scope: CallerScope) -> dict[str, Any]:
    """One profile's own numbers, and the settings it actually runs under.

    The defense block is the caller's own ``profile.defense`` rather than the
    process defaults, which is both narrower and more accurate: a profile with
    its own provider, model or thresholds was never described by the globals.
    """
    defense = scope.profile.defense if scope.profile is not None else None
    return {
        "scope": scope.label,
        "config": {
            "provider": defense.provider if defense else None,
            "model": defense.model if defense else None,
            "l2_threshold": defense.l2_threshold if defense else None,
            "l3_threshold": defense.l3_threshold if defense else None,
            "enforcement": defense.enforcement if defense else None,
        },
        "classifier": {"available": is_classifier_available()},
        "blocklist": get_blocklist_stats(profile=scope.name),
        "gateway_audit": {
            **get_gateway_call_stats(
                profile=scope.name, days=GATEWAY_AUDIT_LOOKBACK_DAYS
            ),
            "column_meanings": COLUMN_MEANINGS,
        },
    }


async def get_trentina_stats() -> dict[str, Any]:
    """Get trentina session stats, configuration, and blocklist summary.

    Returns:
        The caller's own audit rows, detections and effective defense settings;
        or, for an operator, the gateway-wide view including compression
        savings and the classifier's configured path.
    """
    try:
        scope = require_caller("quarantine_stats")
        if not scope.is_operator:
            return _agent_stats(scope)
    except ScopeError as exc:
        return {"scope": "none", "error": str(exc)}

    config = get_config()
    return {
        "scope": "gateway",
        "config": {
            "model": config.model,
            "fallback": config.fallback,
            "max_content": config.max_content,
            "has_api_key": config.has_api_key,
            "classifier_threshold": config.classifier_threshold,
            "classifier_model_path": config.classifier_model_path,
        },
        "classifier": {
            "available": is_classifier_available(),
            "model_path": config.classifier_model_path,
            "threshold": config.classifier_threshold,
        },
        "blocklist": get_blocklist_stats(),
        "gateway_audit": {
            **get_gateway_call_stats(days=GATEWAY_AUDIT_LOOKBACK_DAYS),
            "column_meanings": COLUMN_MEANINGS,
        },
        "compression": get_compression_stats(),
    }
