"""Stats tool — quarantine_stats for session and blocklist information."""

from __future__ import annotations

from typing import Any

from ..config import get_config
from ..database import get_blocklist_stats, get_compression_stats, get_gateway_call_stats
from ..quarantine.classifier import is_classifier_available


async def get_trentina_stats() -> dict[str, Any]:
    """Get trentina session stats, configuration, and blocklist summary.

    The audit block ships ``column_meanings`` inline. Without it the columns
    invite the same misreading the outcome taxonomy was built to prevent:
    "blocked" is the defense doing its job, and only "failed" indicates
    something needs fixing.
    """
    config = get_config()

    blocklist = get_blocklist_stats()

    return {
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
        "blocklist": blocklist,
        "gateway_audit": {
            **get_gateway_call_stats(days=30),
            "column_meanings": {
                "ok": "Call returned content.",
                "blocked": (
                    "Policy stopped the call: defense pipeline block, allowlist "
                    "denial, or parameter guard. Working as designed — a "
                    "security metric, not an error rate."
                ),
                "failed": (
                    "Something broke: tool-reported error, upstream failure, or "
                    "a gateway bug. This is the health signal."
                ),
                "unknown": "Row predates the outcome taxonomy.",
            },
        },
        "compression": get_compression_stats(),
    }
