"""Stats tool — quarantine_stats for session and blocklist information."""

from __future__ import annotations

from typing import Any

from ..config import get_config
from ..database import get_blocklist_stats, get_gateway_call_stats
from ..quarantine.classifier import is_classifier_available


async def get_airlock_stats() -> dict[str, Any]:
    """Get airlock session stats, configuration, and blocklist summary."""
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
        "gateway_audit": get_gateway_call_stats(days=30),
    }
