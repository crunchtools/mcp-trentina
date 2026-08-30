"""Blocklist tool — P-Agent-initiated source blocking."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..database import record_detection
from ..dbus_interface import emit_detection_event


async def blocklist_source(source: str) -> dict[str, Any]:
    """Add a source to the blocklist.

    Called by the P-Agent after evaluating detection metadata.
    Future requests for this source are hard-blocked before fetch.
    """
    # Determine source type and domain
    if source.startswith(("http://", "https://")):
        source_type = "url"
        try:
            domain = urlparse(source).hostname
        except ValueError:
            domain = None
    elif source.startswith("sha256:"):
        source_type = "content"
        domain = None
    else:
        source_type = "file"
        domain = None

    detection_id = record_detection(
        source_type=source_type,
        source=source,
        domain=domain,
        layer1_stats={},
        risk_level="high",
        qagent_assessment={"blocked_by": "p-agent"},
    )

    emit_detection_event(
        layer="P-Agent",
        source=source,
        severity="high",
        details={"action": "blocklist", "detection_id": detection_id},
    )

    return {
        "status": "blocked",
        "source": source,
        "source_type": source_type,
        "detection_id": detection_id,
    }
