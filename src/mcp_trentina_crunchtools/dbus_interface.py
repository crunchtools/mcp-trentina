"""D-Bus interface for mcp-trentina-crunchtools.

Exposes com.crunchtools.Airlock1 on the system bus with methods for
querying pipeline state and signals for live event streaming.

Uses dbus-fast (pure Python, async, no C deps). Gracefully degrades
if D-Bus socket is unavailable (e.g. container without mount).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

_dbus_started = False


def _has_dbus_fast() -> bool:
    """Check if dbus-fast is importable."""
    try:
        import dbus_fast  # noqa: F401
        return True
    except ImportError:
        return False


async def start_dbus() -> None:
    """Start the D-Bus interface. Non-blocking, logs warning on failure."""
    global _dbus_started

    if _dbus_started:
        return

    if not _has_dbus_fast():
        logger.warning("dbus-fast not installed — D-Bus interface disabled")
        return

    try:
        from dbus_fast import BusType
        from dbus_fast.aio import MessageBus

        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

        interface = _build_interface()
        bus.export("/com/crunchtools/Airlock1", interface)

        await bus.request_name("com.crunchtools.Airlock1")

        from .events import get_event_bus

        event_bus = get_event_bus()
        event_bus.subscribe("request_processed", interface.on_request_processed)
        event_bus.subscribe("detection_occurred", interface.on_detection_occurred)

        _dbus_started = True
        logger.info("D-Bus interface registered: com.crunchtools.Airlock1")

    except Exception:
        logger.warning("D-Bus unavailable — interface disabled", exc_info=True)


def _build_interface() -> Any:
    """Build the Airlock1 D-Bus interface object."""
    from dbus_fast.service import ServiceInterface, method, signal

    class Airlock1Interface(ServiceInterface):
        """com.crunchtools.Airlock1 D-Bus interface."""

        def __init__(self) -> None:
            super().__init__("com.crunchtools.Airlock1")

        @method()
        def GetStats(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON config + blocklist stats + layer status."""
            from .database import get_blocklist_stats
            from .quarantine.classifier import is_classifier_available

            stats = get_blocklist_stats()
            from .config import get_config
            config = get_config()

            return json.dumps({
                "blocklist": stats,
                "config": {
                    "model": config.model,
                    "fallback": config.fallback,
                    "max_content": config.max_content,
                },
                "layers": {
                    "l1_sanitize": True,
                    "l2_classifier": is_classifier_available(),
                    "l3_qagent": config.has_api_key,
                },
            })

        @method()
        def GetRecentEvents(self, count: "u") -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON array of last N events from ring buffer."""
            from .events import get_event_bus
            events = get_event_bus().recent_events(count)
            return json.dumps(events)

        @method()
        def GetLayerStatus(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON layer availability status."""
            from .config import get_config
            from .quarantine.classifier import is_classifier_available

            config = get_config()
            return json.dumps({
                "l1_sanitize": {"active": True, "description": "Deterministic sanitization"},
                "l2_classifier": {
                    "active": is_classifier_available(),
                    "description": "Prompt Guard 2 classifier",
                },
                "l3_qagent": {
                    "active": config.has_api_key,
                    "description": "Gemini Q-Agent",
                    "model": config.model,
                },
            })

        @method()
        def GetTrustConfig(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON trust configuration."""
            from .config import get_config
            config = get_config()
            return json.dumps(config._trust_config)

        @signal()
        def RequestProcessed(  # noqa: N802
            self,
            tool: "s",  # type: ignore[name-defined]  # noqa: F821
            source: "s",  # type: ignore[name-defined]  # noqa: F821
            trust_level: "s",  # type: ignore[name-defined]  # noqa: F821
            risk_level: "s",  # type: ignore[name-defined]  # noqa: F821
            duration_ms: "u",  # type: ignore[name-defined]  # noqa: F821
            stats_json: "s",  # type: ignore[name-defined]  # noqa: F821
        ) -> None:
            """Signal emitted when a request completes."""

        @signal()
        def DetectionOccurred(  # noqa: N802
            self,
            layer: "s",  # type: ignore[name-defined]  # noqa: F821
            source: "s",  # type: ignore[name-defined]  # noqa: F821
            severity: "s",  # type: ignore[name-defined]  # noqa: F821
            details_json: "s",  # type: ignore[name-defined]  # noqa: F821
        ) -> None:
            """Signal emitted when injection is detected."""

        def on_request_processed(self, _event: str, event_payload: dict[str, Any]) -> None:
            """EventBus callback — emit D-Bus signal."""
            self.RequestProcessed(
                event_payload.get("tool", ""),
                event_payload.get("source", ""),
                event_payload.get("trust_level", ""),
                event_payload.get("risk_level", ""),
                int(event_payload.get("duration_ms", 0)),
                json.dumps(event_payload.get("stats", {})),
            )

        def on_detection_occurred(self, _event: str, event_payload: dict[str, Any]) -> None:
            """EventBus callback — emit D-Bus signal."""
            self.DetectionOccurred(
                event_payload.get("layer", ""),
                event_payload.get("source", ""),
                event_payload.get("severity", ""),
                json.dumps(event_payload.get("details", {})),
            )

    return Airlock1Interface()


def emit_request_event(
    tool: str,
    source: str,
    trust_level: str,
    risk_level: str,
    l1_detections: int,
    l1_suspicious: int,
    l2_label: str | None,
    l2_score: float | None,
    input_size: int,
    output_size: int,
    stats: dict[str, int],
    start_time: float | None = None,
) -> None:
    """Convenience: emit a request_processed event."""
    from .events import get_event_bus

    duration_ms = int((time.time() - start_time) * 1000) if start_time else 0

    get_event_bus().emit("request_processed", {
        "tool": tool,
        "source": source,
        "trust_level": trust_level,
        "risk_level": risk_level,
        "duration_ms": duration_ms,
        "l1_detections": l1_detections,
        "l1_suspicious": l1_suspicious,
        "l2_label": l2_label,
        "l2_score": l2_score,
        "input_size": input_size,
        "output_size": output_size,
        "stats": stats,
    })


def emit_detection_event(
    layer: str,
    source: str,
    severity: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Convenience: emit a detection_occurred event."""
    from .events import get_event_bus

    get_event_bus().emit("detection_occurred", {
        "layer": layer,
        "source": source,
        "severity": severity,
        "details": details or {},
    })
