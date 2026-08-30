"""D-Bus interface for mcp-airlock-crunchtools.

Exposes com.crunchtools.Airlock1 on the system bus with methods for
querying pipeline state and signals for live event streaming.

Uses dbus-fast (pure Python, async, no C deps). Runs in a daemon thread
with its own persistent event loop so the D-Bus connection stays alive
for the lifetime of the server. Signal emission from tool threads uses
call_soon_threadsafe to schedule on the D-Bus event loop.

Gracefully degrades if D-Bus socket is unavailable (e.g. container
without mount).
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from typing import Any

logger = logging.getLogger(__name__)

_dbus_started = False
_dbus_loop: asyncio.AbstractEventLoop | None = None
_dbus_interface: Any = None


def _has_dbus_fast() -> bool:
    """Check if dbus-fast is importable."""
    try:
        import dbus_fast  # noqa: F401
        return True
    except ImportError:
        return False


async def _start_dbus_async() -> None:
    """Start the D-Bus interface on the current event loop.

    Called from the D-Bus daemon thread. The loop must be kept running
    after this coroutine completes to maintain the connection.
    """
    global _dbus_started, _dbus_interface

    from dbus_fast import BusType
    from dbus_fast.aio import MessageBus
    from dbus_fast.auth import (
        UID_NOT_SPECIFIED,
        AuthExternal,
    )

    # Use UID_NOT_SPECIFIED so EXTERNAL auth sends no UID argument.
    # This lets the D-Bus daemon use SO_PEERCRED to determine the real UID,
    # which is required for rootless Podman where the container UID
    # differs from the host-mapped UID.
    auth = AuthExternal(uid=UID_NOT_SPECIFIED)
    bus = await MessageBus(bus_type=BusType.SYSTEM, auth=auth).connect()

    _dbus_interface = _build_interface()
    bus.export("/com/crunchtools/Airlock1", _dbus_interface)

    await bus.request_name("com.crunchtools.Airlock1")

    from .events import get_event_bus

    event_bus = get_event_bus()
    event_bus.subscribe("request_processed", _on_request_processed_threadsafe)
    event_bus.subscribe("detection_occurred", _on_detection_occurred_threadsafe)

    _dbus_started = True
    logger.info("D-Bus interface registered: com.crunchtools.Airlock1")


def _dbus_thread_target() -> None:
    """Daemon thread entry point. Runs D-Bus event loop forever."""
    global _dbus_loop

    _dbus_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_dbus_loop)

    try:
        _dbus_loop.run_until_complete(_start_dbus_async())
        _dbus_loop.run_forever()  # Keep loop alive for D-Bus connection
    except Exception:
        logger.warning("D-Bus thread failed", exc_info=True)


def start_dbus_thread() -> None:
    """Start D-Bus in a daemon thread. Non-blocking, logs warning on failure."""
    if _dbus_started:
        return

    if not _has_dbus_fast():
        logger.warning("dbus-fast not installed — D-Bus interface disabled")
        return

    thread = threading.Thread(
        target=_dbus_thread_target,
        name="dbus-airlock",
        daemon=True,
    )
    thread.start()

    # Give the thread a moment to connect
    thread.join(timeout=3.0)
    if not _dbus_started:
        logger.warning("D-Bus thread started but registration not confirmed within 3s")


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

            # P-Agent name: the MCP client that called us
            from .server import mcp
            p_agent_name = getattr(mcp, "name", "Unknown") or "Unknown"

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
                "p_agent": p_agent_name,
            })

        @method()
        def GetRecentEvents(self, count: "u") -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON array of last N events from SQLite."""
            from .database import get_recent_events
            events = get_recent_events(count)
            # Wrap each row into the event envelope format Cockpit expects
            wrapped = []
            for row in events:
                wrapped.append({
                    "event": row.get("event_type", "request_processed"),
                    "timestamp": row.get("timestamp", 0),
                    "data": row,
                })
            return json.dumps(wrapped)

        @method()
        def GetLayerStatus(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON layer availability status."""
            import os

            from .config import get_config
            from .quarantine.classifier import is_classifier_available

            config = get_config()

            # Derive L2 model name from classifier path basename
            l2_model = os.path.basename(config.classifier_model_path.rstrip("/"))
            # Clean up common prefixes for display
            l2_display = l2_model.replace("-", " ").replace("_", " ").title()

            return json.dumps({
                "l1_sanitize": {
                    "active": True,
                    "engine": "Python",
                    "description": "Deterministic sanitization",
                },
                "l2_classifier": {
                    "active": is_classifier_available(),
                    "model": l2_display,
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

        @method()
        def GetTrustedDomains(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON array of trusted domains from SQLite."""
            from .database import get_trusted_domains
            return json.dumps(get_trusted_domains())

        @method()
        def AddTrustedDomain(self, domain: "s") -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Add a domain to the trust list. Returns JSON result."""
            from .database import add_trusted_domain
            row_id = add_trusted_domain(domain)
            return json.dumps({"status": "added", "domain": domain, "id": row_id})

        @method()
        def RemoveTrustedDomain(self, domain: "s") -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Remove a domain from the trust list. Returns JSON result."""
            from .database import remove_trusted_domain
            removed = remove_trusted_domain(domain)
            return json.dumps({"status": "removed" if removed else "not_found", "domain": domain})

        @method()
        def ImportTrustedDomains(self, domains_json: "s") -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Import domains from JSON array. Returns count added."""
            from .database import import_trusted_domains
            try:
                domains = json.loads(domains_json)
            except (json.JSONDecodeError, TypeError):
                return json.dumps({"error": "Invalid JSON"})
            if not isinstance(domains, list):
                return json.dumps({"error": "Expected JSON array"})
            added = import_trusted_domains(domains, source="dbus-import")
            return json.dumps({"status": "imported", "added": added, "total": len(domains)})

        @method()
        def ExportTrustedDomains(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Export trusted domains as JSON array of domain strings."""
            from .database import get_trusted_domains
            domains = [d["domain"] for d in get_trusted_domains()]
            return json.dumps(domains)

        @method()
        def GetBlocklist(self) -> "s":  # type: ignore[name-defined]  # noqa: N802, F821
            """Return JSON array of all blocklist entries."""
            from .database import get_db
            db = get_db()
            rows = db.execute(
                "SELECT id, source_type, source, domain, detected_at, "
                "risk_level, layer1_stats, qagent_assessment "
                "FROM detections WHERE blocked = 1 "
                "ORDER BY detected_at DESC"
            ).fetchall()
            return json.dumps([dict(r) for r in rows])

        @signal()
        def RequestProcessed(  # noqa: N802
            self,
            tool: "s",  # type: ignore[name-defined]  # noqa: F821
            source: "s",  # type: ignore[name-defined]  # noqa: F821
            trust_level: "s",  # type: ignore[name-defined]  # noqa: F821
            risk_level: "s",  # type: ignore[name-defined]  # noqa: F821
            duration_ms: "u",  # type: ignore[name-defined]  # noqa: F821
            stats_json: "s",  # type: ignore[name-defined]  # noqa: F821
            event_id: "s",  # type: ignore[name-defined]  # noqa: F821
        ) -> None:
            """Signal emitted when a request completes."""

        @signal()
        def DetectionOccurred(  # noqa: N802
            self,
            layer: "s",  # type: ignore[name-defined]  # noqa: F821
            source: "s",  # type: ignore[name-defined]  # noqa: F821
            severity: "s",  # type: ignore[name-defined]  # noqa: F821
            details_json: "s",  # type: ignore[name-defined]  # noqa: F821
            event_id: "s",  # type: ignore[name-defined]  # noqa: F821
            p_agent_name: "s",  # type: ignore[name-defined]  # noqa: F821
        ) -> None:
            """Signal emitted when injection is detected."""

    return Airlock1Interface()


def _on_request_processed_threadsafe(_event: str, data: dict[str, Any]) -> None:
    """EventBus callback — schedule D-Bus signal on the D-Bus event loop."""
    if not _dbus_loop or not _dbus_interface:
        return
    try:
        _dbus_loop.call_soon_threadsafe(
            _dbus_interface.RequestProcessed,
            data.get("tool", ""),
            data.get("source", ""),
            data.get("trust_level", ""),
            data.get("risk_level", ""),
            int(data.get("duration_ms", 0)),
            json.dumps(data.get("stats", {})),
            data.get("event_id", ""),
        )
    except Exception:
        logger.debug("Failed to emit RequestProcessed signal", exc_info=True)


def _on_detection_occurred_threadsafe(_event: str, data: dict[str, Any]) -> None:
    """EventBus callback — schedule D-Bus signal on the D-Bus event loop."""
    if not _dbus_loop or not _dbus_interface:
        return
    try:
        # Resolve P-Agent name for sandboxing daemon correlation
        try:
            from .server import mcp
            p_agent = getattr(mcp, "name", "Unknown") or "Unknown"
        except Exception:
            p_agent = "Unknown"

        _dbus_loop.call_soon_threadsafe(
            _dbus_interface.DetectionOccurred,
            data.get("layer", ""),
            data.get("source", ""),
            data.get("severity", ""),
            json.dumps(data.get("details", {})),
            data.get("event_id", ""),
            p_agent,
        )
    except Exception:
        logger.debug("Failed to emit DetectionOccurred signal", exc_info=True)


MAX_PAYLOAD_PREVIEW = 2000


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
    raw_content: str | None = None,
    sanitized_content: str | None = None,
    l3_model: str | None = None,
    l3_confidence: str | None = None,
    l3_injection_detected: bool | None = None,
    l3_extracted_text: str | None = None,
    l3_input_tokens: int | None = None,
    l3_output_tokens: int | None = None,
) -> None:
    """Convenience: emit a request_processed event and persist to SQLite."""
    from .events import get_event_bus

    event_id = str(uuid.uuid4())
    duration_ms = int((time.time() - start_time) * 1000) if start_time else 0
    now = time.time()

    event_data = {
        "event_id": event_id,
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
        "raw_content": raw_content[:MAX_PAYLOAD_PREVIEW] if raw_content else None,
        "sanitized_content": (
            sanitized_content[:MAX_PAYLOAD_PREVIEW] if sanitized_content else None
        ),
        "l3_model": l3_model,
        "l3_confidence": l3_confidence,
        "l3_injection_detected": l3_injection_detected,
        "l3_extracted_text": (
            l3_extracted_text[:MAX_PAYLOAD_PREVIEW] if l3_extracted_text else None
        ),
        "l3_input_tokens": l3_input_tokens,
        "l3_output_tokens": l3_output_tokens,
        "timestamp": now,
    }

    get_event_bus().emit("request_processed", event_data)

    # Persist to SQLite for durability across restarts
    try:
        from .database import record_event
        record_event(event_id, event_data)
    except Exception:
        logger.debug("Failed to persist event %s to SQLite", event_id, exc_info=True)


def emit_detection_event(
    layer: str,
    source: str,
    severity: str,
    details: dict[str, Any] | None = None,
    event_id: str | None = None,
) -> None:
    """Convenience: emit a detection_occurred event."""
    from .events import get_event_bus

    get_event_bus().emit("detection_occurred", {
        "layer": layer,
        "source": source,
        "severity": severity,
        "details": details or {},
        "event_id": event_id or "",
    })
