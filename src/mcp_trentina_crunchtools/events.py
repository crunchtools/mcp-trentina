"""Internal event bus for mcp-trentina-crunchtools.

Fire-and-forget event emission for D-Bus, Cockpit, and future consumers.
Thread-safe ring buffer stores recent events for GetRecentEvents queries.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

RING_BUFFER_SIZE = 100

EventCallback = Callable[[str, dict[str, Any]], None]

_bus: EventBus | None = None
_lock = threading.Lock()


class EventBus:
    """Singleton event bus with thread-safe ring buffer."""

    def __init__(self, max_events: int = RING_BUFFER_SIZE) -> None:
        self._subscribers: dict[str, list[EventCallback]] = {}
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def subscribe(self, event_name: str, callback: EventCallback) -> None:
        """Register a listener for an event type."""
        with self._lock:
            if event_name not in self._subscribers:
                self._subscribers[event_name] = []
            self._subscribers[event_name].append(callback)

    def emit(self, event_name: str, event_data: dict[str, Any]) -> None:
        """Fire-and-forget event emission.

        Stores the event in the ring buffer and notifies all subscribers.
        Exceptions in callbacks are logged but never propagated.
        """
        event = {
            "event": event_name,
            "timestamp": time.time(),
            "data": event_data,
        }

        with self._lock:
            self._events.append(event)
            callbacks = list(self._subscribers.get(event_name, []))

        for cb in callbacks:
            try:
                cb(event_name, event_data)
            except Exception:
                logger.exception("EventBus callback error for %s", event_name)

    def recent_events(self, count: int = RING_BUFFER_SIZE) -> list[dict[str, Any]]:
        """Return the last N events from the ring buffer."""
        with self._lock:
            events = list(self._events)
        return events[-count:] if count < len(events) else events


def get_event_bus() -> EventBus:
    """Get or create the singleton EventBus."""
    global _bus
    if _bus is None:
        with _lock:
            if _bus is None:
                _bus = EventBus()
    return _bus


def reset_event_bus() -> None:
    """Reset the singleton for testing."""
    global _bus
    with _lock:
        _bus = None
