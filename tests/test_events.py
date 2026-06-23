"""Tests for the internal EventBus."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

from mcp_trentina_crunchtools.events import EventBus, get_event_bus, reset_event_bus


class TestEventBusEmitSubscribe:
    """Verify emit/subscribe round-trip."""

    def test_subscribe_receives_events(self) -> None:
        bus = EventBus()
        received: list[dict] = []
        bus.subscribe("test_event", lambda name, data: received.append(data))

        bus.emit("test_event", {"key": "value"})

        assert len(received) == 1
        assert received[0]["key"] == "value"

    def test_unsubscribed_events_ignored(self) -> None:
        bus = EventBus()
        received: list[dict] = []
        bus.subscribe("other_event", lambda name, data: received.append(data))

        bus.emit("test_event", {"key": "value"})

        assert len(received) == 0

    def test_multiple_subscribers(self) -> None:
        bus = EventBus()
        cb1 = MagicMock()
        cb2 = MagicMock()
        bus.subscribe("test_event", cb1)
        bus.subscribe("test_event", cb2)

        bus.emit("test_event", {"key": "value"})

        cb1.assert_called_once_with("test_event", {"key": "value"})
        cb2.assert_called_once_with("test_event", {"key": "value"})

    def test_callback_exception_does_not_propagate(self) -> None:
        bus = EventBus()
        good_cb = MagicMock()

        def bad_cb(_name: str, _data: dict) -> None:
            msg = "boom"
            raise RuntimeError(msg)

        bus.subscribe("test_event", bad_cb)
        bus.subscribe("test_event", good_cb)

        bus.emit("test_event", {"key": "value"})

        good_cb.assert_called_once()


class TestRingBuffer:
    """Verify ring buffer behavior."""

    def test_stores_events(self) -> None:
        bus = EventBus(max_events=10)
        bus.emit("e", {"n": 1})
        bus.emit("e", {"n": 2})

        events = bus.recent_events()
        assert len(events) == 2
        assert events[0]["data"]["n"] == 1
        assert events[1]["data"]["n"] == 2

    def test_max_size_enforcement(self) -> None:
        bus = EventBus(max_events=5)
        for i in range(10):
            bus.emit("e", {"n": i})

        events = bus.recent_events()
        assert len(events) == 5
        assert events[0]["data"]["n"] == 5
        assert events[-1]["data"]["n"] == 9

    def test_recent_events_count_limit(self) -> None:
        bus = EventBus(max_events=100)
        for i in range(20):
            bus.emit("e", {"n": i})

        events = bus.recent_events(count=3)
        assert len(events) == 3
        assert events[0]["data"]["n"] == 17

    def test_event_structure(self) -> None:
        bus = EventBus()
        bus.emit("request_processed", {"tool": "safe_fetch"})

        events = bus.recent_events()
        assert len(events) == 1
        assert events[0]["event"] == "request_processed"
        assert "timestamp" in events[0]
        assert events[0]["data"]["tool"] == "safe_fetch"


class TestThreadSafety:
    """Verify concurrent emit/subscribe safety."""

    def test_concurrent_emit(self) -> None:
        bus = EventBus(max_events=1000)
        results: list[int] = []
        lock = threading.Lock()

        def cb(_name: str, data: dict) -> None:
            with lock:
                results.append(data["n"])

        bus.subscribe("e", cb)

        threads = []
        for i in range(50):
            t = threading.Thread(target=bus.emit, args=("e", {"n": i}))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 50
        assert set(results) == set(range(50))

    def test_concurrent_subscribe_and_emit(self) -> None:
        bus = EventBus(max_events=1000)
        call_count = {"n": 0}
        lock = threading.Lock()

        def add_subscriber() -> None:
            def cb(_name: str, _data: dict) -> None:
                with lock:
                    call_count["n"] += 1
            bus.subscribe("e", cb)

        def emit_event(n: int) -> None:
            bus.emit("e", {"n": n})

        threads = []
        for i in range(20):
            threads.append(threading.Thread(target=add_subscriber))
            threads.append(threading.Thread(target=emit_event, args=(i,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        events = bus.recent_events()
        assert len(events) == 20


class TestSingleton:
    """Verify get_event_bus singleton behavior."""

    def test_returns_same_instance(self) -> None:
        reset_event_bus()
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    def test_reset_creates_new_instance(self) -> None:
        reset_event_bus()
        bus1 = get_event_bus()
        reset_event_bus()
        bus2 = get_event_bus()
        assert bus1 is not bus2
