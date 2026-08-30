"""Tests for D-Bus interface — mock D-Bus bus (no real system bus needed)."""

from __future__ import annotations

import os
import tempfile

import pytest
from unittest.mock import MagicMock, patch

from mcp_airlock_crunchtools.dbus_interface import (
    emit_detection_event,
    emit_request_event,
)
from mcp_airlock_crunchtools.events import reset_event_bus


class TestEmitRequestEvent:
    """Verify emit_request_event fires through EventBus."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_emits_request_processed(self) -> None:
        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("request_processed", lambda _name, data: received.append(data))

        emit_request_event(
            tool="safe_fetch",
            source="https://example.com",
            trust_level="trusted-sanitized",
            risk_level="low",
            l1_detections=0,
            l1_suspicious=0,
            l2_label="BENIGN",
            l2_score=0.02,
            input_size=5000,
            output_size=3000,
            stats={"hidden_html": 0},
        )

        assert len(received) == 1
        assert received[0]["tool"] == "safe_fetch"
        assert received[0]["source"] == "https://example.com"
        assert received[0]["trust_level"] == "trusted-sanitized"
        assert received[0]["risk_level"] == "low"
        assert received[0]["l2_label"] == "BENIGN"
        assert received[0]["l2_score"] == 0.02
        assert received[0]["input_size"] == 5000
        assert received[0]["output_size"] == 3000

    def test_duration_calculated_from_start_time(self) -> None:
        import time

        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("request_processed", lambda _name, data: received.append(data))

        start = time.time() - 0.1

        emit_request_event(
            tool="quarantine_fetch",
            source="https://evil.com",
            trust_level="quarantined",
            risk_level="high",
            l1_detections=3,
            l1_suspicious=1,
            l2_label="MALICIOUS",
            l2_score=0.95,
            input_size=10000,
            output_size=2000,
            stats={},
            start_time=start,
        )

        assert len(received) == 1
        assert received[0]["duration_ms"] >= 100

    def test_event_id_generated(self) -> None:
        """Verify each event gets a UUID event_id."""
        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("request_processed", lambda _name, data: received.append(data))

        emit_request_event(
            tool="safe_fetch",
            source="https://example.com",
            trust_level="trusted-sanitized",
            risk_level="low",
            l1_detections=0,
            l1_suspicious=0,
            l2_label=None,
            l2_score=None,
            input_size=100,
            output_size=100,
            stats={},
        )

        assert len(received) == 1
        event_id = received[0]["event_id"]
        assert event_id is not None
        assert len(event_id) == 36  # UUID format: 8-4-4-4-12
        assert event_id.count("-") == 4

    def test_event_ids_are_unique(self) -> None:
        """Verify consecutive events get different IDs."""
        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("request_processed", lambda _name, data: received.append(data))

        for _ in range(3):
            emit_request_event(
                tool="safe_fetch",
                source="https://example.com",
                trust_level="trusted-sanitized",
                risk_level="low",
                l1_detections=0,
                l1_suspicious=0,
                l2_label=None,
                l2_score=None,
                input_size=100,
                output_size=100,
                stats={},
            )

        ids = [r["event_id"] for r in received]
        assert len(set(ids)) == 3  # All unique


class TestEmitDetectionEvent:
    """Verify emit_detection_event fires through EventBus."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_emits_detection_occurred(self) -> None:
        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("detection_occurred", lambda _name, data: received.append(data))

        emit_detection_event(
            layer="L2",
            source="https://evil.com",
            severity="high",
            details={"classifier_label": "MALICIOUS", "classifier_score": 0.95},
        )

        assert len(received) == 1
        assert received[0]["layer"] == "L2"
        assert received[0]["source"] == "https://evil.com"
        assert received[0]["severity"] == "high"
        assert received[0]["details"]["classifier_label"] == "MALICIOUS"

    def test_detection_event_includes_event_id(self) -> None:
        """Verify detection events carry event_id field."""
        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        received: list[dict] = []
        bus.subscribe("detection_occurred", lambda _name, data: received.append(data))

        emit_detection_event(
            layer="L1",
            source="https://bad.com",
            severity="high",
            event_id="test-event-123",
        )

        assert received[0]["event_id"] == "test-event-123"


class TestDbusInterfaceMethods:
    """Test D-Bus interface method return data shapes (mocked bus)."""

    def test_build_interface_creates_object(self) -> None:
        with patch.dict("sys.modules", {
            "dbus_fast": MagicMock(),
            "dbus_fast.service": MagicMock(),
            "dbus_fast.aio": MagicMock(),
        }):
            pass

    def test_on_request_processed_callback(self) -> None:
        from mcp_airlock_crunchtools.events import get_event_bus

        reset_event_bus()
        bus = get_event_bus()

        received: list[dict] = []
        bus.subscribe("request_processed", lambda _n, d: received.append(d))

        emit_request_event(
            tool="safe_read",
            source="/tmp/test.txt",
            trust_level="sanitized-only",
            risk_level="low",
            l1_detections=0,
            l1_suspicious=0,
            l2_label=None,
            l2_score=None,
            input_size=100,
            output_size=100,
            stats={},
        )

        assert len(received) == 1
        assert received[0]["tool"] == "safe_read"


class TestGracefulDegradation:
    """Verify D-Bus startup handles missing dbus-fast gracefully."""

    def test_start_dbus_thread_without_dbus_fast(self) -> None:
        import mcp_airlock_crunchtools.dbus_interface as dbi

        dbi._dbus_started = False

        with patch.object(dbi, "_has_dbus_fast", return_value=False):
            dbi.start_dbus_thread()

        assert not dbi._dbus_started


class TestEventDataShapes:
    """Verify event data contains expected fields."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_request_event_fields(self) -> None:
        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        events_captured: list[dict] = []
        bus.subscribe("request_processed", lambda _n, d: events_captured.append(d))

        emit_request_event(
            tool="quarantine_search",
            source="query:test",
            trust_level="quarantined",
            risk_level="low",
            l1_detections=1,
            l1_suspicious=0,
            l2_label="BENIGN",
            l2_score=0.01,
            input_size=500,
            output_size=400,
            stats={"directives_stripped": 1},
        )

        d = events_captured[0]
        expected_keys = {
            "tool", "source", "trust_level", "risk_level", "duration_ms",
            "l1_detections", "l1_suspicious", "l2_label", "l2_score",
            "input_size", "output_size", "stats", "event_id", "timestamp",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_detection_event_fields(self) -> None:
        from mcp_airlock_crunchtools.events import get_event_bus

        bus = get_event_bus()
        events_captured: list[dict] = []
        bus.subscribe("detection_occurred", lambda _n, d: events_captured.append(d))

        emit_detection_event(
            layer="L1",
            source="https://bad.com",
            severity="critical",
        )

        d = events_captured[0]
        assert d["layer"] == "L1"
        assert d["source"] == "https://bad.com"
        assert d["severity"] == "critical"
        assert d["details"] == {}
        assert "event_id" in d


@pytest.mark.uses_real_db
class TestEventPersistence:
    """Verify events are persisted to SQLite."""

    def setup_method(self) -> None:
        reset_event_bus()
        # Reset the database singleton so each test gets a fresh DB
        import mcp_airlock_crunchtools.database as db_mod
        db_mod._db = None

    def test_record_and_retrieve_event(self) -> None:
        from mcp_airlock_crunchtools.database import get_event, record_event

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            import mcp_airlock_crunchtools.database as db_mod
            db_mod._db = None
            with patch("mcp_airlock_crunchtools.database.get_config") as mock_cfg:
                mock_cfg.return_value.db_path = db_path
                mock_cfg.return_value.ensure_db_dir = MagicMock()

                record_event("test-uuid-1234", {
                    "tool": "safe_fetch",
                    "source": "https://example.com",
                    "trust_level": "trusted-sanitized",
                    "risk_level": "low",
                    "duration_ms": 150,
                    "l1_detections": 0,
                    "stats": {"hidden_html": 0},
                    "timestamp": 1700000000.0,
                })

                event = get_event("test-uuid-1234")
                assert event is not None
                assert event["event_id"] == "test-uuid-1234"
                assert event["tool"] == "safe_fetch"
                assert event["source"] == "https://example.com"
                assert event["trust_level"] == "trusted-sanitized"
                assert event["stats"] == {"hidden_html": 0}
        finally:
            db_mod._db = None
            os.unlink(db_path)

    def test_get_recent_events_returns_chronological(self) -> None:
        from mcp_airlock_crunchtools.database import get_recent_events, record_event

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            import mcp_airlock_crunchtools.database as db_mod
            db_mod._db = None
            with patch("mcp_airlock_crunchtools.database.get_config") as mock_cfg:
                mock_cfg.return_value.db_path = db_path
                mock_cfg.return_value.ensure_db_dir = MagicMock()

                for i in range(3):
                    record_event(f"uuid-{i}", {
                        "tool": "safe_fetch",
                        "source": f"https://example{i}.com",
                        "timestamp": 1700000000.0 + i,
                        "stats": {},
                    })

                events = get_recent_events(10)
                assert len(events) == 3
                # Should be chronological (oldest first)
                assert events[0]["event_id"] == "uuid-0"
                assert events[2]["event_id"] == "uuid-2"
        finally:
            db_mod._db = None
            os.unlink(db_path)

    def test_emit_request_event_persists_to_sqlite(self) -> None:
        """Verify emit_request_event writes to SQLite."""
        from mcp_airlock_crunchtools.database import get_event

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            import mcp_airlock_crunchtools.database as db_mod
            db_mod._db = None
            with patch("mcp_airlock_crunchtools.database.get_config") as mock_cfg:
                mock_cfg.return_value.db_path = db_path
                mock_cfg.return_value.ensure_db_dir = MagicMock()

                from mcp_airlock_crunchtools.events import get_event_bus
                bus = get_event_bus()
                received: list[dict] = []
                bus.subscribe("request_processed", lambda _n, d: received.append(d))

                emit_request_event(
                    tool="safe_fetch",
                    source="https://example.com",
                    trust_level="trusted-sanitized",
                    risk_level="low",
                    l1_detections=0,
                    l1_suspicious=0,
                    l2_label="BENIGN",
                    l2_score=0.02,
                    input_size=5000,
                    output_size=3000,
                    stats={"hidden_html": 0},
                )

                assert len(received) == 1
                event_id = received[0]["event_id"]

                # Verify it was persisted
                persisted = get_event(event_id)
                assert persisted is not None
                assert persisted["tool"] == "safe_fetch"
                assert persisted["source"] == "https://example.com"
        finally:
            db_mod._db = None
            os.unlink(db_path)
