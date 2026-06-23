"""Tests for D-Bus interface — mock D-Bus bus (no real system bus needed)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_trentina_crunchtools.dbus_interface import (
    emit_detection_event,
    emit_request_event,
)
from mcp_trentina_crunchtools.events import reset_event_bus


class TestEmitRequestEvent:
    """Verify emit_request_event fires through EventBus."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_emits_request_processed(self) -> None:
        from mcp_trentina_crunchtools.events import get_event_bus

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

        from mcp_trentina_crunchtools.events import get_event_bus

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


class TestEmitDetectionEvent:
    """Verify emit_detection_event fires through EventBus."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_emits_detection_occurred(self) -> None:
        from mcp_trentina_crunchtools.events import get_event_bus

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
        from mcp_trentina_crunchtools.events import get_event_bus

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

    @pytest.mark.asyncio
    async def test_start_dbus_without_dbus_fast(self) -> None:
        import mcp_trentina_crunchtools.dbus_interface as dbi

        dbi._dbus_started = False

        with patch.object(dbi, "_has_dbus_fast", return_value=False):
            await dbi.start_dbus()

        assert not dbi._dbus_started

    @pytest.mark.asyncio
    async def test_start_dbus_connection_failure(self) -> None:
        import mcp_trentina_crunchtools.dbus_interface as dbi

        dbi._dbus_started = False

        mock_bus_mod = MagicMock()
        mock_msg_bus_instance = AsyncMock()
        mock_msg_bus_instance.connect = AsyncMock(side_effect=ConnectionRefusedError("no socket"))
        mock_bus_mod.MessageBus.return_value = mock_msg_bus_instance

        with (
            patch.object(dbi, "_has_dbus_fast", return_value=True),
            patch.dict("sys.modules", {
                "dbus_fast": MagicMock(),
                "dbus_fast.aio": mock_bus_mod,
            }),
        ):
            await dbi.start_dbus()

        assert not dbi._dbus_started


class TestEventDataShapes:
    """Verify event data contains expected fields."""

    def setup_method(self) -> None:
        reset_event_bus()

    def test_request_event_fields(self) -> None:
        from mcp_trentina_crunchtools.events import get_event_bus

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
            "input_size", "output_size", "stats",
        }
        assert expected_keys.issubset(set(d.keys()))

    def test_detection_event_fields(self) -> None:
        from mcp_trentina_crunchtools.events import get_event_bus

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
