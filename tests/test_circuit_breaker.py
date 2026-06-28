"""Tests for gateway/circuit.py — circuit breaker state machine."""

from __future__ import annotations

from unittest.mock import patch

from mcp_trentina_crunchtools.gateway.circuit import (
    CircuitBreaker,
    State,
)

URL = "http://mcp-rotv:8080/mcp"
URL_B = "http://mcp-slack:8005/mcp"


class TestCircuitBreaker:
    """State machine transitions: closed → open → half-open → closed."""

    def _breaker(self, threshold: int = 3, cooldown: float = 60.0) -> CircuitBreaker:
        return CircuitBreaker(failure_threshold=threshold, cooldown_seconds=cooldown)

    def test_initial_state_is_closed(self) -> None:
        cb = self._breaker()
        assert cb.get_state(URL) is State.CLOSED
        assert cb.allow(URL) is True

    def test_success_keeps_closed(self) -> None:
        cb = self._breaker()
        cb.record_success(URL)
        assert cb.get_state(URL) is State.CLOSED
        assert cb.allow(URL) is True

    def test_failures_below_threshold_stay_closed(self) -> None:
        cb = self._breaker(threshold=3)
        cb.record_failure(URL)
        cb.record_failure(URL)
        assert cb.get_state(URL) is State.CLOSED
        assert cb.allow(URL) is True

    def test_failures_at_threshold_open_circuit(self) -> None:
        cb = self._breaker(threshold=3)
        cb.record_failure(URL)
        cb.record_failure(URL)
        cb.record_failure(URL)
        assert cb.get_state(URL) is State.OPEN
        assert cb.allow(URL) is False

    def test_open_circuit_blocks_calls(self) -> None:
        cb = self._breaker(threshold=1)
        cb.record_failure(URL)
        assert cb.allow(URL) is False
        assert cb.allow(URL) is False

    def test_success_resets_failure_count(self) -> None:
        cb = self._breaker(threshold=3)
        cb.record_failure(URL)
        cb.record_failure(URL)
        cb.record_success(URL)
        cb.record_failure(URL)
        cb.record_failure(URL)
        assert cb.get_state(URL) is State.CLOSED

    def test_cooldown_transitions_to_half_open(self) -> None:
        cb = self._breaker(threshold=1, cooldown=10.0)
        cb.record_failure(URL)
        assert cb.get_state(URL) is State.OPEN

        with patch("mcp_trentina_crunchtools.gateway.circuit.time") as mock_time:
            mock_time.monotonic.side_effect = [100.0, 200.0]
            cb._get(URL).opened_at = 90.0
            assert cb.allow(URL) is True
            assert cb.get_state(URL) is State.HALF_OPEN

    def test_cooldown_not_expired_stays_open(self) -> None:
        cb = self._breaker(threshold=1, cooldown=60.0)
        cb.record_failure(URL)

        with patch("mcp_trentina_crunchtools.gateway.circuit.time") as mock_time:
            mock_time.monotonic.return_value = 30.0
            cb._get(URL).opened_at = 0.0
            assert cb.allow(URL) is False
            assert cb.get_state(URL) is State.OPEN

    def test_half_open_success_closes_circuit(self) -> None:
        cb = self._breaker(threshold=1, cooldown=0.0)
        cb.record_failure(URL)

        with patch("mcp_trentina_crunchtools.gateway.circuit.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            cb._get(URL).opened_at = 0.0
            assert cb.allow(URL) is True

        cb.record_success(URL)
        assert cb.get_state(URL) is State.CLOSED
        assert cb.allow(URL) is True

    def test_half_open_failure_reopens_circuit(self) -> None:
        cb = self._breaker(threshold=1, cooldown=0.0)
        cb.record_failure(URL)

        with patch("mcp_trentina_crunchtools.gateway.circuit.time") as mock_time:
            mock_time.monotonic.side_effect = [100.0, 200.0]
            cb._get(URL).opened_at = 0.0
            assert cb.allow(URL) is True

        cb.record_failure(URL)
        assert cb.get_state(URL) is State.OPEN

    def test_half_open_blocks_second_probe(self) -> None:
        cb = self._breaker(threshold=1, cooldown=0.0)
        cb.record_failure(URL)

        with patch("mcp_trentina_crunchtools.gateway.circuit.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            cb._get(URL).opened_at = 0.0
            assert cb.allow(URL) is True
            assert cb.allow(URL) is False

    def test_independent_circuits_per_url(self) -> None:
        cb = self._breaker(threshold=1)
        cb.record_failure(URL)
        assert cb.get_state(URL) is State.OPEN
        assert cb.get_state(URL_B) is State.CLOSED
        assert cb.allow(URL_B) is True

    def test_reset_single_url(self) -> None:
        cb = self._breaker(threshold=1)
        cb.record_failure(URL)
        cb.record_failure(URL_B)
        cb.reset(URL)
        assert cb.get_state(URL) is State.CLOSED
        assert cb.get_state(URL_B) is State.OPEN

    def test_reset_all(self) -> None:
        cb = self._breaker(threshold=1)
        cb.record_failure(URL)
        cb.record_failure(URL_B)
        cb.reset()
        assert cb.get_state(URL) is State.CLOSED
        assert cb.get_state(URL_B) is State.CLOSED
