"""Per-URL circuit breaker for backend MCP connections.

Tracks consecutive failures per backend URL. After ``failure_threshold``
consecutive failures the circuit opens and immediately rejects calls for
``cooldown_seconds``.  After cooldown, one probe call is allowed through
(half-open); success closes the circuit, failure re-opens it.

All state is in-memory (single event loop, no locking needed).  Timing
uses ``time.monotonic`` so clock adjustments cannot extend a cooldown.
"""

from __future__ import annotations

import logging
import time
from enum import Enum

logger = logging.getLogger(__name__)

DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_COOLDOWN_SECONDS = 60.0


class State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class _CircuitState:
    """Mutable state for one circuit (one backend URL)."""

    __slots__ = (
        "consecutive_failures",
        "opened_at",
        "probe_in_flight",
        "state",
    )

    def __init__(self) -> None:
        self.state = State.CLOSED
        self.consecutive_failures = 0
        self.opened_at = 0.0
        self.probe_in_flight = False


class CircuitBreaker:
    """Circuit breaker registry keyed by backend URL."""

    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
    ) -> None:
        self._threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._circuits: dict[str, _CircuitState] = {}

    def _get(self, url: str) -> _CircuitState:
        circuit = self._circuits.get(url)
        if circuit is None:
            circuit = _CircuitState()
            self._circuits[url] = circuit
        return circuit

    def allow(self, url: str) -> bool:
        """Return True if a call to *url* should proceed.

        - Closed: always allowed.
        - Open: blocked until cooldown expires, then one probe is allowed
          (transition to half-open).
        - Half-open: blocked if a probe is already in flight.
        """
        circuit = self._get(url)

        if circuit.state is State.CLOSED:
            return True

        if circuit.state is State.OPEN:
            elapsed = time.monotonic() - circuit.opened_at
            if elapsed < self._cooldown:
                return False
            circuit.state = State.HALF_OPEN
            circuit.probe_in_flight = True
            logger.info("circuit: %s half-open, allowing probe", url)
            return True

        if circuit.probe_in_flight:
            return False
        circuit.probe_in_flight = True
        return True

    def record_success(self, url: str) -> None:
        """Record a successful call — reset failures and close the circuit."""
        circuit = self._get(url)
        was_open = circuit.state is not State.CLOSED
        circuit.consecutive_failures = 0
        circuit.probe_in_flight = False
        circuit.state = State.CLOSED
        if was_open:
            logger.info("circuit: %s closed after successful probe", url)

    def record_failure(self, url: str) -> None:
        """Record a failed call — increment counter, open if threshold reached."""
        circuit = self._get(url)
        circuit.consecutive_failures += 1
        circuit.probe_in_flight = False

        if circuit.state is State.HALF_OPEN:
            circuit.state = State.OPEN
            circuit.opened_at = time.monotonic()
            logger.warning("circuit: %s re-opened after failed probe", url)
            return

        if circuit.consecutive_failures >= self._threshold:
            circuit.state = State.OPEN
            circuit.opened_at = time.monotonic()
            logger.warning(
                "circuit: %s opened after %d consecutive failures",
                url,
                circuit.consecutive_failures,
            )

    def get_state(self, url: str) -> State:
        """Return the current state for *url* (for diagnostics/logging)."""
        return self._get(url).state

    def reset(self, url: str | None = None) -> None:
        """Reset one circuit or all circuits (for testing)."""
        if url is None:
            self._circuits.clear()
        else:
            self._circuits.pop(url, None)


breaker = CircuitBreaker()
