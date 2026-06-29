"""Shared fixtures for gateway tests."""

from __future__ import annotations

import pytest

from mcp_trentina_crunchtools.gateway.circuit import breaker


@pytest.fixture(autouse=True)
def _reset_circuit_breaker() -> None:
    """Reset the global circuit breaker before every test.

    The module-level ``breaker`` singleton accumulates state across tests.
    Without this fixture, a test that opens a circuit and then fails before
    calling ``breaker.reset()`` leaks that state into subsequent tests.
    """
    breaker.reset()
