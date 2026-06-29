"""Shared fixtures for gateway tests."""

from __future__ import annotations

import pytest

from mcp_trentina_crunchtools.gateway.circuit import breaker
from mcp_trentina_crunchtools.quarantine.providers import reset_provider


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    """Reset global singletons before every test."""
    breaker.reset()
    reset_provider()
