"""Shared fixtures for gateway tests."""

from __future__ import annotations

import contextlib

import pytest

from mcp_trentina_crunchtools import config as config_mod
from mcp_trentina_crunchtools import database as database_mod
from mcp_trentina_crunchtools.gateway.backend import reset_tool_list_cache
from mcp_trentina_crunchtools.gateway.circuit import breaker
from mcp_trentina_crunchtools.gateway.ingress_defense import reset_verdict_cache
from mcp_trentina_crunchtools.gateway.router import reset_profile_tools_cache
from mcp_trentina_crunchtools.quarantine.providers import reset_provider


@pytest.fixture(autouse=True)
def _reset_singletons() -> None:
    """Reset global singletons before every test."""
    breaker.reset()
    reset_provider()
    reset_tool_list_cache()
    reset_profile_tools_cache()
    reset_verdict_cache()
    # The sqlite connection is bound to the thread that created it, and
    # Starlette's TestClient runs apps on a worker thread — a connection one
    # test created on the main thread poisons the next test's defend()
    # audit write with sqlite3.ProgrammingError. Fresh connection per test.
    if database_mod._db is not None:
        with contextlib.suppress(Exception):
            # close() is itself thread-bound; dropping the reference is the
            # part that matters.
            database_mod._db.close()
        database_mod._db = None


@pytest.fixture(autouse=True)
def _no_ambient_gemini_key(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unit tests must not inherit the shell's GEMINI_API_KEY.

    The defense pipeline gates L3 on ``get_config().has_api_key``. With a key
    in the environment, a test that forgot to patch ``defense.get_config``
    passes on one machine and fails on another — and worse, one that forgot to
    mock ``quarantine_detect`` makes a live Gemini call from a unit test.
    Tests that need a key patch ``defense.get_config`` and say so.

    The provider integration suite is the one deliberate exception: it exists
    to make live calls and reads the key from the environment at call time.
    """
    if "integration" in request.node.path.name:
        yield
        return
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    config_mod._config = None
    yield
    config_mod._config = None
