"""Tests for _configure_logging — TRENTINA_LOG_LEVEL must reach uvicorn and
httpx, not just the root logger.

Note: logging.basicConfig() is a no-op once the root logger already has
handlers, which is always true under pytest (it attaches its own capture
handlers). So these tests don't assert on logging.getLogger().level —
that would test pytest's logging setup, not ours. They assert on the
resolved level name (what callers forward to mcp.run(log_level=...)) and
on the httpx logger, which _configure_logging sets directly via an
unconditional setLevel() call rather than through basicConfig.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from mcp_trentina_crunchtools import _configure_logging, _run_with_gateway
from mcp_trentina_crunchtools.gateway.loader import GatewayConfig


@pytest.fixture(autouse=True)
def _restore_httpx_logger_level() -> Iterator[None]:
    """_configure_logging mutates the shared httpx logger; restore it after each test."""
    previous = logging.getLogger("httpx").level
    yield
    logging.getLogger("httpx").setLevel(previous)


def test_configure_logging_defaults_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TRENTINA_LOG_LEVEL", raising=False)
    assert _configure_logging() == "INFO"


def test_configure_logging_resolves_requested_level(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "warning")
    assert _configure_logging() == "WARNING"


def test_configure_logging_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "Debug")
    assert _configure_logging() == "DEBUG"


def test_configure_logging_invalid_level_falls_back_to_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unrecognized value must resolve to a real level name rather than being
    passed through verbatim — mcp.run(log_level=...) hands this straight to
    uvicorn.Config, which raises KeyError on anything outside its known set."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "bogus")
    assert _configure_logging() == "INFO"


def test_configure_logging_notset_falls_back_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    """NOTSET is a real logging level name, but it isn't one of uvicorn's
    recognized levels, and forwarding it verbatim as log_level would raise
    KeyError at server startup instead of just being ignored like it would
    have been before this level was forwarded anywhere."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "NOTSET")
    assert _configure_logging() == "INFO"


def test_configure_logging_rejects_non_level_module_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A naive getattr(logging, level_name, default) resolves *any* uppercase
    attribute of the logging module, not just level constants — e.g. the
    internal _STYLES dict — and passing a non-int through to basicConfig()/
    getLevelName() raises TypeError instead of falling back to INFO. Level
    names must be checked against a fixed allowlist before ever touching
    getattr, not validated after the fact."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "_styles")
    assert _configure_logging() == "INFO"


def test_configure_logging_clamps_httpx_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    """httpx's request logger sits outside uvicorn's logging config entirely, so
    it needs its own explicit level — root-logger configuration alone never
    reaches it in practice (see issue #73)."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "WARNING")
    _configure_logging()
    assert logging.getLogger("httpx").level == logging.WARNING


def test_configure_logging_httpx_tracks_requested_level(monkeypatch: pytest.MonkeyPatch) -> None:
    """DEBUG should restore full httpx verbosity, not stay clamped to WARNING —
    the fix must not hardcode a floor that fights an operator's explicit ask."""
    monkeypatch.setenv("TRENTINA_LOG_LEVEL", "DEBUG")
    _configure_logging()
    assert logging.getLogger("httpx").level == logging.DEBUG


def test_run_with_gateway_forwards_log_level_to_uvicorn() -> None:
    """Regression test for the actual reported symptom: uvicorn.access kept
    logging at INFO regardless of TRENTINA_LOG_LEVEL because FastMCP passes its
    own default log_level to uvicorn.Config, and uvicorn re-applies that level
    to uvicorn.access/error *after* its own dictConfig runs — so nothing short
    of an explicit log_level reaching mcp_server.run() fixes it. This exercises
    the gateway-mode path from the deployment described in issue #73, where
    resolving the right string in _configure_logging() alone would not have
    caught a regression in the plumbing that forwards it."""
    empty_config = GatewayConfig(profiles={})
    mock_server = MagicMock()

    with (
        patch("mcp_trentina_crunchtools.gateway.load_profiles", return_value=empty_config),
        patch("mcp_trentina_crunchtools.gateway.register_internal_server"),
        patch("mcp_trentina_crunchtools.gateway.register_with_fastmcp"),
        patch("mcp_trentina_crunchtools._wire_circuit_notifications"),
        patch("mcp_trentina_crunchtools.gateway.llm_proxy.load_llm_providers", return_value={}),
        patch("mcp_trentina_crunchtools.gateway.llm_proxy.register_llm_routes"),
        patch("mcp_trentina_crunchtools.gateway.alert_ingress.register_alert_routes"),
        patch("mcp_trentina_crunchtools.gateway.compress.load_compression_cache"),
        patch("mcp_trentina_crunchtools.gateway.compress.set_profiles"),
        patch("mcp_trentina_crunchtools.gateway.backend.load_tool_list_cache"),
    ):
        _run_with_gateway(mock_server, host="127.0.0.1", port=8019, log_level="WARNING")

    mock_server.run.assert_called_once_with(
        transport="streamable-http",
        host="127.0.0.1",
        port=8019,
        log_level="WARNING",
    )
