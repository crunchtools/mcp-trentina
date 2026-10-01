"""``bool_env``: the parser behind the TRENTINA_REQUIRE_L2/L3 opt-outs.

A security opt-out must not open on a typo, so only an explicit false-ish
value turns a default-true setting off.
"""

from __future__ import annotations

import logging

import pytest

from mcp_trentina_crunchtools.config import bool_env

VAR = "TRENTINA_TEST_BOOL"


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on", " On "])
def test_true_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(VAR, raw)
    assert bool_env(VAR, default=False) is True


@pytest.mark.parametrize("raw", ["0", "false", "False", "no", "off"])
def test_false_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(VAR, raw)
    assert bool_env(VAR, default=True) is False


def test_unset_and_empty_take_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VAR, raising=False)
    assert bool_env(VAR, default=True) is True
    monkeypatch.setenv(VAR, "")
    assert bool_env(VAR, default=True) is True


def test_a_typo_keeps_the_default_and_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(VAR, "flase")
    with caplog.at_level(logging.WARNING, logger="mcp_trentina_crunchtools.config"):
        assert bool_env(VAR, default=True) is True
    assert VAR in caplog.text


@pytest.mark.parametrize("layer", ["L2", "L3"])
def test_turning_a_layer_off_warns_at_startup(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, layer: str
) -> None:
    """A fail-closed switch turned off is announced, like the egress hatch (#298)."""
    from mcp_trentina_crunchtools.config import Config

    monkeypatch.setenv(f"TRENTINA_REQUIRE_{layer}", "false")
    with caplog.at_level(logging.WARNING, logger="mcp_trentina_crunchtools.config"):
        Config()
    assert f"TRENTINA_REQUIRE_{layer} is off" in caplog.text


def test_the_default_is_silent(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from mcp_trentina_crunchtools.config import Config

    monkeypatch.delenv("TRENTINA_REQUIRE_L2", raising=False)
    monkeypatch.delenv("TRENTINA_REQUIRE_L3", raising=False)
    with caplog.at_level(logging.WARNING, logger="mcp_trentina_crunchtools.config"):
        Config()
    assert "TRENTINA_REQUIRE_" not in caplog.text
