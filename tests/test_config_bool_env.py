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
