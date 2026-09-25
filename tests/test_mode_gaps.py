"""A layer that could not finish: block and redact refuse, flag delivers loudly (#187 D3/D4).

A scan that did not fully happen must never read like a scan that found
nothing. Absent layers (no ONNX model, no provider) can be excused per layer
with TRENTINA_REQUIRE_L2/L3=false; a partial read never can — that is the
padding attack, where the payload sits past the cap and the head reads clean.

One of these cells was a live bug: flag_fetch RAISED on a large page, because
the tools passed guarded=True to defend() in every mode.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_trentina_crunchtools import config as config_mod
from mcp_trentina_crunchtools.errors import BlockedSourceError, UnscannableContentError
from mcp_trentina_crunchtools.modes import Mode
from mcp_trentina_crunchtools.quarantine.classifier import ClassifierResult

from .mode_harness import BENIGN, FAMILIES, call, layers

TRUNCATED = ClassifierResult(label="BENIGN", score=0.01, latency_ms=1.0, truncated=True)


def _l2_truncated() -> Any:
    """What classify_async does on an oversized payload, per caller."""

    async def fake(_text: str, *, fail_on_truncate: bool = False, source: str = "") -> Any:
        if fail_on_truncate:
            raise UnscannableContentError(source, 99_999, 32_768)
        return TRUNCATED

    return fake


GAPS = ("l2_absent", "l2_truncated", "l3_absent", "l3_truncated")


def _arrange(gap: str, monkeypatch: pytest.MonkeyPatch, fakes: Any) -> None:
    match gap:
        case "l2_absent":
            fakes.classify.return_value = None
        case "l2_truncated":
            fakes.classify.side_effect = _l2_truncated()
        case "l3_absent":
            monkeypatch.delenv("GEMINI_API_KEY")
            config_mod._config = None
        case "l3_truncated":
            monkeypatch.setenv("QUARANTINE_MAX_CONTENT", "8")
            config_mod._config = None


def _key(gap: str) -> str:
    return {
        "l2_absent": "l2_unavailable",
        "l2_truncated": "l2_truncated",
        "l3_absent": "l3_unavailable",
        "l3_truncated": "l3_truncated",
    }[gap]


# content refuses anything over QUARANTINE_MAX_CONTENT before judging, so the
# L3-truncated cell does not exist for it.
def _cells() -> list[tuple[str, str]]:
    return [
        (family, gap)
        for family in FAMILIES
        for gap in GAPS
        if not (family == "content" and gap == "l3_truncated")
    ]


@pytest.mark.parametrize(("family", "gap"), _cells())
@pytest.mark.parametrize("mode", [Mode.BLOCK, Mode.REDACT], ids=lambda m: m.value)
async def test_block_and_redact_refuse(
    env: Path, monkeypatch: pytest.MonkeyPatch, family: str, gap: str, mode: Mode
) -> None:
    with layers(env) as fakes:
        _arrange(gap, monkeypatch, fakes)
        with pytest.raises(BlockedSourceError):
            await call(family, mode, fakes)
        assert fakes.extract.await_count == 0


@pytest.mark.parametrize(("family", "gap"), _cells())
async def test_flag_delivers_and_says_so(
    env: Path, monkeypatch: pytest.MonkeyPatch, family: str, gap: str
) -> None:
    with layers(env) as fakes:
        _arrange(gap, monkeypatch, fakes)
        result = await call(family, Mode.FLAG, fakes)
    assert result["scan"]["disposition"] == "annotated"
    assert result["_trentina_warning"][_key(gap)] is True


async def test_flag_fetch_no_longer_raises_on_a_large_page(env: Path) -> None:
    """The live bug: flag's contract is deliver-with-warning, not raise."""
    with layers(env) as fakes:
        fakes.classify.side_effect = _l2_truncated()
        result = await call("fetch", Mode.FLAG, fakes)
    assert result["content"] == fakes.payload
    assert result["_trentina_warning"]["l2_truncated"] is True
    assert result["scan"]["layers"]["l2"] == "partial"


@pytest.mark.parametrize(
    ("gap", "optout"), [("l2_absent", "TRENTINA_REQUIRE_L2"), ("l3_absent", "TRENTINA_REQUIRE_L3")]
)
async def test_an_absent_layer_can_be_excused(
    env: Path, monkeypatch: pytest.MonkeyPatch, gap: str, optout: str
) -> None:
    monkeypatch.setenv(optout, "false")
    config_mod._config = None
    with layers(env) as fakes:
        _arrange(gap, monkeypatch, fakes)
        result = await call("fetch", Mode.BLOCK, fakes)
    assert result["content"] == fakes.payload
    assert result["_trentina_warning"][_key(gap)] is True


@pytest.mark.parametrize("optout", ["TRENTINA_REQUIRE_L2", "TRENTINA_REQUIRE_L3"])
async def test_no_optout_excuses_a_partial_read(
    env: Path, monkeypatch: pytest.MonkeyPatch, optout: str
) -> None:
    monkeypatch.setenv(optout, "false")
    config_mod._config = None
    with layers(env) as fakes:
        fakes.classify.side_effect = _l2_truncated()
        with pytest.raises(BlockedSourceError):
            await call("fetch", Mode.BLOCK, fakes)


def test_quarantine_fallback_is_refused_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp_trentina_crunchtools.errors import ConfigError

    monkeypatch.setenv("QUARANTINE_FALLBACK", "layer1")
    config_mod._config = None
    with pytest.raises(ConfigError, match="TRENTINA_REQUIRE_L3"):
        config_mod.get_config()
    config_mod._config = None


def test_a_typo_in_an_optout_keeps_the_layer_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRENTINA_REQUIRE_L3", "flase")
    config_mod._config = None
    assert config_mod.get_config().require_l3 is True
    config_mod._config = None


async def test_benign_complete_scan_needs_no_warning(env: Path) -> None:
    with layers(env, classification=BENIGN) as fakes:
        result = await call("fetch", Mode.BLOCK, fakes)
    assert "_trentina_warning" not in result
