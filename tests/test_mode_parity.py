"""Every family, every mode, the same three layers (#187).

The drift this guards against was real and silent. Until 0.31.0, clean_*
spent L3 on extraction and got no detection verdict, and block_search and
warn_search never called L3 at all — three of six delivery paths without a
semantic judge, each one a copy that had wandered from the others. Nothing
failed: every path returned something plausible. So this test does not ask
whether a response looks right. It counts which layers ran and which L3
turns fired, for every (family, mode) cell, against the real pipeline.

The mode decides delivery, never detection:

| mode  | L1 | L2 | L3 detect | L3 extract | L3 verify | delivers            |
|-------|----|----|-----------|------------|-----------|---------------------|
| block | 1  | 1  | 1         | —          | —         | the original        |
| warn  | 1  | 1  | 1         | —          | —         | the original        |
| clean | 1  | 1  | 1         | 1          | 1         | a verified extract  |
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_trentina_crunchtools.l1 import pipeline as l1_pipeline
from mcp_trentina_crunchtools.modes import Mode

from .mode_harness import FAMILIES, MODES, call, layers

CELLS = [(family, mode) for family in FAMILIES for mode in MODES]


@pytest.mark.parametrize(("family", "mode"), CELLS, ids=lambda v: getattr(v, "value", v))
async def test_every_cell_runs_every_layer(env: Path, family: str, mode: Mode) -> None:
    real_run_l1 = l1_pipeline.run_l1
    with (
        layers(env) as fakes,
        patch.object(l1_pipeline, "run_l1", side_effect=real_run_l1) as l1,
        patch("mcp_trentina_crunchtools.defense.run_l1", l1),
        patch("mcp_trentina_crunchtools.tools.dir.run_l1", l1),
    ):
        result = await call(family, mode, fakes)

    l1_on_payload = [c for c in l1.call_args_list if c.args and c.args[0].strip()]
    assert l1_on_payload, f"{family}/{mode.value}: L1 never ran"
    assert fakes.classify.await_count == 1, f"{family}/{mode.value}: L2"
    assert fakes.detect.await_count == 1, f"{family}/{mode.value}: L3 detect"

    cleans = mode is Mode.CLEAN
    assert fakes.extract.await_count == int(cleans), f"{family}/{mode.value}: t2"
    assert fakes.verify.await_count == int(cleans), f"{family}/{mode.value}: t3"

    layers_state = result["scan"]["layers"]
    assert layers_state == {"l1": "complete", "l2": "complete", "l3": "complete"}
    if cleans:
        assert result["scan"]["disposition"] == "extracted"
        assert set(result["content"]) <= {"extracted_text", "title", "confidence"}
    else:
        assert result["scan"]["disposition"] == "delivered"
        assert "_trentina_warning" not in result


@pytest.mark.parametrize("family", FAMILIES)
async def test_block_and_warn_deliver_the_same_bytes(env: Path, family: str) -> None:
    with layers(env) as fakes:
        blocked = await call(family, Mode.BLOCK, fakes)
        warned = await call(family, Mode.WARN, fakes)
    assert blocked["content"] == warned["content"]


@pytest.mark.parametrize("family", FAMILIES)
async def test_l3_detect_is_briefed_with_l1_and_l2(env: Path, family: str) -> None:
    """D1, on every path: L3 hears L2's score and the caveat about L2."""
    from mcp_trentina_crunchtools.quarantine.prompts import L2_BLINDSPOT_CAVEAT

    with layers(env) as fakes:
        await call(family, Mode.WARN, fakes)
    briefing = fakes.detect.call_args.kwargs["layer1_context"]
    assert "Layer 1" in briefing
    assert "Layer 2 labelled it BENIGN" in briefing
    assert L2_BLINDSPOT_CAVEAT in briefing


async def test_search_judges_titles_and_uris_too(env: Path) -> None:
    """They used to reach L1 only. Now they are part of the judged document."""
    with layers(env) as fakes:
        await call("search", Mode.WARN, fakes)
    judged = fakes.detect.call_args.args[0]
    assert "https://example.com/a" in judged
    assert "[A]" in judged
