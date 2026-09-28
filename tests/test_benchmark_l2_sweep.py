"""The offline L2 threshold sweep (issue #86): arithmetic and harness wiring."""

from __future__ import annotations

import json
from itertools import pairwise
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from benchmarks import l2_sweep
from benchmarks import provider_benchmark as bench
from mcp_trentina_crunchtools.quarantine.classifier import ClassifierResult

if TYPE_CHECKING:
    from pathlib import Path

SCORED = [(0.95, True), (0.80, True), (0.30, True), (0.60, False), (0.10, False)]


def test_point_counts_at_or_above_as_flagged() -> None:
    p = l2_sweep.point(SCORED, 0.60)
    assert (p.tp, p.fn, p.fp, p.tn) == (2, 1, 1, 1)
    assert p.detection == pytest.approx(2 / 3)
    assert p.fp_rate == pytest.approx(0.5)
    assert p.precision == pytest.approx(2 / 3)


def test_sweep_is_monotone() -> None:
    points = l2_sweep.sweep(SCORED)
    assert [p.threshold for p in points] == list(l2_sweep.DEFAULT_GRID)
    for lo, hi in pairwise(points):
        assert hi.tp <= lo.tp
        assert hi.fp <= lo.fp


def test_best_searches_observed_scores_and_prefers_higher_cutoff() -> None:
    # 0.80 and 0.95 are not tied; 0.80 catches 2/3 with 0 FP (J 0.67),
    # 0.30 catches 3/3 with 1/2 FP (J 0.5), 0.60 is J 0.17.
    top = l2_sweep.best(SCORED)
    assert top is not None
    assert top.threshold == pytest.approx(0.80)
    tied = [(0.9, True), (0.7, True), (0.2, False)]
    top = l2_sweep.best(tied)
    assert top is not None
    assert top.threshold == pytest.approx(0.7)


@pytest.mark.parametrize("scored", [[], [(0.9, True)], [(0.1, False)]])
def test_best_undefined_without_both_classes(scored: list[tuple[float, bool]]) -> None:
    assert l2_sweep.best(scored) is None


def test_markdown_marks_current_and_warns_on_small_benign_set() -> None:
    md = l2_sweep.render_markdown(SCORED, 0.5)
    assert "| **0.50** |" in md
    assert "Low resolution" in md
    assert "Best separation" not in md


def test_markdown_names_best_cutoff_on_enough_benign() -> None:
    scored = [*SCORED, *[(0.05, False)] * l2_sweep.MIN_BENIGN_FOR_FP]
    md = l2_sweep.render_markdown(scored, 0.5)
    assert "Low resolution" not in md
    assert "Best separation" in md


def test_markdown_inserts_off_grid_current() -> None:
    md = l2_sweep.render_markdown(SCORED, 0.72)
    assert "| **0.72** |" in md


def test_markdown_without_scores_says_so() -> None:
    assert "not loaded" in l2_sweep.render_markdown([], 0.5, unscored=4)


def test_default_threshold_tracks_the_profile_default() -> None:
    from mcp_trentina_crunchtools.gateway.profile import DefenseConfig

    assert DefenseConfig().l2_threshold == bench.L2_DEFAULT_THRESHOLD


def _fake_score(text: str, **_: object) -> ClassifierResult:
    return ClassifierResult(label="BENIGN", score=len(text) % 97 / 100, latency_ms=0.0)


def test_l2_only_run_writes_scores_and_sweep_without_providers(tmp_path: Path) -> None:
    with (
        patch.object(bench, "is_classifier_available", return_value=True),
        patch("mcp_trentina_crunchtools.defense.classify_async", side_effect=_fake_score),
        patch.object(bench, "available_providers", side_effect=AssertionError("no providers")),
    ):
        rc = bench.main(["--l2-only", "--limit", "6", "--out", str(tmp_path)])
    assert rc == 0
    (json_path,) = tmp_path.glob("*.json")
    payload = json.loads(json_path.read_text())
    assert payload["providers"] == []
    assert len(payload["l2"]["scores"]) == 6
    assert all(s is not None for s in payload["l2"]["scores"].values())
    assert len(payload["l2"]["sweep"]) == len(l2_sweep.DEFAULT_GRID)
    (md_path,) = tmp_path.glob("*.md")
    assert "## L2 threshold sweep" in md_path.read_text()


def test_missing_model_yields_none_scores(tmp_path: Path) -> None:
    with patch.object(bench, "is_classifier_available", return_value=False):
        rc = bench.main(["--l2-only", "--limit", "3", "--out", str(tmp_path)])
    assert rc == 0
    (json_path,) = tmp_path.glob("*.json")
    payload = json.loads(json_path.read_text())
    assert set(payload["l2"]["scores"].values()) == {None}
    assert payload["l2"]["best_threshold"] is None
