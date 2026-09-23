"""The mandate: L1, L2 and L3 run on every input the gateway scans.

This file exists because the property is easy to lose by accident. It was
lost once already — not by anyone deciding to skip L3, but by a cost-control
threshold that looked like configuration and behaved like an off switch. A
gate that only fires on suspicious content is invisible in every test written
with suspicious content, which is most of them.

So these tests are deliberately boring. They feed the pipeline the most
innocuous input imaginable and assert the judge was called anyway. The day
someone adds a "cheap path" for clean traffic, this file is what says no.

The one thing that may stop L3 is L3 being unable to run. That is a degraded
state, and it must be visible as one rather than silently reading as clean.
"""

from __future__ import annotations

import inspect
from contextlib import ExitStack
from typing import Any
from unittest.mock import patch

import pytest

from mcp_trentina_crunchtools.defense import (
    Layer,
    Provenance,
    _should_run_l3,
    advise,
    defend,
)
from mcp_trentina_crunchtools.gateway.profile import DefenseConfig
from mcp_trentina_crunchtools.quarantine.classifier import ClassifierResult

_D = "mcp_trentina_crunchtools.defense"

BENIGN_ZERO = ClassifierResult(label="BENIGN", score=0.0, latency_ms=1.0)
BENIGN_MID = ClassifierResult(label="BENIGN", score=0.5, latency_ms=1.0)
MALICIOUS = ClassifierResult(label="MALICIOUS", score=0.95, latency_ms=1.0)

INNOCUOUS = "The quarterly maintenance window is Tuesday at 02:00 UTC."


def _patches(
    stack: ExitStack,
    *,
    classification: ClassifierResult | None = BENIGN_ZERO,
    detection: dict[str, Any] | None = None,
    has_api_key: bool = True,
) -> dict[str, Any]:
    def p(name: str, **kw: Any) -> Any:
        return stack.enter_context(patch(f"{_D}.{name}", **kw))

    mocks = {
        "classify_guarded": p("classify_guarded", return_value=classification),
        "classify_async": p("classify_async", return_value=classification),
        "quarantine_detect": p(
            "quarantine_detect",
            return_value=detection or {"injection_detected": False},
        ),
        "record_detection": p("record_detection"),
        "emit_detection_event": p("emit_detection_event"),
    }
    cfg = p("get_config")
    cfg.return_value.has_api_key = has_api_key
    mocks["get_config"] = cfg
    return mocks


async def _defend(**kw: Any) -> Any:
    stack_kw = {
        k: kw.pop(k)
        for k in ("classification", "detection", "has_api_key")
        if k in kw
    }
    with ExitStack() as stack:
        mocks = _patches(stack, **stack_kw)
        verdict = await defend(
            kw.pop("content", INNOCUOUS),
            source=kw.pop("source", "https://example.com"),
            source_type=kw.pop("source_type", "url"),
            **kw,
        )
        return verdict, mocks


class TestL3RunsOnCleanTraffic:
    """The case that never ran before. Every one of these used to skip L3."""

    async def test_clean_content_clean_l2_still_reaches_l3(self) -> None:
        _, mocks = await _defend()
        mocks["quarantine_detect"].assert_called_once()

    @pytest.mark.parametrize("score", [0.0, 0.01, 0.1, 0.29, 0.3, 0.5, 0.69])
    async def test_every_l2_score_below_the_old_threshold_reaches_l3(
        self, score: float
    ) -> None:
        """0.7 was the old escalation point. Nothing below it reached L3."""
        cls = ClassifierResult(label="BENIGN", score=score, latency_ms=1.0)
        _, mocks = await _defend(
            classification=cls, defense=DefenseConfig(l3_threshold=0.7)
        )
        mocks["quarantine_detect"].assert_called_once()

    async def test_the_flagged_but_unjudged_band(self) -> None:
        """The sharpest case: L2 flags at 0.3, escalation needed 0.7.

        Content scoring 0.5 was flagged as suspicious by L2 and then never
        shown to the layer that could tell an attack from a CVE ticket
        discussing one. That band is the reason this file exists.
        """
        _, mocks = await _defend(
            classification=BENIGN_MID,
            defense=DefenseConfig(l2_threshold=0.3, l3_threshold=0.7),
        )
        mocks["quarantine_detect"].assert_called_once()

    async def test_no_l1_detections_still_reaches_l3(self) -> None:
        verdict, mocks = await _defend(content="Nothing hostile here at all.")
        assert verdict.pipeline.stats.total_detections() == 0
        mocks["quarantine_detect"].assert_called_once()


class TestThresholdCannotSuppressL3:
    """`l3_threshold` is deprecated and ignored. Prove it, do not trust it."""

    @pytest.mark.parametrize("threshold", [0.0, 0.5, 0.7, 0.99, 1.0])
    async def test_no_threshold_value_prevents_l3(self, threshold: float) -> None:
        """Including 1.0, which under the old gate meant 'effectively never'."""
        _, mocks = await _defend(
            classification=BENIGN_ZERO,
            defense=DefenseConfig(l3_threshold=threshold),
        )
        mocks["quarantine_detect"].assert_called_once()

    async def test_gate_helper_ignores_the_threshold_entirely(self) -> None:
        """Belt and braces: the decision function takes no score at all now,
        so there is nothing for a threshold to be compared against."""
        params = set(inspect.signature(_should_run_l3).parameters)
        assert params == {"defense", "l3_gate"}, (
            "a new parameter here is a new way to skip L3 — if one is added, "
            "it needs a test in this file saying why it is allowed to"
        )


class TestL3RunsRegardlessOfOtherLayers:
    async def test_runs_when_l2_is_unavailable(self) -> None:
        """No classifier result at all must not mean 'nothing to judge'."""
        _, mocks = await _defend(classification=None)
        mocks["quarantine_detect"].assert_called_once()

    async def test_runs_when_l2_says_malicious(self) -> None:
        _, mocks = await _defend(classification=MALICIOUS)
        mocks["quarantine_detect"].assert_called_once()

    async def test_runs_on_model_output(self) -> None:
        _, mocks = await _defend(provenance=Provenance.MODEL_OUTPUT)
        mocks["quarantine_detect"].assert_called_once()

    async def test_runs_for_trusted_sources(self) -> None:
        """Trust changes what a finding COSTS, never whether a layer looks."""
        _, mocks = await _defend(is_trusted=True)
        mocks["quarantine_detect"].assert_called_once()

    async def test_trusted_content_is_still_flagged_by_l3(self) -> None:
        verdict, _ = await _defend(
            is_trusted=True,
            detection={"injection_detected": True, "risk_level": "high"},
        )
        assert verdict.flagged_by is Layer.L3, (
            "trust suppresses an L1 flag, not a judge that read the "
            "content and concluded it is an attack"
        )


class TestTheOnlyPermittedSkips:
    """Two, both named, both visible. Any third is a regression."""

    async def test_no_provider_skips_but_is_reported(self) -> None:
        """Unable to run is a DEGRADED state, never a clean one."""
        verdict, mocks = await _defend(has_api_key=False, defense=None)
        mocks["quarantine_detect"].assert_not_called()
        assert verdict.l3_assessment is not None, (
            "a skipped L3 must leave evidence; None here would read as "
            "'ran and found nothing'"
        )
        assert verdict.l3_assessment.get("l3_unavailable") is True

    async def test_a_configured_provider_opens_the_gate_without_gemini_key(
        self,
    ) -> None:
        """A profile bringing its own provider is not 'no provider'."""
        _, mocks = await _defend(
            has_api_key=False, defense=DefenseConfig(provider="ollama")
        )
        mocks["quarantine_detect"].assert_called_once()

    async def test_advise_still_opts_out_of_detection_mode(self) -> None:
        """`advise()` and safe_search spend L3 on EXTRACTION instead.

        This is not a coverage hole and not a policy switch: the layer still
        runs for those callers, in a different mode. Pinned so that if the
        opt-out is ever repurposed into a way of skipping L3 entirely, this
        test has to be deleted on purpose rather than quietly passing.
        """
        with ExitStack() as stack:
            mocks = _patches(stack)
            await advise(INNOCUOUS, source="s", source_type="url")
            mocks["quarantine_detect"].assert_not_called()


class TestDeprecatedKeyIsAnnounced:
    async def test_setting_l3_threshold_warns_at_load(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A key that silently stopped mattering is worse than one that is
        rejected. Tell the operator."""
        from mcp_trentina_crunchtools.gateway.loader import load_profiles

        monkeypatch.setenv("TEST_TOK", "x")
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            "profiles:\n"
            "  agent2:\n"
            "    auth:\n"
            "      bearer_token_env: TEST_TOK\n"
            "    defense:\n"
            "      l3_threshold: 0.7\n"
            "    backends: {}\n",
            encoding="utf-8",
        )
        with caplog.at_level("WARNING"):
            load_profiles(cfg)
        assert "l3_threshold" in caplog.text
        assert "ignored" in caplog.text

    async def test_no_warning_when_the_key_is_absent(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from mcp_trentina_crunchtools.gateway.loader import load_profiles

        monkeypatch.setenv("TEST_TOK", "x")
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            "profiles:\n"
            "  agent2:\n"
            "    auth:\n"
            "      bearer_token_env: TEST_TOK\n"
            "    backends: {}\n",
            encoding="utf-8",
        )
        with caplog.at_level("WARNING"):
            load_profiles(cfg)
        assert "l3_threshold" not in caplog.text
