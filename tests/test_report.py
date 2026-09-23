"""Tests for the `scan` block — what ran, what was decided, where it came from.

The block that replaced `trust`. The property it used to claim does not exist:
content that crossed the perimeter is untrusted, permanently, because the
layers are detectors and a detector finding nothing has not made anything
safe.
"""

from __future__ import annotations

from mcp_trentina_crunchtools.defense import DefenseVerdict, Layer
from mcp_trentina_crunchtools.l1.pipeline import PipelineResult, PipelineStats
from mcp_trentina_crunchtools.quarantine.classifier import ClassifierResult
from mcp_trentina_crunchtools.report import (
    Disposition,
    LayerState,
    build_report,
    layer_states,
)


def _verdict(
    *,
    text: str = "some content",
    classification: ClassifierResult | None = None,
    l3: dict | None = None,
    flagged_by: Layer | None = None,
) -> DefenseVerdict:
    pipeline = PipelineResult(
        content=text,
        l2_input=text,
        stats=PipelineStats(),
        input_size=len(text),
        output_size=len(text),
    )
    return DefenseVerdict(
        content=text,
        pipeline=pipeline,
        classification=classification,
        l3_assessment=l3,
        risk_level="low",
        flagged_by=flagged_by,
    )


class TestLayerStates:
    """A layer that could not run must never read like one that found
    nothing. That is the same rule `warning.py` enforces for findings."""

    def test_l1_is_always_complete(self) -> None:
        """L1 is free, deterministic and has no off switch."""
        states = layer_states(_verdict())
        assert states["l1"] == LayerState.COMPLETE.value

    def test_l2_unavailable_when_no_classification_came_back(self) -> None:
        """`classify_async` returns None when the ONNX model is missing. That
        used to be indistinguishable from a clean scan."""
        states = layer_states(_verdict(classification=None))
        assert states["l2"] == LayerState.UNAVAILABLE.value

    def test_l2_partial_when_truncated(self) -> None:
        states = layer_states(
            _verdict(
                classification=ClassifierResult(
                    label="BENIGN", score=0.01, latency_ms=1.0, truncated=True
                )
            )
        )
        assert states["l2"] == LayerState.PARTIAL.value

    def test_l2_complete_when_it_read_everything(self) -> None:
        states = layer_states(
            _verdict(
                classification=ClassifierResult(
                    label="BENIGN", score=0.01, latency_ms=1.0
                )
            )
        )
        assert states["l2"] == LayerState.COMPLETE.value

    def test_l3_unavailable_when_it_said_so(self) -> None:
        states = layer_states(_verdict(l3={"l3_unavailable": True}))
        assert states["l3"] == LayerState.UNAVAILABLE.value

    def test_l3_complete_when_it_judged(self) -> None:
        states = layer_states(_verdict(l3={"injection_detected": False}))
        assert states["l3"] == LayerState.COMPLETE.value

    def test_empty_payload_is_not_applicable_not_clean(self) -> None:
        """Nothing to judge is a third thing, distinct from both 'ran and
        found nothing' and 'could not run'."""
        states = layer_states(_verdict(text="   "))
        assert states["l2"] == LayerState.NOT_APPLICABLE.value
        assert states["l3"] == LayerState.NOT_APPLICABLE.value


class TestThreeAxesStaySeparate:
    """The old `trust.level` collapsed four questions into one enum, which is
    how it ended up meaning nothing."""

    def test_what_ran_what_was_decided_and_origin_are_independent(self) -> None:
        report = build_report(
            _verdict(l3={"injection_detected": False}),
            disposition=Disposition.ANNOTATED,
            kind="url",
            ref="https://example.com",
        )
        assert set(report) == {"layers", "disposition", "origin"}
        assert report["disposition"] == "annotated"
        assert report["origin"]["kind"] == "url"
        assert report["layers"]["l1"] == "complete"

    def test_there_is_no_trust_field(self) -> None:
        """Deliberate: content that crossed the perimeter is untrusted, and a
        key named for a property nothing has is worse than no key."""
        report = build_report(
            _verdict(), disposition=Disposition.DELIVERED, kind="url", ref="u"
        )
        assert "trust" not in report
        assert "level" not in report

    def test_findings_are_not_duplicated_here(self) -> None:
        """`_trentina_warning` owns what was FOUND. Two sources for one fact
        is two answers that can disagree."""
        report = build_report(
            _verdict(flagged_by=Layer.L1),
            disposition=Disposition.ANNOTATED,
            kind="url",
            ref="u",
        )
        assert "risk_level" not in report
        assert "flagged_by" not in report


class TestAllowlisting:
    """Allowlisting suppresses FLAGS. It does not skip layers, and reporting
    it as though it did would be the error the old field made."""

    def test_an_allowlisted_source_still_reports_every_layer_as_run(self) -> None:
        report = build_report(
            _verdict(
                classification=ClassifierResult(
                    label="MALICIOUS", score=0.99, latency_ms=1.0
                ),
                l3={"injection_detected": True},
            ),
            disposition=Disposition.DELIVERED,
            kind="url",
            ref="https://trusted.example.com",
            allowlisted=True,
        )
        assert report["layers"] == {
            "l1": "complete",
            "l2": "complete",
            "l3": "complete",
        }
        assert report["origin"]["allowlisted"] is True

    def test_not_allowlisted_by_default(self) -> None:
        report = build_report(
            _verdict(), disposition=Disposition.DELIVERED, kind="url", ref="u"
        )
        assert report["origin"]["allowlisted"] is False


class TestDisposition:
    def test_extraction_names_the_model_that_produced_it(self) -> None:
        report = build_report(
            _verdict(),
            disposition=Disposition.EXTRACTED,
            kind="url",
            ref="u",
            extracted_by="gemini-2.5-flash-lite",
        )
        assert report["disposition"] == "extracted"
        assert report["extracted_by"] == "gemini-2.5-flash-lite"

    def test_no_extraction_means_the_key_is_absent_not_null(self) -> None:
        """A key that is sometimes meaningless gets read as meaningful."""
        report = build_report(
            _verdict(), disposition=Disposition.DELIVERED, kind="url", ref="u"
        )
        assert "extracted_by" not in report

    def test_a_refusal_before_any_layer_ran_says_not_applicable(self) -> None:
        """The advisory paths refuse a URL on its shape, so there is no
        verdict — and claiming the layers were 'complete' would be a lie
        about work that never happened."""
        report = build_report(
            None, disposition=Disposition.REFUSED, kind="url", ref="http://evil"
        )
        assert report["disposition"] == "refused"
        assert set(report["layers"].values()) == {"not_applicable"}
