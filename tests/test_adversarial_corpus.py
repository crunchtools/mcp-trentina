"""Integrity tests for the Layer 3 adversarial corpus.

These tests make NO API calls. They prove two things about
``tests/adversarial_corpus.py``:

1. The corpus is well-formed (unique ids, valid risk levels, coherent
   attack/benign split).
2. Each case reaches the layer it claims to. Semantic attacks must survive
   Layer 1 (deterministic sanitization) untouched — otherwise they would never
   reach the Q-Agent and the provider benchmark would be measuring nothing.
   Structural attacks and the quoted-attack trap must be stripped by Layer 1,
   as annotated.

The Layer 2 assertions run only when the Prompt Guard model is available
(it lives at ``/models`` in the deployed container, not in local/CI checkouts).

If Layer 1 or Layer 2 ever changes such that a case's annotation no longer
holds, the corresponding test fails loudly — which is the signal to re-annotate
the case (e.g. move a now-caught attack down a layer), not to paper over it.
"""

from __future__ import annotations

import pytest

from mcp_trentina_crunchtools.quarantine.classifier import (
    classify,
    is_classifier_available,
)
from mcp_trentina_crunchtools.sanitize.pipeline import sanitize_text
from tests.adversarial_corpus import (
    ATTACKS,
    BENIGN,
    CORPUS,
    RISK_ORDER,
    Case,
)

_has_classifier = is_classifier_available()


class TestCorpusWellFormed:
    """Structural invariants of the corpus itself."""

    def test_nonempty(self) -> None:
        assert CORPUS, "corpus is empty"
        assert ATTACKS, "no attack cases"
        assert BENIGN, "no benign cases"

    def test_ids_unique(self) -> None:
        ids = [c.id for c in CORPUS]
        dupes = {i for i in ids if ids.count(i) > 1}
        assert not dupes, f"duplicate case ids: {sorted(dupes)}"

    @pytest.mark.parametrize("case", ATTACKS, ids=[c.id for c in ATTACKS])
    def test_attacks_have_valid_min_risk(self, case: Case) -> None:
        assert case.min_risk in RISK_ORDER, (
            f"{case.id}: min_risk {case.min_risk!r} not one of {sorted(RISK_ORDER)}"
        )
        assert RISK_ORDER[case.min_risk] >= RISK_ORDER["medium"], (
            f"{case.id}: attacks should require at least medium risk"
        )

    @pytest.mark.parametrize("case", BENIGN, ids=[c.id for c in BENIGN])
    def test_benign_have_no_min_risk(self, case: Case) -> None:
        assert case.min_risk == "", f"{case.id}: benign case should not set min_risk"

    def test_category_coverage(self) -> None:
        """The corpus must exercise the semantic attack families we care about."""
        required = {
            "authority_social",
            "exfil_action",
            "role_reassignment",
            "fake_config",
            "indirect_second_order",
            "tool_invocation",
            "conditional_trigger",
            "context_confusion",
            "detector_meta",
            "obfuscation_semantic",
            "memory_poison",
        }
        present = {c.category for c in CORPUS}
        missing = required - present
        assert not missing, f"corpus missing attack families: {sorted(missing)}"


class TestLayer1Boundary:
    """Each case reaches Layer 1's output in the state it claims to."""

    @pytest.mark.parametrize("case", CORPUS, ids=[c.id for c in CORPUS])
    def test_l1_annotation_holds(self, case: Case) -> None:
        count = sum(sanitize_text(case.payload).stats.to_flat_dict().values())
        if case.bypasses_l1:
            assert count == 0, (
                f"{case.id}: expected to bypass Layer 1, but L1 made {count} "
                f"detection(s). This attack no longer reaches L3 intact — "
                f"re-annotate bypasses_l1=False or adjust the payload."
            )
        else:
            assert count > 0, (
                f"{case.id}: expected Layer 1 to strip this, but it made 0 "
                f"detections. Re-annotate bypasses_l1=True."
            )

    def test_semantic_attacks_are_genuinely_semantic(self) -> None:
        """The headline claim: most attacks pass Layer 1 clean.

        If this ratio collapses, the corpus has drifted toward structural
        payloads that L1 already handles and the L3 benchmark loses its point.
        """
        semantic = [c for c in ATTACKS if c.bypasses_l1]
        assert len(semantic) >= 0.7 * len(ATTACKS), (
            f"only {len(semantic)}/{len(ATTACKS)} attacks bypass L1 — "
            f"corpus is drifting structural"
        )


@pytest.mark.skipif(not _has_classifier, reason="Prompt Guard model not available")
class TestLayer2Boundary:
    """Where annotated deterministically, Layer 2 agrees with the corpus."""

    @pytest.mark.parametrize(
        "case",
        [c for c in CORPUS if c.bypasses_l2 is not None],
        ids=[c.id for c in CORPUS if c.bypasses_l2 is not None],
    )
    def test_l2_annotation_holds(self, case: Case) -> None:
        result = classify(case.payload)
        assert result is not None
        expected = "BENIGN" if case.bypasses_l2 else "MALICIOUS"
        assert result.label == expected, (
            f"{case.id}: L2 returned {result.label} (score={result.score:.4f}), "
            f"expected {expected}. If Prompt Guard changed, re-annotate this case."
        )
