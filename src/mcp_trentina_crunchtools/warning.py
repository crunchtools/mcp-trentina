"""The `_trentina_warning` annotation, built in exactly one place.

Every ingress that delivers content it has judged attaches the same
annotation. Until now each one built it from scratch, and the copies drifted
in the way duplicated logic always does — silently, in the direction of
whichever copy was written first.

The drift had teeth. `ClassifierResult.truncated` means L2 ran out of window
and read only part of the content; two of the three call sites raised a
warning for it and the Matrix proxy did not, so a Matrix response whose tail
was never classified was delivered looking exactly like one that came back
clean. That is the failure this module exists to prevent: a fourth copy would
have missed it too.

It lived under `gateway/` until 0.26.0, when the `warn_*` tools started
attaching the same annotation. A module whose whole claim is "built in
exactly one place" cannot sit inside one of the two places that build it.

The rule the annotation encodes: **a scan that did not fully happen must never
look like a scan that found nothing.** Flagged content warns, and so does
content the layers could not completely read — truncated input, an
unavailable classifier, an unavailable judge, unscannable blobs, or a scan
that timed out. Only a scan that ran to completion and found nothing returns
None.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .defense import DefenseVerdict

logger = logging.getLogger(__name__)


def build_warning(
    verdict: DefenseVerdict,
    *,
    unscannable: Mapping[str, int] | None = None,
    extras: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build the `_trentina_warning` body, or None if there is nothing to say.

    Args:
        verdict: What the layers concluded.
        unscannable: Counts of content no layer could read, keyed by kind
            (``images``, ``blobs``). Zero-valued entries are dropped.
        extras: Additional caller-specific fields. A truthy value here also
            forces a warning to be emitted, because a caller only passes one
            when it has something to report — a scan deadline that expired, a
            coverage floor that was crossed. Falsy values are carried through
            without forcing, so ``{"scan_timeout": False}`` stays quiet.
    """
    classification = verdict.classification
    l2_truncated = bool(classification is not None and classification.truncated)
    # There was text for L2 to read and no result came back: the ONNX model
    # is missing or failed to load, so the classifier silently did not run.
    # ``classify_async`` returns None for that, which used to read as a
    # clean scan — survivable while a verdict expired in fifteen minutes,
    # not survivable now that one is written down.
    l2_unavailable = bool(verdict.pipeline.l2_input.strip()) and classification is None
    l3_unavailable = bool(
        verdict.l3_assessment is not None
        and verdict.l3_assessment.get("l3_unavailable")
    )
    gaps = {k: v for k, v in (unscannable or {}).items() if v}
    forced = {k: v for k, v in (extras or {}).items() if v}

    if (
        not verdict.flagged
        and not l2_truncated
        and not l2_unavailable
        and not l3_unavailable
        and not gaps
        and not forced
    ):
        return None

    warning: dict[str, Any] = {
        "risk_level": verdict.risk_level,
        "flagged_by": verdict.flagged_by.value if verdict.flagged_by else None,
        "l1_detections": verdict.pipeline.stats.total_detections(),
        "l1_suspicious": verdict.pipeline.stats.suspicious_detections(),
        "l2_label": classification.label if classification else None,
        "l2_score": classification.score if classification else None,
        "l2_truncated": l2_truncated,
        "l3_injection_detected": (
            verdict.l3_assessment.get("injection_detected")
            if verdict.l3_assessment is not None
            else None
        ),
    }
    if l2_unavailable:
        warning["l2_unavailable"] = True
    if l3_unavailable:
        warning["l3_unavailable"] = True
    if gaps:
        warning["unscannable"] = gaps
    if extras:
        warning.update(extras)
    return warning
