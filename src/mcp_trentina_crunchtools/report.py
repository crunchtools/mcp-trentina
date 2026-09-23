"""The `scan` block: what ran, what was decided, where it came from.

Replaces the `trust` object, which was a lie in the literal sense — it was
named for a property no content in this system ever has. Content that crossed
the perimeter is untrusted, permanently, because the layers are DETECTORS and
a detector finding nothing has not made anything safe. It has failed to find
something, and the gap between those two claims is the false-negative rate:
L2 misses social engineering 40% of the time and exfiltration intent 20%, and
L3 on the default model catches 86% of attacks written to evade L1 and L2,
dropping to 33% on attacks aimed at the detector itself.

So there is no trust ladder here and there must not be one. A label saying
`l3_trusted` would be wrong two times out of three on the attack class that
targets judges, and it would travel into the agent's context telling it to
relax. That converts "the attacker got through" into "the attacker got
promoted", and publishes what to aim at.

`trust.level` collapsed four unrelated questions into one enum, which is how
it ended up meaning nothing: `advisory` and `quarantined` described what was
PRODUCED, `l1-only` and `layer1-fallback` described what RAN, `trusted-l1`
described who VOUCHED, and `blocked` described what was DECIDED. Nothing in
the codebase ever branched on any of them — the value reached one cockpit
table cell, rendered as a text label hardcoded to the "low" risk style, so
not even the UI read it.

Three independent facts, never collapsed:

* **layers** — which layers ran and whether each COMPLETED. A scan that did
  not finish must never read like a scan that found nothing; that is the rule
  ``warning.py`` already enforces for findings, and it applies here too.
* **disposition** — what the caller did about it.
* **origin** — where the bytes came from, and whether an operator has
  allowlisted that source.

WHAT IT FOUND is deliberately NOT here. That is ``_trentina_warning``'s job
and duplicating it would give two answers that can disagree.

ALLOWLISTING SUPPRESSES FLAGS; IT DOES NOT SKIP LAYERS. This distinction was
invisible under the old field and is worth being loud about: a trusted source
still runs L1, still runs L2, still runs L3. What ``is_trusted`` does is stop
an L1 risk level or an L2 label from FLAGGING — see ``defense._decide`` and
the ``l2_flagged`` computation. So the layer states below stay ``complete``
for an allowlisted source, and ``origin.allowlisted`` is what explains why a
detection did not become a refusal. Reporting those layers as "skipped" would
be the same class of error the old field made.

The one place something genuinely IS skipped: ``clean_*`` on an allowlisted
source returns the original L1 text without calling the Q-Agent at all, so no
extraction happens. That used to be reported as ``trusted-l1`` and nothing
else, which meant an agent that asked for an extraction got the raw page with
no way to tell. It is now ``disposition: delivered`` rather than
``extracted``, which says it outright.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .defense import DefenseVerdict


class LayerState(str, Enum):
    """Whether a layer ran, and whether it finished."""

    COMPLETE = "complete"
    """Ran over the whole input and returned a result."""

    PARTIAL = "partial"
    """Ran, but did not read everything — L2 hitting its token cap."""

    UNAVAILABLE = "unavailable"
    """Could not run: no ONNX model for L2, no API key or a provider error
    for L3. Distinct from COMPLETE with nothing found, which is the confusion
    this whole module exists to prevent."""

    NOT_APPLICABLE = "not_applicable"
    """There was nothing to judge — an empty payload, or a JSON body whose
    string leaves are all blank."""


class Disposition(str, Enum):
    """What the caller did with what the layers concluded."""

    DELIVERED = "delivered"
    """The bytes that arrived, unchanged, with nothing attached."""

    ANNOTATED = "annotated"
    """The bytes that arrived, unchanged, plus ``_trentina_warning``."""

    EXTRACTED = "extracted"
    """A Q-Agent extraction INSTEAD of the original bytes."""

    REFUSED = "refused"
    """Nothing delivered. The caller raised."""

    REPORTED = "reported"
    """No content at all, in either direction — a diagnostic returned findings
    ABOUT a payload. `quarantine_scan` and friends carry no mode prefix for
    exactly this reason: they report, they do not deliver."""


def layer_states(verdict: DefenseVerdict) -> dict[str, str]:
    """Derive per-layer state from a verdict.

    L1 is always ``complete``: it is free, deterministic, has no off switch,
    and a profile that could disable it would only be hiding its own eyes.

    L2 is ``unavailable`` when there was text to read and no classification
    came back — ``classify_async`` returns None when the model is missing or
    failed to load, which used to be indistinguishable from a clean scan.
    """
    has_text = bool(verdict.pipeline.l2_input.strip())
    classification = verdict.classification

    if not has_text:
        l2 = LayerState.NOT_APPLICABLE
    elif classification is None:
        l2 = LayerState.UNAVAILABLE
    elif classification.truncated:
        l2 = LayerState.PARTIAL
    else:
        l2 = LayerState.COMPLETE

    assessment = verdict.l3_assessment
    # No assessment and an assessment that says it could not run are the same
    # fact from the caller's side: nothing judged this semantically.
    if not has_text:
        l3 = LayerState.NOT_APPLICABLE
    elif assessment is None or assessment.get("l3_unavailable"):
        l3 = LayerState.UNAVAILABLE
    else:
        l3 = LayerState.COMPLETE

    return {"l1": LayerState.COMPLETE.value, "l2": l2.value, "l3": l3.value}


def build_report(
    verdict: DefenseVerdict | None,
    *,
    disposition: Disposition,
    kind: str,
    ref: str,
    allowlisted: bool = False,
    extracted_by: str | None = None,
) -> dict[str, Any]:
    """Build the `scan` block.

    Args:
        verdict: What the layers concluded, or None when no layer ran — the
            advisory paths refuse a URL on its shape before fetching it.
        disposition: What the caller did.
        kind: What ``ref`` identifies: ``url``, ``file``, ``content``,
            ``search``.
        ref: The URL, path, query, or content hash.
        allowlisted: Whether an operator has vouched for this source. It
            suppresses flags; it does not skip layers.
        extracted_by: The model that produced an extraction, when there is
            one. Absent otherwise rather than null, because a key that is
            sometimes meaningless is read as meaningful.
    """
    layers = (
        layer_states(verdict)
        if verdict is not None
        else dict.fromkeys(("l1", "l2", "l3"), LayerState.NOT_APPLICABLE.value)
    )
    report: dict[str, Any] = {
        "layers": layers,
        "disposition": disposition.value,
        "origin": {"kind": kind, "ref": ref, "allowlisted": allowlisted},
    }
    if extracted_by is not None:
        report["extracted_by"] = extracted_by
    return report
