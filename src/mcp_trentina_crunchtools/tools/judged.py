"""One path from a produced payload to a tool response, for every family and mode.

Until 0.31.0 each family carried its own copy: ``_fetch_judged``,
``_read_judged``, ``_content_judged``, ``_search_judged``, and four separate
``clean_*`` bodies. The copies drifted in exactly the way copies do. clean
ran a different pipeline from block and warn; search built its own recipe,
blocked on a private ``total_l1 >= 3`` rule, and never called L3 at all.

A producer now does only what only it can: fetch the URL, read the file,
list the directory, hash the inline text, run the grounded search — and the
checks that need what it knows (the blocklist, the allowlist, HTTP status
advisories). Everything after the payload exists is here, once.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ..config import get_config
from ..dbus_interface import emit_request_event
from ..defense import DefenseVerdict, Provenance, defend
from ..errors import BlockedSourceError
from ..modes import Mode, gaps_of
from ..quarantine.agent import quarantine_clean
from ..report import Disposition, build_report
from ..warning import build_warning

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..l1.pipeline import PipelineResult

DEFAULT_CLEAN_PROMPT = "Extract the main content."
"""Used when block downgrades an allowlisted source to clean: the agent asked
for the bytes, so there is no extraction prompt of its own to use."""


def l1_metadata(pipeline: PipelineResult) -> dict[str, Any]:
    """The ``l1`` section of a response: sizes and every stage's counts."""
    return {
        "input_size": pipeline.input_size,
        "output_size": pipeline.output_size,
        "stripped": pipeline.stats.to_flat_dict(),
    }


def _refusal(verdict: DefenseVerdict) -> str | None:
    """Why block or clean may not deliver the original, or None.

    The reason names layers and gaps only. It is ours, never the payload's.
    """
    if verdict.flagged_by is not None:
        return f"flagged by {verdict.flagged_by.value}"
    gaps = gaps_of(verdict)
    if not gaps.blocking():
        return None
    missing = [
        name
        for name, present in (
            ("L2 unavailable", gaps.l2_unavailable),
            ("L2 read only part of the payload", gaps.l2_truncated),
            ("L3 unavailable", gaps.l3_unavailable),
            ("L3 read only part of the payload", gaps.l3_truncated),
        )
        if present
    ]
    return "not fully judged: " + ", ".join(missing)


class _Call:
    """What one tool call knows, carried through judging and delivery."""

    def __init__(
        self,
        *,
        mode: Mode,
        family: str,
        source: str,
        kind: str,
        ref: str,
        allowlisted: bool,
        blocklisted_at: str | None,
    ) -> None:
        self.mode = mode
        self.tool = f"{mode.value}_{family}"
        self.source = source
        self.kind = kind
        self.ref = ref
        self.allowlisted = allowlisted
        self.blocklisted = blocklisted_at is not None
        self.start = time.time()

    def emit(self, verdict: DefenseVerdict, disposition: Disposition, output_size: int) -> None:
        stats = verdict.pipeline.stats
        classification = verdict.classification
        emit_request_event(
            tool=self.tool,
            source=self.source,
            disposition=disposition.value,
            risk_level=stats.risk_level(),
            l1_detections=stats.total_detections(),
            l1_suspicious=stats.suspicious_detections(),
            l2_label=classification.label if classification else None,
            l2_score=classification.score if classification else None,
            input_size=verdict.pipeline.input_size,
            output_size=output_size,
            stats=stats.to_flat_dict(),
            start_time=self.start,
        )

    def refuse(self, verdict: DefenseVerdict, reason: str) -> BlockedSourceError:
        self.emit(verdict, Disposition.REFUSED, 0)
        return BlockedSourceError(self.source, reason)

    def warning(self, verdict: DefenseVerdict, **more: Any) -> dict[str, Any] | None:
        """``_trentina_warning``, or None when the scan completed and found nothing."""
        forced = {**more, "blocklisted": self.blocklisted}
        warning = build_warning(verdict, extras={k: v for k, v in forced.items() if v})
        if warning is not None:
            warning["mode"] = self.mode.value
        return warning


async def judge_and_deliver(
    document: str,
    *,
    mode: Mode,
    family: str,
    source: str,
    source_type: str,
    kind: str,
    ref: str,
    prompt: str | None = None,
    allowlisted: bool = False,
    blocklisted_at: str | None = None,
    provenance: Provenance = Provenance.EXTERNAL,
    domain: str | None = None,
    precomputed_l1: PipelineResult | None = None,
    l3_context: str | None = None,
    delivered: Any = None,
    extras: Mapping[str, Any] | None = None,
    clean_extras: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Judge ``document`` with all three layers and dispose of it per ``mode``.

    Args:
        document: The payload as produced — what every layer reads.
        mode: block, warn or clean. It decides delivery, never detection.
        family: ``fetch``, ``read``, ``dir``, ``content`` or ``search``.
        prompt: The extraction request, for clean.
        allowlisted: An operator vouched for the source. Its flags still
            stand; block sends a flagged or partially-read payload to clean
            instead of refusing it. An ABSENT layer still refuses.
        blocklisted_at: Set when clean proceeds on a blocklisted source.
        delivered: What block and warn hand over, when it is not the document
            itself (search delivers L0's text, the sources separately).
        extras: Family fields for block and warn responses.
        clean_extras: Family fields for clean responses. Separate because
            clean must not re-deliver the payload it replaced.

    Raises:
        BlockedSourceError: block or clean refused. The message names the
            layer or gap, never the payload.
    """
    call = _Call(
        mode=mode,
        family=family,
        source=source,
        kind=kind,
        ref=ref,
        allowlisted=allowlisted,
        blocklisted_at=blocklisted_at,
    )
    verdict = await defend(
        document,
        source=source,
        source_type=source_type,
        provenance=provenance,
        domain=domain,
        # warn delivers a partial scan with a warning, so it pays for the
        # partial scan; block and clean would refuse it, so they do not.
        stop_on_partial=mode is not Mode.WARN,
        precomputed_l1=precomputed_l1,
        l3_context=l3_context,
        # `blocked` feeds the blocklist. Only a block refusal belongs there:
        # a warn row marked blocked made the NEXT warn of the same page raise.
        attribution={
            "tool": call.tool,
            "blocked": mode is Mode.BLOCK and not allowlisted,
        },
    )
    original = document if delivered is None else delivered

    if mode is Mode.WARN:
        return _deliver(call, verdict, original, extras)

    reason = _refusal(verdict)
    if mode is Mode.BLOCK:
        if reason is None:
            return _deliver(call, verdict, original, extras)
        gaps = gaps_of(verdict)
        absent = gaps.blocking() and not gaps.truncated_only()
        if allowlisted and not absent:
            return await _clean(call, verdict, DEFAULT_CLEAN_PROMPT, clean_extras, downgraded=True)
        raise call.refuse(verdict, reason)

    if gaps_of(verdict).blocking():
        raise call.refuse(verdict, reason or "not fully judged")
    return await _clean(call, verdict, prompt or DEFAULT_CLEAN_PROMPT, clean_extras)


def _deliver(
    call: _Call,
    verdict: DefenseVerdict,
    original: Any,
    extras: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """The bytes as they arrived, with the verdict when there is one to give."""
    warning = call.warning(verdict)
    disposition = Disposition.ANNOTATED if warning is not None else Disposition.DELIVERED
    call.emit(verdict, disposition, verdict.pipeline.output_size)
    response: dict[str, Any] = {
        "content": original,
        "scan": build_report(
            verdict,
            disposition=disposition,
            kind=call.kind,
            ref=call.ref,
            allowlisted=call.allowlisted,
        ),
        "l1": l1_metadata(verdict.pipeline),
        **(extras or {}),
    }
    if warning is not None:
        response["_trentina_warning"] = warning
    return response


async def _clean(
    call: _Call,
    verdict: DefenseVerdict,
    prompt: str,
    clean_extras: Mapping[str, Any] | None,
    *,
    downgraded: bool = False,
) -> dict[str, Any]:
    """Turns 2 and 3 over L1's normalized text; refuse if either objects."""
    result = await quarantine_clean(
        verdict.pipeline.l2_input[: get_config().max_content],
        prompt,
        detection=verdict.l3_assessment,
    )
    if result.refused_by is not None:
        raise call.refuse(verdict, f"clean refused: {result.refused_by}")

    extraction = result.content
    # A downgraded block keeps block's response shape: `content` is text.
    content: Any = extraction.get("extracted_text", "") if downgraded else extraction
    warning = call.warning(verdict, downgraded_to_clean=downgraded)
    call.emit(verdict, Disposition.EXTRACTED, len(str(extraction.get("extracted_text", ""))))
    response: dict[str, Any] = {
        "content": content,
        "scan": build_report(
            verdict,
            disposition=Disposition.EXTRACTED,
            kind=call.kind,
            ref=call.ref,
            allowlisted=call.allowlisted,
            extracted_by=get_config().model,
        ),
        "l1": l1_metadata(verdict.pipeline),
        "usage": result.usage,
        **(clean_extras or {}),
    }
    if warning is not None:
        response["_trentina_warning"] = warning
    return response
