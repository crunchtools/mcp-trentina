"""The internal tools' pre-processing: what the call selected, run before judging (#183).

The gateway's ``transform_response`` never sees these tools — the router
skips it for internal backends, because they judge at their own ingress — so
the same selection has to happen here, on the producer path. It runs before
``judge_and_deliver`` and everything after judges and delivers its output:
what is scanned is what is delivered.

Here it FAILS CLOSED. ``gateway/transform.py`` fails open because its
mandate is tokens; these processors were asked for, by the operator's
default, the operator's floor, or the agent, and delivering something else in
their place would be a silent substitution. A processor that reports a
breakage as a decline, or could not parse the payload (``FAILED_DECLINES``),
refuses the same way.

What ``html`` deleted reaches nobody, but a page that hid text from its reader
has shown its intent. So L1's hiding stage counts the ORIGINAL, the way
``dir`` merges its shadow counts, and L3 is told how many elements went.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..channels import Channel
from ..defense import Provenance
from ..errors import PreProcessFailedError
from ..l1.hidden import detect_hidden_markup
from ..l1.pipeline import PipelineResult, run_l1
from ..preprocess import Cost, PreProcessContext, PreProcessResult
from ..preprocess.policy import FAILED_DECLINES, current_preprocess_policy

if TYPE_CHECKING:
    from collections.abc import Sequence

_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_HIDING_DETAILS = ("hidden_elements", "off_screen_elements", "same_color_text", "template_tags")


@dataclass
class Prepared:
    """What a tool judges and delivers, and what pre-processing did to it."""

    content: str  # judged and delivered, byte for byte
    extras: dict[str, Any] = field(default_factory=dict)  # the result's `preprocess` list
    pipeline: PipelineResult | None = None  # L1 with the original's hiding counts
    briefing: str | None = None  # L3 context: what conversion removed
    provenance: Provenance = Provenance.EXTERNAL  # MODEL_OUTPUT after a METERED rewrite


def is_html_type(content_type: str | None) -> bool:
    """The declared type, never a sniff of the bytes."""
    return (content_type or "").split(";", 1)[0].strip().lower() in _HTML_TYPES


def _l1_with_original_hiding(converted: str, original: str) -> PipelineResult:
    """L1 over what is delivered, with the hiding counts of what arrived."""
    pipeline = run_l1(converted)
    _, pipeline.stats.hidden = detect_hidden_markup(original)
    return pipeline


async def _run(names: Sequence[str], content: str, source: str) -> list[Any]:
    """The chain, each fed the previous output. Raises instead of passing through."""
    from ..gateway.drivers import build_preprocessors
    from ..gateway.profile import ProcessorChainConfig

    processors = build_preprocessors(
        ProcessorChainConfig.model_validate({"processors": list(names)}),
        channel=Channel.TOOL,
    )
    results: list[PreProcessResult] = []
    current = content
    ctx = PreProcessContext(source=source)
    for processor in processors:
        try:
            result = await processor.run(current, ctx)
        except Exception as exc:
            raise PreProcessFailedError(processor.name, type(exc).__name__) from exc
        declined = str(result.details.get("declined", ""))
        if declined in FAILED_DECLINES:
            raise PreProcessFailedError(processor.name, declined)
        results.append(result)
        current = result.content
    return results


async def prepare(
    content: str,
    *,
    requested: Any,
    default: Sequence[str],
    source: str,
) -> Prepared:
    """Resolve the call's selection under the bound policy and run it.

    Raises:
        PreProcessNotPermittedError: the agent named a processor its policy
            does not offer.
        PreProcessFailedError: a processor raised, or declined in a way that
            means it did not do its job (``FAILED_DECLINES``).
    """
    policy = current_preprocess_policy()
    names = policy.resolve(requested, default)
    if not names:
        return Prepared(content)

    results = await _run(names, content, source)
    applied = [r for r in results if r.applied]
    if not applied:
        return Prepared(content)

    final = applied[-1].content
    prepared = Prepared(
        final,
        extras={
            "preprocess": [
                {"name": r.name, "bytes_in": r.bytes_in, "bytes_out": r.bytes_out, **r.details}
                for r in applied
            ]
        },
    )
    if any(r.cost is Cost.METERED for r in applied):
        # A model rewrote the payload: the perimeter owes it unconditional L3.
        prepared.provenance = Provenance.MODEL_OUTPUT

    html = next((r for r in applied if r.name == "html"), None)
    if html is not None:
        prepared.pipeline = await asyncio.to_thread(_l1_with_original_hiding, final, content)
        removed = sum(int(html.details.get(k, 0)) for k in _HIDING_DETAILS)
        if removed:
            prepared.briefing = (
                f"This page was converted from HTML to Markdown before judging, and "
                f"the conversion removed {removed} element(s) hidden from a human "
                f"reader, so you are not reading all of the original. Hiding text is "
                f"a common way to address an agent without the reader noticing."
            )
    return prepared
