"""Composition — run pre-processors independently or remixed, outside the wall.

The owner's framing: pre-processors are LEGO. Run a log through petit, then
summarize the result; or run both and keep whichever came out smaller; or
run FREE ones always and spend LLM money only when the payload is still over
budget. New processors join the registry and every strategy can use them.

Whatever the strategy, the caller receives ONE artifact plus its accounting,
scans that artifact through ``defend()``, and delivers that artifact. The
composition layer itself never touches the defense pipeline — the perimeter
is the caller's job, and keeping this module import-free of the detectors is
what the architecture contract test checks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from ..defense import Provenance
from .base import Cost, PreProcessContext, PreProcessor, PreProcessResult

logger = logging.getLogger(__name__)

Strategy = Literal["none", "chain", "best_of", "auto"]


@dataclass(frozen=True)
class PreProcessOutcome:
    """The reduced artifact and everything the perimeter should know about it."""

    content: str
    results: list[PreProcessResult] = field(default_factory=list)
    bytes_in: int = 0
    bytes_out: int = 0

    @property
    def metered_used(self) -> bool:
        """True if any LLM touched the payload on its way here."""
        return any(r.cost is Cost.METERED and r.applied for r in self.results)

    def provenance(self, input_provenance: Provenance = Provenance.EXTERNAL) -> Provenance:
        """What the perimeter should treat the artifact as.

        Deterministic reduction preserves the input's provenance — petit
        deleting lines cannot compose a payload. An LLM rewriting the
        payload makes it model output, and model output gets unconditional
        L3 regardless of how innocent it scores.
        """
        if self.metered_used:
            return Provenance.MODEL_OUTPUT
        return input_provenance

    def sidecar(self) -> dict[str, object]:
        """Accounting for the audit log — the token-mandate evidence."""
        return {
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "ratio": round(self.bytes_out / self.bytes_in, 4) if self.bytes_in else 1.0,
            "processors": [
                {
                    "name": r.name,
                    "cost": r.cost.value,
                    "applied": r.applied,
                    "bytes_in": r.bytes_in,
                    "bytes_out": r.bytes_out,
                    **r.details,
                }
                for r in self.results
            ],
        }

    def describe_for_l3(self) -> str | None:
        """The sidecar as a briefing line for the Q-Agent's context.

        A judge should know it is reading a reduced artifact: an anomalous
        compression ratio, or a summarizer having rewritten the text, changes
        what suspicion looks like.
        """
        applied = [r for r in self.results if r.applied]
        if not applied:
            return None
        steps = ", ".join(
            f"{r.name} ({r.bytes_in}B -> {r.bytes_out}B"
            + (", LLM-generated output" if r.cost is Cost.METERED else "")
            + ")"
            for r in applied
        )
        return (
            "This payload was reduced by pre-processing before reaching you: "
            f"{steps}. You are judging the reduced artifact, which is exactly "
            "what will be delivered if it passes."
        )


async def run_preprocessors(
    content: str,
    *,
    processors: list[PreProcessor],
    strategy: Strategy = "chain",
    ctx: PreProcessContext | None = None,
) -> PreProcessOutcome:
    """Reduce ``content`` per ``strategy``. Never raises on hostile input —
    a processor that fails is logged, skipped, and recorded as not applied."""
    ctx = ctx or PreProcessContext()
    bytes_in = len(content.encode("utf-8"))

    if strategy == "none" or not processors:
        return PreProcessOutcome(content=content, bytes_in=bytes_in, bytes_out=bytes_in)

    if strategy == "chain":
        results = await _chain(content, processors, ctx)
    elif strategy == "best_of":
        results = await _best_of(content, processors, ctx)
    elif strategy == "auto":
        results = await _auto(content, processors, ctx)
    else:  # pragma: no cover - Literal keeps this unreachable from typed code
        raise ValueError(f"unknown preprocess strategy: {strategy}")

    final = results[-1].content if results else content
    return PreProcessOutcome(
        content=final,
        results=results,
        bytes_in=bytes_in,
        bytes_out=len(final.encode("utf-8")),
    )


async def _run_one(
    processor: PreProcessor, payload: str, ctx: PreProcessContext
) -> PreProcessResult:
    try:
        return await processor.run(payload, ctx)
    except Exception:
        logger.exception("preprocess: %s failed; passing payload through", processor.name)
        size = len(payload.encode("utf-8"))
        return PreProcessResult(
            name=processor.name,
            cost=processor.cost,
            content=payload,
            applied=False,
            bytes_in=size,
            bytes_out=size,
            details={"declined": "error"},
        )


async def _chain(
    content: str, processors: list[PreProcessor], ctx: PreProcessContext
) -> list[PreProcessResult]:
    """Feed each processor the previous one's output."""
    results: list[PreProcessResult] = []
    current = content
    for processor in processors:
        result = await _run_one(processor, current, ctx)
        results.append(result)
        current = result.content
    return results


async def _best_of(
    content: str, processors: list[PreProcessor], ctx: PreProcessContext
) -> list[PreProcessResult]:
    """Run every processor on the SAME input; keep the smallest artifact.

    Results list still records every attempt (the sidecar shows what was
    tried), but only the winner's content is last — and the winner is the
    smallest applied result, or the original when nobody improved on it.
    """
    attempts = [await _run_one(p, content, ctx) for p in processors]
    applied = [r for r in attempts if r.applied]
    if not applied:
        return attempts
    winner = min(applied, key=lambda r: r.bytes_out)
    # Reorder so the winner is last: outcome content is always results[-1].
    return [r for r in attempts if r is not winner] + [winner]


async def _auto(
    content: str, processors: list[PreProcessor], ctx: PreProcessContext
) -> list[PreProcessResult]:
    """FREE processors always; METERED only while still over budget.

    With no target_bytes, METERED processors are never invoked — spending
    LLM money requires the caller to say what "small enough" means.
    """
    free = [p for p in processors if p.cost is Cost.FREE]
    metered = [p for p in processors if p.cost is Cost.METERED]

    results = await _chain(content, free, ctx)
    current = results[-1].content if results else content

    if ctx.target_bytes is None:
        return results

    for processor in metered:
        if len(current.encode("utf-8")) <= ctx.target_bytes:
            break
        result = await _run_one(processor, current, ctx)
        results.append(result)
        current = result.content
    return results
