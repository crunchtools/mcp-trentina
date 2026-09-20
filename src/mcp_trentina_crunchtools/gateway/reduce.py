"""Wire the pre-processors into the tool-response path.

This module is the call site the ``preprocess`` package was built for. It owns
two things and nothing else: resolving which reduction policy applies to a
given (profile, backend, tool), and rewriting the response's text blocks with
whatever came back.

It does NOT scan, judge, or block. Per ``preprocess/base.py`` invariant 2 the
caller reduces first and then scans the REDUCED artifact — so the router calls
``reduce_response`` before ``scan_tool_response``, and what the perimeter
judges is exactly what the agent will receive. Reduction happening before the
wall is the whole point: what reduction dropped never reaches the agent, and
never reaches the scanner either, so there is nothing to smuggle through.

Two-level resolution, profile then tool:

    profile.preprocess          how aggressive is this agent
    backend.preprocess_tools    is this tool's output shape worth it

Tool wins field-by-field; anything it leaves unset inherits. Whether petit
helps is a property of the tool's output shape rather than of its caller —
``syslog_tail_tool`` is log-shaped for everybody — which is why the override
lives on the backend next to ``parameter_guards`` and not in a second copy
per profile.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..defense import Provenance
from ..preprocess import (
    EmailProcessor,
    PetitProcessor,
    PreProcessContext,
    PreProcessor,
    StructuredProcessor,
    SummarizeProcessor,
    run_preprocessors,
)
from .profile import Backend, PreProcessConfig, Profile, ToolPreProcess

logger = logging.getLogger(__name__)

# Stateless by contract (``PreProcessor`` protocol), so one instance each.
_REGISTRY: dict[str, PreProcessor] = {
    "email": EmailProcessor(),
    "petit": PetitProcessor(),
    "structured": StructuredProcessor(),
    "summarize": SummarizeProcessor(),
}


@dataclass(frozen=True)
class ReduceOutcome:
    """What the router needs to finish the response.

    ``content_blocks`` is always delivered — on a no-op it is the input
    unchanged, so the caller never branches on whether reduction ran.
    """

    content_blocks: list[Any] | None
    applied: bool = False
    provenance: Provenance = Provenance.EXTERNAL
    sidecar: dict[str, Any] | None = None


def resolve(profile: Profile, backend: Backend, tool_name: str) -> PreProcessConfig:
    """Merge the profile default with any per-tool override.

    Returns a fully-populated config; the caller never has to think about
    which level a value came from.
    """
    base = profile.preprocess
    override: ToolPreProcess | None = backend.preprocess_tools.get(tool_name)
    if override is None:
        return base

    return PreProcessConfig(
        enabled=base.enabled if override.enabled is None else override.enabled,
        strategy=base.strategy if override.strategy is None else override.strategy,
        processors=(
            base.processors if override.processors is None else override.processors
        ),
        target_bytes=(
            base.target_bytes
            if override.target_bytes is None
            else override.target_bytes
        ),
        min_bytes=(
            base.min_bytes if override.min_bytes is None else override.min_bytes
        ),
    )


def _text_blocks(content_blocks: list[Any] | None) -> list[tuple[int, str]]:
    """Indices and text of the blocks this module is willing to rewrite.

    Deliberately narrow. ``structuredContent`` is left alone: it is typed
    data a caller may parse and a backend may validate against its
    outputSchema (see ``Backend.validate_output_schema``), and silently
    rewriting it would break both. Resource blocks are left alone for the
    same reason — their text carries a declared mime type. Images and blobs
    are not text at all.

    The cost of that narrowness is real and worth stating: a backend that
    returns its bulk only in structuredContent is not reduced at all. The
    honest fix is to teach specific backends to emit reducible text, not to
    have the gateway quietly mangle typed payloads.
    """
    out: list[tuple[int, str]] = []
    for i, block in enumerate(content_blocks or []):
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str) and text:
                out.append((i, text))
    return out


def _describe_decline(outcome: Any) -> str:
    """One processor's decline, with the evidence it already measured.

    A bare reason is the same word for very different outcomes, so print
    what the processor measured before giving up.

    Shape stays `name:reason(...)` so existing greps for a reason string
    keep matching.
    """
    detail = outcome.details
    parts: list[str] = []
    if "would_be_ratio" in detail:
        parts.append(f"would_be={detail['would_be_ratio']:.0%}")
    if "lines_in" in detail:
        parts.append(f"lines={detail['lines_in']}")
        if "bytes_in" in detail:
            parts.append(f"bytes={detail['bytes_in']}")
    suffix = f"({','.join(parts)})" if parts else ""
    return f"{outcome.name}:{detail.get('declined', '?')}{suffix}"


async def reduce_response(
    *,
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    content_blocks: list[Any] | None,
) -> ReduceOutcome:
    """Shrink a tool response's text blocks. Never raises, never judges.

    Any failure returns the input unchanged — a reducer that cannot reduce
    must not be able to cost you the response. ``run_preprocessors`` already
    fails open per processor; this adds the same guarantee around config
    resolution and block rewriting.
    """
    cfg = resolve(profile, backend, tool_name)
    if not cfg.enabled or cfg.strategy == "none" or not cfg.processors:
        return ReduceOutcome(content_blocks=content_blocks)

    targets = _text_blocks(content_blocks)
    if not targets:
        return ReduceOutcome(content_blocks=content_blocks)

    total = sum(len(t.encode("utf-8")) for _, t in targets)
    if total < cfg.min_bytes:
        return ReduceOutcome(content_blocks=content_blocks)

    processors = [_REGISTRY[n] for n in cfg.processors if n in _REGISTRY]
    if not processors:
        return ReduceOutcome(content_blocks=content_blocks)

    # Per block rather than on the joined text: blocks are a structure the
    # backend chose, and a reducer that welds them into one loses it.
    # target_bytes is shared across blocks so a response's budget does not
    # multiply by how many pieces it arrived in.
    per_block_target = max(1, cfg.target_bytes // len(targets))

    new_blocks = list(content_blocks or [])
    results: list[Any] = []
    metered = False
    bytes_in = 0
    bytes_out = 0

    for idx, text in targets:
        try:
            outcome = await run_preprocessors(
                text,
                processors=processors,
                strategy=cfg.strategy,
                ctx=PreProcessContext(
                    source=f"{profile.name}:{backend_name}:{tool_name}",
                    target_bytes=per_block_target,
                ),
            )
        except Exception:
            logger.exception(
                "reduce: preprocessing failed for %s:%s; delivering block unchanged",
                backend_name,
                tool_name,
            )
            continue

        bytes_in += outcome.bytes_in
        bytes_out += outcome.bytes_out
        results.extend(outcome.results)
        if outcome.metered_used:
            metered = True
        if outcome.content != text:
            block = dict(new_blocks[idx])
            block["text"] = outcome.content
            new_blocks[idx] = block

    applied = any(getattr(r, "applied", False) for r in results)

    # Every candidate is logged, applied or not, at WARNING: the gateway runs
    # at TRENTINA_LOG_LEVEL=WARNING so INFO goes nowhere, and this is the same
    # operational-notice shape as ingress_defense's "tool response flagged
    # ... blocked=False".
    #
    # Declines are the valuable half — a large payload that every processor
    # declined is the specification for the next one. Volume stays bounded
    # because a candidate has already cleared min_bytes.
    declines = ",".join(_describe_decline(r) for r in results if not r.applied)
    logger.warning(
        "reduce: %s:%s:%s %d -> %d bytes (%d%%) applied=%s metered=%s%s",
        profile.name,
        backend_name,
        tool_name,
        bytes_in,
        bytes_out,
        (100 * bytes_out // bytes_in) if bytes_in else 100,
        applied,
        metered,
        f" declined={declines}" if declines else "",
    )

    if not applied:
        return ReduceOutcome(content_blocks=content_blocks)

    # An LLM rewrote the payload, so the artifact is model output and the
    # perimeter owes it unconditional L3 — see preprocess/compose.py's
    # provenance() and defense.Provenance. Deterministic reduction cannot
    # compose a payload, so it keeps the input's provenance.
    provenance = Provenance.MODEL_OUTPUT if metered else Provenance.EXTERNAL

    sidecar: dict[str, Any] = {
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "ratio": round(bytes_out / bytes_in, 4) if bytes_in else 1.0,
        "metered": metered,
        "processors": [
            {
                "name": r.name,
                "cost": r.cost.value,
                "applied": r.applied,
                "bytes_in": r.bytes_in,
                "bytes_out": r.bytes_out,
                **r.details,
            }
            for r in results
        ],
    }

    return ReduceOutcome(
        content_blocks=new_blocks,
        applied=True,
        provenance=provenance,
        sidecar=sidecar,
    )
