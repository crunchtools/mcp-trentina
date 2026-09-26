"""Wire the pre-processors into the tool-response path.

This module is the call site the ``preprocess`` package was built for. It owns
two things and nothing else: resolving which transformation policy applies to
a given (profile, backend, tool), and rewriting the response's text blocks
with whatever came back. Which processors exist, and whether one may run on
this channel, is ``gateway/drivers.py``'s question.

It does NOT scan, judge, or block — it is not a guard. Per
``preprocess/base.py`` invariant 2 the caller transforms first and then scans
the TRANSFORMED artifact, so the router calls ``transform_response`` before
``scan_tool_response``, and what the perimeter judges is exactly what the
agent will receive. Transforming before the wall is the whole point: what a
processor dropped never reaches the agent, and never reaches the scanner
either, so there is nothing to smuggle through.

This file was ``reduce.py`` until issue #160. Reduction is what every
processor wired here does today; the contract is transformation generally
(``preprocess/base.py``), and the narrower name was part of how the two roles
got muddled in the first place.

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

from ..channels import Channel
from ..defense import Provenance
from ..preprocess import PreProcessContext, PreProcessor, Strategy, run_preprocessors
from ..preprocess.policy import FAILED_DECLINES
from .drivers import build_preprocessors
from .errors import ProfileConfigError
from .profile import Backend, PreProcessConfig, Profile, ToolPreProcess

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TransformOutcome:
    """What the router needs to finish the response.

    ``content_blocks`` is always delivered — on a no-op it is the input
    unchanged, so the caller never branches on whether transformation ran.
    """

    content_blocks: list[Any] | None
    applied: bool = False
    provenance: Provenance = Provenance.EXTERNAL
    sidecar: dict[str, Any] | None = None
    # Set when a REQUIRED processor could not run. The router delivers
    # nothing: a floor that fails open is not a floor.
    failed: str | None = None


def resolve(profile: Profile, backend: Backend, tool_name: str) -> PreProcessConfig:
    """Merge the profile default with any per-tool override.

    Returns a fully-populated config; the caller never has to think about
    which level a value came from.
    """
    base = profile.preprocess
    override: ToolPreProcess | None = backend.preprocess_tools.get(tool_name)
    if override is None:
        return base

    # The profile's floor survives a tool override that narrows the ceiling:
    # validation below would refuse a required name outside processors, so a
    # tool that drops it from processors must say required explicitly.
    return PreProcessConfig(
        enabled=base.enabled if override.enabled is None else override.enabled,
        strategy=base.strategy if override.strategy is None else override.strategy,
        processors=(base.processors if override.processors is None else override.processors),
        target_bytes=(
            base.target_bytes if override.target_bytes is None else override.target_bytes
        ),
        min_bytes=(base.min_bytes if override.min_bytes is None else override.min_bytes),
        required=base.required if override.required is None else override.required,
        selectable=(base.selectable if override.selectable is None else override.selectable),
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


def _processors_for(
    cfg: PreProcessConfig,
    profile_name: str,
    backend_name: str,
    tool_name: str,
    names: list[str] | None = None,
) -> list[PreProcessor]:
    """Resolve the configured processors, or none at all.

    ``build_preprocessors`` fails closed, which is right at config load —
    ``loader._check_drivers`` builds every driver a profile names so an
    unusable one is a refused start — and wrong here. If one reaches this far
    anyway, it should cost the profile its transformation, not its tool call.
    That is the place that refuses; this is the place that copes.
    """
    if names is not None:
        if not names:
            return []
        cfg = cfg.model_copy(update={"processors": names, "required": []})
    try:
        return build_preprocessors(cfg, channel=Channel.TOOL, profile_name=profile_name)
    except ProfileConfigError:
        logger.exception(
            "transform: unusable processor config for %s:%s; delivering unchanged",
            backend_name,
            tool_name,
        )
        return []


@dataclass
class _Block:
    content: str
    results: list[Any]
    metered: bool = False
    failed: str | None = None


async def _transform_block(
    text: str,
    floor: list[PreProcessor],
    processors: list[PreProcessor],
    strategy: Strategy,
    ctx: PreProcessContext,
) -> _Block:
    """Stage 1 the floor, fail-closed; stage 2 the rest, fail-open."""
    block = _Block(text, [])
    if floor:
        stage = await run_preprocessors(text, processors=floor, strategy="chain", ctx=ctx)
        broken = next(
            (r for r in stage.results if r.details.get("declined") in FAILED_DECLINES), None
        )
        if broken is not None:
            block.failed = (
                f"required pre-processor {broken.name!r} could not run "
                f"({broken.details.get('declined')})"
            )
            return block
        block.results.extend(stage.results)
        block.metered = stage.metered_used
        block.content = stage.content
    if processors:
        try:
            outcome = await run_preprocessors(
                block.content, processors=processors, strategy=strategy, ctx=ctx
            )
        except Exception:
            logger.exception(
                "transform: preprocessing failed for %s; delivering block unchanged", ctx.source
            )
            return block
        block.results.extend(outcome.results)
        block.metered = block.metered or outcome.metered_used
        block.content = outcome.content
    return block


async def transform_response(
    *,
    profile: Profile,
    backend: Backend,
    backend_name: str,
    tool_name: str,
    content_blocks: list[Any] | None,
    selection: tuple[str, ...] | None = None,
) -> TransformOutcome:
    """Transform a tool response's text blocks. Never raises, never judges.

    Two stages. The profile's ``required`` processors run first, as a chain,
    whatever the agent asked for and regardless of ``enabled`` and
    ``min_bytes`` — first, so ``best_of`` can never discard them. They FAIL
    CLOSED: one that raises or cannot parse the payload sets ``failed`` and
    the router delivers nothing. Then the optional processors run under the
    configured strategy, and they fail open: a processor that cannot improve
    a payload must not be able to cost you the response.

    Args:
        profile, backend, backend_name, tool_name: where the response came
            from; they resolve the config (``resolve``) and label the log.
        content_blocks: the response's MCP content; only text blocks are
            rewritten.
        selection: the agent's ``trentina_preprocess``, already resolved
            against the policy (required names included), or None for the
            operator's default.

    Returns:
        The blocks to scan and deliver. When ``failed`` is set, a required
        processor did not run and the caller must deliver nothing.
    """
    cfg = resolve(profile, backend, tool_name)
    required: list[str] = list(cfg.required)
    # None is the operator's default: the configured chain when enabled and
    # the response clears min_bytes. An explicit selection runs whatever the
    # size — the agent asked for it.
    default_on = cfg.enabled and cfg.strategy != "none"
    chosen = selection if selection is not None else (cfg.processors if default_on else [])
    optional = [n for n in chosen if n not in required]
    if not (required or optional):
        return TransformOutcome(content_blocks=content_blocks)
    targets = _text_blocks(content_blocks)
    if selection is None and sum(len(t.encode("utf-8")) for _, t in targets) < cfg.min_bytes:
        optional = []
    if not targets or not (required or optional):
        return TransformOutcome(content_blocks=content_blocks)

    floor = _processors_for(cfg, profile.name, backend_name, tool_name, required)
    if len(floor) != len(required):
        return TransformOutcome(
            content_blocks=None, failed=f"required pre-processors {required} unusable"
        )
    processors = _processors_for(cfg, profile.name, backend_name, tool_name, optional)
    if not floor and not processors:
        return TransformOutcome(content_blocks=content_blocks)

    # Per block rather than on the joined text: blocks are a structure the
    # backend chose, and a reducer that welds them into one loses it.
    # target_bytes is shared across blocks so a response's budget does not
    # multiply by how many pieces it arrived in.
    ctx = PreProcessContext(
        source=f"{profile.name}:{backend_name}:{tool_name}",
        target_bytes=max(1, cfg.target_bytes // len(targets)),
    )
    # An explicit selection under strategy none still runs: the agent asked.
    strategy: Strategy = "chain" if cfg.strategy == "none" else cfg.strategy
    new_blocks = list(content_blocks or [])
    results: list[Any] = []
    metered = False
    sizes = [0, 0]
    for idx, text in targets:
        block = await _transform_block(text, floor, processors, strategy, ctx)
        if block.failed is not None:
            return TransformOutcome(content_blocks=None, failed=block.failed)
        results.extend(block.results)
        metered = metered or block.metered
        sizes[0] += len(text.encode("utf-8"))
        sizes[1] += len(block.content.encode("utf-8"))
        if block.content != text:
            new_blocks[idx] = {**new_blocks[idx], "text": block.content}
    return _account(ctx.source, content_blocks, new_blocks, results, metered, *sizes)


def _account(
    source: str,
    content_blocks: list[Any] | None,
    new_blocks: list[Any],
    results: list[Any],
    metered: bool,
    bytes_in: int,
    bytes_out: int,
) -> TransformOutcome:
    """Log what every processor did, and build the outcome and its sidecar."""
    applied = any(getattr(r, "applied", False) for r in results)

    # Every candidate is logged, applied or not, at WARNING: the gateway runs
    # at TRENTINA_LOG_LEVEL=WARNING so INFO goes nowhere, and this is the same
    # operational-notice shape as ingress_defense's "tool response flagged
    # ... blocked=False".
    #
    # Declines are the valuable half — a large payload that every processor
    # declined is the specification for the next one. Volume stays bounded:
    # a candidate cleared min_bytes, or was asked for by name.
    declines = ",".join(_describe_decline(r) for r in results if not r.applied)
    logger.warning(
        "transform: %s %d -> %d bytes (%d%%) applied=%s metered=%s%s",
        source,
        bytes_in,
        bytes_out,
        (100 * bytes_out // bytes_in) if bytes_in else 100,
        applied,
        metered,
        f" declined={declines}" if declines else "",
    )

    if not applied:
        return TransformOutcome(content_blocks=content_blocks)

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

    return TransformOutcome(
        content_blocks=new_blocks,
        applied=True,
        provenance=provenance,
        sidecar=sidecar,
    )
