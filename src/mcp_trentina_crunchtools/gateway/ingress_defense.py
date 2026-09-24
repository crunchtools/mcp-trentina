"""The perimeter at the MCP proxy ingress — warn mode (plan step 5).

Until tonight the gateway's README claim was false: proxied tool responses
and tool descriptions crossed into the agent verbatim, and the three-layer
pipeline ran only for the web tools and the alert ingress. These two
functions are the missing wall:

* ``scan_tool_response`` — every ``tools/call`` result from a REMOTE
  backend: text content blocks, resource text, and every string leaf of
  ``structuredContent``, judged as one document. Internal backends are
  deliberately exempt: their tools (block_fetch and friends) run the
  pipeline at their own ingress — the firewall filters where content
  ENTERS, and scanning the same bytes twice on the way through is cost,
  not defense.

* ``scan_tool_list`` — every tool's name, title, description, inputSchema
  and annotations: the classic MCP tool-poisoning channel. Runs on the
  post-compression text, because compressed descriptions are LLM output
  and it is the OUTPUT that reaches the agent; a description the
  compressor rewrote carries MODEL_OUTPUT provenance and earns
  unconditional L3. This hook sits on the build path for every tools/list,
  so entries replayed from the persisted SQLite caches (written before the
  perimeter existed) are scanned exactly like live ones — the poisoned-
  cache ingress closes structurally rather than by a deploy-time flush.

Enforcement here is hardwired ANNOTATE: content is never modified (L1 is a
owner's rule), a flagged payload gets a ``_trentina_warning``
sibling field, and every flag lands in the detections table as
``source_type="tool_response"`` / ``"tool_description"`` — the score
distribution that step 7's calibration needs before anything fails closed.

A content-hash verdict cache keeps the cost sane: ~210 descriptions are
rebuilt on every circuit-breaker flap, and agents re-read the same tickets
all day. Verdicts are cached per (defense-config, content) pair; a cache
hit re-records nothing.

Tool-description verdicts also OUTLIVE the process, in ``perimeter_db`` —
a store of its own, not a table beside the blocklist. Judging them from
cold took over five minutes, which every MCP client reports as a timeout
rather than as a warm-up. Responses stay in memory: unbounded, mostly seen
once, and not what a restart pays for.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..defense import Provenance, defend
from ..modes import gaps_of, warning_blocks
from ..warning import build_warning

if TYPE_CHECKING:
    from .profile import Profile

logger = logging.getLogger(__name__)

#: Kill switch (owner requirement, ahead of any enforcement flip): setting
#: TRENTINA_ENFORCEMENT_OVERRIDE=warn forces every profile to warn, for the
#: night `block` misfires at 3am. Any other value is ignored loudly.
#:
#: `annotate` is still accepted, because the one moment this variable is
#: reached for is the moment nobody wants to discover it was renamed.
_OVERRIDE_ENV = "TRENTINA_ENFORCEMENT_OVERRIDE"
_OVERRIDE_VALUES = {"warn": "warn", "annotate": "warn"}


def effective_enforcement(profile: Profile) -> str:
    override = os.environ.get(_OVERRIDE_ENV, "").strip().lower()
    if override:
        if override in _OVERRIDE_VALUES:
            if override != "warn":
                logger.warning(
                    "%s=%r is the pre-0.25.0 spelling of 'warn'; honouring it",
                    _OVERRIDE_ENV,
                    override,
                )
            return _OVERRIDE_VALUES[override]
        logger.error(
            "%s=%r is not a valid override (only 'warn' is); ignoring",
            _OVERRIDE_ENV,
            override,
        )
    return profile.defense.enforcement


@dataclass(frozen=True)
class IngressDecision:
    """What the router should do with a scanned tool response."""

    warning: dict[str, Any] | None
    blocked: bool = False


_CACHE_MAX = 4096

# A COMPLETE verdict is a pure function of (detector set, defence config,
# content), and all three are pinned — the first by the row's version
# stamp, the other two by the cache key. So it does not go stale and does
# not expire. It used to, on a 900-second TTL, which meant fifteen quiet
# minutes re-armed a full rescan of every tool description.
_verdicts: OrderedDict[str, dict[str, Any] | None] = OrderedDict()

# Set when the store refuses a write. A read-only or full disk fails the
# same way for every subsequent verdict, and retrying 200 more times per
# boot turns one logged problem into a flood.
_persist_broken = False


def load_verdict_cache() -> int:
    """Populate the verdict cache from the perimeter store at startup.

    Without this, every restart re-judges ~210 tool descriptions through
    L1, L2 and L3 before the first ``tools/list`` can answer — measured at
    over five minutes, which every MCP client reports as a timeout rather
    than as a warm-up.

    On the trust question: the store is owned by this process's own uid, so
    an attacker able to write it can equally rewrite this dict in memory,
    the code, or the image. Re-deriving every verdict on each boot defends
    only against someone who has already won. The version stamp covers the
    case that actually happens — a row written by an older perimeter.
    """
    from ..perimeter_db import PERIMETER_VERSION, get_all_verdicts

    global _persist_broken
    _persist_broken = False

    loaded = get_all_verdicts(PERIMETER_VERSION)
    _verdicts.update(loaded)
    while len(_verdicts) > _CACHE_MAX:
        _verdicts.popitem(last=False)
    logger.info("perimeter: loaded %d cached verdict(s)", len(_verdicts))
    return len(_verdicts)


def reset_verdict_cache() -> None:
    """Clear the in-memory cache without touching the store (for testing)."""
    global _persist_broken
    _verdicts.clear()
    _persist_broken = False


def _cache_key(profile: Profile, kind: str, text: str) -> str:
    d = profile.defense
    cfg = f"{d.l2_threshold}"
    return hashlib.sha256(f"{kind}:{cfg}:{text}".encode()).hexdigest()


def _cache_get(key: str) -> tuple[bool, dict[str, Any] | None]:
    hit = key in _verdicts
    if hit:
        _verdicts.move_to_end(key)
    return hit, _verdicts.get(key)


def _cache_put(key: str, value: dict[str, Any] | None, *, persist: bool = False) -> None:
    """Remember one verdict, and for tool descriptions write it down.

    ``persist`` is set only by ``scan_tool_list``. Tool descriptions are
    what a restart pays for — a bounded set of a few hundred, judged again
    on every boot and every circuit-breaker flap. Tool RESPONSES are
    unbounded and mostly seen once, so persisting them would put a disk
    write in the hot path of every proxied call to buy a hit rate near
    zero. They stay in memory, where the LRU already bounds them.
    """
    global _persist_broken

    # A verdict reached while L3 was unavailable, or while L2 truncated its
    # input, is NOT the verdict the perimeter would reach today. Keeping it
    # would let an outage's "clean" outlive the outage. This is the one
    # thing the old TTL was really buying, and refusing the verdict outright
    # buys it without the recurring rescan.
    if value is not None and (
        value.get("l3_unavailable")
        or value.get("l3_truncated")
        or value.get("l2_truncated")
        or value.get("l2_unavailable")
    ):
        return

    _verdicts[key] = value
    _verdicts.move_to_end(key)
    while len(_verdicts) > _CACHE_MAX:
        _verdicts.popitem(last=False)

    if not persist or _persist_broken:
        return
    try:
        from ..perimeter_db import PERIMETER_VERSION, save_verdict

        save_verdict(key, value, PERIMETER_VERSION)
    except Exception:
        # A store that cannot be written is a slow next boot, not a wrong
        # answer, and must never cost the request in front of us. Stop
        # trying: whatever broke the write breaks the next two hundred.
        _persist_broken = True
        logger.warning(
            "perimeter: cannot write the verdict store; verdicts will not survive this restart",
            exc_info=True,
        )


def _collect_strings(value: Any, out: list[str]) -> None:
    """Iterative walk over keys AND values.

    Iterative because a few KB of "[[[[..." nesting is an attacker-supplied
    RecursionError; keys because a model reads {"IGNORE ALL PREVIOUS
    INSTRUCTIONS": true} exactly like a value, and keys used to be a
    scan-free channel.
    """
    stack: list[Any] = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if node:
                out.append(node)
        elif isinstance(node, dict):
            for k, v in reversed(list(node.items())):
                stack.append(v)
                stack.append(k)
        elif isinstance(node, list):
            stack.extend(reversed(node))


def _collect_response_texts(
    content_blocks: list[Any] | None,
    structured_content: Any,
) -> tuple[list[str], dict[str, int]]:
    """Pull every judgeable string out of an MCP tool result.

    Returns the texts and a count of what CANNOT be judged — image blocks
    and binary resource blobs. Unscannable content is not silently fine; the
    counts go into the warning so the agent (and later, a block-mode
    enforcement) knows the wall had a gap on this response.
    """
    texts: list[str] = []
    unscannable = {"images": 0, "blobs": 0}

    for block in content_blocks or []:
        if isinstance(block, dict):
            _collect_block(block, texts, unscannable)

    if structured_content is not None:
        _collect_strings(structured_content, texts)

    return texts, unscannable


def _collect_block(block: dict[str, Any], texts: list[str], unscannable: dict[str, int]) -> None:
    btype = block.get("type")
    if btype == "text":
        text = block.get("text")
        if isinstance(text, str) and text:
            texts.append(text)
    elif btype == "image":
        unscannable["images"] += 1
    elif btype == "resource":
        resource = block.get("resource")
        if isinstance(resource, dict):
            rtext = resource.get("text")
            if isinstance(rtext, str) and rtext:
                texts.append(rtext)
            elif resource.get("blob") is not None:
                unscannable["blobs"] += 1


async def scan_tool_response(
    *,
    profile: Profile,
    backend_name: str,
    tool_name: str,
    content_blocks: list[Any] | None,
    structured_content: Any,
    provenance: Provenance = Provenance.EXTERNAL,
    l3_context: str | None = None,
) -> IngressDecision:
    """Judge one tool response and decide its fate under the profile's
    enforcement mode.

    warn — deliver intact, warning attached (`blocked=False`).
    block — a flagged response is refused (`blocked=True`); the caller
        delivers the warning INSTEAD of the content.

    Those are the only two. `clean` used to be accepted here and degraded to
    block with a logged notice; since 0.27.0 a profile naming it is refused
    at LOAD, because a config that names a capability the gateway does not
    have is a config that lies to whoever reads it.

    Flags are recorded to the detections table (source_type="tool_response")
    except on a verdict-cache hit.
    """
    texts, unscannable = _collect_response_texts(content_blocks, structured_content)
    joined = "\n".join(texts)
    enforcement = effective_enforcement(profile)

    if not joined.strip():
        gaps = {k: v for k, v in unscannable.items() if v}
        return IngressDecision(warning={"unscannable": gaps} if gaps else None)

    key = _cache_key(
        profile,
        f"response:{enforcement}:{provenance.value}",
        joined + json.dumps(unscannable, sort_keys=True),
    )
    hit, cached = _cache_get(key)
    if hit:
        return IngressDecision(
            warning=cached,
            blocked=bool(cached and cached.get("blocked")),
        )

    verdict = await defend(
        joined,
        source=f"{profile.name}:{backend_name}:{tool_name}",
        source_type="tool_response",
        defense=profile.defense,
        provenance=provenance,
        l3_context=l3_context,
        stop_on_partial=enforcement != "warn",
        attribution={
            "profile": profile.name,
            "backend": backend_name,
            "tool": tool_name,
            "direction": "response",
            "blocked": enforcement != "warn",
        },
    )
    warning = build_warning(verdict, unscannable=unscannable)

    # Under block, "we could not finish judging this" is treated exactly
    # like "this is hostile" — the adversarial review's H1/H3: padding a
    # response past the classifier's token cap made L2 scan only the benign
    # head, and an L3 outage answered "clean". The rule is modes.Gaps, the
    # same one the tools use. A missing ONNX model now refuses too, unless
    # TRENTINA_REQUIRE_L2=false: one rule, and an escape hatch for a bad
    # image rather than a silent exemption.
    layer_gaps = gaps_of(verdict)
    unjudgeable = layer_gaps.blocking()

    blocked = False
    # `!= "warn"` rather than `== "block"`, deliberately. `warn` is the only
    # mode that DELIVERS flagged content, so making it the sole exception
    # means any mode added later fails closed until someone implements it.
    # The opposite spelling puts a new mode on the delivering side by
    # default, which is how an unimplemented enforcement mode becomes a hole
    # rather than an outage.
    if (verdict.flagged or unjudgeable) and enforcement != "warn":
        blocked = True
        if warning is None:
            # build_warning() only returns None when nothing was flagged and
            # nothing was unjudgeable -- entering this branch means one of
            # those was true, so warning cannot be None here. If it is, the
            # invariant broke and failing loudly beats silently skipping the
            # block under python -O.
            raise RuntimeError(
                "ingress_defense: warning is None while blocking -- invariant violated"
            )
        if unjudgeable and not verdict.flagged:
            logger.warning(
                "gateway: refusing incompletely-judged response for profile=%s (%s)",
                profile.name,
                layer_gaps,
            )
        warning = {**warning, "blocked": True}

    _cache_put(key, warning)
    if warning is not None:
        logger.warning(
            "gateway: tool response flagged profile=%s backend=%s tool=%s "
            "risk=%s flagged_by=%s enforcement=%s blocked=%s",
            profile.name,
            backend_name,
            tool_name,
            warning.get("risk_level"),
            warning.get("flagged_by"),
            enforcement,
            blocked,
        )
    return IngressDecision(warning=warning, blocked=blocked)


def _tool_surface_text(tool: dict[str, Any]) -> str:
    """Everything on a tool definition that a model will read.

    inputSchema is the classic poisoning channel — instructions hidden in a
    parameter's description field — so the whole schema is serialized in.
    """
    parts: list[str] = []
    for field in ("name", "title", "description"):
        value = tool.get(field)
        if isinstance(value, str) and value:
            parts.append(value)
    for field in ("inputSchema", "annotations"):
        value = tool.get(field)
        if value is not None:
            collected: list[str] = []
            _collect_strings(value, collected)
            parts.extend(collected)
    return "\n".join(parts)


async def scan_tool_list(
    profile: Profile,
    backend_name: str,
    tools_before_compression: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Judge every tool definition; annotate the flagged ones in place.

    ``tools_before_compression`` decides provenance per tool: a description
    the compressor rewrote is LLM output and earns unconditional L3. The
    lists are positionally parallel (compress_tools preserves order and
    length).
    """
    annotated: list[dict[str, Any]] = []
    for tool, before in zip(tools, tools_before_compression, strict=True):
        surface = _tool_surface_text(tool)
        if not surface.strip():
            annotated.append(tool)
            continue

        compressed = tool.get("description", "") != before.get("description", "")
        provenance = Provenance.MODEL_OUTPUT if compressed else Provenance.EXTERNAL

        key = _cache_key(profile, f"tool:{provenance.value}", surface)
        hit, warning = _cache_get(key)
        if not hit:
            verdict = await defend(
                surface,
                source=f"{profile.name}:{backend_name}:{tool.get('name', '?')}",
                source_type="tool_description",
                defense=profile.defense,
                provenance=provenance,
                attribution={
                    "profile": profile.name,
                    "backend": backend_name,
                    "tool": str(tool.get("name", "?")),
                    "direction": "tool_list",
                    "blocked": effective_enforcement(profile) != "warn",
                },
            )
            warning = build_warning(verdict)
            _cache_put(key, warning, persist=True)

        if warning is not None:
            if not hit:
                # Only on a fresh judgement. Logging cache hits as well made
                # the journal read as though nothing were cached at all,
                # which is how an earlier "the gateway is rescanning
                # everything" report started.
                logger.warning(
                    "gateway: tool description flagged profile=%s backend=%s tool=%s risk=%s",
                    profile.name,
                    backend_name,
                    tool.get("name"),
                    warning.get("risk_level"),
                )
            # A poisoned description's whole attack is being READ during tool
            # selection, and a sibling warning key is exactly the part strict
            # MCP clients strip before the model sees the schema. So under
            # block/extract the tool is withheld from the list outright —
            # blocking the description IS removing it.
            # A description that could not be fully judged is withheld under
            # block exactly like a flagged one: same rule as responses.
            if effective_enforcement(profile) != "warn" and (
                warning.get("flagged_by") or warning_blocks(warning)
            ):
                logger.warning(
                    "gateway: withholding tool %s from profile=%s (enforcement)",
                    tool.get("name"),
                    profile.name,
                )
                continue
            entry = dict(tool)
            entry["_trentina_warning"] = warning
            annotated.append(entry)
        else:
            annotated.append(tool)

    return annotated
