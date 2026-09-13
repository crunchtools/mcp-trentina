"""The perimeter at the MCP proxy ingress — annotate mode (plan step 5).

Until tonight the gateway's README claim was false: proxied tool responses
and tool descriptions crossed into the agent verbatim, and the three-layer
pipeline ran only for the web tools and the alert ingress. These two
functions are the missing wall:

* ``scan_tool_response`` — every ``tools/call`` result from a REMOTE
  backend: text content blocks, resource text, and every string leaf of
  ``structuredContent``, judged as one document. Internal backends are
  deliberately exempt: their tools (safe_fetch and friends) run the
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
tripwire; the owner's rule), a flagged payload gets a ``_trentina_warning``
sibling field, and every flag lands in the detections table as
``source_type="tool_response"`` / ``"tool_description"`` — the score
distribution that step 7's calibration needs before anything fails closed.

A content-hash verdict cache keeps the cost sane: ~210 descriptions are
rebuilt on every circuit-breaker flap, and agents re-read the same tickets
all day. Verdicts are cached per (defense-config, content) pair; a cache
hit re-records nothing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..defense import Provenance, defend

if TYPE_CHECKING:
    from .profile import Profile

logger = logging.getLogger(__name__)

#: Kill switch (owner requirement, ahead of any enforcement flip): setting
#: TRENTINA_ENFORCEMENT_OVERRIDE=annotate forces every profile to annotate,
#: for the night `block` misfires at 3am. Any other value is ignored loudly.
_OVERRIDE_ENV = "TRENTINA_ENFORCEMENT_OVERRIDE"


def effective_enforcement(profile: Profile) -> str:
    override = os.environ.get(_OVERRIDE_ENV, "").strip().lower()
    if override:
        if override == "annotate":
            return "annotate"
        logger.error(
            "%s=%r is not a valid override (only 'annotate' is); ignoring",
            _OVERRIDE_ENV, override,
        )
    return profile.defense.enforcement


@dataclass(frozen=True)
class IngressDecision:
    """What the router should do with a scanned tool response."""

    warning: dict[str, Any] | None
    blocked: bool = False


_CACHE_MAX = 4096
# A verdict is not forever: a clean cached during an L3 outage, or before a
# model/config change, must age out rather than shadow the fix.
_CACHE_TTL_SECONDS = 900.0
_verdicts: OrderedDict[str, tuple[float, dict[str, Any] | None]] = OrderedDict()


def reset_verdict_cache() -> None:
    _verdicts.clear()


def _cache_key(profile: Profile, kind: str, text: str) -> str:
    d = profile.defense
    cfg = (
        f"{d.sanitize}:{d.classify}:{d.classify_threshold}:"
        f"{d.quarantine}:{d.quarantine_threshold}"
    )
    return hashlib.sha256(f"{kind}:{cfg}:{text}".encode()).hexdigest()


def _cache_get(key: str) -> tuple[bool, dict[str, Any] | None]:
    entry = _verdicts.get(key)
    if entry is None:
        return False, None
    expires, value = entry
    if time.monotonic() > expires:
        del _verdicts[key]
        return False, None
    _verdicts.move_to_end(key)
    return True, value


def _cache_put(key: str, value: dict[str, Any] | None) -> None:
    _verdicts[key] = (time.monotonic() + _CACHE_TTL_SECONDS, value)
    _verdicts.move_to_end(key)
    while len(_verdicts) > _CACHE_MAX:
        _verdicts.popitem(last=False)


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


def _collect_block(
    block: dict[str, Any], texts: list[str], unscannable: dict[str, int]
) -> None:
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


def _build_warning(verdict: Any, unscannable: dict[str, int]) -> dict[str, Any] | None:
    classification = verdict.classification
    l2_truncated = bool(classification is not None and classification.truncated)
    l3_unavailable = bool(
        verdict.l3_assessment is not None
        and verdict.l3_assessment.get("l3_unavailable")
    )
    gaps = {k: v for k, v in unscannable.items() if v}

    if not verdict.flagged and not l2_truncated and not l3_unavailable and not gaps:
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
    if l3_unavailable:
        warning["l3_unavailable"] = True
    if gaps:
        warning["unscannable"] = gaps
    return warning


async def scan_tool_response(
    *,
    profile: Profile,
    backend_name: str,
    tool_name: str,
    content_blocks: list[Any] | None,
    structured_content: Any,
) -> IngressDecision:
    """Judge one tool response and decide its fate under the profile's
    enforcement mode.

    annotate — deliver intact, warning attached (`blocked=False`).
    block — a flagged response is refused (`blocked=True`); the caller
        delivers the warning INSTEAD of the content. `extract` currently
        degrades to block with a logged notice: the extraction response
        contract ships with the josui flip, and until then failing closed
        is the only honest reading of "extract" — falling back to annotate
        would silently deliver what the mode existed to transform.

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
        f"response:{enforcement}",
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
        is_html=False,
        guarded=False,
    )
    warning = _build_warning(verdict, unscannable)

    # Under block/extract, "we could not finish judging this" is treated
    # exactly like "this is hostile" — the adversarial review's H1/H3:
    # padding a response past the classifier's token cap made L2 scan only
    # the benign head, and an L3 outage answered "clean" — either one used
    # to walk a payload through block mode.
    l2_truncated = bool(warning and warning.get("l2_truncated"))
    l3_unavailable = bool(warning and warning.get("l3_unavailable"))
    unjudgeable = l2_truncated or l3_unavailable

    blocked = False
    if (verdict.flagged or unjudgeable) and enforcement in ("block", "extract"):
        blocked = True
        assert warning is not None
        if enforcement == "extract":
            logger.warning(
                "gateway: enforcement=extract not yet implemented — failing "
                "closed (block) for profile=%s", profile.name,
            )
        if unjudgeable and not verdict.flagged:
            logger.warning(
                "gateway: refusing incompletely-judged response for "
                "profile=%s (l2_truncated=%s l3_unavailable=%s)",
                profile.name, l2_truncated, l3_unavailable,
            )
        warning = {**warning, "blocked": True}

    _cache_put(key, warning)
    if warning is not None:
        logger.warning(
            "gateway: tool response flagged profile=%s backend=%s tool=%s "
            "risk=%s flagged_by=%s enforcement=%s blocked=%s",
            profile.name, backend_name, tool_name,
            warning.get("risk_level"), warning.get("flagged_by"),
            enforcement, blocked,
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
                is_html=False,
                guarded=False,
            )
            warning = _build_warning(verdict, {})
            _cache_put(key, warning)

        if warning is not None:
            logger.warning(
                "gateway: tool description flagged profile=%s backend=%s tool=%s risk=%s",
                profile.name, backend_name, tool.get("name"), warning.get("risk_level"),
            )
            # A poisoned description's whole attack is being READ during tool
            # selection, and a sibling warning key is exactly the part strict
            # MCP clients strip before the model sees the schema. So under
            # block/extract the tool is withheld from the list outright —
            # blocking the description IS removing it.
            if warning.get("flagged_by") and effective_enforcement(profile) in (
                "block", "extract",
            ):
                logger.warning(
                    "gateway: withholding tool %s from profile=%s (enforcement)",
                    tool.get("name"), profile.name,
                )
                continue
            entry = dict(tool)
            entry["_trentina_warning"] = warning
            annotated.append(entry)
        else:
            annotated.append(tool)

    return annotated
