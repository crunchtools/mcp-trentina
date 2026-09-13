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
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

from ..defense import Provenance, defend

if TYPE_CHECKING:
    from .profile import Profile

logger = logging.getLogger(__name__)

_CACHE_MAX = 4096
_verdicts: OrderedDict[str, dict[str, Any] | None] = OrderedDict()


def reset_verdict_cache() -> None:
    _verdicts.clear()


def _cache_key(profile: Profile, kind: str, text: str) -> str:
    d = profile.defense
    cfg = f"{d.sanitize}:{d.classify}:{d.classify_threshold}:{d.quarantine}"
    return hashlib.sha256(f"{kind}:{cfg}:{text}".encode()).hexdigest()


def _cache_get(key: str) -> tuple[bool, dict[str, Any] | None]:
    if key in _verdicts:
        _verdicts.move_to_end(key)
        return True, _verdicts[key]
    return False, None


def _cache_put(key: str, value: dict[str, Any] | None) -> None:
    _verdicts[key] = value
    _verdicts.move_to_end(key)
    while len(_verdicts) > _CACHE_MAX:
        _verdicts.popitem(last=False)


def _collect_strings(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        if value:
            out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _collect_strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _collect_strings(v, out)


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
    gaps = {k: v for k, v in unscannable.items() if v}

    if not verdict.flagged and not l2_truncated and not gaps:
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
) -> dict[str, Any] | None:
    """Judge one tool response. Returns the annotation, or None when clean.

    The response is never modified; the caller attaches the returned warning
    as a ``_trentina_warning`` sibling. Flags are recorded to the detections
    table (source_type="tool_response") except on a verdict-cache hit.
    """
    texts, unscannable = _collect_response_texts(content_blocks, structured_content)
    joined = "\n".join(texts)
    if not joined.strip():
        gaps = {k: v for k, v in unscannable.items() if v}
        return {"unscannable": gaps} if gaps else None

    key = _cache_key(profile, "response", joined + json.dumps(unscannable, sort_keys=True))
    hit, cached = _cache_get(key)
    if hit:
        return cached

    verdict = await defend(
        joined,
        source=f"{profile.name}:{backend_name}:{tool_name}",
        source_type="tool_response",
        defense=profile.defense,
        is_html=False,
        guarded=False,
    )
    warning = _build_warning(verdict, unscannable)
    _cache_put(key, warning)
    if warning is not None:
        logger.warning(
            "gateway: tool response flagged profile=%s backend=%s tool=%s "
            "risk=%s flagged_by=%s",
            profile.name, backend_name, tool_name,
            warning.get("risk_level"), warning.get("flagged_by"),
        )
    return warning


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

        entry = tool
        if warning is not None:
            entry = dict(tool)
            entry["_trentina_warning"] = warning
            logger.warning(
                "gateway: tool description flagged profile=%s backend=%s tool=%s risk=%s",
                profile.name, backend_name, tool.get("name"), warning.get("risk_level"),
            )
        annotated.append(entry)

    return annotated
