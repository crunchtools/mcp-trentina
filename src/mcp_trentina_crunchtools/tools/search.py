"""Search tools — safe_search and quarantine_search.

Pipeline: L0 → resolve → L1 → L2 [→ L3]

L0 searches via Gemini grounding (plain text + groundingMetadata).
Redirect URLs are resolved. L1 sanitizes text + titles. L2 classifies.
For quarantine_search, L3 (clean Q-Agent with structured JSON) structures
the sanitized output into actionable results.
"""

from __future__ import annotations

import time
from typing import Any

from ..config import get_config
from ..dbus_interface import emit_detection_event, emit_request_event
from ..defense import advise, defend, merge_stats
from ..errors import BlockedSourceError, QuarantineAgentError
from ..l1.pipeline import PipelineResult, PipelineStats, build_scan_view
from ..quarantine.agent import (
    quarantine_extract,
    resolve_grounding_urls,
    search_grounded,
)
from ..quarantine.classifier import (
    join_warnings,
    truncation_warning,
)
from ..warning import build_warning


def _sanitize_l0_output(
    text: str, sources: list[dict[str, str]],
) -> tuple[PipelineResult, list[dict[str, str | bool]], int, PipelineStats]:
    """Run L1 on L0's synthesized text and source titles.

    Returns (text_result, scanned_sources, total_detections, merged_stats).

    The merged stats are what let the shared pipeline judge this the same way
    it judges everything else: L1 ran across several fields here, so the
    aggregate has to be reassembled before L2 sees the document.
    """
    text_result = build_scan_view(text)
    merged = PipelineStats()
    merge_stats(merged, text_result.stats)
    scanned_sources = []
    total_detections = text_result.stats.total_detections()

    for source in sources:
        title_r = build_scan_view(source.get("title", ""))
        url_r = build_scan_view(source.get("uri", ""))
        merge_stats(merged, title_r.stats)
        merge_stats(merged, url_r.stats)
        total_detections += (
            title_r.stats.total_detections()
            + url_r.stats.total_detections()
        )
        scanned_sources.append({
            "uri": url_r.content,
            "title": title_r.content,
            "redirect_failed": source.get("redirect_failed", False),
        })

    return text_result, scanned_sources, total_detections, merged


async def _search_judged(
    query: str, num_results: int, *, mode: str
) -> dict[str, Any]:
    """L0 -> resolve -> L1 -> L2, then dispose of it per `mode`.

    Both modes run the same layers over the same text and deliver the same
    `text`. `block` raises on either refusal condition; `warn` records the
    same finding, attaches it, and hands the grounded answer over anyway.
    """
    start_time = time.time()
    refusals: list[str] = []

    try:
        raw = await search_grounded(query, num_results)
    except QuarantineAgentError as exc:
        raise BlockedSourceError(f"search:{query}", str(exc)) from exc

    resolved_sources = await resolve_grounding_urls(raw.get("sources", []))
    text_result, sanitized_sources, total_l1, l1_stats = _sanitize_l0_output(
        raw["text"], resolved_sources
    )
    sanitized_text = text_result.content

    # safe_search blocks on an L1 COUNT, not a risk level — a fifth distinct
    # L1 policy across the tools. Policy stays with the caller by design; only
    # the mechanics move to the pipeline.
    if total_l1 >= 3:
        emit_detection_event("L1", f"search:{query}", "high", {"total_l1": total_l1})
        reason = f"L1 detected {total_l1} injection vectors in L0 output"
        if mode == "block":
            raise BlockedSourceError(f"search:{query}", reason)
        refusals.append(reason)

    verdict = await defend(
        sanitized_text,
        source=f"search:{query}",
        source_type="url",
        record=False,
        l3_gate=False,
        precomputed_l1=PipelineResult(
            content=sanitized_text,
            scan_view=text_result.scan_view,
            stats=l1_stats,
            input_size=len(raw["text"]),
            output_size=len(sanitized_text),
        ),
    )
    classification = verdict.classification
    if classification and classification.label == "MALICIOUS":
        emit_detection_event("L2", f"search:{query}", "high", {
            "classifier_label": classification.label,
            "classifier_score": classification.score,
        })
        reason = (
            f"L2 classifier flagged L0 output as MALICIOUS "
            f"(score: {classification.score:.3f})"
        )
        if mode == "block":
            raise BlockedSourceError(f"search:{query}", reason)
        refusals.append(reason)

    emit_request_event(
        tool=f"{mode}_search",
        source=f"search:{query}",
        trust_level="sanitized-only",
        risk_level="low",
        l1_detections=total_l1,
        l1_suspicious=0,
        l2_label=classification.label if classification else None,
        l2_score=classification.score if classification else None,
        input_size=len(raw.get("text", "")),
        output_size=len(sanitized_text),
        stats={"total_detections": total_l1},
        start_time=start_time,
    )

    result: dict[str, Any] = {
        "text": sanitized_text,
        "sources": sanitized_sources,
        "query": query,
        "l1_stats": {"total_detections": total_l1},
        "l2_classification": {
            "label": classification.label if classification else "UNAVAILABLE",
            "score": classification.score if classification else None,
        },
        "l0_usage": raw.get("usage", {}),
    }

    # `refusals` is non-empty only under warn: block already raised. It
    # carries the reason this call WOULD have been refused, which is the
    # thing the agent needs in order to weigh the answer it is being handed.
    warning = build_warning(verdict, extras={"refusals": refusals} if refusals else None)
    if warning is not None:
        result["_trentina_warning"] = warning
    return result


async def block_search(query: str, num_results: int = 5) -> dict[str, Any]:
    """Fail closed: a flagged grounded answer raises."""
    return await _search_judged(query, num_results, mode="block")


async def warn_search(query: str, num_results: int = 5) -> dict[str, Any]:
    """Deliver the grounded answer with the verdict attached."""
    return await _search_judged(query, num_results, mode="warn")


async def safe_search(query: str, num_results: int = 5) -> dict[str, Any]:
    """Deprecated spelling of `block_search`. Removed in 0.29.0."""
    return await block_search(query, num_results)


async def quarantine_search(
    query: str, prompt: str, num_results: int = 5,
) -> dict[str, Any]:
    """L0 → resolve → L1 → L2 → L3."""
    start_time = time.time()
    config = get_config()

    try:
        raw = await search_grounded(query, num_results)
    except QuarantineAgentError as exc:
        return {
            "text": "",
            "sources": [],
            "extraction": {},
            "query": query,
            "error": str(exc),
        }

    resolved_sources = await resolve_grounding_urls(raw.get("sources", []))
    text_result, sanitized_sources, _total_l1, _l1_stats = _sanitize_l0_output(
        raw["text"], resolved_sources
    )
    sanitized_text = text_result.content

    classifier_warning = None
    verdict = await advise(
        sanitized_text,
        source=f"search:{query}",
        source_type="url",
    )
    classification = verdict.classification
    if classification and classification.label == "MALICIOUS":
        classifier_warning = (
            f"L2 classifier flagged L0 output as MALICIOUS "
            f"(score: {classification.score:.3f}). L0 may have been "
            "compromised by poisoned web content. Proceeding to L3."
        )
    classifier_warning = join_warnings(
        classifier_warning, truncation_warning(classification)
    )

    if config.has_api_key:
        sources_text = "\n".join(
            f"- [{s['title']}]({s['uri']})"
            + (" [redirect failed]" if s.get("redirect_failed") else "")
            for s in sanitized_sources
        )
        l3_input = (
            f"Sanitized search results for: {query}\n\n"
            f"--- Synthesized text ---\n{sanitized_text}\n\n"
            f"--- Sources ---\n{sources_text}\n\n"
            f"--- Instruction ---\n{prompt}"
        )
        extraction = await quarantine_extract(l3_input, prompt)
    else:
        extraction = {
            "content": {"extracted_text": sanitized_text},
            "usage": {},
        }

    emit_request_event(
        tool="quarantine_search",
        source=f"search:{query}",
        trust_level="quarantined",
        risk_level="low",
        l1_detections=_total_l1,
        l1_suspicious=0,
        l2_label=classification.label if classification else None,
        l2_score=classification.score if classification else None,
        input_size=len(raw.get("text", "")),
        output_size=len(sanitized_text),
        stats={"total_detections": _total_l1},
        start_time=start_time,
    )

    return {
        "text": sanitized_text,
        "sources": sanitized_sources,
        "extraction": extraction.get("content", {}),
        "query": query,
        "trust": {
            "level": "quarantined",
            "source": "l0-grounded → l3-clean",
            "model": config.model,
            "pipeline": "L0 → resolve → L1 → L2 → L3",
        },
        "l0_usage": raw.get("usage", {}),
        "l3_usage": extraction.get("usage", {}),
        "classifier_warning": classifier_warning,
        "classifier_output_warning": extraction.get(
            "classifier_output_warning"
        ),
    }


async def clean_search(
    query: str, prompt: str, num_results: int = 5
) -> dict[str, Any]:
    """Hand back a Q-Agent extraction of the grounded answer."""
    return await quarantine_search(query, prompt, num_results)
