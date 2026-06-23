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
from ..errors import BlockedSourceError, QuarantineAgentError
from ..quarantine.agent import (
    quarantine_extract,
    resolve_grounding_urls,
    search_grounded,
)
from ..quarantine.classifier import classify
from ..sanitize.pipeline import sanitize_text


def _sanitize_l0_output(
    text: str, sources: list[dict[str, str]],
) -> tuple[str, list[dict[str, str | bool]], int]:
    """Run L1 on L0's synthesized text and source titles.

    Returns (sanitized_text, sanitized_sources, total_detections).
    """
    text_result = sanitize_text(text)
    sanitized_sources = []
    total_detections = text_result.stats.total_detections()

    for source in sources:
        title_r = sanitize_text(source.get("title", ""))
        url_r = sanitize_text(source.get("uri", ""))
        total_detections += (
            title_r.stats.total_detections()
            + url_r.stats.total_detections()
        )
        sanitized_sources.append({
            "uri": url_r.content,
            "title": title_r.content,
            "redirect_failed": source.get("redirect_failed", False),
        })

    return text_result.content, sanitized_sources, total_detections


async def safe_search(query: str, num_results: int = 5) -> dict[str, Any]:
    """L0 → resolve → L1 → L2. Fail if injection detected."""
    start_time = time.time()

    try:
        raw = await search_grounded(query, num_results)
    except QuarantineAgentError as exc:
        raise BlockedSourceError(f"search:{query}", str(exc)) from exc

    resolved_sources = await resolve_grounding_urls(raw.get("sources", []))
    sanitized_text, sanitized_sources, total_l1 = _sanitize_l0_output(
        raw["text"], resolved_sources
    )

    if total_l1 >= 3:
        emit_detection_event("L1", f"search:{query}", "high", {"total_l1": total_l1})
        raise BlockedSourceError(
            f"search:{query}",
            f"L1 detected {total_l1} injection vectors in L0 output",
        )

    classification = classify(sanitized_text)
    if classification and classification.label == "MALICIOUS":
        emit_detection_event("L2", f"search:{query}", "high", {
            "classifier_label": classification.label,
            "classifier_score": classification.score,
        })
        raise BlockedSourceError(
            f"search:{query}",
            f"L2 classifier flagged L0 output as MALICIOUS "
            f"(score: {classification.score:.3f})",
        )

    emit_request_event(
        tool="safe_search",
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

    return {
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
    sanitized_text, sanitized_sources, _total_l1 = _sanitize_l0_output(
        raw["text"], resolved_sources
    )

    classifier_warning = None
    classification = classify(sanitized_text)
    if classification and classification.label == "MALICIOUS":
        classifier_warning = (
            f"L2 classifier flagged L0 output as MALICIOUS "
            f"(score: {classification.score:.3f}). L0 may have been "
            "compromised by poisoned web content. Proceeding to L3."
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
