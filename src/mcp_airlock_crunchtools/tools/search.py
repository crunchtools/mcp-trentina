"""Unified search tool — always runs full pipeline (L0 → resolve → L1 → L2 [→ L3]).

L0 searches via Gemini grounding (plain text + groundingMetadata).
Redirect URLs are resolved. L1 sanitizes text + titles. L2 classifies.
If API key available, L3 (clean Q-Agent with structured JSON) structures
the sanitized output into actionable results.
"""

from __future__ import annotations

import time
from typing import Any

from ..config import get_config
from ..dbus_interface import emit_request_event
from ..errors import QuarantineAgentError
from ..quarantine.agent import (
    build_pipeline_context,
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


async def search(
    query: str, prompt: str = "Summarize the search results.", num_results: int = 5,
) -> dict[str, Any]:
    """Search the web through the full defense pipeline.

    Pipeline: L0 (Gemini grounding) → resolve redirects → L1 → L2 [→ L3].
    Always returns results with detection metadata.
    """
    start_time = time.time()
    config = get_config()

    # L0: Gemini grounded search
    try:
        raw = await search_grounded(query, num_results)
    except QuarantineAgentError as exc:
        return {
            "text": "",
            "sources": [],
            "extraction": {},
            "query": query,
            "error": str(exc),
            "detection": {
                "risk_level": "unknown",
                "l1_detections": 0,
                "l2_label": None,
                "l2_score": None,
                "l3_injection_detected": None,
                "l3_confidence": None,
            },
        }

    # Resolve redirect URLs
    resolved_sources = await resolve_grounding_urls(raw.get("sources", []))

    # L1: sanitize L0 output
    sanitized_text, sanitized_sources, total_l1 = _sanitize_l0_output(
        raw["text"], resolved_sources
    )

    # L2: classify
    warnings: list[str] = []
    classification = classify(sanitized_text)
    if classification and classification.label == "MALICIOUS":
        warnings.append(
            f"L2 classifier flagged L0 output as MALICIOUS "
            f"(score: {classification.score:.3f}). L0 may have been "
            "compromised by poisoned web content."
        )

    # L3: structured extraction (if API key available)
    extraction: dict[str, Any]
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
        pipeline_context = build_pipeline_context(
            {"l0_search": 1},
            total_l1,
            classification,
        )
        extraction = await quarantine_extract(l3_input, prompt, pipeline_context)
    else:
        extraction = {
            "content": {"extracted_text": sanitized_text},
            "usage": {},
        }

    if extraction.get("classifier_output_warning"):
        warnings.append(extraction["classifier_output_warning"])

    # Build detection metadata
    risk_level = "low"
    if total_l1 >= 3:
        risk_level = "high"
    if classification and classification.label == "MALICIOUS":
        risk_level = "high"

    detection = {
        "risk_level": risk_level,
        "l1_detections": total_l1,
        "l2_label": classification.label if classification else None,
        "l2_score": classification.score if classification else None,
        "l3_injection_detected": extraction.get("content", {}).get("injection_detected"),
        "l3_confidence": extraction.get("content", {}).get("confidence"),
    }

    l3_content = extraction.get("content", {})
    l3_usage = extraction.get("usage", {})
    emit_request_event(
        tool="search",
        source=f"search:{query}",
        trust_level="quarantined" if config.has_api_key else "sanitized-only",
        risk_level=risk_level,
        l1_detections=total_l1,
        l1_suspicious=0,
        l2_label=classification.label if classification else None,
        l2_score=classification.score if classification else None,
        input_size=len(raw.get("text", "")),
        output_size=len(sanitized_text),
        stats={"total_detections": total_l1},
        start_time=start_time,
        raw_content=raw.get("text", ""),
        sanitized_content=sanitized_text,
        l3_model=config.model if config.has_api_key else None,
        l3_confidence=l3_content.get("confidence"),
        l3_injection_detected=l3_content.get("injection_detected"),
        l3_extracted_text=l3_content.get("extracted_text"),
        l3_input_tokens=l3_usage.get("input_tokens"),
        l3_output_tokens=l3_usage.get("output_tokens"),
    )

    result: dict[str, Any] = {
        "text": sanitized_text,
        "sources": sanitized_sources,
        "extraction": extraction.get("content", {}),
        "query": query,
        "trust": {
            "level": "quarantined" if config.has_api_key else "sanitized-only",
            "source": "l0-grounded → l3-clean" if config.has_api_key else "l0-grounded → l1",
            "model": config.model if config.has_api_key else None,
            "pipeline": "L0 → resolve → L1 → L2 → L3" if config.has_api_key else "L0 → resolve → L1 → L2",
        },
        "detection": detection,
        "l0_usage": raw.get("usage", {}),
        "l3_usage": extraction.get("usage", {}),
    }

    if warnings:
        result["warnings"] = warnings

    return result
