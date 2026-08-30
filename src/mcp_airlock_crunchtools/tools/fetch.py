"""Unified fetch tool — always runs full pipeline, returns content + detection metadata."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from ..client import fetch_url
from ..config import get_config
from ..database import is_blocked
from ..dbus_interface import emit_request_event
from ..errors import BlockedSourceError
from ..quarantine.agent import build_pipeline_context, quarantine_extract
from ..quarantine.classifier import classify
from ..sanitize.pipeline import PipelineResult, looks_like_html, sanitize, sanitize_text


def _build_sanitization_metadata(pipeline_result: PipelineResult) -> dict[str, Any]:
    """Build the sanitization section of tool response."""
    return {
        "input_size": pipeline_result.input_size,
        "output_size": pipeline_result.output_size,
        "stripped": pipeline_result.stats.to_flat_dict(),
    }


def _build_detection_metadata(
    pipeline_result: PipelineResult,
    classification: Any | None,
    l3_content: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build unified detection metadata from all layers."""
    l1_detections = pipeline_result.stats.total_detections()
    risk_level = pipeline_result.stats.risk_level()

    # L2 classifier
    l2_label = classification.label if classification else None
    l2_score = classification.score if classification else None
    if classification and classification.label == "MALICIOUS":
        risk_level = "high" if risk_level in ("low", "medium") else risk_level

    # L3 Q-Agent
    l3_injection = None
    l3_confidence = None
    if l3_content:
        l3_injection = l3_content.get("injection_detected")
        l3_confidence = l3_content.get("confidence")
        if l3_injection:
            risk_level = "high" if risk_level in ("low", "medium") else risk_level

    return {
        "risk_level": risk_level,
        "l1_detections": l1_detections,
        "l2_label": l2_label,
        "l2_score": l2_score,
        "l3_injection_detected": l3_injection,
        "l3_confidence": l3_confidence,
    }


async def fetch(url: str, prompt: str = "Extract the main content.") -> dict[str, Any]:
    """Fetch URL through the full defense pipeline.

    Always runs L1 sanitization and L2 classification.
    Trusted domains: skip L3 extraction (cost savings).
    Untrusted domains with API key: run L3 Q-Agent extraction.
    Untrusted domains without API key: return L1-sanitized content.

    Blocklisted sources are hard-blocked (raises BlockedSourceError).
    Detection metadata is always included in the response.
    """
    start_time = time.time()
    config = get_config()

    # Hard block for known-bad sources
    blocked = is_blocked(url)
    if blocked:
        raise BlockedSourceError(url, blocked["detected_at"])

    content, _content_type = await fetch_url(url)

    pipeline_result = sanitize(content) if looks_like_html(content) else sanitize_text(content)

    is_trusted = config.is_trusted_domain(url)

    # L2 classification (always)
    classification = classify(pipeline_result.content)

    warnings: list[str] = []
    if classification and classification.label == "MALICIOUS":
        warnings.append(
            f"L2 classifier flagged content as MALICIOUS "
            f"(score: {classification.score:.3f})."
        )

    # L3 extraction
    l3_content: dict[str, Any] | None = None
    l3_usage: dict[str, Any] = {}

    if is_trusted:
        # Trusted: skip L3, return L1-sanitized content
        trust_level = "trusted-sanitized"
        response_content: str | dict[str, Any] = pipeline_result.content
    elif config.has_api_key:
        # Untrusted with API key: full L3 extraction
        trust_level = "quarantined"
        truncated = pipeline_result.content[: config.max_content]

        pipeline_context = build_pipeline_context(
            pipeline_result.stats.to_flat_dict(),
            pipeline_result.stats.total_detections(),
            classification,
        )

        extraction = await quarantine_extract(truncated, prompt, pipeline_context)
        l3_content = extraction.get("content", {})
        l3_usage = extraction.get("usage", {})
        response_content = l3_content or {}

        if extraction.get("classifier_output_warning"):
            warnings.append(extraction["classifier_output_warning"])
    else:
        # Untrusted without API key: L1-sanitized fallback
        trust_level = "sanitized-only"
        response_content = pipeline_result.content

    detection = _build_detection_metadata(pipeline_result, classification, l3_content)

    emit_request_event(
        tool="fetch",
        source=url,
        trust_level=trust_level,
        risk_level=detection["risk_level"],
        l1_detections=pipeline_result.stats.total_detections(),
        l1_suspicious=pipeline_result.stats.suspicious_detections(),
        l2_label=classification.label if classification else None,
        l2_score=classification.score if classification else None,
        input_size=pipeline_result.input_size,
        output_size=pipeline_result.output_size,
        stats=pipeline_result.stats.to_flat_dict(),
        start_time=start_time,
        raw_content=content,
        sanitized_content=pipeline_result.content,
        l3_model=config.model if trust_level == "quarantined" else None,
        l3_confidence=l3_content.get("confidence") if l3_content else None,
        l3_injection_detected=l3_content.get("injection_detected") if l3_content else None,
        l3_extracted_text=l3_content.get("extracted_text") if l3_content else None,
        l3_input_tokens=l3_usage.get("input_tokens"),
        l3_output_tokens=l3_usage.get("output_tokens"),
    )

    result: dict[str, Any] = {
        "content": response_content,
        "trust": {
            "level": trust_level,
            "source": "q-agent" if trust_level == "quarantined" else "layer1",
            "source_url": url,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
        "detection": detection,
    }

    if trust_level == "quarantined":
        result["trust"]["model"] = config.model
        result["usage"] = l3_usage

    if warnings:
        result["warnings"] = warnings

    return result
