"""Fetch tools — quarantine_fetch and safe_fetch."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from ..client import fetch_url
from ..config import get_config
from ..database import is_blocked, record_detection
from ..dbus_interface import emit_detection_event, emit_request_event
from ..errors import BlockedSourceError
from ..quarantine.agent import quarantine_detect, quarantine_extract
from ..quarantine.classifier import classify
from ..sanitize.pipeline import PipelineResult, looks_like_html, sanitize, sanitize_text


def _build_sanitization_metadata(pipeline_result: PipelineResult) -> dict[str, Any]:
    """Build the sanitization section of tool response."""
    return {
        "input_size": pipeline_result.input_size,
        "output_size": pipeline_result.output_size,
        "stripped": pipeline_result.stats.to_flat_dict(),
    }


async def safe_fetch(url: str) -> dict[str, Any]:
    """Fetch URL with Layer 1 sanitization. Fails if injection detected.

    For untrusted sources, also runs Q-Agent detection scan.
    Trusted sources get Layer 1 only (no Q-Agent cost).
    """
    start_time = time.time()
    config = get_config()

    blocked = is_blocked(url)
    if blocked:
        raise BlockedSourceError(url, blocked["detected_at"])

    content, _content_type = await fetch_url(url)

    pipeline_result = sanitize(content) if looks_like_html(content) else sanitize_text(content)

    is_trusted = config.is_trusted_domain(url)

    classification = classify(pipeline_result.content)
    if classification and classification.label == "MALICIOUS" and not is_trusted:
        domain = urlparse(url).hostname
        record_detection(
            source_type="url",
            source=url,
            domain=domain,
            layer1_stats=pipeline_result.stats.to_flat_dict(),
            risk_level="high",
            qagent_assessment={
                "classifier_label": classification.label,
                "classifier_score": classification.score,
            },
        )
        emit_detection_event("L2", url, "high", {
            "classifier_label": classification.label,
            "classifier_score": classification.score,
        })
        raise BlockedSourceError(url, "just detected")

    if not is_trusted and config.has_api_key:
        detection = await quarantine_detect(pipeline_result.content)
        if detection.get("injection_detected"):
            domain = urlparse(url).hostname
            record_detection(
                source_type="url",
                source=url,
                domain=domain,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=detection.get("risk_level", "high"),
                qagent_assessment=detection,
            )
            emit_detection_event("L3", url, detection.get("risk_level", "high"), detection)
            raise BlockedSourceError(url, "just detected")

    if pipeline_result.stats.total_detections() > 0 and not is_trusted:
        risk = pipeline_result.stats.risk_level()
        if risk in ("high", "critical"):
            domain = urlparse(url).hostname
            record_detection(
                source_type="url",
                source=url,
                domain=domain,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=risk,
            )
            emit_detection_event("L1", url, risk, pipeline_result.stats.to_flat_dict())
            raise BlockedSourceError(url, "just detected")

    trust_level = "trusted-sanitized" if is_trusted else "sanitized-only"

    result = {
        "content": pipeline_result.content,
        "trust": {
            "level": trust_level,
            "source": "layer1",
            "source_url": url,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
    }

    emit_request_event(
        tool="safe_fetch",
        source=url,
        trust_level=trust_level,
        risk_level=pipeline_result.stats.risk_level(),
        l1_detections=pipeline_result.stats.total_detections(),
        l1_suspicious=pipeline_result.stats.suspicious_detections(),
        l2_label=classification.label if classification else None,
        l2_score=classification.score if classification else None,
        input_size=pipeline_result.input_size,
        output_size=pipeline_result.output_size,
        stats=pipeline_result.stats.to_flat_dict(),
        start_time=start_time,
    )

    return result


async def quarantine_fetch(url: str, prompt: str) -> dict[str, Any]:
    """Fetch URL with Layer 1 + Layer 2 (Q-Agent) extraction.

    Warns but proceeds if source is in blocklist.
    """
    start_time = time.time()
    config = get_config()

    blocked = is_blocked(url)
    blocklist_warning = None
    if blocked:
        blocklist_warning = (
            f"Warning: source previously flagged at {blocked['detected_at']}. "
            "Proceeding in quarantine mode."
        )

    content, _content_type = await fetch_url(url)

    pipeline_result = sanitize(content) if looks_like_html(content) else sanitize_text(content)

    is_trusted = config.is_trusted_domain(url)

    classifier_warning = None
    classification = classify(pipeline_result.content)
    if classification and classification.label == "MALICIOUS":
        classifier_warning = (
            f"Layer 2 classifier flagged content as MALICIOUS "
            f"(score: {classification.score:.3f}). Proceeding in quarantine mode."
        )

    def _emit(trust_level: str) -> None:
        emit_request_event(
            tool="quarantine_fetch",
            source=url,
            trust_level=trust_level,
            risk_level=pipeline_result.stats.risk_level(),
            l1_detections=pipeline_result.stats.total_detections(),
            l1_suspicious=pipeline_result.stats.suspicious_detections(),
            l2_label=classification.label if classification else None,
            l2_score=classification.score if classification else None,
            input_size=pipeline_result.input_size,
            output_size=pipeline_result.output_size,
            stats=pipeline_result.stats.to_flat_dict(),
            start_time=start_time,
        )

    if is_trusted:
        _emit("trusted-sanitized")
        return {
            "content": {"extracted_text": pipeline_result.content},
            "trust": {
                "level": "trusted-sanitized",
                "source": "layer1",
                "source_url": url,
            },
            "sanitization": _build_sanitization_metadata(pipeline_result),
            "blocklist_warning": blocklist_warning,
            "classifier_warning": classifier_warning,
        }

    if not config.has_api_key:
        if config.fallback == "fail":
            from ..errors import ConfigError

            raise ConfigError("GEMINI_API_KEY required and QUARANTINE_FALLBACK=fail")
        _emit("sanitized-only")
        return {
            "content": {"extracted_text": pipeline_result.content},
            "trust": {
                "level": "sanitized-only",
                "source": "layer1-fallback",
                "source_url": url,
            },
            "sanitization": _build_sanitization_metadata(pipeline_result),
            "blocklist_warning": blocklist_warning,
            "classifier_warning": classifier_warning,
        }

    truncated = pipeline_result.content[: config.max_content]

    extraction = await quarantine_extract(truncated, prompt)

    _emit("quarantined")
    return {
        "content": extraction.get("content", {}),
        "trust": {
            "level": "quarantined",
            "source": "q-agent",
            "model": config.model,
            "source_url": url,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
        "usage": extraction.get("usage", {}),
        "blocklist_warning": blocklist_warning,
        "classifier_warning": classifier_warning,
    }
