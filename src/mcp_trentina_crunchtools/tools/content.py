"""Content tools — safe_content, quarantine_content, scan_content, deep_scan_content."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ..config import get_config
from ..database import is_blocked, record_detection
from ..dbus_interface import emit_detection_event, emit_request_event
from ..errors import BlockedSourceError, ContentSizeError
from ..quarantine.agent import quarantine_detect, quarantine_extract
from ..quarantine.classifier import classify
from ..sanitize.pipeline import PipelineResult, looks_like_html, sanitize, sanitize_text
from .scan import _build_layer1_context, _build_scan_result


def _content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for blocklist keying."""
    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"


def _validate_content_size(content: str, max_size: int) -> None:
    """Reject content exceeding the configured maximum size."""
    if len(content) > max_size:
        raise ContentSizeError(len(content), max_size)


def _run_pipeline(content: str, content_type: str) -> PipelineResult:
    """Select and run the appropriate sanitization pipeline."""
    if content_type == "text/html" or looks_like_html(content):
        return sanitize(content)
    return sanitize_text(content)


def _build_sanitization_metadata(pipeline_result: PipelineResult) -> dict[str, Any]:
    """Build the sanitization section of tool response."""
    return {
        "input_size": pipeline_result.input_size,
        "output_size": pipeline_result.output_size,
        "stripped": pipeline_result.stats.to_flat_dict(),
    }


async def safe_content(
    content: str,
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """Sanitize inline content. Fails if injection detected.

    Always untrusted — runs L1 + L2 + L3 detection on every call.
    Uses SHA-256 content hash for blocklist.
    """
    start_time = time.time()
    config = get_config()

    _validate_content_size(content, config.max_content)

    chash = _content_hash(content)

    blocked = is_blocked(chash)
    if blocked:
        raise BlockedSourceError(chash, blocked["detected_at"])

    pipeline_result = _run_pipeline(content, content_type)

    classification = classify(pipeline_result.content)
    if classification and classification.label == "MALICIOUS":
        record_detection(
            source_type="content",
            source=chash,
            domain=None,
            layer1_stats=pipeline_result.stats.to_flat_dict(),
            risk_level="high",
            qagent_assessment={
                "classifier_label": classification.label,
                "classifier_score": classification.score,
            },
        )
        emit_detection_event("L2", chash, "high", {
            "classifier_label": classification.label,
            "classifier_score": classification.score,
        })
        raise BlockedSourceError(chash, "just detected")

    if config.has_api_key:
        detection = await quarantine_detect(pipeline_result.content)
        if detection.get("injection_detected"):
            record_detection(
                source_type="content",
                source=chash,
                domain=None,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=detection.get("risk_level", "high"),
                qagent_assessment=detection,
            )
            emit_detection_event("L3", chash, detection.get("risk_level", "high"), detection)
            raise BlockedSourceError(chash, "just detected")

    if pipeline_result.stats.total_detections() > 0:
        risk = pipeline_result.stats.risk_level()
        if risk in ("high", "critical"):
            record_detection(
                source_type="content",
                source=chash,
                domain=None,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=risk,
            )
            emit_detection_event("L1", chash, risk, pipeline_result.stats.to_flat_dict())
            raise BlockedSourceError(chash, "just detected")

    emit_request_event(
        tool="safe_content",
        source=chash,
        trust_level="sanitized-only",
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

    return {
        "content": pipeline_result.content,
        "trust": {
            "level": "sanitized-only",
            "source": "layer1",
            "content_hash": chash,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
    }


async def quarantine_content(
    content: str,
    prompt: str = "Extract the main content.",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """Sanitize + Q-Agent extraction on inline content.

    Warns but proceeds if content hash is in blocklist.
    """
    start_time = time.time()
    config = get_config()

    _validate_content_size(content, config.max_content)

    chash = _content_hash(content)

    blocked = is_blocked(chash)
    blocklist_warning = None
    if blocked:
        blocklist_warning = (
            f"Warning: content previously flagged at {blocked['detected_at']}. "
            "Proceeding in quarantine mode."
        )

    pipeline_result = _run_pipeline(content, content_type)

    classifier_warning = None
    classification = classify(pipeline_result.content)
    if classification and classification.label == "MALICIOUS":
        classifier_warning = (
            f"Layer 2 classifier flagged content as MALICIOUS "
            f"(score: {classification.score:.3f}). Proceeding in quarantine mode."
        )

    def _emit(trust_level: str) -> None:
        emit_request_event(
            tool="quarantine_content",
            source=chash,
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
                "content_hash": chash,
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
            "content_hash": chash,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
        "usage": extraction.get("usage", {}),
        "blocklist_warning": blocklist_warning,
        "classifier_warning": classifier_warning,
    }


async def scan_content(
    content: str,
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """Three-layer scan on inline content. L2/L3 see sanitized output.

    Returns threat assessment only — no content in the response.
    """
    start_time = time.time()
    config = get_config()

    _validate_content_size(content, config.max_content)

    chash = _content_hash(content)

    pipeline_result = _run_pipeline(content, content_type)

    layer1_stats = pipeline_result.stats.to_flat_dict()
    layer1_risk = pipeline_result.stats.risk_level()
    layer1_detections = pipeline_result.stats.total_detections()

    classifier_result = None
    classification = classify(pipeline_result.content)
    if classification:
        classifier_result = {
            "label": classification.label,
            "score": classification.score,
            "latency_ms": classification.latency_ms,
        }

    qagent_assessment = None
    if config.has_api_key:
        truncated = pipeline_result.content[: config.max_content]
        layer1_context = _build_layer1_context(layer1_stats, layer1_detections)
        qagent_assessment = await quarantine_detect(truncated, layer1_context=layer1_context)

    result = _build_scan_result(
        source_type="content",
        source=chash,
        layer1_stats=layer1_stats,
        layer1_risk=layer1_risk,
        layer1_detections=layer1_detections,
        qagent_assessment=qagent_assessment,
        has_api_key=config.has_api_key,
        scan_mode="standard",
        classifier_result=classifier_result,
    )

    emit_request_event(
        tool="scan_content",
        source=chash,
        trust_level="scan",
        risk_level=result["risk_level"],
        l1_detections=layer1_detections,
        l1_suspicious=0,
        l2_label=str(classifier_result["label"]) if classifier_result else None,
        l2_score=float(classifier_result["score"]) if classifier_result else None,  # type: ignore[arg-type]
        input_size=pipeline_result.input_size,
        output_size=pipeline_result.output_size,
        stats=layer1_stats,
        start_time=start_time,
    )

    return result


async def deep_scan_content(
    content: str,
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """Three-layer deep scan. L1 runs for stats, L2/L3 see raw content.

    Higher risk of Q-Agent compromise but better detection of injection
    vectors that L1 would strip.
    """
    start_time = time.time()
    config = get_config()

    _validate_content_size(content, config.max_content)

    chash = _content_hash(content)

    pipeline_result = _run_pipeline(content, content_type)

    layer1_stats = pipeline_result.stats.to_flat_dict()
    layer1_risk = pipeline_result.stats.risk_level()
    layer1_detections = pipeline_result.stats.total_detections()

    classifier_result = None
    classification = classify(content)
    if classification:
        classifier_result = {
            "label": classification.label,
            "score": classification.score,
            "latency_ms": classification.latency_ms,
        }

    qagent_assessment = None
    if config.has_api_key:
        truncated = content[: config.max_content]
        layer1_context = _build_layer1_context(layer1_stats, layer1_detections)
        qagent_assessment = await quarantine_detect(truncated, layer1_context=layer1_context)

    result = _build_scan_result(
        source_type="content",
        source=chash,
        layer1_stats=layer1_stats,
        layer1_risk=layer1_risk,
        layer1_detections=layer1_detections,
        qagent_assessment=qagent_assessment,
        has_api_key=config.has_api_key,
        scan_mode="deep",
        classifier_result=classifier_result,
    )

    emit_request_event(
        tool="deep_scan_content",
        source=chash,
        trust_level="scan",
        risk_level=result["risk_level"],
        l1_detections=layer1_detections,
        l1_suspicious=0,
        l2_label=str(classifier_result["label"]) if classifier_result else None,
        l2_score=float(classifier_result["score"]) if classifier_result else None,  # type: ignore[arg-type]
        input_size=pipeline_result.input_size,
        output_size=pipeline_result.output_size,
        stats=layer1_stats,
        start_time=start_time,
    )

    return result
