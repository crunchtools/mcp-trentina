"""Scan tools — quarantine_scan and deep_quarantine_scan."""

from __future__ import annotations

import time
from typing import Any

from ..client import fetch_url
from ..config import get_config
from ..dbus_interface import emit_request_event
from ..quarantine.agent import quarantine_detect
from ..quarantine.classifier import classify
from ..sanitize.pipeline import looks_like_html, sanitize, sanitize_text
from .read import _validate_file

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_RECOMMENDATIONS = {
    "low": "Source appears clean. Safe to use safe_fetch/safe_read.",
    "medium": "Minor vectors detected. Consider quarantine_fetch/quarantine_read.",
    "high": "Significant injection vectors. Use quarantine_fetch/quarantine_read.",
    "critical": "Multiple injection vectors detected. Exercise extreme caution.",
}


def _risk_order(level: str) -> int:
    """Return numeric risk order for comparison."""
    return _RISK_ORDER.get(level, 0)


def _build_layer1_context(stats: dict[str, int], detections: int) -> str | None:
    """Build a Layer 1 context string for the Q-Agent.

    Returns None if no detections were found (no context needed).
    """
    if detections == 0:
        return None

    non_zero = {k: v for k, v in stats.items() if v > 0}
    lines = [f"- {k}: {v}" for k, v in non_zero.items()]

    return (
        "Layer 1 deterministic scanning found the following injection vectors:\n"
        + "\n".join(lines)
        + "\nEvaluate the following sanitized content for additional semantic "
        "injection vectors that may have survived deterministic stripping."
    )


async def _fetch_content(
    url: str | None,
    path: str | None,
) -> tuple[str, str, str]:
    """Fetch content from URL or file. Returns (content, source_type, source)."""
    source_type = "url" if url else "file"
    source = url or path or ""

    if url:
        content, _ = await fetch_url(url)
    else:
        if path is None:
            msg = "Provide either url or path to scan"
            raise ValueError(msg)
        resolved = _validate_file(path)
        with open(resolved, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        source = resolved

    return content, source_type, source


def _build_scan_result(
    source_type: str,
    source: str,
    layer1_stats: dict[str, int],
    layer1_risk: str,
    layer1_detections: int,
    qagent_assessment: dict[str, Any] | None,
    has_api_key: bool,
    scan_mode: str = "standard",
    classifier_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the scan result dict shared by both scan tools."""
    qagent_risk = "low"
    if qagent_assessment:
        qagent_risk = qagent_assessment.get("risk_level", "low")
        if qagent_assessment.get("injection_detected"):
            qagent_risk = max(qagent_risk, "high", key=_risk_order)

    classifier_risk = "low"
    if classifier_result and classifier_result.get("label") == "MALICIOUS":
        classifier_risk = "high"

    overall_risk = max(layer1_risk, classifier_risk, qagent_risk, key=_risk_order)

    return {
        "source_type": source_type,
        "source": source,
        "scan_mode": scan_mode,
        "risk_level": overall_risk,
        "layer1": {
            "detections": layer1_detections,
            "risk_level": layer1_risk,
            "stats": layer1_stats,
        },
        "layer2": {
            "available": classifier_result is not None,
            "result": classifier_result,
            "risk_level": classifier_risk,
        },
        "qagent": {
            "available": has_api_key,
            "assessment": qagent_assessment,
            "risk_level": qagent_risk,
        },
        "recommendation": _RECOMMENDATIONS.get(overall_risk, "Unknown risk level."),
    }


async def quarantine_scan(
    url: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    """Scan a URL or file for injection vectors WITHOUT returning content.

    Returns threat assessment only — risk level, vector counts, Q-Agent observations.
    Always runs full detection regardless of trust level. Q-Agent receives
    sanitized content with Layer 1 stats as context.
    """
    if not url and not path:
        return {"error": "Provide either url or path to scan"}

    start_time = time.time()
    config = get_config()
    content, source_type, source = await _fetch_content(url, path)

    pipeline_result = (
        sanitize(content) if looks_like_html(content, path) else sanitize_text(content)
    )

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
        source_type=source_type,
        source=source,
        layer1_stats=layer1_stats,
        layer1_risk=layer1_risk,
        layer1_detections=layer1_detections,
        qagent_assessment=qagent_assessment,
        has_api_key=config.has_api_key,
        scan_mode="standard",
        classifier_result=classifier_result,
    )

    emit_request_event(
        tool="quarantine_scan",
        source=source,
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


async def deep_quarantine_scan(
    url: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    """Deep scan: Q-Agent analyzes raw unsanitized content.

    Layer 1 still runs for stats reporting, but the Q-Agent receives
    the original content for full semantic analysis. Higher risk of
    Q-Agent compromise, but better detection of injection vectors that
    Layer 1 would strip before the Q-Agent could evaluate them.

    The Q-Agent remains architecturally quarantined (no tools, no memory,
    structured JSON only) — even if compromised, it can only return JSON
    in the fixed schema.
    """
    if not url and not path:
        return {"error": "Provide either url or path to scan"}

    start_time = time.time()
    config = get_config()
    content, source_type, source = await _fetch_content(url, path)

    pipeline_result = (
        sanitize(content) if looks_like_html(content, path) else sanitize_text(content)
    )

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
        source_type=source_type,
        source=source,
        layer1_stats=layer1_stats,
        layer1_risk=layer1_risk,
        layer1_detections=layer1_detections,
        qagent_assessment=qagent_assessment,
        has_api_key=config.has_api_key,
        scan_mode="deep",
        classifier_result=classifier_result,
    )

    emit_request_event(
        tool="deep_quarantine_scan",
        source=source,
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
