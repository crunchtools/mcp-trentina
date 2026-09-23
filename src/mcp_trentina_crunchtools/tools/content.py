"""Content tools — safe_content, quarantine_content, scan_content, deep_scan_content."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from ..config import get_config
from ..database import is_blocked
from ..dbus_interface import emit_request_event
from ..defense import advise, defend, enforce_block
from ..errors import BlockedSourceError, ContentSizeError
from ..l1.pipeline import (
    PipelineResult,
    build_scan_view,
    build_scan_view_from_html,
    looks_like_html,
)
from ..quarantine.agent import quarantine_extract
from ..quarantine.classifier import (
    join_warnings,
    truncation_warning,
)
from ..warning import build_warning
from .scan import _build_layer1_context, _build_scan_result, _classifier_result


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
        return build_scan_view_from_html(content)
    return build_scan_view(content)


def _build_sanitization_metadata(pipeline_result: PipelineResult) -> dict[str, Any]:
    """Build the sanitization section of tool response."""
    return {
        "input_size": pipeline_result.input_size,
        "output_size": pipeline_result.output_size,
        "stripped": pipeline_result.stats.to_flat_dict(),
    }


async def _content_judged(
    content: str, content_type: str, *, mode: str
) -> dict[str, Any]:
    """Judge inline content with all three layers, dispose of it per `mode`.

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

    verdict = await defend(
        content,
        source=chash,
        source_type="content",
        # Inline content has no provenance to appeal to, so nothing about it is
        # ever trusted. fetch asks the domain, read asks the path, this trusts
        # nothing — which is why trust is the caller's answer, not the
        # pipeline's.
        is_trusted=False,
        is_html=content_type == "text/html" or looks_like_html(content),
    )
    if mode == "block":
        enforce_block(verdict, chash)

    pipeline_result = verdict.pipeline
    classification = verdict.classification

    emit_request_event(
        tool=f"{mode}_content",
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

    result: dict[str, Any] = {
        "content": pipeline_result.content,
        "trust": {
            "level": "sanitized-only",
            "source": "layer1",
            "content_hash": chash,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
    }

    warning = build_warning(verdict)
    if warning is not None:
        result["_trentina_warning"] = warning
    return result


async def block_content(
    content: str, content_type: str = "text/plain"
) -> dict[str, Any]:
    """Fail closed: flagged inline content raises."""
    return await _content_judged(content, content_type, mode="block")


async def warn_content(
    content: str, content_type: str = "text/plain"
) -> dict[str, Any]:
    """Deliver the content as given, with the verdict attached."""
    return await _content_judged(content, content_type, mode="warn")


async def safe_content(
    content: str, content_type: str = "text/plain"
) -> dict[str, Any]:
    """Deprecated spelling of `block_content`. Removed in 0.28.0."""
    return await block_content(content, content_type)


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

    verdict = await advise(
        content,
        source=chash,
        source_type="content",
        is_html=content_type == "text/html" or looks_like_html(content),
    )
    pipeline_result = verdict.pipeline
    classification = verdict.classification

    classifier_warning = None
    if classification and classification.label == "MALICIOUS":
        classifier_warning = (
            f"Layer 2 classifier flagged content as MALICIOUS "
            f"(score: {classification.score:.3f}). Proceeding in quarantine mode."
        )
    classifier_warning = join_warnings(
        classifier_warning, truncation_warning(classification)
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

    l1 = _run_pipeline(content, content_type)
    layer1_stats = l1.stats.to_flat_dict()
    layer1_risk = l1.stats.risk_level()
    layer1_detections = l1.stats.total_detections()

    verdict = await defend(
        content,
        source=chash,
        source_type="content",
        guarded=False,
        record=False,
        precomputed_l1=l1,
        l3_context=_build_layer1_context(layer1_stats, layer1_detections),
        l3_max_chars=config.max_content,
    )
    pipeline_result = verdict.pipeline
    classifier_result = _classifier_result(verdict.classification)
    qagent_assessment = verdict.l3_assessment

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
        l2_score=float(classifier_result["score"]) if classifier_result else None,
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

    l1 = _run_pipeline(content, content_type)
    layer1_stats = l1.stats.to_flat_dict()
    layer1_risk = l1.stats.risk_level()
    layer1_detections = l1.stats.total_detections()

    # Deep mode judges the RAW bytes — no normalization, not even the scan
    # view's obfuscation cleanup. Same shape as scan.py's deep variant.
    verdict = await defend(
        content,
        source=chash,
        source_type="content",
        guarded=False,
        record=False,
        precomputed_l1=PipelineResult(
            content=content,
            scan_view=content,
            stats=l1.stats,
            input_size=l1.input_size,
            output_size=l1.output_size,
        ),
        l3_context=_build_layer1_context(layer1_stats, layer1_detections),
        l3_max_chars=config.max_content,
    )
    pipeline_result = verdict.pipeline
    classifier_result = _classifier_result(verdict.classification)
    qagent_assessment = verdict.l3_assessment

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
        l2_score=float(classifier_result["score"]) if classifier_result else None,
        input_size=pipeline_result.input_size,
        output_size=pipeline_result.output_size,
        stats=layer1_stats,
        start_time=start_time,
    )

    return result


async def clean_content(
    content: str,
    prompt: str = "Extract the main content.",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """Hand back a Q-Agent extraction rather than the content as given."""
    return await quarantine_content(content, prompt, content_type)
