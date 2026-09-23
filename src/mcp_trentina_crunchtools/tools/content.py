"""Content tools — block_content, clean_content, scan_content, deep_scan_content."""

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
    run_l1,
)
from ..quarantine.agent import quarantine_extract
from ..quarantine.classifier import (
    join_warnings,
    truncation_warning,
)
from ..report import Disposition, build_report
from ..warning import build_warning
from .scan import _build_layer1_context, _build_scan_result, _classifier_result


def _content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for blocklist keying."""
    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"


def _validate_content_size(content: str, max_size: int) -> None:
    """Reject content exceeding the configured maximum size."""
    if len(content) > max_size:
        raise ContentSizeError(len(content), max_size)


def _build_l1_metadata(pipeline_result: PipelineResult) -> dict[str, Any]:
    """Build the L1 section of a tool response."""
    return {
        "input_size": pipeline_result.input_size,
        "output_size": pipeline_result.output_size,
        "stripped": pipeline_result.stats.to_flat_dict(),
    }


async def _content_judged(
    content: str, _content_type: str, *, mode: str
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
    )
    if mode == "block":
        enforce_block(verdict, chash)

    pipeline_result = verdict.pipeline
    classification = verdict.classification

    warning = build_warning(verdict)
    disposition = (
        Disposition.ANNOTATED if warning is not None else Disposition.DELIVERED
    )

    emit_request_event(
        tool=f"{mode}_content",
        source=chash,
        disposition=disposition.value,
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
        "scan": build_report(
            verdict, disposition=disposition, kind="content", ref=chash,
        ),
        "l1": _build_l1_metadata(pipeline_result),
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


async def clean_content(
    content: str,
    prompt: str = "Extract the main content.",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """L1 detection + L3 extraction on inline content.

    Warns but proceeds if content hash is in blocklist.

    ``content_type`` no longer selects a pipeline — L1 is format-agnostic
    (#172) — but it stays in the signature as published tool surface, and as
    the authoritative hint a converter will want once processors become
    selectable per call. Discarded explicitly rather than silently, so the
    next reader does not go looking for the branch it used to pick.
    """
    del content_type

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

    def _emit(disposition: str) -> None:
        emit_request_event(
            tool="clean_content",
            source=chash,
            disposition=disposition,
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
        _emit(Disposition.DELIVERED.value)
        return {
            "content": {"extracted_text": pipeline_result.content},
            "scan": build_report(
                verdict, disposition=Disposition.DELIVERED, kind="content",
                ref=chash,
            ),
            "l1": _build_l1_metadata(pipeline_result),
            "blocklist_warning": blocklist_warning,
            "classifier_warning": classifier_warning,
        }

    truncated = pipeline_result.content[: config.max_content]

    extraction = await quarantine_extract(truncated, prompt)

    _emit(Disposition.EXTRACTED.value)
    return {
        "content": extraction.get("content", {}),
        "scan": build_report(
            verdict, disposition=Disposition.EXTRACTED, kind="content", ref=chash,
            extracted_by=config.model,
        ),
        "l1": _build_l1_metadata(pipeline_result),
        "usage": extraction.get("usage", {}),
        "blocklist_warning": blocklist_warning,
        "classifier_warning": classifier_warning,
    }


async def scan_content(
    content: str,
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """Three-layer scan on inline content. L2/L3 see what L1 produced.

    Returns threat assessment only — no content in the response.
    """
    start_time = time.time()
    config = get_config()

    _validate_content_size(content, config.max_content)

    chash = _content_hash(content)

    # Published tool surface, discarded explicitly: L1 is format-agnostic and
    # `content_type` selects nothing (#172). See `clean_content`.
    del content_type

    l1 = run_l1(content)
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
        disposition="scan",
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

    # Published tool surface, discarded explicitly: L1 is format-agnostic and
    # `content_type` selects nothing (#172). See `clean_content`.
    del content_type

    l1 = run_l1(content)
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
            l2_input=content,
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
        disposition="scan",
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
