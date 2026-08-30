"""Unified read tool — always runs full pipeline, returns content + detection metadata."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..config import get_config
from ..database import is_blocked
from ..dbus_interface import emit_request_event
from ..errors import BlockedSourceError, FileReadError
from ..models import ALLOWED_TEXT_EXTENSIONS
from ..quarantine.agent import build_pipeline_context, quarantine_extract
from ..quarantine.classifier import classify
from ..sanitize.pipeline import PipelineResult, looks_like_html, sanitize, sanitize_text
from .fetch import _build_detection_metadata

MAX_FILE_SIZE = 2_000_000
BINARY_CHECK_BYTES = 8192

_EXTENSIONLESS_ALLOWED = frozenset(
    {
        "makefile",
        "dockerfile",
        "containerfile",
        "readme",
        "license",
        "changelog",
        "authors",
        "contributors",
    }
)


def _validate_file(path: str) -> str:
    """Validate file path and return resolved absolute path."""
    resolved = str(Path(path).resolve())

    if not os.path.isfile(resolved):
        raise FileReadError(path, "File does not exist")

    file_size = os.path.getsize(resolved)
    if file_size > MAX_FILE_SIZE:
        raise FileReadError(path, f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")

    suffix = Path(resolved).suffix.lower()
    name_lower = Path(resolved).name.lower()

    if suffix and suffix not in ALLOWED_TEXT_EXTENSIONS:
        raise FileReadError(path, f"Binary or unsupported file type: {suffix}")

    if not suffix and name_lower not in _EXTENSIONLESS_ALLOWED:
        raise FileReadError(path, "Unknown file type (no extension)")

    with open(resolved, "rb") as fh:
        chunk = fh.read(BINARY_CHECK_BYTES)
        if b"\x00" in chunk:
            raise FileReadError(path, "Binary file detected")

    return resolved


def _build_sanitization_metadata(pipeline_result: PipelineResult) -> dict[str, Any]:
    """Build the sanitization section of tool response."""
    return {
        "input_size": pipeline_result.input_size,
        "output_size": pipeline_result.output_size,
        "stripped": pipeline_result.stats.to_flat_dict(),
    }


async def read(path: str, prompt: str = "Extract the main content.") -> dict[str, Any]:
    """Read local file through the full defense pipeline.

    Always runs L1 sanitization and L2 classification.
    Trusted paths: skip L3 extraction.
    Untrusted paths with API key: run L3 Q-Agent extraction.
    Untrusted paths without API key: return L1-sanitized content.

    Blocklisted sources are hard-blocked (raises BlockedSourceError).
    """
    start_time = time.time()
    config = get_config()

    resolved = _validate_file(path)

    # Hard block for known-bad sources
    blocked = is_blocked(resolved)
    if blocked:
        raise BlockedSourceError(resolved, blocked["detected_at"])

    with open(resolved, encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    if looks_like_html(content, resolved):
        pipeline_result = sanitize(content)
    else:
        pipeline_result = sanitize_text(content)

    is_trusted = config.is_trusted_path(resolved)

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
        trust_level = "trusted-sanitized"
        response_content: str | dict[str, Any] = pipeline_result.content
    elif config.has_api_key:
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
        trust_level = "sanitized-only"
        response_content = pipeline_result.content

    detection = _build_detection_metadata(pipeline_result, classification, l3_content)

    emit_request_event(
        tool="read",
        source=resolved,
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
            "source_path": resolved,
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
