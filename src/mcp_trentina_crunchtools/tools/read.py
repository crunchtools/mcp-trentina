"""Read tools — quarantine_read and safe_read."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..config import get_config
from ..database import is_blocked, record_detection
from ..dbus_interface import emit_detection_event, emit_request_event
from ..errors import BlockedSourceError, FileReadError
from ..models import ALLOWED_TEXT_EXTENSIONS
from ..quarantine.agent import quarantine_detect, quarantine_extract
from ..quarantine.classifier import classify
from ..sanitize.pipeline import PipelineResult, looks_like_html, sanitize, sanitize_text

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


async def safe_read(path: str) -> dict[str, Any]:
    """Read local file with Layer 1 sanitization. Fails if injection detected."""
    start_time = time.time()
    config = get_config()

    resolved = _validate_file(path)

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

    classification = classify(pipeline_result.content)
    if classification and classification.label == "MALICIOUS" and not is_trusted:
        record_detection(
            source_type="file",
            source=resolved,
            domain=None,
            layer1_stats=pipeline_result.stats.to_flat_dict(),
            risk_level="high",
            qagent_assessment={
                "classifier_label": classification.label,
                "classifier_score": classification.score,
            },
        )
        emit_detection_event("L2", resolved, "high", {
            "classifier_label": classification.label,
            "classifier_score": classification.score,
        })
        raise BlockedSourceError(resolved, "just detected")

    if not is_trusted and config.has_api_key:
        detection = await quarantine_detect(pipeline_result.content)
        if detection.get("injection_detected"):
            record_detection(
                source_type="file",
                source=resolved,
                domain=None,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=detection.get("risk_level", "high"),
                qagent_assessment=detection,
            )
            emit_detection_event("L3", resolved, detection.get("risk_level", "high"), detection)
            raise BlockedSourceError(resolved, "just detected")

    if pipeline_result.stats.total_detections() > 0 and not is_trusted:
        risk = pipeline_result.stats.risk_level()
        if risk in ("high", "critical"):
            record_detection(
                source_type="file",
                source=resolved,
                domain=None,
                layer1_stats=pipeline_result.stats.to_flat_dict(),
                risk_level=risk,
            )
            emit_detection_event("L1", resolved, risk, pipeline_result.stats.to_flat_dict())
            raise BlockedSourceError(resolved, "just detected")

    trust_level = "trusted-sanitized" if is_trusted else "sanitized-only"

    emit_request_event(
        tool="safe_read",
        source=resolved,
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

    return {
        "content": pipeline_result.content,
        "trust": {
            "level": trust_level,
            "source": "layer1",
            "source_path": resolved,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
    }


async def quarantine_read(path: str, prompt: str) -> dict[str, Any]:
    """Read local file with Layer 1 + Layer 2 (Q-Agent) extraction."""
    start_time = time.time()
    config = get_config()

    resolved = _validate_file(path)

    blocked = is_blocked(resolved)
    blocklist_warning = None
    if blocked:
        blocklist_warning = (
            f"Warning: file previously flagged at {blocked['detected_at']}. "
            "Proceeding in quarantine mode."
        )

    with open(resolved, encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    if looks_like_html(content, resolved):
        pipeline_result = sanitize(content)
    else:
        pipeline_result = sanitize_text(content)

    is_trusted = config.is_trusted_path(resolved)

    classifier_warning = None
    classification = classify(pipeline_result.content)
    if classification and classification.label == "MALICIOUS":
        classifier_warning = (
            f"Layer 2 classifier flagged content as MALICIOUS "
            f"(score: {classification.score:.3f}). Proceeding in quarantine mode."
        )

    def _emit(trust_level: str) -> None:
        emit_request_event(
            tool="quarantine_read",
            source=resolved,
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
                "source_path": resolved,
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
                "source_path": resolved,
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
            "source_path": resolved,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
        "usage": extraction.get("usage", {}),
        "blocklist_warning": blocklist_warning,
        "classifier_warning": classifier_warning,
    }
