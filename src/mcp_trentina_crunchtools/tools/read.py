"""Read tools — quarantine_read and safe_read."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from ..config import get_config
from ..database import is_blocked
from ..dbus_interface import emit_request_event
from ..defense import advise, defend, enforce_block
from ..errors import BlockedSourceError, FileReadError
from ..l1.pipeline import PipelineResult, looks_like_html
from ..models import ALLOWED_TEXT_EXTENSIONS
from ..quarantine.agent import quarantine_extract
from ..quarantine.classifier import (
    join_warnings,
    truncation_warning,
)
from ..warning import build_warning

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


async def _read_judged(path: str, *, mode: str) -> dict[str, Any]:
    """Read, judge with all three layers, dispose of it per `mode`.

    `block` and `warn` run identically and deliver the same bytes; they
    differ in one decision. See `fetch.py` for why that is a parameter and
    not a second function.
    """
    start_time = time.time()
    config = get_config()

    resolved = _validate_file(path)

    blocked = is_blocked(resolved)
    if blocked:
        raise BlockedSourceError(resolved, blocked["detected_at"])

    with open(resolved, encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    is_trusted = config.is_trusted_path(resolved)

    verdict = await defend(
        content,
        source=resolved,
        source_type="file",
        is_trusted=is_trusted,
        # read/ decides HTML-ness from the extension as well as the body, which
        # fetch/ cannot do. Pass the answer rather than let the pipeline guess.
        is_html=looks_like_html(content, resolved),
    )
    if mode == "block":
        enforce_block(verdict, resolved)

    pipeline_result = verdict.pipeline
    classification = verdict.classification
    trust_level = "trusted-sanitized" if is_trusted else "sanitized-only"

    emit_request_event(
        tool=f"{mode}_read",
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

    result: dict[str, Any] = {
        "content": pipeline_result.content,
        "trust": {
            "level": trust_level,
            "source": "layer1",
            "source_path": resolved,
        },
        "sanitization": _build_sanitization_metadata(pipeline_result),
    }

    # Only `warn` reaches here flagged; `block` raised. Also attached when
    # nothing flagged but something could not be READ.
    warning = build_warning(verdict)
    if warning is not None:
        result["_trentina_warning"] = warning
    return result


async def block_read(path: str) -> dict[str, Any]:
    """Fail closed: a flagged file raises and the agent never sees the bytes."""
    return await _read_judged(path, mode="block")


async def warn_read(path: str) -> dict[str, Any]:
    """Deliver the bytes that are on disk, with the verdict attached."""
    return await _read_judged(path, mode="warn")


async def safe_read(path: str) -> dict[str, Any]:
    """Deprecated spelling of `block_read`. Removed in 0.28.0."""
    return await block_read(path)


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

    is_trusted = config.is_trusted_path(resolved)

    verdict = await advise(
        content,
        source=resolved,
        source_type="file",
        is_trusted=is_trusted,
        is_html=looks_like_html(content, resolved),
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


async def clean_read(path: str, prompt: str) -> dict[str, Any]:
    """Hand back a Q-Agent extraction rather than the bytes on disk."""
    return await quarantine_read(path, prompt)
