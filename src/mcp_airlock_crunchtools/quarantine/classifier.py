"""Layer 2 — Prompt Guard 2 86M classifier via ONNX Runtime.

Embedded in-process inference. No sidecar, no HTTP API, no network calls.
Synchronous — ONNX inference is CPU-bound (<100ms), not I/O-bound.

The classifier sees sanitized content (post-Layer 1) on the input path,
and extracted text (post-Layer 3) on the output verification path.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from ..config import get_config

logger = logging.getLogger(__name__)

_session: Any | None = None
_tokenizer: Any = None
_loaded = False
_load_attempted = False


@dataclass
class ClassifierResult:
    """Result from the Prompt Guard 2 classifier."""

    label: str  # "BENIGN" or "MALICIOUS"
    score: float  # confidence score (0.0-1.0)
    latency_ms: float  # inference time


def is_classifier_available() -> bool:
    """Check if the ONNX model is loaded and ready. Lazy-loads on first call."""
    global _session, _tokenizer, _loaded, _load_attempted

    if _loaded:
        return True
    if _load_attempted:
        return False

    _load_attempted = True

    config = get_config()
    model_path = config.classifier_model_path

    try:
        import onnxruntime as ort
        from transformers import AutoTokenizer
    except ImportError:
        logger.warning("onnxruntime or transformers not installed — classifier unavailable")
        return False

    try:
        model_file = f"{model_path}/model.onnx"
        _tokenizer = AutoTokenizer.from_pretrained(model_path)
        _session = ort.InferenceSession(
            model_file,
            providers=["CPUExecutionProvider"],
        )
        _loaded = True
        logger.info("Layer 2 classifier loaded from %s", model_path)
    except Exception:
        logger.warning("Failed to load classifier model from %s", model_path, exc_info=True)
        return False

    return True


def _classify_segment(input_ids: list[int], attention_mask: list[int]) -> tuple[str, float]:
    """Classify a single segment. Returns (label, malicious_score)."""
    import numpy as np

    inputs = {
        "input_ids": np.array([input_ids], dtype=np.int64),
        "attention_mask": np.array([attention_mask], dtype=np.int64),
    }

    assert _session is not None  # guaranteed by is_classifier_available() check
    outputs = _session.run(None, inputs)
    logits = outputs[0][0]

    exp_logits = np.exp(logits - np.max(logits))
    probs = exp_logits / exp_logits.sum()

    malicious_score = float(probs[1] + probs[2]) if len(probs) > 2 else float(probs[1])
    label = "MALICIOUS" if malicious_score >= get_config().classifier_threshold else "BENIGN"

    return label, malicious_score


def classify(text: str) -> ClassifierResult | None:
    """Run Layer 2 classifier on text.

    Returns ClassifierResult, or None if the model is not available.
    Synchronous — ONNX Runtime inference is CPU-bound, not I/O-bound.

    For text longer than 512 tokens, splits into overlapping segments
    (stride=256) and returns the highest malicious score.
    """
    if not is_classifier_available():
        return None

    start = time.monotonic()

    max_length = 512
    stride = 256

    encoding = _tokenizer(
        text,
        truncation=False,
        add_special_tokens=False,
        return_attention_mask=False,
    )
    all_ids: list[int] = encoding["input_ids"]

    if len(all_ids) <= max_length:
        enc = _tokenizer(
            text,
            truncation=True,
            max_length=max_length,
            padding="max_length",
            return_attention_mask=True,
        )
        label, score = _classify_segment(enc["input_ids"], enc["attention_mask"])
    else:
        best_label = "BENIGN"
        best_score = 0.0

        for start_idx in range(0, len(all_ids), stride):
            segment_ids = all_ids[start_idx : start_idx + max_length]
            if not segment_ids:
                break

            segment_text = _tokenizer.decode(segment_ids, skip_special_tokens=True)
            enc = _tokenizer(
                segment_text,
                truncation=True,
                max_length=max_length,
                padding="max_length",
                return_attention_mask=True,
            )
            seg_label, seg_score = _classify_segment(enc["input_ids"], enc["attention_mask"])

            if seg_score > best_score:
                best_score = seg_score
                best_label = seg_label

            if start_idx + max_length >= len(all_ids):
                break

        label = best_label
        score = best_score

    elapsed_ms = (time.monotonic() - start) * 1000

    return ClassifierResult(label=label, score=score, latency_ms=round(elapsed_ms, 2))


def reset_classifier() -> None:
    """Reset classifier state. For testing only."""
    global _session, _tokenizer, _loaded, _load_attempted
    _session = None
    _tokenizer = None
    _loaded = False
    _load_attempted = False
