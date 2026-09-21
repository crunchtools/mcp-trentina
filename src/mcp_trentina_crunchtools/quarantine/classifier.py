"""Layer 2 — Prompt Guard 2 86M classifier via ONNX Runtime.

Embedded in-process inference. No sidecar, no HTTP API, no network calls.
Synchronous — ONNX inference is CPU-bound (<100ms), not I/O-bound.

The classifier sees sanitized content (post-Layer 1) on the input path,
and extracted text (post-Layer 3) on the output verification path.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from ..config import get_config
from ..errors import UnscannableContentError

logger = logging.getLogger(__name__)

TELEMETRY_ENV = "ORT_DISABLE_TELEMETRY"
"""Turns off onnxruntime's telemetry, set below before onnxruntime loads.

onnxruntime's C++ init reads this, so it has to land before the lazy
``import onnxruntime`` in :func:`is_classifier_available` — hence module
scope. The Containerfile sets it too; this covers running outside the
container.

With telemetry live, importing onnxruntime reads /etc/machine-id, reads
/etc/os-release four times, reads /proc/cpuinfo, writes a debug log to
/tmp/mat-debug-1.log and creates a session file at /tmp/.ses. None of that
belongs in a process whose job is handling untrusted content. Disabling
leaves only the /sys/class/drm and /sys/class/accel probes onnxruntime
genuinely needs to choose an execution provider.

It is also a second line of defence against the import-time segfault the
Containerfile addresses: the machine-id read that trips a shell-less image
sits on this same telemetry path, so either mitigation alone prevents it.
"""

os.environ.setdefault(TELEMETRY_ENV, "1")

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
    truncated: bool = False  # content exceeded the token cap; scan is partial
    tokens: int = 0  # total tokens in the input, including any beyond the cap


def is_classifier_available() -> bool:
    """Check if the ONNX model is loaded and ready. Lazy-loads on first call.

    Thread count is pinned here: left at its default the CPU provider starts
    one intra-op thread per core and spin-waits on them, so a single long
    scan pegs every core and starves the gateway.
    """
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

        sess_options = ort.SessionOptions()
        threads = config.classifier_threads
        if threads > 0:
            sess_options.intra_op_num_threads = threads
            sess_options.inter_op_num_threads = 1

        _session = ort.InferenceSession(
            model_file,
            sess_options=sess_options,
            providers=["CPUExecutionProvider"],
        )
        _loaded = True
        logger.info("Layer 2 classifier loaded from %s", model_path)
    except Exception:
        logger.warning("Failed to load classifier model from %s", model_path, exc_info=True)
        return False

    return True


def _pad_segment(segment_ids: list[int], max_length: int) -> tuple[list[int], list[int]]:
    """Wrap token IDs in special tokens and pad to ``max_length``.

    Builds the model input straight from IDs the tokenizer already produced.
    The previous approach decoded each window back to text and re-tokenized
    it, which cost a second tokenizer pass per segment for a result that is
    identical on any real text — verified against the model's own tokenizer
    on prose, code, HTML, and non-Latin scripts.

    The two differ only on binary decoded as text, where the round trip
    silently dropped tokens (242 of 302 in testing) because U+FFFD runs do
    not survive decode and re-encode. Slicing keeps what the tokenizer
    actually produced, so the scan sees more of the input, not less.
    """
    ids = [_tokenizer.cls_token_id, *segment_ids, _tokenizer.sep_token_id]
    padding = max_length - len(ids)
    if padding <= 0:
        return ids[:max_length], [1] * max_length
    return ids + [_tokenizer.pad_token_id] * padding, [1] * len(ids) + [0] * padding


def _classify_segment(input_ids: list[int], attention_mask: list[int]) -> tuple[str, float]:
    """Classify a single segment. Returns (label, malicious_score)."""
    import numpy as np

    inputs = {
        "input_ids": np.array([input_ids], dtype=np.int64),
        "attention_mask": np.array([attention_mask], dtype=np.int64),
    }

    if _session is None:
        # is_classifier_available() guards every caller of this function, so
        # this should be unreachable -- fail loudly rather than silently
        # under python -O if that invariant ever breaks.
        raise RuntimeError("_classify_segment called without a loaded classifier session")
    outputs = _session.run(None, inputs)
    logits = outputs[0][0]

    exp_logits = np.exp(logits - np.max(logits))
    probs = exp_logits / exp_logits.sum()

    malicious_score = float(probs[1] + probs[2]) if len(probs) > 2 else float(probs[1])
    label = "MALICIOUS" if malicious_score >= get_config().classifier_threshold else "BENIGN"

    return label, malicious_score


WINDOW_TOKENS = 512
"""Prompt Guard 2's context window. max_position_embeddings is 512, so a
segment longer than this cannot be scanned in one pass."""

WINDOW_SPECIAL_TOKENS = 2
"""Special tokens the model wraps each window in (CLS ... SEP).

``classify()`` takes the real count from the tokenizer rather than this
constant, so a model that wraps differently stays correct. This is the value
the window geometry below is stated against, and a test pins the two together.
"""

WINDOW_CONTENT_TOKENS = WINDOW_TOKENS - WINDOW_SPECIAL_TOKENS
"""Content tokens one window actually carries.

The window is WINDOW_TOKENS wide, but the special tokens occupy two of those
slots, so only this many tokens of the input fit. The overlap below is the
guard band over CONTENT, which is the thing an injection is made of -- stating
it against WINDOW_TOKENS overstates it by WINDOW_SPECIAL_TOKENS.
"""

WINDOW_STRIDE = 446
"""How far the window advances, leaving a 64-token guard band of overlap.

Overlap exists so an injection straddling a window boundary still lands
intact inside at least one window. It only has to exceed the longest
injection we care about catching whole: the canonical forms
("ignore all previous instructions and ...") run 10-30 tokens, so 64 is a
comfortable margin.

This was stride=256 -- a 256-token guard band, which meant a 50% overlap
and ran the model over every token TWICE. On a 32,768-token scan that is
128 passes instead of 74, and at the measured 872 ms per pass on lotor it
cost roughly 47 seconds of pure duplicate work per scan. The Matrix proxy
scans every /sync response, so Kagetora paid it on every message and
Takeda could not finish an initial sync inside its 30 s budget at all
(RT #1460).
"""


def classify(
    text: str, *, fail_on_truncate: bool = False, source: str = "content"
) -> ClassifierResult | None:
    """Run Layer 2 classifier on text.

    Returns ClassifierResult, or None if the model is not available.
    Synchronous — ONNX Runtime inference is CPU-bound, not I/O-bound.
    Prefer :func:`classify_async` from async code so a long scan cannot
    block the event loop.

    For text longer than ``WINDOW_TOKENS``, splits into overlapping segments
    (advancing by ``WINDOW_STRIDE``, leaving a 64-token guard band) and
    returns the highest malicious score.  Scanning stops
    after ``CLASSIFIER_MAX_TOKENS`` tokens and the result is marked
    ``truncated``; callers must treat a truncated scan of an untrusted
    source as unscannable rather than clean.  Without that bound an 855 KB
    PDF decoded as text produced ~462k tokens and ~1,800 inference passes,
    which pegged every core for the better part of an hour.

    ``fail_on_truncate`` raises :class:`UnscannableContentError` as soon as
    the token count is known, before any inference runs.  A caller that
    will reject a truncated scan anyway gains nothing from the ~74 passes
    it would take to produce one, and letting them run hands an attacker a
    cheap way to burn two minutes of CPU per request.
    """
    if not is_classifier_available():
        return None

    start = time.monotonic()

    max_length = WINDOW_TOKENS
    stride = WINDOW_STRIDE

    encoding = _tokenizer(
        text,
        truncation=False,
        add_special_tokens=False,
        return_attention_mask=False,
    )
    all_ids: list[int] = encoding["input_ids"]

    total_tokens = len(all_ids)
    max_tokens = get_config().classifier_max_tokens
    truncated = max_tokens > 0 and total_tokens > max_tokens
    if truncated:
        if fail_on_truncate:
            raise UnscannableContentError(source, total_tokens, max_tokens)
        all_ids = all_ids[:max_tokens]

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

        # WINDOW_CONTENT_TOKENS states this; the tokenizer is the source of
        # truth so a model wrapping windows differently stays correct.
        content_length = max_length - _tokenizer.num_special_tokens_to_add()

        for start_idx in range(0, len(all_ids), stride):
            segment_ids = all_ids[start_idx : start_idx + content_length]
            if not segment_ids:
                break

            input_ids, attention_mask = _pad_segment(segment_ids, max_length)
            seg_label, seg_score = _classify_segment(input_ids, attention_mask)

            if seg_score > best_score:
                best_score = seg_score
                best_label = seg_label

            if start_idx + content_length >= len(all_ids):
                break

        label = best_label
        score = best_score

    elapsed_ms = (time.monotonic() - start) * 1000

    if truncated:
        logger.warning(
            "Layer 2 scan truncated: %d tokens exceeds cap of %d; "
            "scanned the first %d only",
            total_tokens,
            max_tokens,
            max_tokens,
        )

    return ClassifierResult(
        label=label,
        score=score,
        latency_ms=round(elapsed_ms, 2),
        truncated=truncated,
        tokens=total_tokens,
    )


async def classify_async(text: str) -> ClassifierResult | None:
    """Run :func:`classify` on a worker thread.

    Inference holds the GIL only inside ONNX Runtime's C++ kernels, so
    offloading keeps the asyncio event loop responsive while a scan runs.
    Every async caller should use this instead of calling classify directly.
    """
    return await asyncio.to_thread(classify, text)


def classifier_status() -> str:
    """Report load state without triggering the lazy load.

    Health probes must stay cheap; calling is_classifier_available() here
    would pull an 86M model off disk on the first request.
    """
    if _loaded:
        return "loaded"
    return "failed" if _load_attempted else "not-loaded"


def truncation_warning(scan: ClassifierResult | None) -> str | None:
    """Warning text when a scan covered only part of its input, else None.

    Used by the quarantine_* and scan_* tools, which surface risk to the
    caller rather than refusing outright.  The safe_* tools use
    :func:`classify_guarded` and fail closed instead.
    """
    if scan is None or not scan.truncated:
        return None

    return (
        f"Layer 2 scanned only the first {get_config().classifier_max_tokens} "
        f"of {scan.tokens} tokens. Anything past that point was not "
        "examined for injection."
    )


def join_warnings(*warnings: str | None) -> str | None:
    """Combine warning strings into one, dropping the empty ones."""
    present = [w for w in warnings if w]
    if not present:
        return None
    return " ".join(present)


async def classify_guarded(
    text: str, source: str, *, is_trusted: bool
) -> ClassifierResult | None:
    """Classify off-thread and fail closed when an untrusted scan is partial.

    Returning BENIGN on a truncated scan of untrusted content would hand an
    attacker a clean verdict for anything hidden past the token cap, so that
    case raises instead.  Trusted sources are allowed through with the
    ``truncated`` flag set for the caller to surface.

    Untrusted input bails at the token count rather than after the scan, so
    oversized content costs one tokenizer pass instead of ~74 inference
    passes for a verdict that was never going to be accepted.
    """
    return await asyncio.to_thread(
        classify, text, fail_on_truncate=not is_trusted, source=source
    )


def reset_classifier() -> None:
    """Reset classifier state. For testing only."""
    global _session, _tokenizer, _loaded, _load_attempted
    _session = None
    _tokenizer = None
    _loaded = False
    _load_attempted = False
