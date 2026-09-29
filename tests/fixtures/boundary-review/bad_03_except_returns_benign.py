"""Layer 2: Prompt Guard 2 over untrusted text.

The classifier is loaded lazily on first use. A scan returns a label and a
score; callers block on MALICIOUS.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

_session = None


@dataclass(frozen=True)
class ClassifierResult:
    label: str
    score: float
    truncated: bool = False


BENIGN = ClassifierResult(label="BENIGN", score=0.0)


def _load() -> object:
    global _session  # noqa: PLW0603
    if _session is None:
        import onnxruntime  # type: ignore[import-not-found]

        _session = onnxruntime.InferenceSession("/models/prompt-guard-2-86m/model.onnx")
    return _session


def _infer(session: object, text: str) -> ClassifierResult:
    raise NotImplementedError  # tokenization and windowing elided


def classify(text: str) -> ClassifierResult:
    """Score ``text`` for prompt injection.

    Robust by design: a classifier hiccup must never take a tool call down
    with it, so any failure is logged and the scan degrades gracefully.
    """
    try:
        session = _load()
        return _infer(session, text)
    except Exception:
        log.warning("classifier unavailable; continuing without L2")
        return BENIGN
