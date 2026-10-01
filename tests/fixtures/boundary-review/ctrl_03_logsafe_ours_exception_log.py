"""Loading the L2 model at startup.

Runs once from the server lifespan, before any route is served, so no
request, caller or backend is in flight. The path is CLASSIFIER_MODEL_PATH,
which only the operator sets.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = "/models/prompt-guard-2-86m"


class ClassifierUnavailableError(RuntimeError):
    """L2 cannot run. With TRENTINA_REQUIRE_L2 (default true) block and redact refuse."""


def load_model() -> object:
    """Open the ONNX session, or raise ClassifierUnavailableError.

    The failure is logged in full because the operator needs onnxruntime's own
    words to fix a bad model directory, and every string in it is the server's:
    the operator's path and the library's message about files it shipped.
    """
    model_dir = Path(os.environ.get("CLASSIFIER_MODEL_PATH", DEFAULT_MODEL_PATH))
    try:
        import onnxruntime  # type: ignore[import-not-found]

        return onnxruntime.InferenceSession(str(model_dir / "model.onnx"))
    except Exception as exc:
        # logsafe: ours -- startup only, before any route is served; the message
        # names the operator's CLASSIFIER_MODEL_PATH and onnxruntime's own text.
        log.exception("classifier: could not load the L2 model at startup")
        raise ClassifierUnavailableError("L2 model failed to load") from exc
