"""L1: the deterministic layer, and the one that builds the L2 input.

Deterministic stages, no model, no network. What they produce is a normalized COPY
for L2 to read — ``l2_input`` — while the delivered bytes stay
whatever the call site decided to deliver. Scan-differs-from-deliver is what
this layer has always done, which is why `preprocess/` is allowed to do it
too (see `preprocess/base.py`, invariant 2).

Called `sanitize/` until 0.24.0. The word claimed the layer made content
safe; it does not, and cannot. It normalizes a copy so the layers that
judge have something stable to judge, and it counts what it found.
"""

from __future__ import annotations

from .hidden import HiddenStats, detect_hidden_markup
from .pipeline import (
    PipelineResult,
    PipelineStats,
    risk_level_for_count,
    run_l1,
)

__all__ = [
    "HiddenStats",
    "PipelineResult",
    "PipelineStats",
    "detect_hidden_markup",
    "risk_level_for_count",
    "run_l1",
]
