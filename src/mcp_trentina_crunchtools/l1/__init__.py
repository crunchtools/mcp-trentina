"""L1: the deterministic layer. It counts what it finds, by type.

Deterministic stages, no model, no network. L1 reads the arrived bytes, like
L2 and L3, and its counts reach L3's briefing by type
(``PipelineStats.findings``). Some stages undo obfuscation on a private copy
so their patterns can match; that copy, ``l2_input``, is read by no detector
(#359) and only by redact's extraction turn (#360).

Called `sanitize/` until 0.24.0. The word claimed the layer made content
safe; it does not, and cannot. It counts what it found.
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
