"""L1: the deterministic layer, and the one that builds the scan view.

Seven stages, no model, no network. What they produce is a normalized COPY
for L2 and L3 to read — the scan view — while the delivered bytes stay
whatever the call site decided to deliver. Scan-differs-from-deliver is what
this layer has always done, which is why `preprocess/` is allowed to do it
too (see `preprocess/base.py`, invariant 2).

Called `sanitize/` until 0.24.0. The word claimed the layer made content
safe; it does not, and cannot. It normalizes a copy so the layers that
judge have something stable to judge, and it counts what it found.
"""

from __future__ import annotations

from .pipeline import (
    PipelineResult,
    PipelineStats,
    build_scan_view,
    build_scan_view_from_html,
    risk_level_for_count,
)

__all__ = [
    "PipelineResult",
    "PipelineStats",
    "build_scan_view",
    "build_scan_view_from_html",
    "risk_level_for_count",
]
