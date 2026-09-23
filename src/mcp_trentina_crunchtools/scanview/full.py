"""The extractor that scans everything — today's behaviour, named.

Making "no selection at all" a first-class registry entry rather than a
special case is what lets S5 be implemented as *fall back to this one*, makes
the config default (``extractor: full``) byte-identical to what shipped
before any of this, and means the fail-open path is the same code as the
default path instead of a branch nobody exercises.
"""

from __future__ import annotations

from typing import Any

from ..channels import Channel
from ..jsonwalk import iter_leaves
from .base import ScanView, ScanViewContext


class FullExtractor:
    """Scan every string leaf. No skipping, coverage always 1.0."""

    name = "full"
    channels = frozenset({Channel.MATRIX, Channel.ALERT, Channel.TOOL})

    async def extract(self, payload: Any, _ctx: ScanViewContext) -> ScanView:
        leaves = iter_leaves(payload)
        total = sum(len(leaf) for leaf in leaves)
        return ScanView(
            extractor=self.name,
            segments=tuple(leaves),
            chars_total=total,
            chars_scanned=total,
            skipped_chars={},
            details={"leaves": len(leaves)},
        )
