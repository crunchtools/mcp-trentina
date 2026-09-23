"""Scan-view extraction: a guard choosing what it reads.

Guard machinery, not a driver role of its own -- see ``base.py`` for why
"scans less than it delivers" is a guard's privilege and a pre-processor's
prohibition, and ``channels.py`` for the two roles.
"""

from ..channels import Channel
from ..jsonwalk import iter_leaves
from .base import (
    ScanView,
    ScanViewContext,
    ScanViewExtractor,
    SkipReason,
    UndecryptableEvent,
)
from .full import FullExtractor
from .generic import DEFAULT_SKIP_SAMPLE_BYTES, GenericExtractor
from .matrix import MatrixExtractor

__all__ = [
    "DEFAULT_SKIP_SAMPLE_BYTES",
    "Channel",
    "FullExtractor",
    "GenericExtractor",
    "MatrixExtractor",
    "ScanView",
    "ScanViewContext",
    "ScanViewExtractor",
    "SkipReason",
    "UndecryptableEvent",
    "iter_leaves",
]
