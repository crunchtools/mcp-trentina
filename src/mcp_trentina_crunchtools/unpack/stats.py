"""The unpack stage's counts, carried in L1's ``PipelineStats`` (#367)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class UnpackStats:
    """What the unpack stage did to the text the layers read.

    Informational: none of these is evidence of an attack, so none feeds
    ``PipelineStats.suspicious_detections``. They reach L3's briefing so the
    judge knows that part of what it reads was decoded or labelled.
    """

    text_decoded: int = field(default=0)
    binary_labelled: int = field(default=0)
    binary_unread: int = field(default=0)
    archives_opened: int = field(default=0)
