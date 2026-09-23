"""The one place a scan view gets built and reported.

A guard read policy (``scanview/``) is selected by name in ``profiles.yaml``;
``gateway/drivers.py`` turns that name into an extractor and enforces the
channel lock. This module is the call site: run the extractor the profile
asked for, degrade to a full scan if it fails, and turn the coverage
accounting into the fields an operator reads.

Until issue #160 this file also held a second driver registry, a mirror of
the pre-processor one in ``reduce.py``. Two registries for two roles is how
the pre-processor table ended up with no channel lock at all; both tables now
live in ``drivers.py`` behind one mechanism and one parity test. The roles
stay distinct — a pre-processor may never scan less than it delivers, which
is exactly what an extractor does — and that distinction lives in the
Protocols, not in a duplicated lookup table.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ..scanview import FullExtractor, ScanView

if TYPE_CHECKING:
    from ..scanview import ScanViewContext, ScanViewExtractor
    from .profile import ScanViewConfig

logger = logging.getLogger(__name__)


async def build_scan_view(
    payload: Any,
    *,
    extractor: ScanViewExtractor,
    ctx: ScanViewContext,
) -> ScanView:
    """Run an extractor, degrading to a full scan if it fails.

    S5: the fallback is MORE scanning, never less. An extractor that raises
    has told us nothing about the payload, and the only honest response to
    knowing nothing is to read all of it.
    """
    try:
        return await extractor.extract(payload, ctx)
    except Exception:
        logger.exception(
            "scanview: extractor %r failed for %s — falling back to a full scan",
            extractor.name, ctx.path or ctx.source,
        )
        view = await FullExtractor().extract(payload, ctx)
        return ScanView(
            extractor=f"{extractor.name}->full",
            segments=view.segments,
            chars_total=view.chars_total,
            chars_scanned=view.chars_scanned,
            skipped_chars=view.skipped_chars,
            degraded=True,
            details={"fallback_from": extractor.name},
        )


def describe(view: ScanView, cfg: ScanViewConfig) -> dict[str, Any]:
    """The extractor's contribution to `_trentina_warning`.

    Only reports when there is something to report: a full scan that read
    everything adds nothing, so the annotation stays quiet on the common path
    and an operator who sees these fields knows they mean something.
    """
    extras: dict[str, Any] = {}
    if view.coverage < 1.0:
        extras["scan_coverage"] = round(view.coverage, 4)
        extras["chars_scanned"] = view.chars_scanned
        extras["chars_total"] = view.chars_total
        extras["scan_extractor"] = view.extractor
        extras["skipped"] = {r.value: n for r, n in view.skipped_chars.items() if n}
    if view.chars_total and view.coverage < cfg.min_coverage:
        extras["low_scan_coverage"] = True
    if view.degraded:
        extras["scan_degraded"] = True
    if view.undecryptable:
        extras["undecryptable_events"] = len(view.undecryptable)
    return extras
