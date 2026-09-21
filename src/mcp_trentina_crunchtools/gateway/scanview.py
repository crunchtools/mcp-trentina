"""Extractor registry and the one place a scan view gets built.

Sibling of ``gateway/reduce.py``, which does the same job for pre-processors.
The two registries answer different questions — reduce asks "what can this
payload be shrunk to", this asks "what of this payload must be read" — and
they deliberately do not share a Protocol, for the reason spelled out in
``scanview/base.py``.

Channel locking lives here. An extractor declares which ingresses it
understands and selecting one it does not is a load-time error, not a runtime
surprise. That matters because the failure is silent otherwise: a Matrix
extractor pointed at alert-ingress JSON would find no Matrix event shape,
fall through to generic rules, and produce a perimeter nobody had checked
against that payload.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from ..scanview import (
    Channel,
    FullExtractor,
    GenericExtractor,
    ScanView,
    ScanViewContext,
    ScanViewExtractor,
)
from .errors import ProfileConfigError

if TYPE_CHECKING:
    from collections.abc import Callable

    from .profile import ScanViewConfig

logger = logging.getLogger(__name__)

# Factories, not the singletons gateway/reduce.py uses: an extractor may own
# per-profile state (the Matrix one will own a key cache), so one instance per
# configured profile rather than one per process.
_REGISTRY: dict[str, Callable[[ScanViewConfig], ScanViewExtractor]] = {
    "full": lambda _cfg: FullExtractor(),
    "generic": lambda cfg: GenericExtractor(skip_sample_bytes=cfg.skip_sample_bytes),
}


def build_extractor(
    cfg: ScanViewConfig | None, *, channel: Channel, profile_name: str = "",
) -> ScanViewExtractor:
    """Construct the configured extractor, or fail closed at config load.

    ``None`` means "no scan_view block", which is the same thing as the
    default: read everything.
    """
    from .profile import ScanViewConfig as _Cfg

    cfg = cfg or _Cfg()
    factory = _REGISTRY.get(cfg.extractor)
    if factory is None:  # pragma: no cover - the Literal makes this unreachable
        raise ProfileConfigError(
            f"Profile {profile_name!r}: unknown scan_view extractor "
            f"{cfg.extractor!r}; known: {sorted(_REGISTRY)}"
        )
    extractor = factory(cfg)
    if channel not in extractor.channels:
        raise ProfileConfigError(
            f"Profile {profile_name!r}: scan_view extractor "
            f"{cfg.extractor!r} is not valid on the {channel.value} channel "
            f"(valid: {sorted(c.value for c in extractor.channels)})"
        )
    return extractor


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
