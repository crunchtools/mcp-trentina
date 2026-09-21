"""Shape-based selection for any JSON payload.

Three mechanisms, in order of how much they save on a real Matrix sync:

1. STRUCTURAL SKIPPING (``shapes.classify_skip``) removes ciphertext,
   identifiers, enum constants and numbers — 53 KB of the measured 68 KB.
2. DEDUPLICATION removes repeats. 1,289 key names in that sync are about
   forty distinct strings; every distinct one is still scanned exactly once.
   A classifier learns nothing from the second ``"origin_server_ts"``, and
   nothing can hide in a duplicate, because hiding requires the string to be
   absent and it is not — it is right there, the first time.
3. SKIP SAMPLING puts the opening of every skipped string into one extra
   segment, so a payload hidden in a field the rules declined still gets its
   first bytes in front of L1 and L2. This is the backstop for the residual
   hole in ``shapes``: it does not depend on any of the shape rules being
   right, which is exactly what a backstop should not do.

The sample is deterministic — first N by document order, never random — so an
incident is reproducible from the payload alone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import Channel, ScanView, ScanViewContext, SkipReason
from .shapes import MIN_SKIP_LEN, classify_skip
from .walk import iter_leaves

if TYPE_CHECKING:
    from collections.abc import Iterable

DEFAULT_SKIP_SAMPLE_BYTES = 1024
"""Budget for the sampled-openings segment. Two L2 windows, near enough."""

_SAMPLE_HEAD_CHARS = 64
"""How much of each skipped string the sample carries."""


class GenericExtractor:
    """Scan what could be language; account for everything else."""

    name = "generic"
    channels = frozenset({Channel.MATRIX, Channel.ALERT, Channel.TOOL})

    def __init__(self, *, skip_sample_bytes: int = DEFAULT_SKIP_SAMPLE_BYTES) -> None:
        self.skip_sample_bytes = skip_sample_bytes

    async def extract(self, payload: Any, _ctx: ScanViewContext) -> ScanView:
        return self.select(iter_leaves(payload))

    def select(
        self,
        leaves: Iterable[str],
        *,
        extra_segments: Iterable[str] = (),
        extra_skipped: dict[SkipReason, int] | None = None,
        encrypted_events: int = 0,
        decrypted_events: int = 0,
        undecryptable: tuple[Any, ...] = (),
        extractor_name: str | None = None,
    ) -> ScanView:
        """Apply the rules to an already-collected leaf list.

        Split out from ``extract`` so the Matrix extractor can hand its
        decrypted message bodies through the same rules rather than trusting
        them — a base64 blob pasted inside a decrypted message is still a
        base64 blob, and plaintext recovered from ciphertext is no more
        trustworthy than plaintext that arrived in the clear.
        """
        segments: list[str] = []
        skipped: dict[SkipReason, int] = dict(extra_skipped or {})
        seen: set[str] = set()
        sample_parts: list[str] = []
        sample_budget = self.skip_sample_bytes
        total = 0
        scanned = 0

        def bump(reason: SkipReason, n: int) -> None:
            skipped[reason] = skipped.get(reason, 0) + n

        for leaf in list(leaves) + list(extra_segments):
            total += len(leaf)

            if leaf in seen:
                bump(SkipReason.DUPLICATE, len(leaf))
                continue

            reason = classify_skip(leaf)
            if reason is None:
                seen.add(leaf)
                segments.append(leaf)
                scanned += len(leaf)
                continue

            bump(reason, len(leaf))
            seen.add(leaf)
            if sample_budget > 0 and len(leaf) >= MIN_SKIP_LEN:
                head = leaf[:_SAMPLE_HEAD_CHARS]
                sample_parts.append(head)
                sample_budget -= len(head)

        if sample_parts:
            # One segment, not many: the classifier pays per window, so
            # sampled openings are cheapest concatenated.
            sample = "\n".join(sample_parts)
            segments.append(sample)
            # Sampled characters were already counted under their skip
            # reason. Counting them as scanned too would break S3's identity,
            # and the honest reading is that they WERE skipped — the sample
            # is a probe, not coverage.

        return ScanView(
            extractor=extractor_name or self.name,
            segments=tuple(segments),
            chars_total=total,
            chars_scanned=scanned,
            skipped_chars=skipped,
            encrypted_events=encrypted_events,
            decrypted_events=decrypted_events,
            undecryptable=undecryptable,
            details={
                "distinct_leaves": len(seen),
                "sampled_openings": len(sample_parts),
            },
        )
