"""Petit — FREE log reduction: remove certainty, leave uncertainty.

After https://github.com/fatherlinux/petit. Repetitive machine output (a
syslog tail, a CI log, a Nagios burst) is mostly the same line wearing
different timestamps. Fingerprint each line by normalizing its volatile
tokens, group identical fingerprints, keep the first few real samples of
each group, and account for the rest.

The load-bearing rule: **normalize only tokens that cannot carry meaning to
a model** — digits, hex runs, IPs, UUIDs, timestamps. Never words. Two lines
that differ in a single word have different fingerprints and both survive,
so a semantic payload buried in 10,000 lines of boilerplate cannot be
normalized into the boilerplate's group: it stays its own line and reaches
the perimeter scan. Conversely, an attacker who crafts a payload to collide
with a boilerplate group achieves only its deletion — dropped lines are
never delivered, and a line that is never delivered injects nothing.

Honest scope (from the plan, deliberately): petit reduces log-shaped
content. It does ~nothing for prose, minified JS, base64 blobs, or extracted
PDF text, and it declines (applied=False) rather than pretend.

Hostile-input hardening: every regex here is linear-time (character classes
and bounded repetition, no nested quantifiers), and fingerprinting reads at
most ``_FINGERPRINT_MAX_CHARS`` of a line, so a single enormous line costs
O(cap) not O(line).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Cost, PreProcessContext, PreProcessResult

# Order matters: specific shapes before the bare-number catch-all, so an ISO
# timestamp becomes one <TS> instead of six <N>s.
_VOLATILE: list[tuple[re.Pattern[str], str]] = [
    # ISO 8601 / RFC 3339-ish timestamps, with optional fraction and zone.
    (
        re.compile(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"
        ),
        "<TS>",
    ),
    # Syslog-style: "Sep 13 04:22:01"
    (
        re.compile(
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,2}\d{1,2}"
            r"\s\d{2}:\d{2}:\d{2}\b"
        ),
        "<TS>",
    ),
    # Bare clock times.
    (re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?\b"), "<TS>"),
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    # Long hex runs: hashes, addresses, ids. 8+ so ordinary words like
    # "deadbeef" pay the price but "cafe" and "added" do not.
    (re.compile(r"\b(?:0x)?[0-9a-fA-F]{8,}\b"), "<HEX>"),
    (re.compile(r"\d+"), "<N>"),
]

_FINGERPRINT_MAX_CHARS = 400

# Below this many lines there is nothing worth grouping.
_MIN_LINES = 20

# Keep this many real sample lines per group.
_SAMPLES_PER_GROUP = 3

# Apply only if the reduced artifact is at most this fraction of the input;
# otherwise the reshuffling costs more clarity than it saves tokens.
_MIN_REDUCTION_RATIO = 0.7


def _fingerprint(line: str) -> str:
    fp = line[:_FINGERPRINT_MAX_CHARS]
    for pattern, placeholder in _VOLATILE:
        fp = pattern.sub(placeholder, fp)
    return fp


@dataclass
class _Group:
    fingerprint: str
    samples: list[str]
    count: int


class PetitProcessor:
    """FREE. Collapses repetitive lines, keeps samples, accounts for the rest."""

    name = "petit"
    cost = Cost.FREE

    async def run(
        self,
        payload: str,
        ctx: PreProcessContext,  # noqa: ARG002 - protocol signature; petit needs no context
    ) -> PreProcessResult:
        bytes_in = len(payload.encode("utf-8"))
        lines = payload.split("\n")

        if len(lines) < _MIN_LINES:
            return self._declined(payload, bytes_in, reason="too_few_lines")

        groups: dict[str, _Group] = {}
        out_lines: list[str] = []
        for line in lines:
            fp = _fingerprint(line)
            group = groups.get(fp)
            if group is None:
                group = _Group(fingerprint=fp, samples=[], count=0)
                groups[fp] = group
            group.count += 1
            if group.count <= _SAMPLES_PER_GROUP:
                group.samples.append(line)
                out_lines.append(line)

        collapsed_groups = [g for g in groups.values() if g.count > _SAMPLES_PER_GROUP]
        if not collapsed_groups:
            return self._declined(payload, bytes_in, reason="nothing_repetitive")

        summary = [
            "",
            (
                f"[petit] {len(lines)} lines reduced to {len(out_lines)}; "
                f"{len(collapsed_groups)} repetitive group(s) collapsed "
                f"(showing first {_SAMPLES_PER_GROUP} of each):"
            ),
        ]
        for group in sorted(collapsed_groups, key=lambda g: -g.count):
            summary.append(f"[petit]   {group.count}x: {group.fingerprint}")

        reduced = "\n".join(out_lines + summary)
        bytes_out = len(reduced.encode("utf-8"))

        if bytes_in > 0 and bytes_out / bytes_in > _MIN_REDUCTION_RATIO:
            return self._declined(payload, bytes_in, reason="reduction_below_floor")

        return PreProcessResult(
            name=self.name,
            cost=self.cost,
            content=reduced,
            applied=True,
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            details={
                "lines_in": len(lines),
                "lines_out": len(out_lines),
                "groups_collapsed": len(collapsed_groups),
            },
        )

    def _declined(self, payload: str, bytes_in: int, *, reason: str) -> PreProcessResult:
        return PreProcessResult(
            name=self.name,
            cost=self.cost,
            content=payload,
            applied=False,
            bytes_in=bytes_in,
            bytes_out=bytes_in,
            details={"declined": reason},
        )
