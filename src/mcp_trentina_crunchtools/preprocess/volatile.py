"""The normalization policy every pre-processor in this package shares.

The package's purest transformation: it rewrites tokens rather than removing
them, its size effect is incidental and runs both ways (``<TS>`` shrinks a
timestamp, ``<N>`` grows a digit), and its output is never delivered — it
feeds fingerprints. Reduction vocabulary has never described it.

One definition, because it is a security boundary and not a convenience.
The load-bearing rule: **normalize only tokens that cannot carry meaning to
a model** — digits, hex runs, IPs, UUIDs, timestamps. Never words.

Two artifacts that differ in a single word therefore have different
fingerprints and both survive, so a semantic payload buried in boilerplate
cannot be normalized into the boilerplate's group: it stays distinct and
reaches the perimeter scan. An attacker who crafts a payload to collide
with a boilerplate group achieves only its deletion — what a pre-processor
drops is never delivered, and a line that is never delivered injects nothing.

A second copy of these patterns, drifting from this one, would mean one
pre-processor quietly enforcing a weaker rule than the other. Import, never
duplicate.

Every pattern is linear-time: character classes and bounded repetition, no
nested quantifiers. An attacker choosing the input must not be able to buy
quadratic work.
"""

from __future__ import annotations

import re

# Order matters: specific shapes before the bare-number catch-all, so an ISO
# timestamp becomes one <TS> instead of six <N>s.
#
# Each replacement is distinct on purpose. Collapsing everything to one
# character would merge shapes that are not the same — something carrying a
# timestamp and something carrying a bare number in the same position — and
# would leave the summary saying only that something was normalized away.
VOLATILE: list[tuple[str, str]] = [
    # ISO 8601 / RFC 3339-ish timestamps, with optional fraction and zone.
    (
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?",
        "<TS>",
    ),
    # Syslog-style: "Sep 13 04:22:01"
    (
        (
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,2}\d{1,2}"
            r"\s\d{2}:\d{2}:\d{2}\b"
        ),
        "<TS>",
    ),
    # Bare clock times.
    (r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?\b", "<TS>"),
    (
        (
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>"),
    # Long hex runs: hashes, addresses, ids. 8+ so ordinary words like
    # "deadbeef" pay the price but "cafe" and "added" do not.
    (r"\b(?:0x)?[0-9a-fA-F]{8,}\b", "<HEX>"),
    (r"\d+", "<N>"),
]

_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern), replacement) for pattern, replacement in VOLATILE
]


def normalize(text: str) -> str:
    """Replace volatile tokens, leaving every word intact.

    For callers that fingerprint in this process. ``petit.py`` hands the raw
    pattern list to the library instead, which applies the same rules in the
    same order — same policy, two consumers.
    """
    for pattern, replacement in _COMPILED:
        text = pattern.sub(replacement, text)
    return text
