"""Structured — FREE reduction for JSON-shaped tool output.

Output is COMPACT JSON (0.38.0): no indentation, no space after separators.
It re-serialized with ``indent=2`` until then, which is easier on a human and
costs an agent tokens for whitespace it never reads. Compaction alone is now
a reason to apply: a pretty-printed payload with nothing to collapse still
comes out smaller, and still parses to the same document.

Phase 2 of the reduction plan. The sidecar's two dominant decline reasons,
``too_few_lines`` and ``reduction_below_floor``, both say the same thing:
the comparable UNIT is not a line. A Jira search result is one enormous
line, or forty pretty-printed ones that share no repetition petit can see,
and either way petit correctly declines.

So apply petit's idea at the right altitude. Where petit fingerprints a
line, this fingerprints an ARRAY ELEMENT: serialize it, normalize the
tokens that cannot carry meaning, group identical fingerprints, keep the
first few real elements of each group, and account for the rest.

Why fingerprinting and not key-sets. The obvious move — collapse array
elements that share a key-set — is both too aggressive and useless: forty
Jira issues all have the same keys, so a search for forty issues would
deliver three. Fingerprinting the normalized VALUES keeps forty genuinely
different issues distinct (different summaries are different words) while
forty near-identical status rows collapse to one group. The rule from
petit's ``strict.stopwords`` applies: words are never normalized, so an
element carrying a semantic payload keeps its own fingerprint and reaches
the perimeter scan.

What it deletes, it deletes. Elements past the sample budget are dropped,
not summarized, so colliding a payload into a group achieves only its
deletion. The same caveat as petit applies and is worth restating: an
attacker who controls the ORDER of an array can push a victim element past
the sample budget, so this defends against smuggling, not against
suppression by someone who already controls the payload's position. The
count marker still shows the elements existed, and every marker this module
writes is in-band and therefore spoofable — consumers must treat reduced
output as untrusted, which the perimeter already assumes.

Output is always valid JSON. A reducer that emits something a caller cannot
parse has moved the cost rather than removed it.

The truncation cap. ``_MAX_STRING_CHARS`` is a PROSE policy and nothing
else. Record-shaped payloads reduce identically at every setting, because
their win comes from grouping elements rather than clipping values — a
200-issue Jira search measures 1.7% whether the cap is 2,000 or 200,000.
What it decides is how hard an article body or a base64 blob is amputated.
20,000 chars is about 5,000 tokens: above stack traces, embedded documents
and the fields that make tool output pathological, but high enough that
clipping a long article is a trim rather than an amputation. Measured on a
29k-char feed entry, 2,000 delivers 7% of it, 8,000 delivers 28%, 20,000
delivers 68%, and 50,000 declines to touch it. Going lower buys real bytes
and costs the agent the document it asked for — that trade is phase 4's
open question about METERED summarize, and belongs in a decision with
numbers attached rather than in a constant chosen quietly here.

Hostile-input hardening: parsing is bounded by ``_MAX_PARSE_BYTES``, the
walk is depth-limited, and fingerprinting reads at most
``_FINGERPRINT_MAX_CHARS`` per element, so neither deep nesting nor one
enormous value can buy unbounded work. ``json.loads`` is synchronous and
``_reduce`` is a plain walk, so both run on a worker thread — a large
payload must not stall the gateway's event loop.
"""

from __future__ import annotations

import asyncio
import json
from functools import partial
from typing import Any

from petit.Filter import Filter

from ..channels import Channel, Kind
from .base import Cost, PreProcessContext, PreProcessResult

# The normalization policy, loaded from petit rather than restated here — the
# same file its JSON and mail drivers declare, so this fingerprint and petit's
# are normalized by one table. It replaced a local copy (`volatile.py`) whose
# only possible future was drifting into a second, weaker rule, and it is
# stricter: `<N>` is `(?<![\w-])\d+(?![\w-])`, leaving a digit inside a word
# alone, so `PROJ-1234`/`PROJ-1235` stay distinct. Reduces less; deletes
# nothing real. Module-level because constructing it reads a packaged data
# file and this is the gateway's hot path.
_SCRUB = Filter("strict.stopwords")

# Past this, do not even parse. QUARANTINE_MAX_CONTENT caps what reaches
# the gateway; this is the reducer refusing to be the expensive step.
_MAX_PARSE_BYTES = 4_000_000

# Arrays shorter than this have nothing worth grouping.
_MIN_ARRAY_ITEMS = 8

# Real elements retained per fingerprint group.
_SAMPLES_PER_GROUP = 3

# A string value longer than this is truncated. See "The truncation cap"
# above: this is a prose policy and does not affect record-shaped payloads.
_MAX_STRING_CHARS = 20_000

# How deep to walk before leaving a subtree alone. Hostile JSON nests.
_MAX_DEPTH = 40

_FINGERPRINT_MAX_CHARS = 400

# There is no minimum saving. A reducer that declines a 5% win throws
# away 5%, and across a swarm of agents even 1% compounds. What remains
# is arithmetic rather than policy: the rewrite appends a summary block,
# so content with nothing to collapse can come out no smaller than it
# went in, and delivering that would cost bytes for nothing.

# Marker text. In-band and therefore spoofable, like petit's [petit] prefix.
_OMITTED = "[structured] {count} more element(s) with this shape omitted"
_TRUNCATED = "... [structured] {count} more character(s) truncated"


class _Reducer:
    """One walk over one document, accumulating what it removed.

    The counts are the walk's own state rather than an argument threaded
    through every level, because they are the walk's result as much as the
    reduced document is: the sidecar reports them and the apply/decline
    decision reads them.
    """

    def __init__(self, *, truncate: bool = False) -> None:
        # Long strings are clipped only when the payload is over the caller's
        # budget. Under it, the agent asked for the document and gets it.
        self.truncate = truncate
        self.groups_collapsed = 0
        self.elements_dropped = 0
        self.strings_truncated = 0
        self.chars_truncated = 0

    @property
    def changed(self) -> bool:
        return bool(self.elements_dropped or self.strings_truncated)

    def walk(self, node: Any, depth: int = 0) -> Any:
        """Reduce arrays and long strings, leaving everything else alone.

        Past ``_MAX_DEPTH`` the subtree comes back untouched. Declining to
        reduce is always safe; blowing the stack on attacker-chosen nesting
        is not.

        An array element's fingerprint is its JSON with keys sorted — so two
        objects written in different key orders are one shape, and an
        attacker cannot multiply an array's delivered size by shuffling keys
        — and with volatile tokens normalized, which leaves every word
        intact. Order is preserved: kept elements come back where they were
        and each group's omission marker is appended once at the end.
        """
        if depth >= _MAX_DEPTH or not isinstance(node, (str, list, dict)):
            return node

        if isinstance(node, str):
            if not self.truncate or len(node) <= _MAX_STRING_CHARS:
                return node
            removed = len(node) - _MAX_STRING_CHARS
            self.strings_truncated += 1
            self.chars_truncated += removed
            return node[:_MAX_STRING_CHARS] + _TRUNCATED.format(count=removed)

        if isinstance(node, dict):
            return {key: self.walk(value, depth + 1) for key, value in node.items()}

        if len(node) < _MIN_ARRAY_ITEMS:
            return [self.walk(item, depth + 1) for item in node]

        seen: dict[str, int] = {}
        kept: list[Any] = []
        dropped: dict[str, int] = {}

        for item in node:
            # Every item came out of json.loads, so it is serializable by
            # construction; there is no unserializable case to guard.
            text = json.dumps(item, sort_keys=True, ensure_ascii=False)
            fingerprint = _SCRUB.scrub(text[:_FINGERPRINT_MAX_CHARS])

            count = seen.get(fingerprint, 0) + 1
            seen[fingerprint] = count
            if count <= _SAMPLES_PER_GROUP:
                kept.append(self.walk(item, depth + 1))
            else:
                dropped[fingerprint] = dropped.get(fingerprint, 0) + 1

        if dropped:
            self.groups_collapsed += len(dropped)
            self.elements_dropped += sum(dropped.values())
            kept.extend(
                _OMITTED.format(count=count) for count in sorted(dropped.values(), reverse=True)
            )
        return kept


def _parse_and_reduce(payload: str, *, truncate: bool) -> tuple[str | None, _Reducer, str]:
    """Parse, reduce, re-serialize. Returns (text, reducer, decline_reason)."""
    reducer = _Reducer(truncate=truncate)
    try:
        document = json.loads(payload)
    except (ValueError, RecursionError):
        return None, reducer, "not_json"

    # A bare scalar is JSON but has nothing to reduce.
    if not isinstance(document, (list, dict)):
        return None, reducer, "not_json"

    try:
        reduced = reducer.walk(document)
    except RecursionError:
        return None, reducer, "too_deep"

    # Serializable by construction: everything in `reduced` came out of
    # json.loads or is a marker string this module wrote.
    text = json.dumps(reduced, separators=(",", ":"), ensure_ascii=False)
    if not reducer.changed and len(text.encode("utf-8")) >= len(payload.encode("utf-8")):
        return None, reducer, "nothing_repetitive"
    return text, reducer, ""


class StructuredProcessor:
    """FREE. Collapses repeated JSON elements, truncates long strings."""

    name = "structured"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, ctx: PreProcessContext) -> PreProcessResult:
        bytes_in = len(payload.encode("utf-8"))

        if bytes_in > _MAX_PARSE_BYTES:
            return PreProcessResult.declined(
                self.name,
                self.cost,
                payload,
                reason="too_large",
            )

        # Cheap gate before spending a parse: JSON documents worth reducing
        # start with a bracket.
        stripped = payload.lstrip()
        if not stripped or stripped[0] not in "[{":
            return PreProcessResult.declined(
                self.name,
                self.cost,
                payload,
                reason="not_json",
            )

        over_budget = ctx.target_bytes is not None and bytes_in > ctx.target_bytes
        text, reducer, reason = await asyncio.to_thread(
            partial(_parse_and_reduce, payload, truncate=over_budget)
        )
        if text is None:
            return PreProcessResult.declined(
                self.name,
                self.cost,
                payload,
                reason=reason,
            )

        bytes_out = len(text.encode("utf-8"))
        if bytes_in > 0 and bytes_out >= bytes_in:
            # See petit.py: the ratio is measured, so report it rather than
            # collapse every near-miss and every no-hoper into one word.
            return PreProcessResult.declined(
                self.name,
                self.cost,
                payload,
                reason="not_smaller",
                details={
                    "would_be_bytes": bytes_out,
                    "would_be_ratio": round(bytes_out / bytes_in, 4),
                    "groups_collapsed": reducer.groups_collapsed,
                    "elements_dropped": reducer.elements_dropped,
                },
            )

        return PreProcessResult(
            name=self.name,
            cost=self.cost,
            content=text,
            applied=True,
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            details={
                "groups_collapsed": reducer.groups_collapsed,
                "elements_dropped": reducer.elements_dropped,
                "strings_truncated": reducer.strings_truncated,
                "chars_truncated": reducer.chars_truncated,
            },
        )
