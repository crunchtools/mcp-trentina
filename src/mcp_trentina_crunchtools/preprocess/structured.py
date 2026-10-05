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

Identifier-varying records are LISTED, not sampled (#173). Records that
differ only in identifier-shaped values (``PROJ-1000``, ``"10234"``, a UUID,
an integer id) would otherwise each keep their own fingerprint and reduce by
nothing. petit's ``pull_identifiers`` masks those values; records whose
masked JSON is EXACTLY equal form a group, delivered as its first element
verbatim and one marker listing every other element's values. Exact, not
scrubbed and not cut at ``_FINGERPRINT_MAX_CHARS``: the representative plus
the list reconstructs every record, so the group deletes nothing. A group
past ``_MAX_LISTED`` opens a new group rather than dropping the rest.
Integers are not petit's to pull, so they are stringified first and the
group key records which fields were integers.

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
from dataclasses import dataclass, field
from functools import partial
from typing import Any, NamedTuple

from petit import pull_identifiers
from petit.Filter import Filter

from ..channels import Channel, Kind
from ..unpack.office import reduce_base64
from .base import Cost, PreProcessContext, PreProcessResult
from .pdf import reduce_base64 as reduce_pdf

# The normalization policy, loaded from petit rather than restated here — the
# same file its JSON and mail drivers declare, so this fingerprint and petit's
# are normalized by one table. It replaced a local copy (`volatile.py`) whose
# only possible future was drifting into a second, weaker rule, and it is
# stricter: `<N>` is `(?<![\w-])\d+(?![\w-])`, leaving a digit inside a word
# alone, so `PROJ-1234`/`PROJ-1235` stay distinct. Reduces less; deletes
# nothing real. Module-level because constructing it reads a packaged data
# file and this is the gateway's hot path.
_SCRUB = Filter("strict.stopwords")

# Past this, do not even parse. A parse guard, not a content policy: the
# token count at admission (#225) decides what is judged; this is the
# reducer refusing to be the expensive step on the way there.
_MAX_PARSE_BYTES = 4_000_000

# Arrays shorter than this have nothing worth grouping.
_MIN_ARRAY_ITEMS = 8

# Real elements retained per fingerprint group.
_SAMPLES_PER_GROUP = 3

# A string value longer than this is truncated. See "The truncation cap"
# above: this is a prose policy and does not affect record-shaped payloads.
_MAX_STRING_CHARS = 20_000

# How deep to walk before leaving a subtree alone. Hostile JSON nests.
_MAX_OFFICE_CHARS = 140_000
"""Base64 characters of an office file stage 1 will open: the unpack
stage's own token cap, so a file too big for the layers to read whole is
never reduced into something they can."""

_MAX_DEPTH = 40

_FINGERPRINT_MAX_CHARS = 400

# There is no minimum saving. A reducer that declines a 5% win throws
# away 5%, and across a swarm of agents even 1% compounds. What remains
# is arithmetic rather than policy: the rewrite appends a summary block,
# so content with nothing to collapse can come out no smaller than it
# went in, and delivering that would cost bytes for nothing.

# Elements one listing marker names before the next element of the group
# opens a new one. Bounds a marker, never what is delivered.
_MAX_LISTED = 100

# Marker text. In-band and therefore spoofable, like petit's [petit] prefix.
_OMITTED = "[structured] {count} more element(s) with this shape omitted"
_LISTED = "[structured] {count} more element(s) with this shape; {fields}: {rows}"
_IDENTICAL = "[structured] {count} more element(s) identical to the one above"


class _GroupKey(NamedTuple):
    """What an element must share with the others to be listed with them."""

    masked_json: str
    fields: tuple[str, ...]
    """Identifier pointers, as petit writes them."""
    int_pointers: frozenset[str]
    """Every pointer that held an integer, pulled or not."""


class _Pulled(NamedTuple):
    key: _GroupKey
    values: tuple[str, ...]


def _pointer_token(key: str) -> str:
    """RFC 6901 escaping, as petit writes its pointers."""
    return key.replace("~", "~0").replace("/", "~1")


def _stringify_ints(node: Any, pointer: str, depth: int, found: set[str]) -> Any:
    """``node`` with every integer (never a bool) as its decimal string.

    ``found`` collects the pointers that held one. Copy-on-write: a container
    is copied only once a child has changed, so a record without integers
    costs one walk and no allocation. Past ``_MAX_DEPTH`` the subtree comes
    back as it is.
    """
    if depth >= _MAX_DEPTH:
        return node
    if isinstance(node, int) and not isinstance(node, bool):
        found.add(pointer)
        return str(node)
    if not isinstance(node, (dict, list)):
        return node
    slots = node.items() if isinstance(node, dict) else enumerate(node)
    copied: Any = None
    for k, v in slots:
        new = _stringify_ints(v, f"{pointer}/{_pointer_token(str(k))}", depth + 1, found)
        if new is not v and copied is None:
            copied = dict(node) if isinstance(node, dict) else list(node)
        if copied is not None:
            copied[k] = new
    return node if copied is None else copied


def _identifiers(item: Any) -> _Pulled | None:
    """The element's listing key and its identifier values, or None.

    Tried with integers stringified first; if that finds nothing to pull, or
    too many fields for petit to take, again with integers left alone.
    """
    ints: set[str] = set()
    widened = _stringify_ints(item, "", 0, ints)
    masked, fields, values = pull_identifiers(widened) if ints else (item, (), ())
    if not fields:
        ints = set()
        masked, fields, values = pull_identifiers(item)
    if not fields:
        return None
    # Every integer's pointer, not only the pulled ones: `-1` stringified is
    # not an identifier, stays in the masked text as "-1", and must not
    # match a record whose "-1" was a string all along.
    text = json.dumps(masked, sort_keys=True, ensure_ascii=False)
    return _Pulled(_GroupKey(text, fields, frozenset(ints)), values)


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
        self.groups_listed = 0
        self.elements_listed = 0
        self.strings_truncated = 0
        self.chars_truncated = 0
        self.office_converted = 0
        self.office_hidden = 0
        self.pdf_converted = 0
        self.pdf_hidden = 0

    @property
    def changed(self) -> bool:
        return bool(
            self.elements_dropped
            or self.elements_listed
            or self.strings_truncated
            or self.office_converted
            or self.pdf_converted
        )

    def _document(self, node: str) -> dict[str, str] | None:
        """A base64 office file or PDF as its visible text (#368, #369).

        Both are reducer formats, as HTML is: the agent asked for a document
        and gets its text, at a fraction of the tokens. Text the file hides
        is dropped and counted, and L1 is handed the count.
        ``trentina_preprocess: false`` keeps the file itself.
        """
        office = reduce_base64(node, _MAX_OFFICE_CHARS)
        if office is not None:
            kind, markdown, hidden = office
            self.office_converted += 1
            self.office_hidden += hidden
            return {"format": kind, "as_markdown": markdown}
        pdf = reduce_pdf(node)
        if pdf is not None:
            self.pdf_converted += 1
            self.pdf_hidden += pdf[1]
            return {"format": "pdf", "as_markdown": pdf[0]}
        return None

    def _clipped(self, node: str) -> str:
        removed = len(node) - _MAX_STRING_CHARS
        self.strings_truncated += 1
        self.chars_truncated += removed
        return node[:_MAX_STRING_CHARS] + _TRUNCATED.format(count=removed)

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
            long = self.truncate and len(node) > _MAX_STRING_CHARS
            return self._document(node) or (self._clipped(node) if long else node)

        if isinstance(node, dict):
            return {key: self.walk(value, depth + 1) for key, value in node.items()}

        if len(node) < _MIN_ARRAY_ITEMS:
            return [self.walk(item, depth + 1) for item in node]
        return self._reduce_array(node, depth)

    def _reduce_array(self, node: list[Any], depth: int) -> list[Any]:
        """Listing groups first, then sample-and-count for everything else."""
        lister = _Lister(node)
        seen: dict[str, int] = {}
        kept: list[Any] = []
        dropped: dict[str, int] = {}

        for item, found in zip(node, lister.pulled, strict=True):
            if lister.take(found):
                continue
            if found is not None and lister.opens(found):
                # Verbatim, not walked: the marker below reconstructs the
                # group from exactly this record.
                kept.append(item)
                lister.open(found, kept)
                continue

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

        kept = lister.finish(kept)
        self.groups_listed += lister.groups
        self.elements_listed += lister.elements
        if dropped:
            self.groups_collapsed += len(dropped)
            self.elements_dropped += sum(dropped.values())
            kept.extend(
                _OMITTED.format(count=count) for count in sorted(dropped.values(), reverse=True)
            )
        return kept


@dataclass
class _Listing:
    """One open group: where its marker goes, the first element's values, the rest's."""

    slot: int
    fields: tuple[str, ...]
    first: tuple[str, ...]
    rows: list[tuple[str, ...]] = field(default_factory=list)

    def marker(self) -> str:
        """Fields constant across the group are named by the element above
        the marker, so only the varying ones are listed."""
        varying = [
            i for i in range(len(self.fields)) if any(r[i] != self.first[i] for r in self.rows)
        ]
        if not varying:
            return _IDENTICAL.format(count=len(self.rows))
        return _LISTED.format(
            count=len(self.rows),
            fields=" ".join(self.fields[i] for i in varying),
            rows=", ".join(" ".join(row[i] for i in varying) for row in self.rows),
        )


class _Lister:
    """The identifier groups of one array (#173).

    An element joins a group only when at least one other element shares its
    key, and a group's marker takes at most ``_MAX_LISTED`` rows; the next
    member after that is delivered verbatim and opens a fresh marker.
    """

    def __init__(self, node: list[Any]) -> None:
        self.pulled = [_identifiers(item) for item in node]
        self._sizes: dict[_GroupKey, int] = {}
        for found in self.pulled:
            if found is not None:
                self._sizes[found.key] = self._sizes.get(found.key, 0) + 1
        self._open: dict[_GroupKey, _Listing] = {}
        self._all: list[_Listing] = []
        self.groups = 0
        self.elements = 0

    def take(self, found: _Pulled | None) -> bool:
        """List the element in its open group, if it has one with room."""
        if found is None:
            return False
        listing = self._open.get(found.key)
        if listing is None or len(listing.rows) >= _MAX_LISTED:
            return False
        listing.rows.append(found.values)
        return True

    def opens(self, found: _Pulled) -> bool:
        """Whether another element of the array shares this element's key."""
        return self._sizes[found.key] > 1

    def open(self, found: _Pulled, kept: list[Any]) -> None:
        """The element just appended to ``kept`` starts a group; reserve its marker."""
        kept.append(None)
        listing = _Listing(len(kept) - 1, found.key.fields, found.values)
        self._open[found.key] = listing
        self._all.append(listing)

    def finish(self, kept: list[Any]) -> list[Any]:
        """Fill each reserved slot with its marker, or remove it if nothing joined."""
        empty = set()
        for listing in self._all:
            if listing.rows:
                kept[listing.slot] = listing.marker()
                self.groups += 1
                self.elements += len(listing.rows)
            else:
                empty.add(listing.slot)
        return [k for i, k in enumerate(kept) if i not in empty]


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
                "groups_listed": reducer.groups_listed,
                "elements_listed": reducer.elements_listed,
                "strings_truncated": reducer.strings_truncated,
                "chars_truncated": reducer.chars_truncated,
                "office_converted": reducer.office_converted,
                "office_hidden": reducer.office_hidden,
                "pdf_converted": reducer.pdf_converted,
                "pdf_hidden": reducer.pdf_hidden,
            },
        )
