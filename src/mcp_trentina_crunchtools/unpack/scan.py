"""Decode what decodes to text, label what does not (#367).

One pass over the text, linear in its length. A token qualifies only when
decoding it is exact: strict base64 whose re-encoding reproduces it, or hex.
Anything a lenient decoder would read differently (URL-safe characters,
missing padding, junk after ``=``) is left as it arrived, so the layers and
the agent's own tools can never disagree about what it says.

What becomes of a token:

* **It decodes to text:** the layers read the text in its place, unmarked,
  and it is unpacked again, to ``MAX_DEPTH`` levels. There is no length
  floor, because ``cm0gLXJmIH4=`` is ``rm -rf ~``, and hex is decoded at any
  length too. English words that happen to be valid base64 (``findings``,
  ``annotate``) decode to bytes that fail ``_as_text``, and are left alone.
* **It decodes to binary of ``LABEL_FLOOR`` characters or more:** the
  layers read a label in its place, ``(image/png, 1.1 KB, not read)``. An
  image, PDF or archive is always labelled, and that label is the
  ``binary_unread`` refusal. Anything else is labelled only when its own
  characters read as noise (``_reads_as_noise``): otherwise an instruction
  written without spaces could hide behind a label. Measured with the default L2
  (``benchmarks/l2_blob_length.py``), blobs from 64 characters up are where
  L2 starts reacting: a 64-character integrity hash scored 0.92, an SSH
  public key 0.99. A 44-character key in a config scored 0.47.
* **Anything else stays verbatim:** short binary, hex digests up to SHA-512's
  128 characters, and runs that decode to binary but read like words, such
  as a URL path or a run of ``x``.

Why decoded text carries no marker: any bracketed note in front of it, such
as ``[base64 → text]``, made L2 flag 4 to 8 of the 14 benign corpus texts,
against 1 without one (docs/benchmark.md). L3 learns what was decoded from
its briefing, which names the counts. Labels for binary measured at L2's
baseline in parentheses.

A data URI is labelled whole, so the layers read its type rather than its
payload, and ``data:image/...`` stops looking like an exfiltration URL to L1.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import string
from collections import Counter
from dataclasses import dataclass, field

from .signatures import OPAQUE, Kind, from_media_type, identify
from .stats import UnpackStats

LABEL_FLOOR = 64
"""Base64 characters from which binary is labelled. Measured; see the module docstring."""

MIN_TOKEN = 8
"""Shorter tokens are never decoded: ``rm -rf`` needs eight characters."""

MAX_DEPTH = 2
"""Levels of decoding: base64 of base64 is read, a third layer is left."""

MAX_TOKEN = 140_000
"""Characters past which a token is left encoded. L1's decode cap
(``l1/encoded.py``), and above what admission lets through anyway."""

HEX_DIGEST_MAX = 128
"""Hex runs up to SHA-512's length that do not decode to text are digests,
identifiers read as they are. Hex that decodes to text is decoded at any
length."""

TINY_IMAGE_PIXELS = 4
"""An image whose header says it is at most this many pixels a side cannot
draw a letter or a QR code (21 modules a side at the least), so it counts as
read: tracking pixels and spacers. Byte size is no guide; a QR code PNG is a
couple of hundred bytes."""

_TOKEN = re.compile(
    r"(?P<uri>data:(?P<type>[a-z0-9.+-]{1,127}/[a-z0-9.+-]{1,127})"
    r"(?:;[a-z0-9=.+-]{1,64}){0,4};base64,(?P<payload>[A-Za-z0-9+/]*={0,2}))"
    r"|(?P<run>[A-Za-z0-9+/_-]+={0,2})",
    re.IGNORECASE,
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_HEX = re.compile(r"[0-9a-fA-F]+")
_PLAIN = frozenset(string.printable) - frozenset("\r\x0b\x0c")
SHORT_TEXT = 32
"""Decodings shorter than this must read as plain text, not merely as UTF-8."""


HEAD = 4096
"""Characters of an oversized token decoded to find its signature."""


@dataclass(frozen=True)
class Unpacked:
    """What the layers read, and what they could not.

    Attributes:
        text: The delivery with every packed part unpacked. The same object
            as the input when nothing qualified.
        stats: Counts for L3's briefing.
        unread: Kinds of binary an agent's tools could open and no layer
            read, sorted and distinct. Non-empty is the ``binary_unread`` gap.
    """

    text: str
    stats: UnpackStats
    unread: tuple[str, ...]


@dataclass
class _Pass:
    stats: UnpackStats = field(default_factory=UnpackStats)
    unread: set[str] = field(default_factory=set)


def unpack(text: str) -> Unpacked:
    """Build what the layers read from ``text``. Pure; never raises on content."""
    # TRUST: decoding a payload's encodings before any layer has judged it
    #   untrusted: all of `text`, chosen by whoever wrote the payload
    #   judged-by: L1, L2 and L3 read what this returns; the delivery is never replaced
    #   on-failure: fail-closed (binary no layer reads is the binary_unread gap); a
    #     token that does not decode strictly is read as it arrived
    #   owner: unpack.scan.unpack
    #   evidence: T1 b64decode(validate=True) plus re-encode equality; T1 `re` with no
    #     ambiguous repeat; T4 tests/test_unpack.py linearity; T3 Layer contract rule 1
    state = _Pass()
    out = _unpack(text, 0, state)
    return Unpacked(text=out, stats=state.stats, unread=tuple(sorted(state.unread)))


def _unpack(text: str, depth: int, state: _Pass) -> str:
    changed = False
    pieces: list[str] = []
    last = 0
    for match in _TOKEN.finditer(text):
        if match["uri"] is not None:
            replacement = _data_uri(match, depth, state)
        else:
            replacement = _run(match["run"], depth, state)
        if replacement is not None:
            pieces.append(text[last : match.start()])
            pieces.append(replacement)
            last = match.end()
            changed = True
    if not changed:
        return text
    pieces.append(text[last:])
    return "".join(pieces)


def _run(token: str, depth: int, state: _Pass) -> str | None:
    """The replacement for one run of base64 or hex characters, or None."""
    if len(token) > MAX_TOKEN:
        # Too long to decode whole, so identified from its head. Admission
        # refuses most of these on length, but flag reads an over-cap
        # payload's head, so an openable format is still counted unread.
        head = _strict_base64(token[:HEAD]) or b""
        kind = identify(head)
        return _label(kind, head, state, size=len(token) * 3 // 4) if kind.extractable else None
    if len(token) < MIN_TOKEN:
        return None
    if _HEX.fullmatch(token) and not len(token) % 2:
        unhexed = bytes.fromhex(token)
        if _as_text(unhexed) is None and len(token) <= HEX_DIGEST_MAX:
            return None  # a digest: an identifier, read as it is
        return _decoded(unhexed, token, depth, state)
    decoded = None if len(token) % 4 else _strict_base64(token)
    return None if decoded is None else _decoded(decoded, token, depth, state)


def _data_uri(match: re.Match[str], depth: int, state: _Pass) -> str | None:
    """A data URI, labelled or decoded whole, or None to leave it as it is."""
    media_type = match["type"].lower()
    payload = match["payload"]
    if len(payload) > MAX_TOKEN:
        head = _strict_base64(payload[:HEAD]) or b""
        kind = identify(head)
        kind = kind if kind is not OPAQUE else from_media_type(media_type)
        return _label(kind, head, state, size=len(payload) * 3 // 4) if kind.extractable else None
    decoded = _strict_base64(payload) if payload else None
    if decoded is None:
        return None
    # Text is text whatever the URI declares: application/javascript or
    # octet-stream can carry an instruction as well as text/plain can.
    text = _as_text(decoded)
    if text is not None:
        return _text(text, depth, state)
    kind = identify(decoded)
    return _label(kind if kind is not OPAQUE else from_media_type(media_type), decoded, state)


def _decoded(decoded: bytes, token: str, depth: int, state: _Pass) -> str | None:
    text = _as_text(decoded)
    if text is not None:
        return _text(text, depth, state)
    kind = identify(decoded, short=len(token) < LABEL_FLOOR)
    if kind.extractable:
        return _label(kind, decoded, state)  # an openable format at any size
    if len(token) < LABEL_FLOOR or not _reads_as_noise(token):
        return None
    # Readable strings inside the bytes are what a `strings` tool would show
    # an agent, so the layers read them too, bare after the label.
    inside = " ".join(run.decode("ascii") for run in _SENTENCE.findall(decoded) if b" " in run)
    label = _label(kind, decoded, state)
    return f"{label} {inside}" if inside else label


def _text(text: str, depth: int, state: _Pass) -> str:
    state.stats.text_decoded += 1
    return _unpack(text, depth + 1, state) if depth + 1 < MAX_DEPTH else text


def _label(kind: Kind, decoded: bytes, state: _Pass, *, size: int | None = None) -> str:
    state.stats.binary_labelled += 1
    unread = kind.extractable and not _too_small_to_draw(decoded)
    if unread:
        state.stats.binary_unread += 1
        state.unread.add(kind.name)
    tail = ", not read" if unread else ""
    return f"({kind.name}, {_size(len(decoded) if size is None else size)}{tail})"


def _too_small_to_draw(decoded: bytes) -> bool:
    """A PNG or GIF whose header gives both sides as ``TINY_IMAGE_PIXELS`` or less."""
    if decoded.startswith(b"\x89PNG\r\n\x1a\n") and decoded[12:16] == b"IHDR":
        width, height = int.from_bytes(decoded[16:20]), int.from_bytes(decoded[20:24])
    elif decoded[:6] in (b"GIF87a", b"GIF89a"):
        width = int.from_bytes(decoded[6:8], "little")
        height = int.from_bytes(decoded[8:10], "little")
    else:
        return False
    return 0 < width <= TINY_IMAGE_PIXELS and 0 < height <= TINY_IMAGE_PIXELS


def image_too_small_to_draw(encoded: str) -> bool:
    """An MCP image block whose header states 4 by 4 pixels or less (see ``_label``)."""
    decoded = _strict_base64(encoded) if len(encoded) <= MAX_TOKEN else None
    return decoded is not None and _too_small_to_draw(decoded)


def read_blob(blob: str) -> Unpacked | None:
    """What the layers read for an MCP resource blob, or None if they cannot.

    A blob is one base64 token, so it unpacks like one: to its text, to a
    label, or, when short, to itself. None for a blob that is not canonical
    base64 or is too long to decode: it cannot be identified, so the caller
    counts it as unread, never as harmless.
    """
    decoded = _strict_base64(blob) if len(blob) <= MAX_TOKEN else None
    if decoded is None:
        return None
    state = _Pass()
    text = _decoded(decoded, blob, 0, state)
    return Unpacked(
        text=blob if text is None else text, stats=state.stats, unread=tuple(sorted(state.unread))
    )


UNDECODABLE = Kind("undecodable blob", extractable=True)
"""A blob ``read_blob`` could not decode. Counted as unread."""

IMAGE_BLOCK = Kind("image", extractable=True)
"""An MCP image content block. Its declared ``mimeType`` is the backend's
text, so the label does not echo it."""


WINDOW = 64
"""Characters per window of the surface test, the label floor."""

MIN_ENTROPY = 4.8
"""Bits per character a window needs to read as random. Random base64
measured 4.91 at the least over 64 characters; spaceless English 4.72 at
the most (corpus payloads, camel-cased)."""

MAX_WORD_SHARE = 0.5
"""Share of a window in word-shaped letter runs past which it reads as
language. Random base64 measured 0.58 at the most, 0.36 at the 99th
percentile; spaceless English built from short words 0.58 at the least."""

_LETTER_RUN = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_SENTENCE = re.compile(rb"[\x20-\x7e]{12,}")
"""Printable ASCII runs in binary long enough to say something. Kept only
with a space in them: twelve random bytes are all printable about once in
150,000 tries, and nearly never hold a space as well."""
_VOWELS = frozenset("aeiouAEIOU")


def _reads_as_noise(token: str) -> bool:
    """Whether every window of the token's own characters reads as random.

    Asked before binary that an agent cannot open is labelled, since a label
    means no layer reads the token's characters. Decoding says nothing about
    the surface: ``MIIB`` followed by an instruction written without spaces
    decodes to a DER signature. An agent reads that surface, so it is
    labelled only when no window of it reads as language: each must have the
    entropy of random base64 and few word-shaped runs. Windows overlap by
    half, so a sentence hidden inside a random blob lands whole in one.
    """
    last = max(len(token) - WINDOW, 0)
    starts = [*range(0, last, WINDOW // 2), last]  # the last window ends at the end
    return all(_noise(token[i : i + WINDOW]) for i in starts)


def _noise(window: str) -> bool:
    counts = Counter(window).values()
    entropy = -sum(n / len(window) * math.log2(n / len(window)) for n in counts)
    worded = sum(len(run) for run in _LETTER_RUN.findall(window) if _word_shaped(run))
    return entropy >= MIN_ENTROPY and worded < MAX_WORD_SHARE * len(window)


def _word_shaped(run: str) -> bool:
    """Three letters or more, a vowel, and no four consonants together."""
    if len(run) < 3 or not _VOWELS.intersection(run):
        return False
    consonants = 0
    for letter in run:
        consonants = 0 if letter in _VOWELS else consonants + 1
        if consonants >= 4:
            return False
    return True


def _strict_base64(token: str) -> bytes | None:
    """Decode only canonical base64: what decodes must re-encode to ``token``."""
    if not _BASE64.fullmatch(token):
        return None
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if base64.b64encode(decoded).decode("ascii") == token else None


def _as_text(decoded: bytes) -> str | None:
    """``decoded`` as text when it reads as text, else None.

    Long decodings need 95% printable UTF-8. Short ones, where chance matters,
    must be plain printable ASCII, at least half letters, digits and spaces:
    without that, ordinary words that happen to be valid base64 ("findings",
    "annotate") decoded to garbage. Measured over every token in this
    repository's docs and source, the rule decodes only real base64, and
    accepts 37 in 20,000 random six-byte tokens.
    """
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not any(c.isalpha() for c in text):
        return None
    if len(text) < SHORT_TEXT:
        plain = all(c in _PLAIN for c in text)
        wordy = sum(c.isalnum() or c == " " for c in text) * 2 >= len(text)
        return text if plain and wordy else None
    printable = sum(c.isprintable() or c in "\n\r\t" for c in text)
    return text if printable >= 0.95 * len(text) else None


_UNITS = ((1024 * 1024, "MB"), (1024, "KB"))


def _size(n: int) -> str:
    return next((f"{n / scale:.1f} {unit}" for scale, unit in _UNITS if n >= scale), f"{n} B")
