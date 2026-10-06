"""Encoded payload detection — find base64/hex-encoded instruction injection."""

from __future__ import annotations

import base64
import binascii
import html
import re
import urllib.parse
from dataclasses import dataclass, field

_INSTRUCTION_PATTERN = re.compile(
    r"\b(ignore|forget|disregard|override|bypass|reveal|you are now|new instruction|"
    r"system prompt|execute|eval\s*\(|import\s*\(|require\s*\(|"
    r"api.?key|password|secret|curl\s|wget\s|rm\s+-|sudo\s)",
    re.IGNORECASE,
)

_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_PATTERN = re.compile(r"(?:0x|\\x)?([0-9a-f]{2}[\s,;]?){20,}", re.IGNORECASE)
# The subtype is bounded at RFC 6838's 127-character name limit. Unbounded,
# `[^;]*` ran to the end of the payload from every `data:text/`, so repeating
# that prefix made the scan quadratic: a 5 MB fetch held a worker for ~25 min
# (#295).
_DATA_URI_PATTERN = re.compile(r"data:text/[^;]{0,127};base64,([A-Za-z0-9+/=]+)", re.IGNORECASE)

# Decoded characters past which a base64 run is left undecoded. Was 500, with
# no recorded reason, and that made padding a free bypass: repeat an
# instruction until the blob clears ~700 encoded characters and it was never
# decoded, so never detected (#179). Decode and scan are linear and cost
# milliseconds at this size. The value was `QUARANTINE_MAX_CONTENT`'s default
# until that cap became a token count (#225). The cap stays as a backstop for
# callers that hand L1 content nothing upstream has bounded.
MAX_BASE64_DECODE_LENGTH = 100_000
BASE64_EXPANSION_RATIO = 1.4


@dataclass
class EncodedStats:
    """Counts of detected encoded payloads."""

    base64_payloads: int = field(default=0)
    hex_payloads: int = field(default=0)
    data_uris: int = field(default=0)
    escaped_payloads: int = field(default=0)


# Percent-encoding, backslash escapes and character references (#363). Each
# anchor is three ASCII LETTERS in a row written in the encoding. Nothing
# needs to encode a letter, so three together are someone hiding a word:
# `%20`, `\\x1b` and `&#8212;` are ordinary and are not letters.
_LETTER_HEX = r"(?:4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a])"
_LETTER_DEC = r"(?:6[5-9]|[78][0-9]|90|9[7-9]|1[01][0-9]|12[0-2])"
_ESCAPED_ANCHORS: tuple[re.Pattern[str], ...] = (
    re.compile(rf"(?:%{_LETTER_HEX}){{3}}", re.IGNORECASE),
    re.compile(rf"(?:\\x{_LETTER_HEX}|\\u00{_LETTER_HEX}){{3}}", re.IGNORECASE),
    re.compile(rf"(?:&#(?:x0{{0,2}}{_LETTER_HEX}|0{{0,2}}{_LETTER_DEC});){{3}}", re.IGNORECASE),
)
_BACKSLASH_UNIT = re.compile(r"\\x([0-9a-f]{2})|\\u([0-9a-f]{4})", re.IGNORECASE)


def _unescape(line: str) -> str:
    """``line`` with all three encodings undone, once each."""
    decoded = urllib.parse.unquote(line, errors="replace")
    decoded = _BACKSLASH_UNIT.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), decoded)
    return html.unescape(decoded)


def _escaped_payloads(text: str) -> int:
    """Lines whose escapes hide an instruction word.

    A line counts when it holds an anchor and decoding it yields MORE matches
    of ``_INSTRUCTION_PATTERN`` than the line had as written, so the word came
    out of the encoding. Each line is decoded at most once.
    """
    if not any(anchor.search(text) for anchor in _ESCAPED_ANCHORS):
        return 0
    found = 0
    for line in text.split("\n"):
        if not any(anchor.search(line) for anchor in _ESCAPED_ANCHORS):
            continue
        before = len(_INSTRUCTION_PATTERN.findall(line))
        if len(_INSTRUCTION_PATTERN.findall(_unescape(line))) > before:
            found += 1
    return found


def _decode_base64_safe(encoded: str) -> str | None:
    """Attempt to decode a base64 string, returning None on failure."""
    try:
        decoded_bytes = base64.b64decode(encoded, validate=True)
        return decoded_bytes.decode("utf-8", errors="strict")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


def _decode_hex_safe(encoded: str) -> str | None:
    """Attempt to decode a hex string, returning None on failure."""
    try:
        hex_clean = re.sub(r"[^0-9a-f]", "", encoded, flags=re.IGNORECASE)
        decoded_bytes = bytes.fromhex(hex_clean)
        return decoded_bytes.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None


def normalize_encoded(
    text: str,
    max_decode_length: int = MAX_BASE64_DECODE_LENGTH,
) -> tuple[str, EncodedStats]:
    """Detect and remove base64/hex-encoded instruction payloads."""
    stats = EncodedStats()
    cleaned = text

    def _replace_data_uri(_match: re.Match[str]) -> str:
        stats.data_uris += 1
        return "[data-uri-removed]"

    cleaned = _DATA_URI_PATTERN.sub(_replace_data_uri, cleaned)

    def _replace_base64(match: re.Match[str]) -> str:
        encoded_str = match.group(0)
        if len(encoded_str) > max_decode_length * BASE64_EXPANSION_RATIO:
            return encoded_str
        decoded = _decode_base64_safe(encoded_str)
        if decoded and _INSTRUCTION_PATTERN.search(decoded):
            stats.base64_payloads += 1
            return "[encoded-removed]"
        return encoded_str

    cleaned = _BASE64_PATTERN.sub(_replace_base64, cleaned)

    def _replace_hex(match: re.Match[str]) -> str:
        decoded = _decode_hex_safe(match.group(0))
        if decoded and _INSTRUCTION_PATTERN.search(decoded):
            stats.hex_payloads += 1
            return "[encoded-removed]"
        return match.group(0)

    cleaned = _HEX_PATTERN.sub(_replace_hex, cleaned)
    stats.escaped_payloads = _escaped_payloads(text)

    return cleaned, stats
