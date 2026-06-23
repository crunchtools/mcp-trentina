"""Encoded payload detection — find base64/hex-encoded instruction injection."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

_INSTRUCTION_PATTERN = re.compile(
    r"\b(ignore|forget|disregard|override|you are now|new instruction|"
    r"system prompt|execute|eval\s*\(|import\s*\(|require\s*\(|"
    r"api.?key|password|secret|curl\s|wget\s|rm\s+-|sudo\s)",
    re.IGNORECASE,
)

_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_PATTERN = re.compile(r"(?:0x|\\x)?([0-9a-f]{2}[\s,;]?){20,}", re.IGNORECASE)
_DATA_URI_PATTERN = re.compile(r"data:text/[^;]*;base64,([A-Za-z0-9+/=]+)", re.IGNORECASE)

MAX_BASE64_DECODE_LENGTH = 500
BASE64_EXPANSION_RATIO = 1.4


@dataclass
class EncodedStats:
    """Counts of detected encoded payloads."""

    base64_payloads: int = field(default=0)
    hex_payloads: int = field(default=0)
    data_uris: int = field(default=0)


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


def sanitize_encoded(
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

    return cleaned, stats
