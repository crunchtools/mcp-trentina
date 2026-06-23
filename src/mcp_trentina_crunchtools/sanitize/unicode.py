"""Unicode sanitization — strip invisible chars, bidi overrides, NFKC normalize."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class UnicodeStats:
    """Counts of stripped unicode characters."""

    zero_width_chars: int = field(default=0)
    control_chars: int = field(default=0)
    bidi_overrides: int = field(default=0)
    unicode_tags: int = field(default=0)
    variation_selectors: int = field(default=0)


_INVISIBLE_CHARS = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\u2063\ufeff\u00ad]")
_BIDI_CHARS = re.compile("[\u202a-\u202e\u2066-\u2069]")
_VARIATION_SELECTORS = re.compile("[\ufe00-\ufe0f]")
_UNICODE_TAGS = re.compile("[\U000e0001-\U000e007f]")
_CONTROL_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sanitize_unicode(text: str) -> tuple[str, UnicodeStats]:
    """Strip invisible unicode characters and normalize with NFKC."""
    stats = UnicodeStats()

    stats.zero_width_chars = len(_INVISIBLE_CHARS.findall(text))
    stats.bidi_overrides = len(_BIDI_CHARS.findall(text))
    stats.variation_selectors = len(_VARIATION_SELECTORS.findall(text))
    stats.unicode_tags = len(_UNICODE_TAGS.findall(text))
    stats.control_chars = len(_CONTROL_CHARS.findall(text))

    cleaned = _INVISIBLE_CHARS.sub("", text)
    cleaned = _BIDI_CHARS.sub("", cleaned)
    cleaned = _VARIATION_SELECTORS.sub("", cleaned)
    cleaned = _UNICODE_TAGS.sub("", cleaned)
    cleaned = _CONTROL_CHARS.sub("", cleaned)

    cleaned = unicodedata.normalize("NFKC", cleaned)

    return cleaned, stats
