"""Unicode — strip invisible chars, bidi overrides, NFKC normalize.

Stripping and counting are two different questions (#204). The L2 copy loses
every invisible character, because any of them can split Prompt Guard's
tokens. The COUNT feeds risk, and counting characters rather than attacks
rated ordinary content critical: a coloured container log carries an ESC per
line, a document export writes each soft return as ``\\x0b``, a newsletter
pads its preheader with a hundred ZWNJs, and every emoji carries a variation
selector. So each class counts only in the context an attack needs:

* A zero-width character counts **inside a Latin word**: ``ig\\u200bnore``,
  the token-splitting signature. Between emoji, in padding runs, or in the
  scripts that need ZWJ/ZWNJ to spell (Persian, the Indic scripts), it does
  not. A soft hyphen is hyphenation and never counts.
* ``\\x0b`` and ``\\x0c`` are whitespace. A complete ANSI CSI or OSC escape is
  terminal formatting; a lone ESC still counts.
* A variation selector after a character is presentation. A RUN of them is
  how data is smuggled, and each one past the first counts.

Unicode tags and bidi overrides count wherever they are: neither has an
innocent use in the text an agent reads.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class UnicodeStats:
    """Counts of unicode characters in a context that signals an attack."""

    zero_width_chars: int = field(default=0)
    control_chars: int = field(default=0)
    bidi_overrides: int = field(default=0)
    unicode_tags: int = field(default=0)
    variation_selectors: int = field(default=0)


_INVISIBLE_CHARS = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\u2063\ufeff\u00ad]")
_BIDI_CHARS = re.compile("[\u202a-\u202e\u2066-\u2069]")
# Both blocks: VS1-16 and the supplementary VS17-256, which is where
# selector smuggling hides its bytes. The second block was not stripped at
# all before #204.
_VARIATION_SELECTORS = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]")
_UNICODE_TAGS = re.compile("[\U000e0001-\U000e007f]")
# The gaps are deliberate: \x09 (tab), \x0a (LF) and \x0d (CR) are the
# whitespace the document is MADE of, and stripping them corrupts the thing
# being cleaned — code blocks collapse onto one line and the L2 input stops
# resembling what the agent would have read. CodeQL reads the syntax and not
# the intent, so it flags this as `py/overly-large-range` (alert #2, dismissed
# as a false positive). Widening to \x00-\x1f to silence it breaks whitespace
# silently: nothing raises, the text just comes out wrong.
_CONTROL_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")

# A run of invisible characters with an ASCII letter on each side. ASCII,
# because the scripts where ZWJ and ZWNJ are orthography are not ASCII, and an
# injection aimed at an English-reading model splits English words. The soft
# hyphen belongs to the run, so `ig\u200b\u00adnore` is still one split word,
# but it is not counted: inside a word is exactly where hyphenation puts it.
_IN_WORD_INVISIBLE = re.compile(
    "(?<=[A-Za-z])[\u200b\u200c\u200d\u200e\u200f\u2060\u2063\ufeff\u00ad]+(?=[A-Za-z])"
)
# Counted as control characters: everything in _CONTROL_CHARS but the two
# whitespace characters, \x0b (vertical tab) and \x0c (form feed).
_COUNTED_CONTROL = re.compile("[\x00-\x08\x0e-\x1f]")
# A complete ANSI escape: CSI (`ESC [ params final`) or OSC (`ESC ] ... BEL`
# or `ESC ] ... ESC \\`). Each class is negated up to its own terminator, so
# a hostile run cannot make this backtrack.
_ANSI_ESCAPE = re.compile("\x1b\\[[0-?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)")
_SELECTOR_RUN = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,}")


_STRIPPED = re.compile(
    "|".join(
        p.pattern
        for p in (
            _INVISIBLE_CHARS,
            _BIDI_CHARS,
            _VARIATION_SELECTORS,
            _UNICODE_TAGS,
            _CONTROL_CHARS,
        )
    )
)


def strips_anything(text: str) -> bool:
    """Whether this stage removes anything from ``text``'s L2 copy, counted or not.

    The counts answer "is this an attack"; this answers "does L2 need to read
    the copy as well". They used to be the same question, and after #204 an
    uncounted ZWNJ between two words is still stripped — and still a token
    boundary Prompt Guard never saw.
    """
    return _STRIPPED.search(text) is not None


def normalize_unicode(text: str) -> tuple[str, UnicodeStats]:
    """Strip invisible unicode characters and normalize with NFKC."""
    stats = UnicodeStats()

    stats.zero_width_chars = sum(
        len(m.group(0).replace("\u00ad", "")) for m in _IN_WORD_INVISIBLE.finditer(text)
    )
    stats.bidi_overrides = len(_BIDI_CHARS.findall(text))
    stats.variation_selectors = sum(len(m.group(0)) - 1 for m in _SELECTOR_RUN.finditer(text))
    stats.unicode_tags = len(_UNICODE_TAGS.findall(text))
    stats.control_chars = len(_COUNTED_CONTROL.findall(_ANSI_ESCAPE.sub("", text)))

    cleaned = _INVISIBLE_CHARS.sub("", text)
    cleaned = _BIDI_CHARS.sub("", cleaned)
    cleaned = _VARIATION_SELECTORS.sub("", cleaned)
    cleaned = _UNICODE_TAGS.sub("", cleaned)
    cleaned = _CONTROL_CHARS.sub("", cleaned)

    cleaned = unicodedata.normalize("NFKC", cleaned)

    return cleaned, stats
