"""Unicode — strip invisible chars, bidi overrides, NFKC normalize.

Stripping and counting are two different questions (#204). L1's normalized
copy loses every invisible character, so the later stages' patterns match
through them; no detector reads that copy (#359). The COUNT feeds risk, and
counting characters rather than attacks rated ordinary content critical: a
coloured container log carries an ESC per line, a document export writes each
soft return as ``\\x0b``, a newsletter pads its preheader with a hundred
ZWNJs, and every emoji carries a variation selector. So each class counts
only in the context an attack needs:

* A zero-width character counts **inside a Latin word**: ``ig\\u200bnore``,
  the token-splitting signature. Between emoji, in padding runs, or in the
  scripts that need ZWJ/ZWNJ to spell (Persian, the Indic scripts), it does
  not. A soft hyphen there is hyphenation and is not counted as one.
* A soft hyphen counts when it **spells a word out**, one between each pair
  of letters (``i\u00adg\u00adn\u00ado\u00adr\u00ade``): hyphenation breaks at syllables,
  never after every letter (#363).
* Fullwidth Latin counts as a **run of two or more words**. One fullwidth
  word is how CJK text writes an acronym or a product name; a sentence of
  them is Latin text dressed up (#363).
* A Cyrillic or Greek letter counts **inside a Latin word** when it is one a
  reader takes for a Latin letter (``p\\u0430ypal``) and every letter
  of the word is Latin or such a lookalike (UTS #39's mixed-script case).
  ``\u03bcm`` and ``\u0394T`` are neither: their Greek letters look like nothing
  Latin (#363).
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
    soft_hyphen_words: int = field(default=0)
    fullwidth_runs: int = field(default=0)
    mixed_script_words: int = field(default=0)


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
# Three letters with a soft hyphen after each of the first two. Hyphenation
# leaves at least two letters to a syllable, so it never writes this.
_SPELLED_SOFT_HYPHEN = re.compile("(?:[A-Za-z]\u00ad){2,}[A-Za-z]")
_FW = "\uff21-\uff3a\uff41-\uff5a"
# Two or more fullwidth words, split by a space or an ideographic space. The
# lookbehind starts a match at a word's first letter only: without it one
# enormous fullwidth word is rescanned from each of its letters.
_FULLWIDTH_RUN = re.compile(f"(?<![{_FW}])[{_FW}]{{2,}}(?:[ \u3000][{_FW}]{{2,}})+")
# Cyrillic and Greek letters a reader takes for a Latin one. Greek's
# scientific letters are absent on purpose.
_LOOKALIKES = (
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501\u04bb"
    "\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0406\u0408\u0405"
    "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7"
    "\u03bf\u03b9\u03ba\u03bd"
)
_WORD = f"A-Za-z{_LOOKALIKES}"
# A whole word of Latin letters and lookalikes holding at least one of each.
# `[^\W\d_]` is "a letter": the word must start and end at one, so a word with
# any other Cyrillic or Greek letter in it is that script's own and no match.
_MIXED_SCRIPT_WORD = re.compile(
    f"(?<![^\\W\\d_])(?=[{_WORD}]*[A-Za-z])(?=[{_WORD}]*[{_LOOKALIKES}])"
    f"[{_WORD}]{{2,}}(?![^\\W\\d_])"
)


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
    stats.soft_hyphen_words = len(_SPELLED_SOFT_HYPHEN.findall(text))
    stats.fullwidth_runs = len(_FULLWIDTH_RUN.findall(text))
    stats.mixed_script_words = len(_MIXED_SCRIPT_WORD.findall(text))

    cleaned = _INVISIBLE_CHARS.sub("", text)
    cleaned = _BIDI_CHARS.sub("", cleaned)
    cleaned = _VARIATION_SELECTORS.sub("", cleaned)
    cleaned = _UNICODE_TAGS.sub("", cleaned)
    cleaned = _CONTROL_CHARS.sub("", cleaned)

    cleaned = unicodedata.normalize("NFKC", cleaned)

    return cleaned, stats
