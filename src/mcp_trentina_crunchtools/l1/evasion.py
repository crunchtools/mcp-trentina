"""Evasion normalization for the directive stage: scrambles, typos, spacing.

An exact pattern is beaten by writing the same words slightly wrong. Three
tricks cover most of it, and OpenRouter's guardrail and the OWASP cheat sheet
catch all three:

* **Typoglycemia** — first and last letters fixed, middle shuffled
  (``ignroe``, ``bpyass``). A reader, human or model, still reads the word.
* **Misspelling** — one Damerau-Levenshtein edit (``1gnore``, ``revael``).
* **Character spacing** — ``i g n o r e  p r e v i o u s``.

None of these is a detection on its own. A typo is not an attack: ``sytsem is
down`` and ``"promt" should be "prompt"`` are ordinary text, and ``systemd`` is
one edit from ``system``. So this module only REWRITES a line toward what it
might have said, and the directive stage counts the line when the rewrite
matches an exact pattern that the original did not. A typo counts only inside
a phrase that would have been an injection spelled correctly.

The one exception is typoglycemia with company: two misspelled keywords on
one line, at least one of them scrambled (``ignroe all prevoius systme
instructions``).
A scramble is not a typing slip. Nobody shuffles the middle of a word by
accident, twice, next to the words an injection uses.
"""

from __future__ import annotations

import re
from functools import lru_cache

#: Words an injection phrase is built from. Corrections only ever produce one
#: of these, so a misspelling of anything else is left alone.
KEYWORDS = frozenset(
    {
        # verbs
        "ignore", "disregard", "forget", "delete", "bypass", "override",
        "skip", "reveal", "expose", "print", "output", "show", "display",
        "leak", "repeat", "disable",
        # qualifiers
        "previous", "prior", "above", "earlier", "initial", "safety",
        "security", "system", "internal", "core", "original", "hidden",
        "secret", "developer",
        # targets
        "instructions", "instruction", "rules", "rule", "guidelines",
        "guideline", "constraints", "directives", "prompt", "prompts",
        "filters", "measures", "restrictions",
    }
)  # fmt: skip

#: The typoglycemia targets OpenRouter and OWASP check.
SCRAMBLE_TARGETS = frozenset(
    {"ignore", "bypass", "override", "reveal", "delete", "system", "prompt", "instructions"}
)

# A misspelling of a word shorter than this is too cheap to make by accident
# (`rule` → `rude`, `core` → `care`), so short keywords are only matched exactly.
_MIN_FUZZY_LEN = 5

_WORD_RE = re.compile(r"[A-Za-z0-9]+")
# Three or more single characters separated by single spaces: `i g n o r e`,
# and `a l l`, which a four-character floor would leave spaced.
_SPACED_RUN_RE = re.compile(r"(?<!\S)\S(?: \S){2,}(?!\S)")
_REPEATED_CHAR_RE = re.compile(r"(.)\1{3,}")


def _scramble_key(word: str) -> tuple[str, str, str, int] | None:
    """First letter, last letter, sorted middle, length: equal for every
    middle-letter scramble of one word. None under four letters, where there
    is no middle to scramble."""
    if len(word) < 4:
        return None
    return (word[0], word[-1], "".join(sorted(word[1:-1])), len(word))


_SCRAMBLES = {k: w for w in SCRAMBLE_TARGETS if (k := _scramble_key(w)) is not None}

# Nothing longer than the longest keyword plus one edit can be a misspelling
# of one. Checked before any per-word work: a 100k-character base64 run is one
# "word", and its deletion neighbourhood alone would be 100k strings of 100k
# characters each.
_MAX_WORD_LEN = max(len(k) for k in KEYWORDS) + 1


def _deletions(word: str) -> set[str]:
    """Every string ``word`` becomes with one character deleted."""
    return {word[:i] + word[i + 1 :] for i in range(len(word))}


# Deletion neighbourhoods (the SymSpell trick): two words within one edit
# share a one-deletion variant, or one is a one-deletion variant of the other.
# Looking a word's handful of variants up in this table is what keeps a
# 100k-character payload from being compared against every keyword.
_BY_DELETION: dict[str, set[str]] = {}
for _kw in KEYWORDS:
    if len(_kw) >= _MIN_FUZZY_LEN:
        for _variant in _deletions(_kw) | {_kw}:
            _BY_DELETION.setdefault(_variant, set()).add(_kw)


def within_one_edit(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance at most 1 (adjacent transposition counts as one)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]]
            and a[diff[1]] == b[diff[0]]
        )
    short, long_ = (a, b) if la < lb else (b, a)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


def scrambled_keyword(word: str) -> str | None:
    """The target ``word`` is a middle-letter scramble of, or None. Not the word itself."""
    # The length check is out here, not in the memoized body: a cache keyed
    # on 100k-character words keeps 8192 of them alive.
    return None if len(word) > _MAX_WORD_LEN else _scrambled(word.lower())


def corrected_keyword(word: str) -> str | None:
    """The keyword ``word`` misspells by one edit or a scramble, or None.

    None too when the word is already a keyword, or is close to two of them
    and so says nothing about which one was meant.
    """
    return None if len(word) > _MAX_WORD_LEN else _corrected(word.lower())


# Memoized per word. Ops output repeats its vocabulary heavily, and the cache
# is bounded in entries and, through the length check above, in entry size.
@lru_cache(maxsize=8192)
def _scrambled(lowered: str) -> str | None:
    """``scrambled_keyword`` for a lower-cased word already known to be short."""
    key = _scramble_key(lowered)
    target = _SCRAMBLES.get(key) if key else None
    return target if target is not None and target != lowered else None


@lru_cache(maxsize=8192)
def _corrected(lowered: str) -> str | None:
    """``corrected_keyword`` for a lower-cased word already known to be short."""
    if lowered in KEYWORDS:
        return None
    scrambled = _scrambled(lowered)
    if scrambled is not None:
        return scrambled
    if len(lowered) < _MIN_FUZZY_LEN - 1:
        return None
    candidates: set[str] = set()
    for variant in _deletions(lowered) | {lowered}:
        candidates |= _BY_DELETION.get(variant, set())
    # A keyword with a letter on the end is a word, not a typo: `overrides`,
    # `systemd`, `Systems`. Correcting those turned "the system overrides the
    # default" into `system override`.
    matches = {
        kw for kw in candidates if within_one_edit(lowered, kw) and not lowered.startswith(kw)
    }
    return matches.pop() if len(matches) == 1 else None


def corrected_line(line: str) -> str | None:
    """``line`` with each misspelled keyword corrected, or None if nothing was."""
    changed = False

    def fix(match: re.Match[str]) -> str:
        nonlocal changed
        fixed = corrected_keyword(match.group(0))
        if fixed is None:
            return match.group(0)
        changed = True
        return fixed

    rewritten = _WORD_RE.sub(fix, line)
    return rewritten if changed else None


def scrambled_with_company(line: str) -> bool:
    """Two misspelled keywords on one line, at least one of them scrambled.

    Misspelled, not merely present: "check the sytsem logs for rules" is one
    typo beside an ordinary word and stays clean, while "bpyass all safety
    measuers" is not a typing slip.
    """
    misspelled = 0
    scrambled = False
    for match in _WORD_RE.finditer(line):
        word = match.group(0)
        if corrected_keyword(word) is None:
            continue
        misspelled += 1
        scrambled = scrambled or scrambled_keyword(word) is not None
    return scrambled and misspelled >= 2


# The short words injection phrases put between keywords, for splitting a run
# that was spaced a letter at a time and so kept no word breaks of its own.
_FILLERS = frozenset(
    {"a", "all", "any", "the", "my", "your", "our", "its", "me", "of", "and", "to", "now", "you"}
)
_SEGMENT_VOCAB = KEYWORDS | _FILLERS
_MAX_SEGMENT_INPUT = 200


def _segmented(joined: str) -> str:
    """``joined`` split into keywords and fillers if it is made of nothing else.

    ``i g n o r e a l l p r e v i o u s`` collapses to ``ignoreallprevious``,
    which no pattern matches. Splitting it back needs a vocabulary, and the
    only words worth recovering are the ones the patterns are built from.
    Fewest pieces wins; text that is not entirely vocabulary is left as it is.
    """
    lowered = joined.lower()
    if len(lowered) > _MAX_SEGMENT_INPUT:
        return joined
    longest = max(len(w) for w in _SEGMENT_VOCAB)
    best: list[list[str] | None] = [[]] + [None] * len(lowered)
    for end in range(1, len(lowered) + 1):
        for start in range(max(0, end - longest), end):
            prefix = best[start]
            if prefix is not None and lowered[start:end] in _SEGMENT_VOCAB:
                candidate = [*prefix, lowered[start:end]]
                if best[end] is None or len(candidate) < len(best[end] or []):
                    best[end] = candidate
    words = best[-1]
    return " ".join(words) if words else joined


def collapsed_spacing(line: str) -> str | None:
    """``line`` with character-spaced runs and long character repeats collapsed.

    ``i g n o r e  p r e v i o u s`` becomes ``ignore previous``: a single space
    inside a run joins, a wider gap stays a word break. None when the line has
    neither trick in it.
    """
    spaced = _SPACED_RUN_RE.search(line) is not None
    repeated = _REPEATED_CHAR_RE.search(line) is not None
    if not (spaced or repeated):
        return None
    collapsed = _SPACED_RUN_RE.sub(lambda m: _segmented(m.group(0).replace(" ", "")), line)
    collapsed = _REPEATED_CHAR_RE.sub(r"\1", collapsed)
    return re.sub(r"\s{2,}", " ", collapsed)
