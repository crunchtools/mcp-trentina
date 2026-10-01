"""A deprecation notice must never name a release that has already shipped.

Every alias in this package carries a sentence promising the release that
removes it. That sentence is the only thing an operator has to plan against,
and it rots in one specific way: the named release ships, nobody removes
anything, and the message keeps claiming a removal that did not happen.

It had already rotted three times when this file was written at 0.27.1.
`defense.l3_threshold` told operators it "is rejected from 0.12.0" while the
loader at 0.27.0 went on accepting it — fifteen minor releases past its own
deadline. The two `l2_input` notices said 0.27.0 while running inside
0.27.0.

That failure is worse than no notice at all. A reader who sees a past release
concludes the removal already happened and stops looking, which is the exact
opposite of what the sentence is for. Nothing else catches it: the strings
are prose, so ruff and mypy have no opinion, and the tests that exercise the
aliases pass precisely BECAUSE the removal never came.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mcp_trentina_crunchtools import __version__

SRC = Path(__file__).resolve().parents[1] / "src"

#: "removed in 0.28.0", "is rejected from 0.28.0", "removing in 1.0.0".
#: IGNORECASE is load-bearing. Without it the pattern missed every
#: ``"""DEPRECATED — use `block_fetch`. Removed in 0.28.0."""`` docstring,
#: because those capitalise the verb — eight live notices this file was
#: supposed to be watching and never saw.
_NOTICE = re.compile(
    r"(?:removed|rejected|removing|removal)\s+(?:in|from)\s+(\d+)\.(\d+)\.(\d+)",
    re.IGNORECASE,
)


#: Joins adjacent string literals before matching, so a notice split across
#: two of them is still seen. This blind spot hid a REAL one: the
#: ``l3_threshold`` field description ended a literal with "it is removed in "
#: and opened the next with "0.12.0." — seventeen minor releases stale, and
#: invisible to a line-by-line scan for the entire life of this file.
_LITERAL_JOIN = re.compile(r'"\s*\n\s*"')


def _notices() -> list[tuple[str, int, str, tuple[int, int, int]]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(SRC))
        # Line numbers come from the raw text; matching happens on the joined
        # text, so report the line the notice STARTS on.
        joined = _LITERAL_JOIN.sub("", text)
        for match in _NOTICE.finditer(joined):
            lineno = joined.count("\n", 0, match.start()) + 1
            version = tuple(int(g) for g in match.groups())
            found.append((rel, lineno, match.group(0), version))
    return found


def _current() -> tuple[int, int, int]:
    parts = __version__.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


class TestDeprecationDeadlines:
    def test_the_pattern_still_matches_how_notices_are_written(self) -> None:
        """A regex that silently matched nothing would pass the test below.

        This used to assert that src/ carried at least three live notices,
        which conflated two things and broke the moment 0.29.0 removed every
        alias at once: zero pending deprecations is a GOOD state, not a
        broken pattern. So exercise the pattern against the spellings this
        codebase actually uses instead, including the split-literal form that
        hid a stale notice for the whole life of this file.
        """
        samples = [
            ('"""DEPRECATED — use `block_fetch`. Removed in 9.9.9."""', (9, 9, 9)),
            ("# is rejected from 1.2.3 onwards", (1, 2, 3)),
            ("# removing in 2.0.0", (2, 0, 0)),
            ('"it is removed in "\n            "0.12.0."', (0, 12, 0)),
        ]
        for text, expected in samples:
            joined = _LITERAL_JOIN.sub("", text)
            match = _NOTICE.search(joined)
            assert match is not None, f"pattern no longer matches: {text!r}"
            assert tuple(int(g) for g in match.groups()) == expected

    @pytest.mark.parametrize(("rel", "lineno", "text", "version"), _notices(), ids=str)
    def test_the_named_release_has_not_shipped(
        self, rel: str, lineno: int, text: str, version: tuple[int, int, int]
    ) -> None:
        """Either remove the thing, or move the date. Not neither."""
        assert version > _current(), (
            f"{rel}:{lineno} says {text!r}, but the current version is "
            f"{__version__} — so the message claims a removal that has not "
            f"happened. Either do the removal, or move the notice to a "
            f"release that is still ahead."
        )
