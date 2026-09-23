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
_NOTICE = re.compile(
    r"(?:removed|rejected|removing|removal)\s+(?:in|from)\s+(\d+)\.(\d+)\.(\d+)"
)


def _notices() -> list[tuple[str, int, str, tuple[int, int, int]]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            for match in _NOTICE.finditer(line):
                version = tuple(int(g) for g in match.groups())
                rel = str(path.relative_to(SRC))
                found.append((rel, lineno, match.group(0), version))
    return found


def _current() -> tuple[int, int, int]:
    parts = __version__.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


class TestDeprecationDeadlines:
    def test_there_are_notices_to_check(self) -> None:
        """A regex that silently matched nothing would pass the test below."""
        assert len(_notices()) >= 3, (
            "found almost no deprecation notices — the pattern probably "
            "stopped matching the way they are written"
        )

    @pytest.mark.parametrize(
        ("rel", "lineno", "text", "version"), _notices(), ids=str
    )
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
