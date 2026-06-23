"""Stage 6: Directive stripping — remove visible LLM instruction patterns.

Strips lines containing common prompt injection directives: instruction
overrides, role reassignment, command execution, and imperative AI
prefixes. Operates on visible English-language text, complementing the
invisible-character stripping (unicode stage) and special-token stripping
(delimiter stage).

False positives are acceptable — if content discusses prompt injection,
stripping those phrases from extracted text is fine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_INLINE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore\s+(?:all\s+)?previous\s+instructions",
        r"ignore\s+all\s+instructions",
        r"you\s+are\s+now\s+a\b",
        r"your\s+new\s+role\s+is\b",
        r"system\s+prompt\s*:",
        r"execute\s+the\s+following",
        r"run\s+this\s+command",
        r"as\s+an\s+ai\s*,?\s+you\s+must",
    ]
]

_PREFIX_PATTERNS = re.compile(
    r"^\s*(?:IMPORTANT|INSTRUCTION|OVERRIDE|ADMIN)\s*:",
    re.IGNORECASE,
)


@dataclass
class DirectiveStats:
    """Statistics from directive stripping."""

    directives_stripped: int = 0


def sanitize_directives(text: str) -> tuple[str, DirectiveStats]:
    """Strip lines containing LLM directive patterns.

    Returns the cleaned text and stats with the count of stripped lines.
    """
    stats = DirectiveStats()
    lines = text.split("\n")
    clean_lines: list[str] = []

    for line in lines:
        stripped = False

        if _PREFIX_PATTERNS.search(line):
            stripped = True

        if not stripped:
            for pattern in _INLINE_PATTERNS:
                if pattern.search(line):
                    stripped = True
                    break

        if stripped:
            stats.directives_stripped += 1
        else:
            clean_lines.append(line)

    return "\n".join(clean_lines), stats
