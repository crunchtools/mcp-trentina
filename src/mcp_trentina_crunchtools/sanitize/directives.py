"""Stage 6: Directive detection — count visible LLM instruction patterns.

Detects lines containing common prompt injection directives: instruction
overrides, role reassignment, command execution, and imperative AI
prefixes. Operates on visible English-language text, complementing the
invisible-character stripping (unicode stage) and special-token stripping
(delimiter stage).

This stage DETECTS and does not modify. It used to remove the whole line
around a match, which destroyed exactly the content an ops agent exists to
read: a CVE ticket, a Nagios alert, or a security mail *discusses* attacks
in the same words attacks use, and a one-line Jira description containing
"ignore previous instructions" came back as an empty string — silently, with
L2 and L3 left judging the void. Every other stage excises a precise token
(a zero-width character, an encoded blob, a delimiter); this one amputated
prose. Now the count feeds the L1 risk verdict and the sidecar, and the
enforcement mode — not this stage — decides whether flagged content reaches
the agent.
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
    """Statistics from directive detection."""

    directives_detected: int = 0


def sanitize_directives(text: str) -> tuple[str, DirectiveStats]:
    """Count lines containing LLM directive patterns; return text unchanged.

    One detection per line, however many patterns hit it — the unit of
    suspicion is the hostile line, and counting each pattern would let a
    single line inflate the risk score on its own.
    """
    stats = DirectiveStats()

    for line in text.split("\n"):
        if _PREFIX_PATTERNS.search(line):
            stats.directives_detected += 1
            continue
        if any(pattern.search(line) for pattern in _INLINE_PATTERNS):
            stats.directives_detected += 1

    return text, stats
