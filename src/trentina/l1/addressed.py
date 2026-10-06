"""Text addressed to the AI reading it (#363).

The most common form of injection in the wild is not a jailbreak phrase. It
is a sentence that turns to the reader: "If you are an AI reading this",
"Note to the model:", "AI assistants processing this page must". A document
written for people has no reason to do that, and none of the directive
patterns match it.

Writing ABOUT agents is ordinary, and this gateway's operators read a great
deal of it: "AI agents must authenticate with OAuth" is a requirement, not an
address. So a pattern needs the turn itself: the conditional, the salutation
with its colon, or the reader named as reading this very text.

One count per line. Counts only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_AI = r"(?:ai|llm|large\s+language\s+model|language\s+model|chatbot)"
_KIND = r"(?:\s+(?:assistants?|agents?|models?|systems?|bots?|crawlers?))?"
_READING = (
    r"(?:reading|processing|summari[sz]ing|parsing|reviewing|analy[sz]ing|scanning|"
    r"crawling|indexing|viewing|seeing)"
)

_ADDRESSED = re.compile(
    # "If you are an AI, ..." / "if you're an LLM agent reading this"
    r"\bif\s+you(?:'re|\s+are)\s+(?:an?\s+)?" + _AI + _KIND + r"(?:\s*,|\s+" + _READING + r"\b)"
    # "Note to the model:" / "Instructions for AI agents:" / "Attention, LLM:"
    r"|\b(?:note|message|instructions?|attention|notice|memo|reminder)\s*,?\s+"
    r"(?:(?:to|for)\s+)?(?:the\s+|any\s+|all\s+)?"
    r"(?:" + _AI + _KIND + r"|assistants?|models?|agents?)\s*" + "[:\u2014\u2013-]"
    # "AI assistants reading this page must" / "To the LLM processing this:"
    r"|\b" + _AI + _KIND + r"\s+" + _READING + r"\s+this\b",
    re.IGNORECASE,
)


@dataclass
class AddressedStats:
    """Count of lines that turn to address an AI reader."""

    ai_addressed_lines: int = 0


def detect_addressed(text: str) -> AddressedStats:
    """Count the lines that address the AI reading them."""
    return AddressedStats(sum(1 for line in text.split("\n") if _ADDRESSED.search(line)))
