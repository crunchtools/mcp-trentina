"""LLM delimiter stripping — remove fake system/user/assistant delimiters."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

LLM_DELIMITER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<\|im_start\|>", re.IGNORECASE),
    re.compile(r"<\|im_end\|>", re.IGNORECASE),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"<\|user\|>", re.IGNORECASE),
    re.compile(r"<\|assistant\|>", re.IGNORECASE),
    re.compile(r"<\|endoftext\|>", re.IGNORECASE),
    re.compile(r"<\|pad\|>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"\[/INST\]", re.IGNORECASE),
    re.compile(r"<<SYS>>", re.IGNORECASE),
    re.compile(r"<</SYS>>", re.IGNORECASE),
    re.compile(r"\n\nHuman:"),
    re.compile(r"\n\nAssistant:"),
]


@dataclass
class DelimiterStats:
    """Counts of stripped LLM delimiters."""

    llm_delimiters: int = field(default=0)
    custom_patterns: int = field(default=0)


def sanitize_delimiters(
    text: str,
    custom_patterns: list[str] | None = None,
) -> tuple[str, DelimiterStats]:
    """Strip known LLM delimiter patterns from text."""
    delimiter_count = 0
    cleaned = text

    for pattern in LLM_DELIMITER_PATTERNS:
        matches = pattern.findall(cleaned)
        if matches:
            delimiter_count += len(matches)
            cleaned = pattern.sub("", cleaned)

    custom_count = 0
    if custom_patterns:
        for raw in custom_patterns:
            escaped = re.escape(raw)
            pat = re.compile(escaped, re.IGNORECASE)
            matches = pat.findall(cleaned)
            if matches:
                custom_count += len(matches)
                cleaned = pat.sub("", cleaned)

    return cleaned, DelimiterStats(
        llm_delimiters=delimiter_count,
        custom_patterns=custom_count,
    )
