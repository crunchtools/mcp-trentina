"""Content tools — block_content, flag_content and redact_content."""

from __future__ import annotations

import hashlib
from typing import Any

from ..config import get_config
from ..database import is_blocked
from ..errors import ContentSizeError
from ..modes import Mode
from .judged import blocklisted, judge_and_deliver


def _content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for blocklist keying."""
    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"


async def judge_content(content: str, mode: Mode, prompt: str | None = None) -> dict[str, Any]:
    """Judge text the agent handed in. It is never allowlisted.

    Inline content has no provenance to appeal to: fetch asks the domain,
    read asks the path, and this has neither. The blocklist is keyed by the
    content's hash.
    """
    max_size = get_config().max_content
    if len(content) > max_size:
        raise ContentSizeError(len(content), max_size)

    chash = _content_hash(content)
    blocked = is_blocked(chash)
    if blocked and mode is not Mode.REDACT:
        raise blocklisted(chash, mode, blocked["detected_at"])

    return await judge_and_deliver(
        content,
        mode=mode,
        family="content",
        source=chash,
        source_type="content",
        kind="content",
        ref=chash,
        prompt=prompt,
        blocklisted_at=blocked["detected_at"] if blocked else None,
    )


# `content_type` stays in the three signatures as published tool surface. It
# selects nothing: L1 is format-agnostic (#172).


async def block_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """Refuse flagged or incompletely judged content; otherwise the same text."""
    del content_type
    return await judge_content(content, Mode.BLOCK)


async def flag_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """The content as given, with the verdict attached when there is one."""
    del content_type
    return await judge_content(content, Mode.FLAG)


async def redact_content(
    content: str,
    prompt: str = "Extract the main content.",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """A verified L3 extraction of the content."""
    del content_type
    return await judge_content(content, Mode.REDACT, prompt)
