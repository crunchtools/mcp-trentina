"""Content tools — block_content, flag_content and redact_content."""

from __future__ import annotations

import hashlib
from typing import Any

from ..config import get_config
from ..database import is_blocked
from ..errors import ContentSizeError
from ..modes import Mode
from ..preprocess.policy import INTERNAL_DEFAULTS
from .judged import blocklisted, judge_and_deliver
from .preprocess import is_html_type, prepare


def _content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for blocklist keying."""
    return f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"


async def judge_content(
    content: str,
    mode: Mode,
    prompt: str | None = None,
    *,
    content_type: str = "text/plain",
    preprocess: Any = None,
) -> dict[str, Any]:
    """Judge text the agent handed in. It is never allowlisted.

    Inline content has no provenance to appeal to: fetch asks the domain,
    read asks the path, and this has neither. The blocklist is keyed by the
    content's hash — of what was handed in, before any pre-processing.

    ``content_type`` is the hint it was kept for (#183): declared HTML is
    converted by default, the way fetch converts a page its server calls
    HTML. ``preprocess`` overrides the default within the policy.
    """
    max_size = get_config().max_content
    if len(content) > max_size:
        raise ContentSizeError(len(content), max_size)

    chash = _content_hash(content)
    blocked = is_blocked(chash)
    if blocked and mode is not Mode.REDACT:
        raise blocklisted(chash, mode, blocked["detected_at"])

    page = await prepare(
        content,
        requested=preprocess,
        default=INTERNAL_DEFAULTS["content_tool"] if is_html_type(content_type) else (),
        source=chash,
    )
    return await judge_and_deliver(
        page.content,
        mode=mode,
        family="content",
        source=chash,
        source_type="content",
        kind="content",
        ref=chash,
        prompt=prompt,
        blocklisted_at=blocked["detected_at"] if blocked else None,
        provenance=page.provenance,
        precomputed_l1=page.pipeline,
        l3_context=page.briefing,
        extras=page.extras,
        redact_extras=page.extras,
    )


async def block_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """Refuse flagged or incompletely judged content; otherwise what was judged.

    That is the text as given, or its Markdown when ``content_type`` is HTML.
    """
    return await judge_content(content, Mode.BLOCK, content_type=content_type)


async def flag_content(content: str, content_type: str = "text/plain") -> dict[str, Any]:
    """What was judged — the text as given, or its Markdown when declared
    HTML — with the verdict attached when there is one."""
    return await judge_content(content, Mode.FLAG, content_type=content_type)


async def redact_content(
    content: str,
    prompt: str = "Extract the main content.",
    content_type: str = "text/plain",
) -> dict[str, Any]:
    """A verified L3 extraction of the content."""
    return await judge_content(content, Mode.REDACT, prompt, content_type=content_type)
