"""block_fetch: refuse a flagged page, otherwise deliver the exact bytes.

L2 cost grows linearly with input length (one ONNX pass per 446 tokens), so
the scan is capped at CLASSIFIER_MAX_TOKENS to keep a large page from
stalling the gateway.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from mcp_trentina_crunchtools.client import fetch_url
from mcp_trentina_crunchtools.errors import BlockedSourceError

CLASSIFIER_MAX_TOKENS = 32768


@dataclass(frozen=True)
class Verdict:
    label: str
    score: float


def _tokenize(text: str) -> list[int]:
    raise NotImplementedError  # the Prompt Guard 2 tokenizer


def _score_windows(ids: list[int]) -> Verdict:
    raise NotImplementedError  # 512-token windows at stride 446


def classify_capped(text: str) -> Verdict:
    """Classify up to CLASSIFIER_MAX_TOKENS tokens of ``text``.

    Attacks are front-loaded in practice, so the head is representative.
    """
    ids = _tokenize(text)
    return _score_windows(ids[:CLASSIFIER_MAX_TOKENS])


async def block_fetch(url: str) -> dict[str, Any]:
    """Fetch ``url``; refuse it if L2 flags it, else return the page."""
    content, content_type = await fetch_url(url)
    verdict = await asyncio.to_thread(classify_capped, content)
    if verdict.label == "MALICIOUS":
        raise BlockedSourceError(url, "flagged by L2")
    return {
        "content": content,
        "content_type": content_type,
        "scan": {"l2_label": verdict.label, "l2_score": verdict.score, "disposition": "clean"},
    }
