"""Search tools — block_search, flag_search and redact_search.

Search is a producer like any other. L0 (a grounded model call) writes an
answer and cites sources; the answer, every title and every URI become ONE
document, and that document crosses the same three layers as a fetched page.

It used to be special, and special meant weaker: its own recipe, L1 run field
by field and merged, a private ``total_l1 >= 3`` refusal rule, titles and
URIs seen by L1 alone, and no L3 at all in block and flag. L0's output is
model output — written by an LLM after reading whatever the web served it —
so it is judged with ``Provenance.MODEL_OUTPUT``, never trusted more.
"""

from __future__ import annotations

from typing import Any

from ..defense import Provenance
from ..errors import BlockedSourceError, QuarantineAgentError
from ..modes import Mode
from ..quarantine.agent import resolve_grounding_urls, search_grounded
from .judged import judge_and_deliver


def _document(text: str, sources: list[dict[str, Any]]) -> str:
    """The answer plus its citations, as the layers read them."""
    if not sources:
        return text
    cited = "\n".join(f"- [{s['title']}]({s['uri']})" for s in sources)
    return f"{text}\n\n--- Sources ---\n{cited}"


async def web_search(
    query: str, num_results: int, mode: Mode, prompt: str | None = None
) -> dict[str, Any]:
    """L0, redirect resolution, then the one judging path."""
    try:
        raw = await search_grounded(query, num_results)
    except QuarantineAgentError as exc:
        raise BlockedSourceError(f"search:{query}", str(exc)) from exc

    resolved = await resolve_grounding_urls(raw.get("sources", []))
    sources = [
        {
            "uri": s.get("uri", ""),
            "title": s.get("title", ""),
            "redirect_failed": bool(s.get("redirect_failed")),
        }
        for s in resolved
    ]
    text = raw.get("text", "")
    family_fields = {"sources": sources, "query": query, "l0_usage": raw.get("usage", {})}

    return await judge_and_deliver(
        _document(text, sources),
        mode=mode,
        family="search",
        source=f"search:{query}",
        source_type="url",
        kind="search",
        ref=query,
        prompt=prompt,
        provenance=Provenance.MODEL_OUTPUT,
        delivered=text,
        extras=family_fields,
        # redact returns the sources beside the extraction (the extraction
        # schema has no URLs, and a search answer without links is useless).
        # They crossed all three layers inside the document.
        redact_extras=family_fields,
    )


async def block_search(query: str, num_results: int = 5) -> dict[str, Any]:
    """Refuse a flagged or incompletely judged answer; otherwise L0's text."""
    return await web_search(query, num_results, Mode.BLOCK)


async def flag_search(query: str, num_results: int = 5) -> dict[str, Any]:
    """L0's answer and sources, with the verdict attached when there is one."""
    return await web_search(query, num_results, Mode.FLAG)


async def redact_search(
    query: str,
    prompt: str,
    num_results: int = 5,
) -> dict[str, Any]:
    """A verified L3 extraction of the answer, plus its sources."""
    return await web_search(query, num_results, Mode.REDACT, prompt)
