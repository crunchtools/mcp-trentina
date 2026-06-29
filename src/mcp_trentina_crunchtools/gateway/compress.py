"""Tool description compression for the gateway.

Compresses verbose tool descriptions via the configured LLM provider,
triggered lazily on the first tools/list request.  Results are cached in
SQLite and looked up synchronously on subsequent calls.  Compression is
best-effort: failures at any level are logged and skipped.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from ..database import get_all_compressions, save_compression
from ..quarantine.providers import get_provider

if TYPE_CHECKING:
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

BATCH_SIZE = 5
DELAY_BETWEEN_BACKENDS = 2
DELAY_BETWEEN_BATCHES = 3
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0
_RETRYABLE_STATUS_CODES = {429, 503}

_cache: dict[str, str] = {}
_profiles: dict[str, Profile] | None = None
_compress_triggered: bool = False
_compress_task: asyncio.Task[dict[str, int]] | None = None

COMPRESS_SYSTEM_PROMPT = """\
You are a tool description compressor. Given MCP tool descriptions, produce \
the shortest possible version of each that preserves:
1. What the tool does (core action)
2. When to call it (trigger conditions, if stated)
3. Key constraints or prerequisites

Rules:
- Remove examples, verbose formatting, markdown, and redundant explanations
- Remove parameter documentation (the inputSchema handles that)
- Keep each description to 1-2 short sentences maximum
- Never invent capabilities not in the original
- If the original is already concise, return it unchanged"""

COMPRESS_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "compressed": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "text": {"type": "string"},
                },
                "required": ["id", "text"],
            },
        },
    },
    "required": ["compressed"],
}


def _hash_description(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def load_compression_cache() -> int:
    """Populate the in-memory cache from SQLite. Returns count loaded."""
    global _cache
    _cache = get_all_compressions()
    logger.info("compress: loaded %d cached compressions from database", len(_cache))
    return len(_cache)


def set_profiles(profiles: dict[str, Profile]) -> None:
    """Store the profile registry for lazy compression."""
    global _profiles
    _profiles = profiles


async def maybe_trigger_compression() -> None:
    """Trigger background compression on the first call, retrying on failure.

    On success, subsequent calls return immediately. If the previous task
    failed, allows re-triggering so transient errors don't permanently
    disable compression.
    """
    global _compress_triggered, _compress_task
    if _profiles is None:
        return
    if _compress_task is not None and _compress_task.done() and _compress_task.exception():
        logger.warning(
            "compress: previous task failed: %s — allowing retry",
            _compress_task.exception(),
        )
        _compress_triggered = False
    if _compress_triggered:
        return
    _compress_triggered = True
    _compress_task = asyncio.create_task(precompress_all(_profiles))
    logger.info("compress: background compression triggered by first tools/list")


def compress_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace tool descriptions from cache. Sync-only, no model calls.

    Cache miss = passthrough (original description kept).
    """
    if not _cache:
        return tools

    compressed_tools: list[dict[str, Any]] = []
    for tool in tools:
        desc = tool.get("description", "")
        if not desc:
            compressed_tools.append(tool)
            continue
        h = _hash_description(desc)
        compressed = _cache.get(h)
        if compressed is not None:
            tool_copy = dict(tool)
            tool_copy["description"] = compressed
            compressed_tools.append(tool_copy)
        else:
            compressed_tools.append(tool)
    return compressed_tools


async def precompress_all(
    profiles: dict[str, Profile],
) -> dict[str, int]:
    """Pre-compress descriptions for all compression-enabled backends.

    Best-effort: each backend is independent. A failure in one backend
    does not affect others. Deduplicates by URL.
    """
    seen_urls: set[str] = set()
    stats: dict[str, int] = {}

    for profile in profiles.values():
        for backend_name, backend in profile.backends.items():
            if not backend.compress_descriptions:
                continue
            if backend.is_internal:
                continue
            if backend.url in seen_urls:
                continue
            seen_urls.add(backend.url)

            try:
                count = await _precompress_backend(backend_name, backend)
                stats[backend_name] = count
            except Exception:
                logger.warning("compress: backend %s failed, skipping", backend_name)
            await asyncio.sleep(DELAY_BETWEEN_BACKENDS)

    total = sum(stats.values())
    if total:
        logger.info("compress: finished — %d descriptions across %d backends", total, len(stats))
    return stats


def _find_uncached(tools: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Return (hash, description) pairs for tools not already in cache."""
    uncached: list[tuple[str, str]] = []
    for tool in tools:
        desc = tool.get("description", "")
        if not desc:
            continue
        h = _hash_description(desc)
        if h not in _cache:
            uncached.append((h, desc))
    return uncached


def _store_result(batch: list[tuple[str, str]], h: str, compressed_text: str) -> bool:
    """Store a compression result if it's actually shorter. Returns True if stored."""
    original = next((desc for bh, desc in batch if bh == h), None)
    if original is None or len(compressed_text) >= len(original):
        return False
    _cache[h] = compressed_text
    save_compression(h, original, compressed_text, "provider")
    return True


async def _precompress_backend(backend_name: str, backend: Backend) -> int:
    """Fetch tools from one backend, compress uncached descriptions."""
    from .backend import list_backend_tools

    try:
        tools = await list_backend_tools(backend_name, backend)
    except Exception:
        logger.warning("compress: %s — could not list tools, skipping", backend_name)
        return 0

    uncached = _find_uncached(tools)
    if not uncached:
        return 0

    logger.info("compress: %s — %d descriptions to compress", backend_name, len(uncached))

    compressed_count = 0
    for i in range(0, len(uncached), BATCH_SIZE):
        if i > 0:
            await asyncio.sleep(DELAY_BETWEEN_BATCHES)
        batch = uncached[i : i + BATCH_SIZE]
        results = await _compress_batch_with_fallback(batch)
        for h, text in results:
            if _store_result(batch, h, text):
                compressed_count += 1

    if compressed_count:
        logger.info("compress: %s — compressed %d descriptions", backend_name, compressed_count)
    return compressed_count


async def _compress_batch_with_fallback(
    batch: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Try batch compression, fall back to one-at-a-time on failure."""
    results = await _call_compress_model(batch)
    if results:
        return results

    if len(batch) == 1:
        return []

    logger.info("compress: batch of %d failed, falling back to one-at-a-time", len(batch))
    all_results: list[tuple[str, str]] = []
    for item in batch:
        await asyncio.sleep(1)
        single = await _call_compress_model([item])
        all_results.extend(single)
    return all_results


async def _call_compress_model(
    items: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Call the configured provider to compress a batch of descriptions.

    Retries up to MAX_RETRIES times on transient errors with exponential
    backoff. Returns [(hash, compressed_text)] for successful compressions,
    or empty list on permanent failure.
    """
    descriptions_payload = [{"id": h, "text": desc} for h, desc in items]
    user_content = json.dumps({"descriptions": descriptions_payload})

    for attempt in range(MAX_RETRIES):
        try:
            provider = get_provider()
            provider_result = await provider.generate(
                system_prompt=COMPRESS_SYSTEM_PROMPT,
                user_content=user_content,
                response_schema=COMPRESS_RESPONSE_SCHEMA,
                temperature=0.1,
                max_output_tokens=4096,
            )
            parsed = json.loads(provider_result.text)
            return _parse_compress_response(parsed)
        except Exception as exc:
            exc_msg = str(exc)
            is_retryable = any(f"HTTP {code}" in exc_msg for code in _RETRYABLE_STATUS_CODES)
            if is_retryable and attempt < MAX_RETRIES - 1:
                delay = RETRY_BASE_DELAY * (2**attempt)
                logger.info(
                    "compress: provider error, retry %d/%d in %.0fs: %s",
                    attempt + 1, MAX_RETRIES, delay, exc,
                )
                await asyncio.sleep(delay)
                continue
            logger.warning("compress: provider call failed for %d items: %s", len(items), exc)
            return []

    return []


def _parse_compress_response(parsed: dict[str, Any]) -> list[tuple[str, str]]:
    """Extract compressed descriptions from a parsed provider response."""
    compressed_list = parsed.get("compressed", [])
    if not isinstance(compressed_list, list):
        logger.warning("compress: unexpected response structure")
        return []
    return [
        (item["id"], item["text"])
        for item in compressed_list
        if isinstance(item, dict) and "id" in item and "text" in item
    ]


