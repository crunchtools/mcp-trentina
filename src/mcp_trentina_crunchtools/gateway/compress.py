"""Tool description compression for the gateway.

Pre-compresses verbose tool descriptions at startup using Gemini Flash Lite.
Results are cached in SQLite and looked up synchronously during tools/list.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from typing import TYPE_CHECKING, Any

import httpx

from ..config import get_config
from ..database import get_all_compressions, save_compression

if TYPE_CHECKING:
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_TIMEOUT = 60.0
BATCH_SIZE = 5
DEFAULT_COMPRESS_MODEL = "gemini-2.5-flash-lite"

_cache: dict[str, str] = {}

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


def compress_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace tool descriptions from cache. Sync-only, no model calls.

    Cache miss = passthrough (original description kept).
    """
    if not _cache:
        return tools

    result: list[dict[str, Any]] = []
    for tool in tools:
        desc = tool.get("description", "")
        if not desc:
            result.append(tool)
            continue
        h = _hash_description(desc)
        compressed = _cache.get(h)
        if compressed is not None:
            tool_copy = dict(tool)
            tool_copy["description"] = compressed
            result.append(tool_copy)
        else:
            result.append(tool)
    return result


async def precompress_all(
    profiles: dict[str, Profile],
) -> dict[str, int]:
    """Pre-compress descriptions for all compression-enabled backends.

    Deduplicates backends by URL so the same server isn't fetched twice.
    Returns {backend_name: count_compressed}.
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
                logger.warning(
                    "compress: failed to pre-compress backend %s",
                    backend_name,
                    exc_info=True,
                )
            await asyncio.sleep(2)
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
    save_compression(h, original, compressed_text, _get_model())
    return True


async def _precompress_backend(backend_name: str, backend: Backend) -> int:
    """Fetch tools from one backend, compress uncached descriptions."""
    from .backend import list_backend_tools

    try:
        tools = await list_backend_tools(backend_name, backend)
    except Exception:
        logger.warning("compress: could not list tools for %s", backend_name)
        return 0

    uncached = _find_uncached(tools)
    if not uncached:
        logger.info("compress: %s — all %d descriptions already cached", backend_name, len(tools))
        return 0

    logger.info("compress: %s — %d uncached descriptions to compress", backend_name, len(uncached))

    compressed_count = 0
    for i in range(0, len(uncached), BATCH_SIZE):
        if i > 0:
            await asyncio.sleep(3)
        batch = uncached[i : i + BATCH_SIZE]
        for h, text in await _call_compress_model(batch):
            if _store_result(batch, h, text):
                compressed_count += 1

    logger.info("compress: %s — compressed %d descriptions", backend_name, compressed_count)
    return compressed_count


async def _call_compress_model(
    items: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Call Gemini to compress a batch of descriptions.

    Returns [(hash, compressed_text)] for successful compressions.
    """
    config = get_config()
    if not config.has_api_key:
        logger.warning("compress: no GEMINI_API_KEY, skipping compression")
        return []

    descriptions_payload = [{"id": h, "text": desc} for h, desc in items]
    user_content = json.dumps({"descriptions": descriptions_payload})

    model = _get_model()
    api_key = config.api_key.get_secret_value()
    url = f"{GEMINI_API_BASE}/{model}:generateContent?key={api_key}"

    request_body = {
        "system_instruction": {"parts": [{"text": COMPRESS_SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_content}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": COMPRESS_RESPONSE_SCHEMA,
            "temperature": 0.1,
            "maxOutputTokens": 4096,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(GEMINI_TIMEOUT)) as client:
            resp = await client.post(url, json=request_body)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        logger.warning("compress: Gemini API call failed", exc_info=True)
        return []

    return _parse_compress_response(data)


def _parse_compress_response(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Extract compressed descriptions from a Gemini API response."""
    try:
        candidates = data.get("candidates", [])
        if not candidates:
            return []
        text = candidates[0]["content"]["parts"][0]["text"]
        parsed = json.loads(text)
        compressed_list = parsed.get("compressed", [])
    except (KeyError, IndexError, json.JSONDecodeError):
        logger.warning("compress: could not parse Gemini response")
        return []

    return [
        (item["id"], item["text"])
        for item in compressed_list
        if "id" in item and "text" in item
    ]


def _get_model() -> str:
    return os.environ.get("TRENTINA_COMPRESS_MODEL", DEFAULT_COMPRESS_MODEL)
