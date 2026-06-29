"""Shared utilities for proxy modules (LLM, Matrix)."""

from __future__ import annotations

from urllib.parse import unquote


def sanitize_proxy_path(raw_path: str) -> str | None:
    """Strip path traversal sequences. Returns None if the path is malicious."""
    decoded = unquote(raw_path)
    segments = decoded.replace("\\", "/").split("/")
    clean = [s for s in segments if s not in (".", "..")]
    if len(clean) != len(segments):
        return None
    return "/".join(clean)
