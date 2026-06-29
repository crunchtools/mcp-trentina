"""Shared utilities for proxy modules (LLM, Matrix)."""

from __future__ import annotations

from urllib.parse import unquote

STRIP_REQUEST_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection",
})

STRIP_RESPONSE_HEADERS = frozenset({
    "content-encoding", "content-length", "transfer-encoding", "connection",
})

PLAIN_TEXT = "text/plain"


def sanitize_proxy_path(raw_path: str) -> str | None:
    """Strip path traversal sequences. Returns None if the path is malicious."""
    decoded = unquote(raw_path)
    segments = decoded.replace("\\", "/").split("/")
    clean = [s for s in segments if s not in (".", "..")]
    if len(clean) != len(segments):
        return None
    return "/".join(clean)


def forward_request_headers(
    raw_headers: list[tuple[str, str]],
) -> dict[str, str]:
    """Filter incoming request headers for upstream forwarding."""
    return {k: v for k, v in raw_headers if k.lower() not in STRIP_REQUEST_HEADERS}


def filter_response_headers(
    raw_headers: list[tuple[str, str]],
) -> dict[str, str]:
    """Filter upstream response headers for client forwarding."""
    return {k: v for k, v in raw_headers if k.lower() not in STRIP_RESPONSE_HEADERS}
