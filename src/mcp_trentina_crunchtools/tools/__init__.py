"""Tool implementations for mcp-trentina-crunchtools."""

from __future__ import annotations

from .content import deep_scan_content, quarantine_content, safe_content, scan_content
from .fetch import quarantine_fetch, safe_fetch
from .read import quarantine_read, safe_read
from .scan import deep_quarantine_scan, quarantine_scan
from .search import quarantine_search, safe_search
from .stats import get_trentina_stats

__all__ = [
    "deep_quarantine_scan",
    "deep_scan_content",
    "quarantine_content",
    "quarantine_fetch",
    "quarantine_read",
    "quarantine_scan",
    "quarantine_search",
    "safe_content",
    "safe_fetch",
    "safe_read",
    "safe_search",
    "scan_content",
    "get_trentina_stats",
]
