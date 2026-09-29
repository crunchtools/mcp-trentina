"""The blocklist: cumulative detection memory for fetch.

A URL refused once in block mode is refused again before any bytes are
fetched, for every caller, so a known-bad page costs no second scan.
Reduced from database.py and tools/fetch.py as of 0.47.0 (see #263).
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Any

from mcp_trentina_crunchtools.errors import BlockedSourceError

_db = sqlite3.connect("/data/trentina.db")
_db.row_factory = sqlite3.Row
_db.execute(
    "CREATE TABLE IF NOT EXISTS detections ("
    " id INTEGER PRIMARY KEY, source TEXT NOT NULL, detected_at TEXT NOT NULL,"
    " risk_level TEXT, blocked INTEGER NOT NULL DEFAULT 1)"
)


def record_detection(source: str, risk_level: str) -> None:
    """Remember a refused source."""
    _db.execute(
        "INSERT INTO detections (source, detected_at, risk_level, blocked) VALUES (?, ?, ?, 1)",
        (source, datetime.now(UTC).isoformat(), risk_level),
    )
    _db.commit()


def is_blocked(source: str) -> dict[str, Any] | None:
    """The newest blocking detection for ``source``, or None."""
    row = _db.execute(
        "SELECT * FROM detections WHERE source = ? AND blocked = 1 "
        "ORDER BY detected_at DESC LIMIT 1",
        (source,),
    ).fetchone()
    return dict(row) if row else None


async def fetch_page(url: str, profile_name: str) -> dict[str, Any]:
    """Refuse a blocklisted URL up front; otherwise fetch and judge it.

    ``profile_name`` is the calling gateway profile; every agent profile
    (kagetora, takeda, josui) holds fetch_tool.
    """
    blocked = is_blocked(url)
    if blocked:
        raise BlockedSourceError(url, f"on the blocklist since {blocked['detected_at']}")
    return await _fetch_and_judge(url, profile_name)


async def _fetch_and_judge(url: str, profile_name: str) -> dict[str, Any]:
    raise NotImplementedError  # fetch, defend(), record_detection(url, ...) on a block
