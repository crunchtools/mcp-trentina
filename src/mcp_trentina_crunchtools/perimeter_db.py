"""The perimeter's own store — what the defense pipeline CONCLUDED.

Separate from ``database.py`` on purpose, and the reason is worth stating
plainly because it is not a security boundary today.

``database.py`` holds dirty data: the blocklist, call audit, compressed
descriptions, and the tool lists backends handed us. This file holds the
opposite kind of fact — the verdict ``defend()`` reached about a piece of
content. Splitting them buys nothing on a single-uid deployment: both files
are owned by the process that reads them, and anyone who can rewrite one
can rewrite the other, the code, or the image. Anything stronger would
need the rows signed, not merely filed apart.

What the split buys is the OPTION. If these ever move to a real database,
two stores can have two owners, two grants, and two code paths; one table
next to the blocklist cannot be given any of that afterwards without
finding every caller that assumed a single connection. That is the whole
argument, and it is an argument about tomorrow.

What is here is a cache and only a cache. Losing this file costs one slow
restart and nothing else.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .config import get_config

logger = logging.getLogger(__name__)

_db: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS verdict_cache (
    cache_key TEXT PRIMARY KEY,
    warning_json TEXT,
    perimeter_version TEXT NOT NULL,
    cached_at TEXT NOT NULL
);
"""

# Bump this whenever a change could alter what a scan CONCLUDES: a new
# detector, a retuned L3 prompt, a different L2 model or threshold set.
# Rows stamped with any other value are ignored on load and swept, which is
# what makes a verdict reached by an older perimeter unusable rather than
# merely old. Thresholds are already inside the cache key; this covers
# everything that is not.
PERIMETER_VERSION = "1"


def get_perimeter_db(db_path: str | None = None) -> sqlite3.Connection:
    """Get or create the perimeter store's connection."""
    global _db
    if _db is None:
        config = get_config()
        path = db_path or config.perimeter_db_path
        config.ensure_perimeter_db_dir()
        _db = sqlite3.connect(path)
        _db.row_factory = sqlite3.Row
        _db.execute("PRAGMA journal_mode=WAL")
        _db.executescript(SCHEMA)
    return _db


def get_all_verdicts(perimeter_version: str) -> dict[str, dict[str, Any] | None]:
    """Load the verdicts this perimeter version reached.

    Rows from any other version are deleted rather than returned: a verdict
    is only meaningful for the detector set that produced it.
    """
    db = get_perimeter_db()
    swept = db.execute(
        "DELETE FROM verdict_cache WHERE perimeter_version != ?",
        (perimeter_version,),
    ).rowcount
    db.commit()
    if swept > 0:
        logger.info(
            "perimeter: swept %d verdict(s) from an older perimeter version", swept
        )
    rows = db.execute(
        "SELECT cache_key, warning_json FROM verdict_cache WHERE perimeter_version = ?",
        (perimeter_version,),
    ).fetchall()
    out: dict[str, dict[str, Any] | None] = {}
    unreadable: list[str] = []
    for key, blob in rows:
        try:
            out[key] = json.loads(blob) if blob is not None else None
        except json.JSONDecodeError:
            unreadable.append(key)

    if unreadable:
        # A row we cannot read is a row we rescan, and leaving it in place
        # means rescanning it on every boot forever. Delete it and say so.
        db.executemany(
            "DELETE FROM verdict_cache WHERE cache_key = ?",
            [(key,) for key in unreadable],
        )
        db.commit()
        logger.warning(
            "perimeter: deleted %d unreadable verdict row(s)", len(unreadable)
        )
    return out


def save_verdict(
    cache_key: str,
    warning: dict[str, Any] | None,
    perimeter_version: str,
) -> None:
    """Persist one verdict. ``warning`` is None for a clean result."""
    db = get_perimeter_db()
    db.execute(
        "INSERT OR REPLACE INTO verdict_cache "
        "(cache_key, warning_json, perimeter_version, cached_at) VALUES (?, ?, ?, ?)",
        (
            cache_key,
            None if warning is None else json.dumps(warning),
            perimeter_version,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    db.commit()


def delete_all_verdicts() -> int:
    """Flush every persisted verdict, forcing a full rescan on next boot."""
    db = get_perimeter_db()
    count = db.execute("DELETE FROM verdict_cache").rowcount
    db.commit()
    return count
