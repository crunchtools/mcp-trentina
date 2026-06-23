"""SQLite blocklist database for mcp-trentina-crunchtools.

Write access is deterministic code ONLY. The Q-Agent cannot write to this database.
The Q-Agent's detection output is returned as structured JSON, parsed by the server's
deterministic code, which decides whether to record a detection.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from .config import get_config

_db: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source TEXT NOT NULL,
    domain TEXT,
    detected_at TEXT NOT NULL,
    layer1_stats TEXT NOT NULL,
    qagent_assessment TEXT,
    risk_level TEXT NOT NULL,
    blocked BOOLEAN DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_detections_domain ON detections(domain);
CREATE INDEX IF NOT EXISTS idx_detections_source ON detections(source);

CREATE TABLE IF NOT EXISTS gateway_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    profile TEXT NOT NULL,
    backend TEXT NOT NULL,
    tool TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    duration_ms INTEGER NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_gateway_calls_timestamp ON gateway_calls(timestamp);
CREATE INDEX IF NOT EXISTS idx_gateway_calls_profile_tool ON gateway_calls(profile, backend, tool);

CREATE TABLE IF NOT EXISTS tool_compressions (
    description_hash TEXT PRIMARY KEY,
    original_description TEXT NOT NULL,
    compressed_description TEXT NOT NULL,
    model TEXT NOT NULL,
    compressed_at TEXT NOT NULL,
    original_length INTEGER NOT NULL,
    compressed_length INTEGER NOT NULL
);
"""


def get_db(db_path: str | None = None) -> sqlite3.Connection:
    """Get or create the singleton database connection."""
    global _db
    if _db is None:
        path = db_path or get_config().db_path
        get_config().ensure_db_dir()
        _db = sqlite3.connect(path)
        _db.row_factory = sqlite3.Row
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("PRAGMA foreign_keys=ON")
        _db.executescript(SCHEMA)
    return _db


def is_blocked(source: str) -> dict[str, Any] | None:
    """Check if a source is in the blocklist. Returns detection details or None."""
    db = get_db()
    cursor = db.execute(
        "SELECT * FROM detections WHERE source = ? AND blocked = 1 "
        "ORDER BY detected_at DESC LIMIT 1",
        (source,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def is_domain_blocked(domain: str) -> dict[str, Any] | None:
    """Check if any URL from a domain is in the blocklist."""
    db = get_db()
    cursor = db.execute(
        "SELECT * FROM detections WHERE domain = ? AND blocked = 1 "
        "ORDER BY detected_at DESC LIMIT 1",
        (domain,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def record_detection(
    source_type: str,
    source: str,
    domain: str | None,
    layer1_stats: dict[str, Any],
    risk_level: str,
    qagent_assessment: dict[str, Any] | None = None,
) -> int:
    """Record a detection in the blocklist. Returns the detection ID."""
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO detections (source_type, source, domain, detected_at, "
        "layer1_stats, qagent_assessment, risk_level, blocked) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        (
            source_type,
            source,
            domain,
            now,
            json.dumps(layer1_stats),
            json.dumps(qagent_assessment) if qagent_assessment else None,
            risk_level,
        ),
    )
    db.commit()
    return cursor.lastrowid or 0


def get_blocklist_stats() -> dict[str, Any]:
    """Get summary statistics for the blocklist."""
    db = get_db()
    total = db.execute("SELECT COUNT(*) as cnt FROM detections WHERE blocked = 1").fetchone()
    recent = db.execute(
        "SELECT source_type, source, domain, detected_at, risk_level "
        "FROM detections WHERE blocked = 1 "
        "ORDER BY detected_at DESC LIMIT 10"
    ).fetchall()

    by_risk = db.execute(
        "SELECT risk_level, COUNT(*) as cnt FROM detections WHERE blocked = 1 GROUP BY risk_level"
    ).fetchall()

    return {
        "total_blocked": total["cnt"] if total else 0,
        "by_risk_level": {row["risk_level"]: row["cnt"] for row in by_risk},
        "recent_detections": [dict(row) for row in recent],
    }


def record_gateway_call(
    profile: str,
    backend: str,
    tool: str,
    success: bool,
    duration_ms: int,
    error_message: str | None = None,
) -> None:
    """Record a gateway tools/call invocation."""
    db = get_db()
    db.execute(
        "INSERT INTO gateway_calls "
        "(timestamp, profile, backend, tool, success, duration_ms, error_message) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (time.time(), profile, backend, tool, success, duration_ms, error_message),
    )
    db.commit()


def get_gateway_call_stats(
    profile: str | None = None,
    days: int = 30,
) -> dict[str, Any]:
    """Per-backend/per-tool call counts for data-driven allowlist tightening."""
    db = get_db()
    cutoff = time.time() - (days * 86400)

    if profile:
        rows = db.execute(
            "SELECT backend, tool, COUNT(*) as cnt, "
            "SUM(CASE WHEN success THEN 1 ELSE 0 END) as ok, "
            "SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as err "
            "FROM gateway_calls WHERE profile = ? AND timestamp > ? "
            "GROUP BY backend, tool ORDER BY cnt DESC",
            (profile, cutoff),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT backend, tool, COUNT(*) as cnt, "
            "SUM(CASE WHEN success THEN 1 ELSE 0 END) as ok, "
            "SUM(CASE WHEN NOT success THEN 1 ELSE 0 END) as err "
            "FROM gateway_calls WHERE timestamp > ? "
            "GROUP BY backend, tool ORDER BY cnt DESC",
            (cutoff,),
        ).fetchall()

    total_row = db.execute(
        "SELECT COUNT(*) as cnt FROM gateway_calls WHERE timestamp > ?",
        (cutoff,),
    ).fetchone()

    return {
        "total_calls": total_row["cnt"] if total_row else 0,
        "days": days,
        "profile_filter": profile,
        "by_tool": [
            {
                "backend": r["backend"], "tool": r["tool"],
                "calls": r["cnt"], "ok": r["ok"], "errors": r["err"],
            }
            for r in rows
        ],
    }


def get_all_compressions() -> dict[str, str]:
    """Load all cached compressions as {description_hash: compressed_description}."""
    db = get_db()
    rows = db.execute(
        "SELECT description_hash, compressed_description FROM tool_compressions"
    ).fetchall()
    return {row["description_hash"]: row["compressed_description"] for row in rows}


def save_compression(
    description_hash: str,
    original: str,
    compressed: str,
    model: str,
) -> None:
    """Persist a compressed description to SQLite."""
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR REPLACE INTO tool_compressions "
        "(description_hash, original_description, compressed_description, "
        "model, compressed_at, original_length, compressed_length) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (description_hash, original, compressed, model, now, len(original), len(compressed)),
    )
    db.commit()


def get_compression_stats() -> dict[str, Any]:
    """Aggregate compression savings from the tool_compressions table."""
    db = get_db()
    row = db.execute(
        "SELECT COUNT(*) as cnt, "
        "COALESCE(SUM(original_length), 0) as orig, "
        "COALESCE(SUM(compressed_length), 0) as comp "
        "FROM tool_compressions"
    ).fetchone()
    total = row["cnt"] if row else 0
    orig = row["orig"] if row else 0
    comp = row["comp"] if row else 0
    savings = round((1 - comp / orig) * 100) if orig > 0 else 0
    return {
        "tools_compressed": total,
        "original_chars": orig,
        "compressed_chars": comp,
        "savings_percent": savings,
        "estimated_tokens_saved": (orig - comp) // 4,
    }
