"""SQLite blocklist database for mcp-airlock-crunchtools.

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

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    tool TEXT,
    source TEXT,
    trust_level TEXT,
    risk_level TEXT,
    duration_ms INTEGER,
    l1_detections INTEGER DEFAULT 0,
    l2_label TEXT,
    l2_score REAL,
    l3_model TEXT,
    l3_injection_detected BOOLEAN,
    l3_confidence TEXT,
    input_size INTEGER,
    output_size INTEGER,
    stats_json TEXT,
    raw_content TEXT,
    sanitized_content TEXT,
    l3_extracted_text TEXT,
    l3_input_tokens INTEGER,
    l3_output_tokens INTEGER
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_tool ON events(tool);

CREATE TABLE IF NOT EXISTS trusted_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    added_at TEXT NOT NULL,
    source TEXT DEFAULT 'manual'
);
"""


def get_db(db_path: str | None = None) -> sqlite3.Connection:
    """Get or create the singleton database connection."""
    global _db
    if _db is None:
        path = db_path or get_config().db_path
        get_config().ensure_db_dir()
        _db = sqlite3.connect(path, check_same_thread=False)
        _db.row_factory = sqlite3.Row
        _db.execute("PRAGMA journal_mode=WAL")
        _db.execute("PRAGMA foreign_keys=ON")
        _db.executescript(SCHEMA)
        seed_trusted_domains_from_config(_db)
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


def record_event(event_id: str, event_data: dict[str, Any]) -> None:
    """Persist an event to the events table."""
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO events "
        "(event_id, event_type, timestamp, tool, source, trust_level, risk_level, "
        "duration_ms, l1_detections, l2_label, l2_score, l3_model, "
        "l3_injection_detected, l3_confidence, input_size, output_size, "
        "stats_json, raw_content, sanitized_content, l3_extracted_text, "
        "l3_input_tokens, l3_output_tokens) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event_id,
            "request_processed",
            event_data.get("timestamp", time.time()),
            event_data.get("tool"),
            event_data.get("source"),
            event_data.get("trust_level"),
            event_data.get("risk_level"),
            event_data.get("duration_ms"),
            event_data.get("l1_detections", 0),
            event_data.get("l2_label"),
            event_data.get("l2_score"),
            event_data.get("l3_model"),
            event_data.get("l3_injection_detected"),
            event_data.get("l3_confidence"),
            event_data.get("input_size"),
            event_data.get("output_size"),
            json.dumps(event_data.get("stats", {})),
            event_data.get("raw_content"),
            event_data.get("sanitized_content"),
            event_data.get("l3_extracted_text"),
            event_data.get("l3_input_tokens"),
            event_data.get("l3_output_tokens"),
        ),
    )
    db.commit()


def get_recent_events(count: int = 100) -> list[dict[str, Any]]:
    """Query recent events from SQLite, ordered by timestamp DESC."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
        (count,),
    ).fetchall()
    results = []
    for row in rows:
        event = dict(row)
        # Parse stats_json back to dict for consistency with ring buffer format
        if event.get("stats_json"):
            try:
                event["stats"] = json.loads(event["stats_json"])
            except (json.JSONDecodeError, TypeError):
                event["stats"] = {}
        else:
            event["stats"] = {}
        del event["stats_json"]
        results.append(event)
    # Return in chronological order (oldest first) to match ring buffer convention
    results.reverse()
    return results


def get_event(event_id: str) -> dict[str, Any] | None:
    """Look up a single event by ID."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    if not row:
        return None
    event = dict(row)
    if event.get("stats_json"):
        try:
            event["stats"] = json.loads(event["stats_json"])
        except (json.JSONDecodeError, TypeError):
            event["stats"] = {}
    else:
        event["stats"] = {}
    del event["stats_json"]
    return event


# -- Trusted domains CRUD --


def seed_trusted_domains_from_config(db: sqlite3.Connection) -> None:
    """One-time seed of trusted_domains table from JSON config.

    Only seeds if the table is empty — subsequent management is via
    SQLite CRUD (D-Bus/Cockpit).
    """
    count = db.execute("SELECT COUNT(*) as cnt FROM trusted_domains").fetchone()
    if count and count["cnt"] > 0:
        return

    config = get_config()
    domains = config._trust_config.get("trusted_domains", [])
    if not isinstance(domains, list) or not domains:
        return

    now = datetime.now(timezone.utc).isoformat()
    for domain in domains:
        if isinstance(domain, str) and domain.strip():
            try:
                db.execute(
                    "INSERT OR IGNORE INTO trusted_domains (domain, added_at, source) "
                    "VALUES (?, ?, ?)",
                    (domain.strip(), now, "json-seed"),
                )
            except sqlite3.IntegrityError:
                pass
    db.commit()


def get_trusted_domains() -> list[dict[str, Any]]:
    """Return all trusted domains from SQLite."""
    db = get_db()
    rows = db.execute(
        "SELECT id, domain, added_at, source FROM trusted_domains ORDER BY domain"
    ).fetchall()
    return [dict(row) for row in rows]


def add_trusted_domain(domain: str, source: str = "manual") -> int:
    """Add a domain to the trust list. Returns the row ID."""
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT OR IGNORE INTO trusted_domains (domain, added_at, source) "
        "VALUES (?, ?, ?)",
        (domain.strip(), now, source),
    )
    db.commit()
    return cursor.lastrowid or 0


def remove_trusted_domain(domain: str) -> bool:
    """Remove a domain from the trust list. Returns True if deleted."""
    db = get_db()
    cursor = db.execute(
        "DELETE FROM trusted_domains WHERE domain = ?",
        (domain.strip(),),
    )
    db.commit()
    return cursor.rowcount > 0


def is_domain_trusted(url: str) -> bool:
    """Check if a URL's domain is in the SQLite trusted_domains table."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except ValueError:
        return False

    db = get_db()
    # Check exact match and parent domain match
    rows = db.execute("SELECT domain FROM trusted_domains").fetchall()
    for row in rows:
        td = row["domain"]
        if hostname == td or hostname.endswith(f".{td}"):
            return True
    return False


def import_trusted_domains(domains: list[str], source: str = "import") -> int:
    """Bulk-import domains. Returns count of newly added domains."""
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    added = 0
    for domain in domains:
        if isinstance(domain, str) and domain.strip():
            try:
                cursor = db.execute(
                    "INSERT OR IGNORE INTO trusted_domains (domain, added_at, source) "
                    "VALUES (?, ?, ?)",
                    (domain.strip(), now, source),
                )
                if cursor.rowcount > 0:
                    added += 1
            except sqlite3.IntegrityError:
                pass
    db.commit()
    return added
