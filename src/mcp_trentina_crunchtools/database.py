"""SQLite blocklist database for mcp-trentina-crunchtools.

Write access is deterministic code ONLY. The Q-Agent cannot write to this database.
The Q-Agent's detection output is returned as structured JSON, parsed by the server's
deterministic code, which decides whether to record a detection.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import UTC, datetime
from typing import Any

from .config import get_config
from .outcomes import Outcome, group_of

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
    blocked BOOLEAN DEFAULT 1,
    profile TEXT,
    backend TEXT,
    tool TEXT,
    direction TEXT,
    provenance TEXT
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
    error_message TEXT,
    outcome TEXT
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

CREATE TABLE IF NOT EXISTS tool_list_cache (
    backend_url TEXT PRIMARY KEY,
    tools_json TEXT NOT NULL,
    cached_at TEXT NOT NULL
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
        _migrate(_db)
    return _db


def _migrate(db: sqlite3.Connection) -> None:
    """Apply additive schema migrations to a database created by an older build.

    ``CREATE TABLE IF NOT EXISTS`` leaves a pre-existing table untouched, so a
    column added to SCHEMA never reaches an existing deployment without this.
    Additive only — no column is dropped and no row is rewritten.
    """
    columns = {row["name"] for row in db.execute("PRAGMA table_info(gateway_calls)")}
    if "outcome" not in columns:
        db.execute("ALTER TABLE gateway_calls ADD COLUMN outcome TEXT")

    detection_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(detections)")
    }
    # Gateway attribution columns (which profile, which backend and tool,
    # which direction the content was moving, and the provenance the L3
    # gate saw). Nullable — 50 web-shaped legacy rows and the standalone
    # tools carry none of this.
    for column in ("profile", "backend", "tool", "direction", "provenance"):
        if column not in detection_columns:
            db.execute(f"ALTER TABLE detections ADD COLUMN {column} TEXT")
        db.commit()


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
    profile: str | None = None,
    backend: str | None = None,
    tool: str | None = None,
    direction: str | None = None,
    provenance: str | None = None,
    blocked: bool = True,
) -> int:
    """Record a detection. Returns the detection ID.

    ``blocked`` was hardcoded 1, which was true when every caller refused
    flagged content. Annotate-mode gateway rows are observations, not
    blocks, and recording them as blocks would poison both the blocklist
    semantics and step 7's calibration read.
    """
    db = get_db()
    now = datetime.now(UTC).isoformat()
    cursor = db.execute(
        "INSERT INTO detections (source_type, source, domain, detected_at, "
        "layer1_stats, qagent_assessment, risk_level, blocked, "
        "profile, backend, tool, direction, provenance) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            source_type,
            source,
            domain,
            now,
            json.dumps(layer1_stats),
            json.dumps(qagent_assessment) if qagent_assessment else None,
            risk_level,
            1 if blocked else 0,
            profile,
            backend,
            tool,
            direction,
            provenance,
        ),
    )
    db.commit()
    return cursor.lastrowid or 0


def get_blocklist_stats(profile: str | None = None) -> dict[str, Any]:
    """Get summary statistics for the blocklist, optionally for one profile.

    The *profile* filter matters more here than the column suggests. A
    detection's ``source`` is written as ``profile:backend:tool``, so an
    unfiltered ``recent_detections`` hands the reader other agents' names, the
    backends they call and the URLs they fetched. Rows that predate the
    attribution columns have a NULL profile and belong to no one; a filtered
    query correctly leaves them out rather than crediting them to whoever asked.

    Returns:
        ``total_blocked``, ``by_risk_level``, ``recent_detections``, and
        ``profile_filter`` — the profile the numbers are for, or None for the
        whole gateway, so a reader never has to guess which it got.
    """
    db = get_db()
    # Same idiom as get_gateway_call_stats above: fixed query templates with
    # one optional clause, the value always bound as a parameter.
    clause = " AND profile = ?" if profile else ""
    args: tuple[Any, ...] = (profile,) if profile else ()

    total_query = (
        "SELECT COUNT(*) as cnt FROM detections WHERE blocked = 1{profile_clause}"
    )
    recent_query = (
        "SELECT source_type, source, domain, detected_at, risk_level "
        "FROM detections WHERE blocked = 1{profile_clause} "
        "ORDER BY detected_at DESC LIMIT 10"
    )
    risk_query = (
        "SELECT risk_level, COUNT(*) as cnt FROM detections "
        "WHERE blocked = 1{profile_clause} GROUP BY risk_level"
    )

    total = db.execute(total_query.format(profile_clause=clause), args).fetchone()
    recent = db.execute(recent_query.format(profile_clause=clause), args).fetchall()
    by_risk = db.execute(risk_query.format(profile_clause=clause), args).fetchall()

    return {
        "total_blocked": total["cnt"] if total else 0,
        "by_risk_level": {row["risk_level"]: row["cnt"] for row in by_risk},
        "recent_detections": [dict(row) for row in recent],
        "profile_filter": profile,
    }


def record_gateway_call(
    profile: str,
    backend: str,
    tool: str,
    outcome: str,
    duration_ms: int,
    error_message: str | None = None,
) -> None:
    """Record a gateway tools/call invocation.

    ``success`` is derived from *outcome* rather than passed in, so the legacy
    boolean can never disagree with the taxonomy. It keeps its original
    meaning — the call returned usable content — which means a fail-closed
    defense block still reads as ``success = 0``, exactly as it did before.
    """
    db = get_db()
    success = outcome == Outcome.OK.value
    db.execute(
        "INSERT INTO gateway_calls "
        "(timestamp, profile, backend, tool, success, duration_ms, error_message, "
        "outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            time.time(),
            profile,
            backend,
            tool,
            success,
            duration_ms,
            error_message,
            outcome,
        ),
    )
    db.commit()


def reset_gateway_calls() -> int:
    """Delete every audit row. Returns the number removed.

    Deliberately not exposed as an MCP tool: erasing the audit trail is not a
    capability any consumer profile should hold. Operators run it directly.
    """
    db = get_db()
    before = db.execute("SELECT COUNT(*) AS cnt FROM gateway_calls").fetchone()["cnt"]
    db.execute("DELETE FROM gateway_calls")
    db.commit()
    return int(before)


def get_gateway_call_stats(
    profile: str | None = None,
    days: int = 30,
) -> dict[str, Any]:
    """Per-backend/per-tool call outcomes for allowlist tuning and health checks.

    Reports ``ok`` / ``blocked`` / ``failed`` as separate columns. A single
    "errors" number cannot be read correctly: it mixes fail-closed defense
    blocks (working as designed) with genuine breakage, which is how a tool
    that blocked 34 hostile pages came to look like a tool that was broken.
    Only ``failed`` is a health signal.

    A NULL outcome means the row predates the taxonomy. It is reported as
    "unknown" rather than guessed at: back-fitting an outcome from the old
    boolean would reintroduce the ambiguity this change removes.
    """
    db = get_db()
    cutoff = time.time() - (days * 86400)

    query = (
        "SELECT backend, tool, outcome, COUNT(*) AS cnt FROM gateway_calls "
        "WHERE timestamp > ?{profile_clause} GROUP BY backend, tool, outcome"
    )
    if profile:
        rows = db.execute(
            query.format(profile_clause=" AND profile = ?"), (cutoff, profile)
        ).fetchall()
    else:
        rows = db.execute(query.format(profile_clause=""), (cutoff,)).fetchall()

    per_tool: dict[tuple[str, str], dict[str, Any]] = {}
    totals: dict[str, int] = {"ok": 0, "blocked": 0, "failed": 0, "unknown": 0}
    for row in rows:
        key = (row["backend"], row["tool"])
        entry = per_tool.setdefault(
            key,
            {
                "backend": row["backend"],
                "tool": row["tool"],
                "calls": 0,
                "ok": 0,
                "blocked": 0,
                "failed": 0,
                "unknown": 0,
                "outcomes": {},
            },
        )
        raw = row["outcome"] or "legacy"
        group = group_of(raw)
        count = int(row["cnt"])
        entry["calls"] += count
        entry[group] += count
        entry["outcomes"][raw] = entry["outcomes"].get(raw, 0) + count
        totals[group] += count

    by_tool = sorted(per_tool.values(), key=lambda e: int(e["calls"]), reverse=True)

    return {
        "total_calls": sum(totals.values()),
        "days": days,
        "profile_filter": profile,
        "totals": totals,
        "by_tool": by_tool,
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
    now = datetime.now(UTC).isoformat()
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


def get_all_tool_lists() -> dict[str, list[dict[str, Any]]]:
    """Load all cached tool lists as {backend_url: tools_list}."""
    db = get_db()
    rows = db.execute(
        "SELECT backend_url, tools_json FROM tool_list_cache"
    ).fetchall()
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        result[row["backend_url"]] = json.loads(row["tools_json"])
    return result


def save_tool_list(
    backend_url: str, tools: list[dict[str, Any]],
) -> None:
    """Persist a tool list to SQLite."""
    db = get_db()
    now = datetime.now(UTC).isoformat()
    db.execute(
        "INSERT OR REPLACE INTO tool_list_cache "
        "(backend_url, tools_json, cached_at) VALUES (?, ?, ?)",
        (backend_url, json.dumps(tools), now),
    )
    db.commit()


def delete_tool_list(backend_url: str) -> None:
    """Delete one backend's cached tool list."""
    db = get_db()
    db.execute(
        "DELETE FROM tool_list_cache WHERE backend_url = ?",
        (backend_url,),
    )
    db.commit()


def delete_all_tool_lists() -> None:
    """Flush all cached tool lists."""
    db = get_db()
    db.execute("DELETE FROM tool_list_cache")
    db.commit()
