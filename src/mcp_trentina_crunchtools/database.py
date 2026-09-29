"""SQLite blocklist database for mcp-trentina-crunchtools.

Write access is deterministic code ONLY. The Q-Agent cannot write to this database.
The Q-Agent's detection output is returned as structured JSON, parsed by the server's
deterministic code, which decides whether to record a detection.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import UTC, datetime, timedelta
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
    provenance TEXT,
    flagged_by TEXT,
    l2_label TEXT,
    l2_score REAL,
    l3_verdict TEXT,
    l3_risk TEXT
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
    outcome TEXT,
    bytes_arrived INTEGER,
    bytes_delivered INTEGER,
    normalized TEXT
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

CREATE TABLE IF NOT EXISTS tool_names (
    profile TEXT NOT NULL,
    issued TEXT NOT NULL,
    backend TEXT NOT NULL,
    tool TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    PRIMARY KEY (profile, issued),
    UNIQUE (profile, backend, tool)
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


_VERDICT_COLUMNS = (
    ("flagged_by", "TEXT"),
    ("l2_label", "TEXT"),
    ("l2_score", "REAL"),
    ("l3_verdict", "TEXT"),
    ("l3_risk", "TEXT"),
)


def _migrate(db: sqlite3.Connection) -> None:
    """Apply additive schema migrations to a database created by an older build.

    ``CREATE TABLE IF NOT EXISTS`` leaves a pre-existing table untouched, so a
    column added to SCHEMA never reaches an existing deployment without this.
    Additive only — no column is dropped and no row is rewritten.
    """
    columns = {row["name"] for row in db.execute("PRAGMA table_info(gateway_calls)")}
    if "outcome" not in columns:
        db.execute("ALTER TABLE gateway_calls ADD COLUMN outcome TEXT")
    # Response sizes as they arrived and as they were delivered. Nullable:
    # older rows, denials that never reached a backend, and internal tools
    # (which minify inside the tool) have no arrived size.
    for column in ("bytes_arrived", "bytes_delivered"):
        if column not in columns:
            db.execute(f"ALTER TABLE gateway_calls ADD COLUMN {column} INTEGER")
    # Arguments the gateway dropped before forwarding, as JSON (#241).
    if "normalized" not in columns:
        db.execute("ALTER TABLE gateway_calls ADD COLUMN normalized TEXT")
    db.commit()

    detection_columns = {row["name"] for row in db.execute("PRAGMA table_info(detections)")}
    # Gateway attribution columns (which profile, which backend and tool,
    # which direction the content was moving, and the provenance the L3
    # gate saw). Nullable — 50 web-shaped legacy rows and the standalone
    # tools carry none of this.
    for column in ("profile", "backend", "tool", "direction", "provenance"):
        if column not in detection_columns:
            db.execute(f"ALTER TABLE detections ADD COLUMN {column} TEXT")
        db.commit()
    # Every layer's opinion on the row, not only the credited one's (#204).
    # A row credited to L2 used to say nothing about what L3 thought, so how
    # often L3 disagreed with an L2 flag could not be measured, and that is
    # the number any rule letting L3 overrule L2 has to be argued from.
    for column, sql_type in _VERDICT_COLUMNS:
        if column not in detection_columns:
            db.execute(f"ALTER TABLE detections ADD COLUMN {column} {sql_type}")
        db.commit()
    # The blocklist is keyed on (profile, source) since #263. Created here, not
    # in SCHEMA: on a table that predates the profile column, SCHEMA runs
    # before the ALTER above and an index naming the column would fail the
    # open. Rows written before #263 by the web tools carry a NULL profile and
    # are read as operator-only; nothing is rewritten.
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_detections_profile_source ON detections(profile, source)"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_detections_detected_at ON detections(detected_at)")
    db.commit()


def _block_cutoff() -> str:
    """The oldest ``detected_at`` a blocklist row may carry and still count."""
    ttl = timedelta(days=get_config().blocklist_ttl_days)
    return (datetime.now(UTC) - ttl).isoformat()


_SWEEP_INTERVAL_SECONDS = 3600.0
_last_sweep = 0.0


def sweep_expired_blocks(db: sqlite3.Connection | None = None) -> int:
    """Delete blocklist rows past ``TRENTINA_BLOCKLIST_TTL_DAYS`` (#263).

    Readers filter on the cutoff themselves, so an expired row never counts
    whether or not a sweep has run; the sweep only stops the table from
    holding what no reader will use. ``is_blocked`` runs it at most hourly,
    the first time on the first lookup after start. Flag-mode observations (``blocked = 0``)
    are not blocklist rows and are kept.

    Returns:
        The number of rows removed.
    """
    global _last_sweep
    conn = db or get_db()
    cursor = conn.execute(
        "DELETE FROM detections WHERE blocked = 1 AND detected_at <= ?", (_block_cutoff(),)
    )
    conn.commit()
    _last_sweep = time.monotonic()
    return cursor.rowcount


def _maybe_sweep(db: sqlite3.Connection) -> None:
    if time.monotonic() - _last_sweep >= _SWEEP_INTERVAL_SECONDS:
        sweep_expired_blocks(db)


def is_blocked(source: str, profile: str | None, *, gateway_wide: bool = False) -> bool:
    """Whether *source* is on the blocklist as *profile* sees it (#263).

    The blocklist is keyed on ``(profile, source)``. It used to be keyed on
    the source alone, so one profile's refusal was every profile's refusal:
    profile A getting ``?slot=N`` flagged was a bit profile B could read, with
    A's timestamp attached, and rows never expired.

    Args:
        source: The URL, resolved path or content hash.
        profile: The calling agent profile. Its own rows count and nobody
            else's; rows with a NULL profile (written before #263, or by a
            standalone server) are operator-only. None with
            ``gateway_wide`` False — a live gateway with no bound caller —
            sees nothing.
        gateway_wide: Every live row, whoever wrote it. Operator and
            standalone scope only; the caller decides that, not this module.

    Returns:
        True or False and nothing else: no row, no timestamp. What a refusal
        can say is decided here, and it is one bit about the caller's own
        history.
    """
    db = get_db()
    _maybe_sweep(db)
    query = (
        "SELECT 1 FROM detections WHERE source = ? AND blocked = 1 "
        "AND detected_at > ?{profile_clause} LIMIT 1"
    )
    if gateway_wide:
        row = db.execute(query.format(profile_clause=""), (source, _block_cutoff())).fetchone()
    elif profile:
        row = db.execute(
            query.format(profile_clause=" AND profile = ?"), (source, _block_cutoff(), profile)
        ).fetchone()
    else:
        return False
    return row is not None


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
    verdicts: dict[str, Any] | None = None,
) -> int:
    """Record a detection. Returns the detection ID.

    ``blocked`` was hardcoded 1, which was true when every caller refused
    flagged content. Flag-mode gateway rows are observations, not
    blocks, and recording them as blocks would poison both the blocklist
    semantics and step 7's calibration read.

    ``verdicts`` holds every layer's opinion whichever one is credited:
    ``flagged_by``, ``l2_label``, ``l2_score``, ``l3_verdict`` (``flagged``,
    ``clean`` or ``unavailable``) and ``l3_risk``. A missing key is NULL.
    """
    db = get_db()
    now = datetime.now(UTC).isoformat()
    cursor = db.execute(
        "INSERT INTO detections (source_type, source, domain, detected_at, "
        "layer1_stats, qagent_assessment, risk_level, blocked, "
        "profile, backend, tool, direction, provenance, "
        # The last five in _VERDICT_COLUMNS order, which the values below are
        # read in; test_database pins the two orders together.
        "flagged_by, l2_label, l2_score, l3_verdict, l3_risk) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            *((verdicts or {}).get(column) for column, _ in _VERDICT_COLUMNS),
        ),
    )
    db.commit()
    return cursor.lastrowid or 0


def get_blocklist_stats(profile: str | None = None) -> dict[str, Any]:
    """Get summary statistics for the live blocklist, optionally for one profile.

    Unfiltered is the gateway-wide view, for operator scope only; every agent
    caller passes its own name (``tools/stats.py``).

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
    # Expired rows are off the blocklist (#263) and are not counted as on it.
    clause = " AND detected_at > ?" + (" AND profile = ?" if profile else "")
    args: tuple[Any, ...] = (_block_cutoff(), profile) if profile else (_block_cutoff(),)

    total_query = "SELECT COUNT(*) as cnt FROM detections WHERE blocked = 1{profile_clause}"
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
    bytes_arrived: int | None = None,
    bytes_delivered: int | None = None,
    normalized: dict[str, str] | None = None,
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
        "outcome, bytes_arrived, bytes_delivered, normalized) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            time.time(),
            profile,
            backend,
            tool,
            success,
            duration_ms,
            error_message,
            outcome,
            bytes_arrived,
            bytes_delivered,
            json.dumps(normalized) if normalized else None,
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
        "delivery": _delivery_stats(db, cutoff, profile),
    }


def _delivery_stats(db: sqlite3.Connection, cutoff: float, profile: str | None) -> dict[str, Any]:
    """Response bytes as they arrived from backends vs. as agents received them.

    Only rows carrying BOTH sizes count. An internal tool minifies inside the
    tool, so the router never saw what arrived; counting its delivered bytes
    against nothing would report a saving that was never measured.
    """
    query = (
        "SELECT backend, tool, COUNT(*) AS cnt, SUM(bytes_arrived) AS arrived, "
        "SUM(bytes_delivered) AS delivered FROM gateway_calls "
        "WHERE timestamp > ? AND bytes_arrived IS NOT NULL "
        "AND bytes_delivered IS NOT NULL{profile_clause} GROUP BY backend, tool"
    )
    if profile:
        rows = db.execute(
            query.format(profile_clause=" AND profile = ?"), (cutoff, profile)
        ).fetchall()
    else:
        rows = db.execute(query.format(profile_clause=""), (cutoff,)).fetchall()

    arrived = sum(int(r["arrived"]) for r in rows)
    delivered = sum(int(r["delivered"]) for r in rows)
    by_saving = sorted(rows, key=lambda r: int(r["arrived"]) - int(r["delivered"]), reverse=True)
    return {
        "calls_measured": sum(int(r["cnt"]) for r in rows),
        "bytes_arrived": arrived,
        "bytes_delivered": delivered,
        "savings_percent": round((1 - delivered / arrived) * 100) if arrived > 0 else 0,
        "estimated_tokens_saved": (arrived - delivered) // 4,
        "top_tools": [
            {
                "backend": r["backend"],
                "tool": r["tool"],
                "calls": int(r["cnt"]),
                "bytes_arrived": int(r["arrived"]),
                "bytes_delivered": int(r["delivered"]),
            }
            for r in by_saving[:10]
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
    rows = db.execute("SELECT backend_url, tools_json FROM tool_list_cache").fetchall()
    result: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        result[row["backend_url"]] = json.loads(row["tools_json"])
    return result


def save_tool_list(
    backend_url: str,
    tools: list[dict[str, Any]],
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


def issued_tool_names(profile: str) -> dict[str, tuple[str, str]]:
    """Every short tool name issued to a profile: {issued: (backend, tool)}."""
    rows = (
        get_db()
        .execute("SELECT issued, backend, tool FROM tool_names WHERE profile = ?", (profile,))
        .fetchall()
    )
    return {row["issued"]: (row["backend"], row["tool"]) for row in rows}


def issued_tool_name(profile: str, issued: str) -> tuple[str, str] | None:
    """The (backend, tool) one issued name stands for, if it was issued."""
    row = (
        get_db()
        .execute(
            "SELECT backend, tool FROM tool_names WHERE profile = ? AND issued = ?",
            (profile, issued),
        )
        .fetchone()
    )
    return (row["backend"], row["tool"]) if row else None


def issue_tool_names(profile: str, names: dict[str, tuple[str, str]]) -> None:
    """Record newly issued names. An issued name is never reassigned."""
    if not names:
        return
    db = get_db()
    now = datetime.now(UTC).isoformat()
    db.executemany(
        "INSERT OR IGNORE INTO tool_names (profile, issued, backend, tool, issued_at) "
        "VALUES (?, ?, ?, ?, ?)",
        [(profile, issued, backend, tool, now) for issued, (backend, tool) in names.items()],
    )
    db.commit()
