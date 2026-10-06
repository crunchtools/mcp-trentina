"""What the bridge remembers: which local room, user and event is which remote one.

One SQLite file per profile, beside the blocklist. Nothing here is a secret
and nothing is a verdict — it is bookkeeping, and losing it costs duplicated
rooms rather than a breach. It is still kept per profile, because one agent's
room list is the shape of its conversations and nobody else's business.

Both directions write to ``events``: a reply, reaction, edit or redaction
names another event by ID, and that ID has to be translated into the other
side's before the relation means anything. ``processed`` is the dedupe for
retried deliveries: the bridge re-sends until the gateway acks, and Conduit
re-sends a transaction until the appservice answers, so both arrive twice
sometimes by design.

Both grow with every message, so both are pruned after ``RETENTION_DAYS``.
A retry is minutes old, not weeks; a reply to a month-old message loses its
relation and arrives as a plain message, which ``rewrite`` already handles.
Rooms, users and memberships are bounded by the conversations themselves
and are kept.

``room_audience`` is the one table here that a decision reads (#264): whether
an upstream room holds another bridged agent, as the bridge last reported its
members or as an event from one proved. A room with no row has never had its
members reported, and outbound refuses it. Losing the table costs a refused
reply until the bridge next announces the room, which it does on every start
for every room it is still in. A room it leaves is reported as left instead,
and its rows go with the mirror it retires (#317).
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rooms (
    remote_id TEXT PRIMARY KEY,
    local_id  TEXT NOT NULL UNIQUE,
    name      TEXT NOT NULL DEFAULT '',
    topic     TEXT NOT NULL DEFAULT '',
    owner     TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
    remote_id   TEXT PRIMARY KEY,
    local_id    TEXT NOT NULL UNIQUE,
    displayname TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS members (
    local_room TEXT NOT NULL,
    local_user TEXT NOT NULL,
    PRIMARY KEY (local_room, local_user)
);
CREATE TABLE IF NOT EXISTS events (
    remote_id TEXT NOT NULL UNIQUE,
    local_id  TEXT NOT NULL UNIQUE,
    created   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS events_created ON events (created);
CREATE TABLE IF NOT EXISTS processed (
    key     TEXT PRIMARY KEY,
    created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS processed_created ON processed (created);
CREATE TABLE IF NOT EXISTS room_audience (
    remote_id     TEXT PRIMARY KEY,
    agent_present INTEGER NOT NULL,
    reported      REAL NOT NULL
);
"""

RETENTION_DAYS = 30
# Prune once per this many writes rather than on a timer: the store has no
# task of its own, and a quiet bridge has nothing to prune.
_PRUNE_EVERY = 500


@dataclass(frozen=True)
class Room:
    """A mapped room and the metadata last mirrored into it.

    ``owner`` is the local user that administers the room: empty for a room
    the appservice bot created, or the stand-in of the other person in a DM,
    which is a true two-member room with no bot in it.
    """

    remote_id: str
    local_id: str
    name: str
    topic: str
    owner: str = ""


class BridgeMapping:
    """The per-profile store.

    Every call is a primary-key read or a single-row write, run in a worker
    thread so a slow disk stalls the bridge's own request and never the
    gateway's event loop.
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Created 0600 before SQLite opens it; SQLite gives the -wal and -shm
        # files the database file's mode. Room lists and display names are
        # the shape of one agent's conversations.
        os.close(os.open(path, os.O_CREAT | os.O_RDWR, 0o600))
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        # 0.45.0 stores had no owner column.
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(rooms)")}
        if "owner" not in columns:
            self._db.execute("ALTER TABLE rooms ADD COLUMN owner TEXT NOT NULL DEFAULT ''")
        self._lock = threading.Lock()
        self._writes = 0
        self._prune_now(time.time())

    def close(self) -> None:
        self._db.close()

    def _row_now(self, sql: str, args: tuple[Any, ...]) -> tuple[Any, ...] | None:
        with self._lock:
            row: tuple[Any, ...] | None = self._db.execute(sql, args).fetchone()
        return row

    async def _row(self, sql: str, *args: Any) -> tuple[Any, ...] | None:
        return await asyncio.to_thread(self._row_now, sql, args)

    async def _one(self, sql: str, *args: Any) -> str | None:
        row = await self._row(sql, *args)
        return None if row is None else str(row[0])

    def _write_now(self, sql: str, args: tuple[Any, ...], counted: bool) -> None:
        with self._lock:
            self._db.execute(sql, args)
        if counted:
            self._writes += 1
            if self._writes % _PRUNE_EVERY == 0:
                self._prune_now(time.time())

    async def _write(self, sql: str, *args: Any, counted: bool = False) -> None:
        await asyncio.to_thread(self._write_now, sql, args, counted)

    # rooms

    async def room_by_remote(self, remote_id: str) -> Room | None:
        row = await self._row(
            "SELECT remote_id, local_id, name, topic, owner FROM rooms WHERE remote_id = ?",
            remote_id,
        )
        return None if row is None else Room(*row)

    async def room_by_local(self, local_id: str) -> Room | None:
        """The mapped room whose local ID this is, or ``None``."""
        row = await self._row(
            "SELECT remote_id, local_id, name, topic, owner FROM rooms WHERE local_id = ?",
            local_id,
        )
        return None if row is None else Room(*row)

    async def set_owner(self, remote_id: str, owner: str) -> None:
        """Record the stand-in that now owns a room, after a handover."""
        await self._write("UPDATE rooms SET owner = ? WHERE remote_id = ?", owner, remote_id)

    def _forget_room_now(self, remote_id: str, local_id: str) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute("DELETE FROM rooms WHERE remote_id = ?", (remote_id,))
                self._db.execute("DELETE FROM room_audience WHERE remote_id = ?", (remote_id,))
                self._db.execute("DELETE FROM members WHERE local_room = ?", (local_id,))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    async def forget_room(self, room: Room) -> None:
        """Drop a retired room: its mapping, its audience and its members
        (#317). A later invite into the same upstream room gets a new mirror,
        not the one the agent was removed from."""
        await asyncio.to_thread(self._forget_room_now, room.remote_id, room.local_id)

    async def put_room(
        self, remote_id: str, local_id: str, name: str, topic: str, owner: str = ""
    ) -> None:
        """Record a room, or update its name and topic. The owner is set on
        creation and moved only by ``set_owner``."""
        await self._write(
            "INSERT INTO rooms (remote_id, local_id, name, topic, owner) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(remote_id) DO UPDATE SET name = excluded.name, topic = excluded.topic",
            remote_id,
            local_id,
            name,
            topic,
            owner,
        )

    # users

    async def local_user(self, remote_id: str) -> str | None:
        return await self._one("SELECT local_id FROM users WHERE remote_id = ?", remote_id)

    async def remote_user(self, local_id: str) -> str | None:
        return await self._one("SELECT remote_id FROM users WHERE local_id = ?", local_id)

    async def displayname(self, remote_id: str) -> str | None:
        return await self._one("SELECT displayname FROM users WHERE remote_id = ?", remote_id)

    async def put_user(self, remote_id: str, local_id: str, displayname: str) -> None:
        await self._write(
            "INSERT INTO users (remote_id, local_id, displayname) VALUES (?, ?, ?) "
            "ON CONFLICT(remote_id) DO UPDATE SET displayname = excluded.displayname",
            remote_id,
            local_id,
            displayname,
        )

    # membership

    async def is_member(self, local_room: str, local_user: str) -> bool:
        row = await self._row(
            "SELECT 1 FROM members WHERE local_room = ? AND local_user = ?", local_room, local_user
        )
        return row is not None

    async def put_member(self, local_room: str, local_user: str) -> None:
        await self._write(
            "INSERT OR IGNORE INTO members (local_room, local_user) VALUES (?, ?)",
            local_room,
            local_user,
        )

    # audience (#264)

    async def agent_present(self, remote_room: str) -> bool | None:
        """Whether another bridged agent is in ``remote_room``; None when its
        members were never reported."""
        row = await self._row(
            "SELECT agent_present FROM room_audience WHERE remote_id = ?", remote_room
        )
        return None if row is None else bool(row[0])

    async def set_agent_present(self, remote_room: str, present: bool) -> None:
        """Record whether another bridged agent is in ``remote_room``, which
        also records that its members have been reported."""
        await self._write(
            "INSERT INTO room_audience (remote_id, agent_present, reported) VALUES (?, ?, ?) "
            "ON CONFLICT(remote_id) DO UPDATE SET agent_present = excluded.agent_present, "
            "reported = excluded.reported",
            remote_room,
            1 if present else 0,
            time.time(),
        )

    # batch lookups: one query for every ID a message references

    def _many_now(self, sql: str, keys: str) -> dict[str, str]:
        with self._lock:
            return {str(k): str(v) for k, v in self._db.execute(sql, (keys,)).fetchall()}

    async def _many(self, sql: str, keys: set[str]) -> dict[str, str]:
        """``{key: value}`` for the keys present, in one query. The key set is
        bound as a single JSON parameter, so no SQL is built from data."""
        if not keys:
            return {}
        return await asyncio.to_thread(self._many_now, sql, json.dumps(sorted(keys)))

    async def local_events(self, remote_ids: set[str]) -> dict[str, str]:
        return await self._many(
            "SELECT remote_id, local_id FROM events WHERE remote_id IN "
            "(SELECT value FROM json_each(?))",
            remote_ids,
        )

    async def remote_events(self, local_ids: set[str]) -> dict[str, str]:
        return await self._many(
            "SELECT local_id, remote_id FROM events WHERE local_id IN "
            "(SELECT value FROM json_each(?))",
            local_ids,
        )

    async def local_users(self, remote_ids: set[str]) -> dict[str, str]:
        return await self._many(
            "SELECT remote_id, local_id FROM users WHERE remote_id IN "
            "(SELECT value FROM json_each(?))",
            remote_ids,
        )

    async def remote_users(self, local_ids: set[str]) -> dict[str, str]:
        return await self._many(
            "SELECT local_id, remote_id FROM users WHERE local_id IN "
            "(SELECT value FROM json_each(?))",
            local_ids,
        )

    # events

    async def local_event(self, remote_id: str) -> str | None:
        return await self._one("SELECT local_id FROM events WHERE remote_id = ?", remote_id)

    async def remote_event(self, local_id: str) -> str | None:
        return await self._one("SELECT remote_id FROM events WHERE local_id = ?", local_id)

    async def put_event(self, remote_id: str, local_id: str) -> None:
        await self._write(
            "INSERT OR IGNORE INTO events (remote_id, local_id, created) VALUES (?, ?, ?)",
            remote_id,
            local_id,
            time.time(),
            counted=True,
        )

    # dedupe

    async def seen(self, key: str) -> bool:
        return await self._row("SELECT 1 FROM processed WHERE key = ?", key) is not None

    async def mark(self, key: str) -> None:
        await self._write(
            "INSERT OR IGNORE INTO processed (key, created) VALUES (?, ?)",
            key,
            time.time(),
            counted=True,
        )

    # retention

    def _prune_now(self, now: float) -> int:
        cutoff = now - RETENTION_DAYS * 86400
        with self._lock:
            removed = self._db.execute("DELETE FROM events WHERE created < ?", (cutoff,)).rowcount
            removed += self._db.execute(
                "DELETE FROM processed WHERE created < ?", (cutoff,)
            ).rowcount
        return int(removed)

    async def prune(self, now: float | None = None) -> int:
        """Drop event mappings and dedupe keys older than the retention."""
        return await asyncio.to_thread(self._prune_now, now if now is not None else time.time())
