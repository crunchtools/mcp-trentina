"""Adopt a mautrix client's device: its Olm identity and the keys it holds.

A bridge that logs in fresh is a new device: nobody's client has shared room
keys with it, so history it did not see is unreadable and every correspondent
sees a new, unverified device. Adopting the device the agent already used
keeps its identity keys, its Olm sessions and every Megolm session it
collected. It needs no password, only the access token the agent already had.

mautrix stores libolm pickles keyed by ``"<user_id>:<device_id>"``; nio loads
libolm pickles natively and re-pickles them under its own key when saved.
The source database is opened read-only, and the agent must be stopped for
good before the bridge starts: two processes driving one Olm account diverge
on the first one-time key either of them spends.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

import vodozemac
from nio.crypto.sessions import InboundGroupSession, OlmAccount, Session
from nio.store import SqliteStore

if TYPE_CHECKING:
    from pathlib import Path


# What a pickle that does not open with the derived key raises.
_UNPICKLABLE = (vodozemac.PickleException, vodozemac.LibolmPickleException, ValueError)


@dataclass(frozen=True)
class ImportResult:
    """What was carried over."""

    user_id: str
    device_id: str
    olm_sessions: int
    megolm_sessions: int
    megolm_skipped: int


class SessionImportError(RuntimeError):
    """The account or one session in the source store would not open."""

    def __init__(self, crypto_db: Path, kind: str, session_id: str) -> None:
        super().__init__(f"{crypto_db}: {kind} session {session_id} would not open")


def _as_bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _chains(value: str | None) -> list[str]:
    if not value:
        return []
    parsed = json.loads(value)
    return [str(key) for key in parsed] if isinstance(parsed, list) else []


def import_mautrix(crypto_db: Path, store_dir: Path, pickle_key: str) -> ImportResult:
    """Copy mautrix's account and sessions into a new nio store in ``store_dir``.

    Args:
        crypto_db: mautrix's ``crypto.db`` (SQLite, the ``crypto_account``,
            ``crypto_olm_session`` and ``crypto_megolm_inbound_session``
            tables). Opened read-only; never written.
        store_dir: the bridge's ``BRIDGE_STORE_DIR``. The nio store is created
            there as ``<user_id>_<device_id>.db``.
        pickle_key: ``BRIDGE_PICKLE_KEY``, which encrypts everything written
            to the new store. mautrix's own key is derived from the account's
            user and device IDs and is not an input.

    Returns:
        The adopted identity, how many Olm and Megolm sessions were carried
        over, and how many Megolm rows were skipped (no session, or no signing
        key to attribute it to).

    Raises:
        ValueError: the database holds no account.
        sqlite3.Error: it is not a mautrix crypto store.
        SessionImportError: the account or a session does not open with the
            derived key; the message names the row.
    """
    source = sqlite3.connect(f"file:{crypto_db}?mode=ro", uri=True)
    try:
        row = source.execute("SELECT account_id, device_id, account FROM crypto_account").fetchone()
        if row is None:
            raise ValueError(f"{crypto_db} holds no account")
        user_id, device_id, account_pickle = str(row[0]), str(row[1]), _as_bytes(row[2])
        passphrase = f"{user_id}:{device_id}"
        try:
            account = OlmAccount.from_pickle(account_pickle, passphrase, shared=True)
        except _UNPICKLABLE as exc:
            raise SessionImportError(crypto_db, "account", device_id) from exc

        store_dir.mkdir(parents=True, exist_ok=True)
        store = SqliteStore(user_id, device_id, str(store_dir), pickle_key)
        store.save_account(account)

        olm = 0
        for session_id, sender_key, pickle, created in source.execute(
            "SELECT session_id, sender_key, session, created_at FROM crypto_olm_session"
        ):
            try:
                session = Session.from_pickle(
                    _as_bytes(pickle), datetime.fromisoformat(str(created)), passphrase
                )
            except _UNPICKLABLE as exc:
                raise SessionImportError(crypto_db, "Olm", session_id) from exc
            store.save_session(sender_key, session)
            olm += 1

        megolm = skipped = 0
        for session_id, sender_key, signing_key, room_id, pickle, chains in source.execute(
            "SELECT session_id, sender_key, signing_key, room_id, session, forwarding_chains "
            "FROM crypto_megolm_inbound_session"
        ):
            if pickle is None or signing_key is None:
                # A withheld placeholder or a session mautrix never verified
                # a signing key for: nothing to decrypt with, or nothing to
                # attribute it to.
                skipped += 1
                continue
            try:
                inbound = InboundGroupSession.from_pickle(
                    _as_bytes(pickle),
                    str(signing_key),
                    str(sender_key),
                    str(room_id),
                    passphrase,
                    _chains(chains),
                )
            except _UNPICKLABLE as exc:
                raise SessionImportError(crypto_db, "Megolm", session_id) from exc
            store.save_inbound_group_session(inbound)
            megolm += 1
    finally:
        source.close()
    return ImportResult(user_id, device_id, olm, megolm, skipped)
