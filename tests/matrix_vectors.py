"""Generate Megolm test vectors with the real crypto library, no credentials.

Nothing here touches a homeserver or a real key. A recovery key, a room key,
a backup blob and an encrypted event are all constructed in process, which
means the decryption path can be tested exhaustively on any machine that can
install the dependency.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from mcp_trentina_crunchtools.matrix.recovery_key import PREFIX

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE = len(_ALPHABET)

CURVE25519_B64_LEN = 43
"""Length of an unpadded base64 curve25519 key. Only the shape matters here."""

FIXED_TS = 1758412345678
"""A fixed origin_server_ts so vectors are byte-reproducible."""


def make_recovery_key(private: bytes) -> str:
    """Encode a private key the way an operator would be shown it: base58 of
    the version prefix, the key, and a parity byte."""
    payload = bytes(PREFIX) + private
    parity = 0
    for b in payload:
        parity ^= b
    raw = payload + bytes([parity])

    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, _BASE)
        out = _ALPHABET[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def _b64(raw: Any) -> str:
    return base64.b64encode(bytes(raw)).decode().rstrip("=")


class Vectors:
    """One room, one session, and whatever events the test needs."""

    def __init__(self, room_id: str = "!room:hs") -> None:
        import vodozemac as v

        self.room_id = room_id
        self.private = secrets.token_bytes(32)
        self.recovery_key = make_recovery_key(self.private)
        self._pk = v.PkDecryption.from_key(
            v.Curve25519SecretKey.from_bytes(self.private)
        )
        self.backup_public_key = self._pk.public_key.to_base64()

        self._group = v.GroupSession()
        self.session_id = self._group.session_id
        exported = v.InboundGroupSession(self._group.session_key).export_at(0)

        session_data = json.dumps({
            "algorithm": "m.megolm.v1.aes-sha2",
            "sender_key": "s" * CURVE25519_B64_LEN,
            "session_key": exported.to_base64(),
            "sender_claimed_keys": {},
            "forwarding_curve25519_key_chain": [],
        })
        enc = v.PkEncryption.from_key(self._pk.public_key).encrypt(
            session_data.encode()
        )
        # By name, not by to_base64()'s tuple: its order is not the
        # constructor's, and mixing them up fails with a key-size error that
        # points nowhere near the mistake.
        self.session_data = {
            "ciphertext": _b64(enc.ciphertext),
            "mac": _b64(enc.mac),
            "ephemeral": _b64(enc.ephemeral_key),
        }

    def version_response(self, *, algorithm: str | None = None) -> dict[str, Any]:
        return {
            "algorithm": algorithm or "m.megolm_backup.v1.curve25519-aes-sha2",
            "version": "7",
            "auth_data": {"public_key": self.backup_public_key},
            "count": 1,
            "etag": "1",
        }

    def keys_response(self) -> dict[str, Any]:
        return {"sessions": {self.session_id: {
            "first_message_index": 0,
            "forwarded_count": 0,
            "is_verified": True,
            "session_data": self.session_data,
        }}}

    def encrypted_event(self, body: str, *, event_id: str = "$ev:hs") -> dict[str, Any]:
        plaintext = json.dumps({
            "type": "m.room.message",
            "room_id": self.room_id,
            "content": {"msgtype": "m.text", "body": body},
        })
        ciphertext = self._group.encrypt(plaintext.encode()).to_base64()
        return {
            "type": "m.room.encrypted",
            "event_id": event_id,
            # Real events outside the /sync timeline carry room_id; inside
            # /sync the room is the enclosing dict key instead.
            "room_id": self.room_id,
            "sender": "@someone:hs",
            "origin_server_ts": FIXED_TS,
            "content": {
                "algorithm": "m.megolm.v1.aes-sha2",
                "ciphertext": ciphertext,
                "sender_key": "k" * CURVE25519_B64_LEN,
                "session_id": self.session_id,
                "device_id": "AAAAAA",
            },
        }

    def sync_response(self, *events: dict[str, Any]) -> dict[str, Any]:
        return {"next_batch": "s1_2_3", "rooms": {"join": {self.room_id: {
            "timeline": {"events": list(events), "limited": False},
            "state": {"events": []},
        }}}}
