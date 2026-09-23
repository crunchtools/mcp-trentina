"""The Matrix extractor: decrypt to build a scan view, forward ciphertext.

Everything the generic extractor does, plus the one thing that changes what
the perimeter can actually see. Message bodies in an encrypted room are
ciphertext at the proxy, so today an injection in a chat message crosses
Trentina as an opaque blob and becomes plaintext inside the agent, past the
perimeter. This reads it.

S4 governs the whole file: decryption is read-only, additive and ephemeral.
Recovered plaintext exists only in the scan view. It is never forwarded --
the response body is built from the upstream buffer and never from anything
here -- never written to disk, and never logged in full.

Two habits worth naming, because both are easy to get wrong:

Decrypted text goes back through the SAME generic rules as anything else. A
base64 blob pasted inside a message is still a base64 blob, and plaintext
recovered from ciphertext is no more trustworthy than plaintext that arrived
in the clear. There is no "it was encrypted, so it is ours" shortcut.

Unrecognised shapes fall through to the generic leaf walk rather than being
skipped. The extractor knows the shapes Matrix uses today; the failure mode
for a shape it does not know must be "scan it anyway", not "ignore it".
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from ..channels import Channel
from .base import ScanView, ScanViewContext, SkipReason, UndecryptableEvent
from .walk import iter_leaves

if TYPE_CHECKING:
    from ..matrix.keybackup import KeyBackupProvider
    from .generic import GenericExtractor

logger = logging.getLogger(__name__)

MEGOLM_ALGORITHM = "m.megolm.v1.aes-sha2"
OLM_ALGORITHM = "m.olm.v1.curve25519-aes-sha2"

_PROSE_FIELDS = ("body", "formatted_body", "topic", "name")
"""Fields of a decrypted event that carry language worth judging."""


class MatrixExtractor:
    """Generic selection, plus Megolm decryption of room events."""

    name = "matrix"
    channels = frozenset({Channel.MATRIX})

    def __init__(
        self,
        *,
        generic: GenericExtractor,
        keys: KeyBackupProvider | None = None,
    ) -> None:
        self._generic = generic
        self._keys = keys

    async def extract(self, payload: Any, ctx: ScanViewContext) -> ScanView:
        encrypted: list[dict[str, Any]] = []
        _collect_encrypted(payload, encrypted)

        decrypted_texts: list[str] = []
        undecryptable: list[UndecryptableEvent] = []
        skipped: dict[SkipReason, int] = {}
        decrypted = 0

        for event in encrypted:
            content = event.get("content") or {}
            ciphertext = content.get("ciphertext")
            room_id = str(event.get("_room_id") or "")
            event_id = str(event.get("event_id") or "")
            session_id = str(content.get("session_id") or "")
            algorithm = content.get("algorithm")

            if not isinstance(ciphertext, str):
                # Olm to-device payloads are a dict keyed by recipient key.
                # Key backup does not cover olm and never will, so counting
                # them as undecryptable would pin the rate high for ever.
                continue
            if algorithm != MEGOLM_ALGORITHM:
                undecryptable.append(UndecryptableEvent(
                    event_id, room_id, session_id, "unsupported_algorithm"))
                _bump(skipped, len(ciphertext))
                continue

            plaintext = await self._decrypt(room_id, session_id, ciphertext)
            if plaintext is None:
                reason = "no_session" if self._keys else "decryption_disabled"
                undecryptable.append(
                    UndecryptableEvent(event_id, room_id, session_id, reason))
                _bump(skipped, len(ciphertext))
                continue

            decrypted += 1
            decrypted_texts.extend(_prose_from(plaintext))

        view = self._generic.select(
            iter_leaves(_without_ciphertext(payload)),
            extra_segments=decrypted_texts,
            extra_skipped=skipped,
            encrypted_events=len(encrypted),
            decrypted_events=decrypted,
            undecryptable=tuple(undecryptable),
            extractor_name=self.name,
        )
        if undecryptable:
            logger.warning(
                "matrix scanview: %s — %d of %d encrypted event(s) unread",
                ctx.path or ctx.source, len(undecryptable), len(encrypted),
            )
        return view

    async def _decrypt(
        self, room_id: str, session_id: str, ciphertext: str
    ) -> str | None:
        if self._keys is None or not session_id:
            return None
        try:
            session = await self._keys.session_for(room_id, session_id)
            if session is None:
                return None
            from ..matrix.megolm import decrypt_event

            return decrypt_event(session, ciphertext).decode("utf-8", "replace")
        except Exception as exc:
            # Identity only. Never the ciphertext, never partial plaintext.
            logger.warning(
                "matrix scanview: decrypt failed for session %s in room %s: %s",
                session_id, room_id, type(exc).__name__,
            )
            return None


def _bump(skipped: dict[SkipReason, int], n: int) -> None:
    key = SkipReason.CIPHERTEXT_UNDECRYPTABLE
    skipped[key] = skipped.get(key, 0) + n


def _prose_from(plaintext: str) -> list[str]:
    """Pull the language-bearing fields out of a decrypted event.

    Falls back to every string leaf when the shape is not the expected one --
    an event we cannot parse is a reason to read more of it, not less.
    """
    try:
        event = json.loads(plaintext)
    except ValueError:
        return [plaintext]
    if not isinstance(event, dict):
        return [plaintext]

    content = event.get("content")
    if not isinstance(content, dict):
        return iter_leaves(event)

    out = [v for f in _PROSE_FIELDS if isinstance(v := content.get(f), str) and v]
    new_content = content.get("m.new_content")
    if isinstance(new_content, dict):
        out += [v for f in _PROSE_FIELDS
                if isinstance(v := new_content.get(f), str) and v]
    return out or iter_leaves(event)


def _collect_encrypted(payload: Any, out: list[dict[str, Any]]) -> None:
    """Find every m.room.encrypted event, tagging each with its room.

    Walks generically rather than by a fixed list of container paths: /sync,
    /messages, /context and /search all nest events differently, and a walk
    that has to know each one is a walk that silently misses the next.
    """
    stack: list[tuple[Any, str]] = [(payload, "")]
    while stack:
        node, room = stack.pop()
        if isinstance(node, dict):
            if node.get("type") == "m.room.encrypted" and "content" in node:
                tagged = dict(node)
                tagged["_room_id"] = node.get("room_id") or room
                out.append(tagged)
                continue
            for key, value in node.items():
                child_room = key if isinstance(key, str) and key.startswith("!") else room
                stack.append((value, child_room))
        elif isinstance(node, list):
            stack.extend((item, room) for item in node)


def _without_ciphertext(payload: Any) -> Any:
    """The payload as the generic rules should see it.

    Returned as-is: ciphertext strings are high-entropy base64 with no
    whitespace, so the generic OPAQUE rule already declines them and counts
    them. Stripping them here would double-count against the accounting
    identity in S3.
    """
    return payload
