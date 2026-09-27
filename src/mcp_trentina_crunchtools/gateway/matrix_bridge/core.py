"""One profile's bridge, gateway side: judge every event, then carry it across.

Inbound, the bridge process hands over one decrypted event at a time. The
gateway runs it through L1 ∥ L2 → L3 (``defend_json``), and only then writes
it into the agent's Conduit as the sender's stand-in — or, under ``block``,
writes a withheld notice in its place. What was judged is what is delivered:
the content, the sender's display name, and the room's name and topic.

Outbound, Conduit pushes the agent's own events to the appservice. Each is
judged the same way before the bridge encrypts and sends it upstream; a
refused one never leaves, and the agent is told so in its room.

Echo suppression is structural. Only events whose sender is the agent's local
user go outbound, so the stand-ins and the bot this module writes as never
loop back; and the bridge process drops upstream events whose sender is its
own account, which is where the agent's replies reappear.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import TYPE_CHECKING, Any

import httpx

from ...defense import defend_json
from ...modes import gaps_of, refusal_reason
from ...warning import build_warning
from ..context import profile_context
from .rewrite import IdMap, referenced_ids, rewrite_content

if TYPE_CHECKING:
    from ..profile import MatrixBridgeConfig, Profile
    from .appservice import AppService
    from .mapping import BridgeMapping

logger = logging.getLogger(__name__)

# Event types carried in either direction. State events are mirrored through
# the room metadata the bridge sends with each event, not replayed.
_CARRIED = frozenset({"m.room.message", "m.reaction", "m.sticker"})
_REDACTION = "m.room.redaction"
# The bridge process announcing a room it is in (bridge/client.py).
_ROOM_ANNOUNCE = "org.crunchtools.trentina.room"

_BRIDGE_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)


class BridgeUnavailableError(RuntimeError):
    """The bridge process refused or did not answer. Conduit retries the txn."""


def _txn(prefix: str, event_id: str) -> str:
    """A transaction ID derived from the event, so a retry is idempotent."""
    return f"{prefix}{hashlib.sha256(event_id.encode()).hexdigest()[:32]}"


class ProfileBridge:
    """Everything the gateway does for one bridged profile.

    Args:
        profile: a profile whose ``matrix_bridge`` is enabled and whose
            tokens the loader has resolved; anything else is a ValueError.
            Its ``defense`` settings judge every event.
        mapping: the profile's mapping store.
        appservice: the write path into the profile's Conduit.
        client: an HTTP client for calling the bridge process, instead of a
            fresh one. ``aclose`` closes it, the appservice and the mapping.
    """

    def __init__(
        self,
        profile: Profile,
        *,
        mapping: BridgeMapping,
        appservice: AppService,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        cfg = profile.matrix_bridge
        if cfg is None or cfg.bridge_token is None:
            raise ValueError(f"profile {profile.name!r} has no enabled matrix_bridge")
        self.profile = profile
        self.cfg: MatrixBridgeConfig = cfg
        self.mapping = mapping
        self.appservice = appservice
        self._client = client or httpx.AsyncClient(timeout=_BRIDGE_TIMEOUT)
        self._bridge_token = cfg.bridge_token.get_secret_value()
        self._inbound_lock = asyncio.Lock()
        self._outbound_lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()
        await self.appservice.aclose()
        self.mapping.close()

    # ------------------------------------------------------------------ ids

    async def _inbound_ids(self, content: dict[str, Any]) -> IdMap:
        """Resolve the IDs one upstream message references to local ones."""
        remote_agent = self.cfg.public_user_id
        agent = self.appservice.agent_id
        event_ids, user_ids = referenced_ids(content)
        users = await self.mapping.local_users(user_ids - {remote_agent})
        users[remote_agent] = agent
        return IdMap(events=await self.mapping.local_events(event_ids), users=users)

    async def _outbound_ids(self, content: dict[str, Any]) -> IdMap:
        """Resolve the IDs one agent message references to upstream ones.

        Only the stand-ins this message names are looked up, never the whole
        user table.
        """
        remote_agent = self.cfg.public_user_id
        agent = self.appservice.agent_id
        event_ids, user_ids = referenced_ids(content)
        users = await self.mapping.remote_users(
            {u for u in user_ids if self.appservice.is_stand_in(u)}
        )
        users[agent] = remote_agent
        return IdMap(events=await self.mapping.remote_events(event_ids), users=users)

    # -------------------------------------------------------------- verdict

    async def _judge(self, scanned: dict[str, Any], *, room: str, direction: str) -> Any:
        with profile_context(self.profile):
            result = await defend_json(
                scanned,
                source=f"matrix_bridge:{self.profile.name}:{room}",
                source_type="matrix_bridge",
                defense=self.profile.defense,
                record=True,
                attribution={
                    "profile": self.profile.name,
                    "direction": direction,
                    "blocked": self.cfg.enforcement == "block",
                },
            )
        return result.verdict

    def _refusal(self, verdict: Any) -> str | None:
        """Why this event may not be delivered as-is, or None."""
        if self.cfg.enforcement != "block":
            return None
        return refusal_reason(
            verdict.flagged_by.value if verdict.flagged_by else None, gaps_of(verdict)
        )

    # -------------------------------------------------------------- inbound

    async def inbound(self, event: dict[str, Any]) -> str:
        """Judge and deliver one upstream event. Returns what happened."""
        async with self._inbound_lock:
            return await self._inbound(event)

    async def _inbound(self, event: dict[str, Any]) -> str:
        event_id = str(event["event_id"])
        key = f"in:{event_id}"
        if await self.mapping.seen(key):
            return "duplicate"
        event_type = str(event["type"])
        room = event.get("room") or {}
        remote_room = str(event["room_id"])
        content = event.get("content") or {}

        if event_type == _REDACTION:
            outcome = await self._inbound_redaction(event, remote_room)
            await self.mapping.mark(key)
            return outcome
        if event_type == _ROOM_ANNOUNCE:
            outcome = await self._inbound_room(event, remote_room)
            await self.mapping.mark(key)
            return outcome
        if event_type not in _CARRIED:
            await self.mapping.mark(key)
            return "skipped"

        scanned = {
            "sender": str(event.get("sender_displayname") or ""),
            "room_name": str(room.get("name") or ""),
            "room_topic": str(room.get("topic") or ""),
            "content": content,
        }
        verdict = await self._judge(scanned, room=remote_room, direction="inbound")
        reason = self._refusal(verdict)
        local_room, stand_in = await self._place(event, scanned, withheld=reason is not None)

        if reason is None:
            out_type = event_type
            out = rewrite_content(content, await self._inbound_ids(content))
            warning = build_warning(verdict)
            if out is not None and warning is not None:
                out["_trentina_warning"] = warning
        else:
            # Event IDs are opaque; who said it and where stays out of the log.
            logger.warning(
                "matrix_bridge: withheld inbound %s for %s: %s", event_id, self.profile.name, reason
            )
            # A withheld reaction has nothing to stand in for: it is dropped.
            out_type = "m.room.message"
            out = (
                None if event_type == "m.reaction" else await self._withheld_notice(content, reason)
            )

        if out is None:
            await self.mapping.mark(key)
            return "withheld" if reason else "skipped"
        local_event = await self.appservice.send(
            local_room, stand_in, out_type, out, _txn("in", event_id)
        )
        await self.mapping.put_event(event_id, local_event)
        await self.mapping.mark(key)
        outcome = "withheld" if reason else "delivered"
        logger.info(
            "matrix_bridge: %s inbound %s -> %s (%s)",
            self.profile.name,
            event_id,
            local_event,
            outcome,
        )
        return outcome

    async def _place(
        self, event: dict[str, Any], scanned: dict[str, str | Any], *, withheld: bool
    ) -> tuple[str, str]:
        """The local room and the sender's stand-in, created as needed.

        A withheld event writes nothing it carried: not its words, not its
        sender's chosen name, not a room name or topic it tried to set.
        """
        remote_room = str(event["room_id"])
        sender = str(event["sender"])
        is_direct = bool((event.get("room") or {}).get("is_direct"))
        if withheld:
            known = await self.mapping.room_by_remote(remote_room)
            name, topic = (known.name, known.topic) if known else ("", "")
            displayname = await self.mapping.displayname(sender) or sender
        else:
            name, topic = scanned["room_name"], scanned["room_topic"]
            displayname = scanned["sender"] or sender
        local_room = await self.appservice.ensure_room(
            remote_room, name=name, topic=topic, is_direct=is_direct
        )
        stand_in = await self.appservice.ensure_user(sender, displayname)
        await self.appservice.ensure_member(local_room, stand_in)
        return local_room, stand_in

    async def _withheld_notice(self, content: dict[str, Any], reason: str) -> dict[str, Any] | None:
        """The notice that replaces a withheld message, in its thread or reply."""
        notice: dict[str, Any] = {"msgtype": "m.notice", "body": f"[trentina] withheld: {reason}"}
        if "m.relates_to" in content:
            notice["m.relates_to"] = content["m.relates_to"]
        return rewrite_content(notice, await self._inbound_ids(notice))

    async def _inbound_room(self, event: dict[str, Any], remote_room: str) -> str:
        """Create the local room for a room the bridge is in, agent invited.

        The name and topic are the only text, and they are judged like any
        other before they are written; refused, the room is created unnamed.
        """
        room = event.get("room") or {}
        scanned = {
            "room_name": str(room.get("name") or ""),
            "room_topic": str(room.get("topic") or ""),
        }
        verdict = await self._judge(scanned, room=remote_room, direction="inbound")
        if self._refusal(verdict) is not None:
            scanned = {"room_name": "", "room_topic": ""}
        local_room = await self.appservice.ensure_room(
            remote_room,
            name=scanned["room_name"],
            topic=scanned["room_topic"],
            is_direct=bool(room.get("is_direct")),
        )
        # Held until the agent is in, so the room's first messages (which the
        # bridge forwards next) are not written before it can read them.
        if not await self.appservice.wait_for_agent(local_room):
            logger.warning(
                "matrix_bridge: %s has not joined a new room; carrying on", self.profile.name
            )
        return "mapped"

    async def _inbound_redaction(self, event: dict[str, Any], remote_room: str) -> str:
        """Mirror a redaction. Only removes: its reason text is not carried.

        Not judged, and not a new power for the bridge process. A redaction
        takes away an event the agent already had judged in front of it; it
        cannot put anything there. A compromised bridge that forged one could
        equally have withheld the original, so honouring it grants nothing
        the bridge did not already hold (``preprocess/base.py`` invariant 1:
        subtract, never absolve).
        """
        redacts = event.get("redacts") or (event.get("content") or {}).get("redacts")
        target = await self.mapping.local_event(str(redacts)) if redacts else None
        room = await self.mapping.room_by_remote(remote_room)
        if target is None or room is None:
            return "skipped"
        # As the bot: it created every local room, so it holds power level
        # 100 there and may redact any stand-in's event.
        await self.appservice.redact(
            room.local_id, self.appservice.bot_id, target, _txn("rd", str(event["event_id"]))
        )
        return "redacted"

    # ------------------------------------------------------------- outbound

    async def outbound(self, txn_id: str, events: list[dict[str, Any]]) -> None:
        """Carry the agent's events in one appservice transaction upstream.

        Raises BridgeUnavailableError when the bridge cannot take one, so the
        transaction is not acked and Conduit sends it again; events already
        carried are skipped on the retry.
        """
        async with self._outbound_lock:
            if await self.mapping.seen(f"txn:{txn_id}"):
                return
            for event in events:
                await self._outbound(event)
            await self.mapping.mark(f"txn:{txn_id}")

    async def _outbound(self, event: dict[str, Any]) -> None:
        if event.get("sender") != self.appservice.agent_id:
            return
        local_room = str(event.get("room_id"))
        remote_room = await self.mapping.remote_room(local_room)
        event_id = str(event.get("event_id"))
        key = f"out:{event_id}"
        if remote_room is None or await self.mapping.seen(key):
            return
        event_type = str(event.get("type"))
        content = event.get("content") or {}

        if event_type == _REDACTION:
            redacts = event.get("redacts") or content.get("redacts")
            target = await self.mapping.remote_event(str(redacts)) if redacts else None
            if target is not None:
                await self._bridge(
                    "/redact",
                    {"room_id": remote_room, "event_id": target, "txn_id": _txn("rdo", event_id)},
                )
            await self.mapping.mark(key)
            return
        if event_type not in _CARRIED:
            await self.mapping.mark(key)
            return

        verdict = await self._judge({"content": content}, room=remote_room, direction="outbound")
        reason = self._refusal(verdict)
        if reason is not None:
            logger.warning(
                "matrix_bridge: withheld outbound %s for %s: %s",
                event_id,
                self.profile.name,
                reason,
            )
            await self.appservice.notice(
                local_room,
                f"[trentina] your message was not sent: {reason}",
                _txn("wo", event_id),
            )
            await self.mapping.mark(key)
            return

        out = rewrite_content(content, await self._outbound_ids(content))
        if out is None:
            await self.mapping.mark(key)
            return
        sent = await self._bridge(
            "/send",
            {
                "room_id": remote_room,
                "type": event_type,
                "content": out,
                "txn_id": _txn("out", event_id),
            },
        )
        await self.mapping.put_event(str(sent["event_id"]), event_id)
        await self.mapping.mark(key)
        logger.info(
            "matrix_bridge: %s outbound %s -> %s", self.profile.name, event_id, sent["event_id"]
        )

    async def _bridge(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._client.post(
                f"{self.cfg.bridge_url}{path}",
                json=body,
                headers={"Authorization": f"Bearer {self._bridge_token}"},
            )
        except httpx.HTTPError as exc:
            raise BridgeUnavailableError(f"bridge {path}: {exc}") from exc
        if resp.status_code != 200:
            raise BridgeUnavailableError(f"bridge {path} -> {resp.status_code} {resp.text[:200]}")
        try:
            reply: dict[str, Any] = resp.json()
        except ValueError as exc:
            raise BridgeUnavailableError(f"bridge {path}: not JSON") from exc
        return reply
