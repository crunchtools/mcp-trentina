"""The gateway's write path into one agent's Conduit, as an application service.

``as_token`` is the only credential that can put an event in front of the
agent, and only the gateway holds it (spec 015). Everything written here has
already been judged; this module decides nothing.

Remote senders become stand-in users in the appservice namespace so the agent
still sees who said what. The appservice's own user creates every local room
and is the inviter the agent's allowlist has to accept. No local room is ever
encrypted: the agent's side of the bridge is plaintext on purpose, because a
client that believes a room is encrypted refuses to send into it without
crypto (matrix-js-sdk does exactly that).
"""

from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import quote

import httpx

from .mapping import Room
from .rewrite import escape_localpart

if TYPE_CHECKING:
    from .mapping import BridgeMapping

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)

# Rooms, names and memberships kept in memory per cache.
_CACHE_ENTRIES = 4096
# The power level that administers a room: what the creator of a room has.
_ADMIN = 100
_K = TypeVar("_K")
_V = TypeVar("_V")


class _Recent(OrderedDict[_K, _V]):
    """A dict that forgets its least recently used entries past ``limit``."""

    def __init__(self, limit: int = _CACHE_ENTRIES) -> None:
        super().__init__()
        self._limit = limit

    def get(self, key: _K, default: Any = None) -> Any:
        """The value, now the most recently used; ``default`` if absent."""
        try:
            self.move_to_end(key)
        except KeyError:
            return default
        return self[key]

    def __setitem__(self, key: _K, value: _V) -> None:
        super().__setitem__(key, value)
        self.move_to_end(key)
        while len(self) > self._limit:
            self.popitem(last=False)


class ConduitError(RuntimeError):
    """Conduit refused a write. The caller does not ack, so it is retried."""


class AppService:
    """One profile's appservice client.

    Args:
        homeserver: the profile's Conduit base URL.
        server_name: that Conduit's server name; every local ID ends in it.
        as_token: the appservice token, the one credential that writes into
            the agent's rooms.
        sender_localpart: the appservice bot, which creates and owns rooms.
        user_prefix: the namespace stand-ins are registered under.
        agent_localpart: the agent's own local user, invited to every room.
        mapping: where rooms, stand-ins and memberships are remembered.
        client: an HTTP client to use instead of a fresh one; owned and
            closed by ``aclose`` either way.
    """

    def __init__(
        self,
        *,
        homeserver: str,
        server_name: str,
        as_token: str,
        sender_localpart: str,
        user_prefix: str,
        agent_localpart: str,
        mapping: BridgeMapping,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._homeserver = homeserver
        self._server_name = server_name
        self._token = as_token
        self._prefix = user_prefix
        self._mapping = mapping
        self._client = client or httpx.AsyncClient(timeout=_TIMEOUT)
        self.bot_id = f"@{sender_localpart}:{server_name}"
        self._sender_localpart = sender_localpart
        self._bot_registered = False
        # The mapping's rooms, names and memberships, most recently used
        # first. A miss falls back to SQLite, so the bound costs a query, not
        # correctness.
        self._rooms: _Recent[str, Room] = _Recent()
        self._rooms_by_local: _Recent[str, Room] = _Recent()
        self._names: _Recent[str, str] = _Recent()
        self._members: _Recent[tuple[str, str], bool] = _Recent()
        self.agent_id = f"@{agent_localpart}:{server_name}"

    async def aclose(self) -> None:
        await self._client.aclose()

    def stand_in_id(self, remote_user: str) -> str:
        return f"@{self._prefix}{escape_localpart(remote_user)}:{self._server_name}"

    def is_stand_in(self, user_id: str) -> bool:
        return user_id.startswith(f"@{self._prefix}") and user_id.endswith(f":{self._server_name}")

    async def _call(
        self,
        method: str,
        *segments: str,
        as_user: str | None = None,
        body: dict[str, Any] | None = None,
        ok_errcodes: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        # Every segment is quoted with safe="": a stand-in ID derives from a
        # remote user ID, and a slash left raw would let it add path segments
        # to a request made with the appservice token.
        path = "/" + "/".join(quote(segment, safe="") for segment in segments)
        params = {"user_id": as_user} if as_user else None
        try:
            resp = await self._client.request(
                method,
                f"{self._homeserver}/_matrix/client/v3{path}",
                params=params,
                json=body if body is not None else {},
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            raise ConduitError(f"{method} {path}: {type(exc).__name__}") from exc
        try:
            reply: dict[str, Any] = resp.json() if resp.content else {}
        except ValueError as exc:
            # A proxy's HTML error page, say. Not the caller's fault, so it is
            # a retryable delivery failure rather than a malformed request.
            raise ConduitError(f"{method} {path} -> {resp.status_code}, not JSON") from exc
        if resp.status_code >= 400 and reply.get("errcode") not in ok_errcodes:
            raise ConduitError(
                f"{method} {path} -> {resp.status_code} {reply.get('errcode')} {reply.get('error')}"
            )
        return reply

    async def ensure_user(self, remote_user: str, displayname: str) -> str:
        """The stand-in for ``remote_user``, registered and named."""
        local = self.stand_in_id(remote_user)
        known = self._names.get(remote_user)
        if known is None:
            known = await self._mapping.displayname(remote_user)
        if known is None:
            await self._call(
                "POST",
                "register",
                body={
                    "type": "m.login.application_service",
                    "username": local[1:].split(":", 1)[0],
                },
                ok_errcodes=frozenset({"M_USER_IN_USE"}),
            )
        if known != displayname:
            await self._call(
                "PUT",
                "profile",
                local,
                "displayname",
                as_user=local,
                body={"displayname": displayname},
            )
            await self._mapping.put_user(remote_user, local, displayname)
        self._names[remote_user] = displayname
        return local

    def actor(self, room: Room) -> str:
        """Who administers ``room``: its owner in a DM, the bot otherwise."""
        return room.owner or self.bot_id

    async def room_for_local(self, local_room: str) -> Room | None:
        """The mapped room with this local ID, cache first."""
        room = self._rooms_by_local.get(local_room) or await self._mapping.room_by_local(local_room)
        if room is not None:
            self._remember(room)
        return room

    def _remember(self, room: Room) -> None:
        self._rooms[room.remote_id] = room
        self._rooms_by_local[room.local_id] = room

    async def ensure_room(
        self,
        remote_room: str,
        *,
        name: str,
        topic: str,
        is_direct: bool,
        peer: str = "",
        peer_displayname: str = "",
    ) -> Room:
        """The local room mirroring ``remote_room``, created on first use and
        renamed when the remote name or topic moved.

        A direct message becomes a true DM: created by the other person's
        stand-in, with only the agent invited. Agents decide DM-or-group by
        member count, and a bot sitting in the room makes three, which reads
        as a group where the agent answers only when mentioned.

        Args:
            remote_room: the upstream room ID.
            name, topic: the upstream name and topic, already judged. A DM
                carries neither.
            is_direct: the upstream room has exactly two members.
            peer: in a DM, the other member's upstream user ID; its stand-in
                owns the local room. Empty for a group.
            peer_displayname: the peer's display name, already judged, for
                the stand-in. Defaults to the peer's ID.

        Returns:
            The ``Room``. ``owner`` is the peer's stand-in for a DM and empty
            for a group, where the appservice bot administers; ``actor``
            resolves either to the user that acts in the room.
        """
        room = self._rooms.get(remote_room) or await self._mapping.room_by_remote(remote_room)
        if room is None:
            room = await self._create_room(
                remote_room,
                name=name,
                topic=topic,
                owner=await self.ensure_user(peer, peer_displayname or peer)
                if is_direct and peer
                else "",
            )
        elif is_direct and peer and not room.owner:
            room = await self._hand_over(
                room, await self.ensure_user(peer, peer_displayname or peer)
            )
        else:
            await self._sync_metadata(room, name=name, topic=topic)
            room = Room(remote_room, room.local_id, name, topic, room.owner)
        self._remember(room)
        return room

    async def _create_room(self, remote_room: str, *, name: str, topic: str, owner: str) -> Room:
        """Create and record the local room, the agent invited.

        With an ``owner`` (a DM) that stand-in creates it as a trusted private
        chat with no name or topic, and is recorded as its member; without
        one the appservice bot creates a named private room.
        """
        if owner:
            creator = owner
            body: dict[str, Any] = {
                "preset": "trusted_private_chat",
                "invite": [self.agent_id],
                "is_direct": True,
            }
            name = topic = ""
        else:
            await self._ensure_bot()
            creator = self.bot_id
            body = {
                "preset": "private_chat",
                "name": name,
                "topic": topic,
                "invite": [self.agent_id],
            }
        created = await self._call("POST", "createRoom", as_user=creator, body=body)
        room = Room(remote_room, str(created["room_id"]), name, topic, owner)
        await self._mapping.put_room(remote_room, room.local_id, name, topic, owner)
        if owner:
            await self._mapping.put_member(room.local_id, owner)
            self._members[(room.local_id, owner)] = True
        logger.info(
            "matrix_bridge: mapped a new %s for %s", "DM" if owner else "room", self.agent_id
        )
        return room

    async def _hand_over(self, room: Room, owner: str) -> Room:
        """Turn a bot-made DM into a true one: the other person's stand-in
        takes the bot's power, and the bot leaves (rooms 0.45.0 made).

        Every step can be repeated, and the owner is recorded last, so a
        handover cut short by a restart is finished by the next one even when
        the bot had already left: the stand-in reads the power levels, a
        promotion already made is not made again, and leaving twice is fine.
        """
        await self.ensure_member(room, owner)
        levels = await self._call(
            "GET", "rooms", room.local_id, "state", "m.room.power_levels", "", as_user=owner
        )
        if levels.get("users", {}).get(owner) != _ADMIN:
            levels.setdefault("users", {})[owner] = _ADMIN
            await self._call(
                "PUT",
                "rooms",
                room.local_id,
                "state",
                "m.room.power_levels",
                "",
                as_user=self.bot_id,
                body=levels,
            )
        await self._call(
            "POST",
            "rooms",
            room.local_id,
            "leave",
            as_user=self.bot_id,
            ok_errcodes=frozenset({"M_FORBIDDEN"}),  # already left
        )
        await self._mapping.set_owner(room.remote_id, owner)
        logger.warning("matrix_bridge: %s's DM is now two-member", self.agent_id)
        return Room(room.remote_id, room.local_id, room.name, room.topic, owner)

    async def _ensure_bot(self) -> None:
        """Register the appservice's own user, which creates every group room.

        Homeservers differ on whether registering an appservice creates its
        sender user; registering it is idempotent either way.
        """
        if self._bot_registered:
            return
        await self._call(
            "POST",
            "register",
            body={"type": "m.login.application_service", "username": self._sender_localpart},
            ok_errcodes=frozenset({"M_USER_IN_USE"}),
        )
        self._bot_registered = True

    async def wait_for_agent(self, room: Room, timeout: float = 30.0) -> bool:
        """Wait until the agent has joined ``room``; False on timeout.

        A message written before the agent joins may never reach it, so a
        freshly created room is not handed messages until the agent is in.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            joined = await self._call(
                "GET", "rooms", room.local_id, "joined_members", as_user=self.actor(room)
            )
            if self.agent_id in (joined.get("joined") or {}):
                return True
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(1.0)

    async def _sync_metadata(self, room: Room, *, name: str, topic: str) -> None:
        if room.owner:
            return  # a DM carries no name or topic of its own
        for event_type, key, value, old in (
            ("m.room.name", "name", name, room.name),
            ("m.room.topic", "topic", topic, room.topic),
        ):
            if value != old:
                await self._call(
                    "PUT",
                    "rooms",
                    room.local_id,
                    "state",
                    event_type,
                    "",
                    as_user=self.bot_id,
                    body={key: value},
                )
        if (name, topic) != (room.name, room.topic):
            await self._mapping.put_room(room.remote_id, room.local_id, name, topic)

    async def ensure_member(self, room: Room, local_user: str) -> None:
        """Put a stand-in in a room: the owner invites, the stand-in joins."""
        key = (room.local_id, local_user)
        if self._members.get(key):
            return
        if await self._mapping.is_member(room.local_id, local_user):
            self._members[key] = True
            return
        await self._call(
            "POST",
            "rooms",
            room.local_id,
            "invite",
            as_user=self.actor(room),
            body={"user_id": local_user},
            ok_errcodes=frozenset({"M_FORBIDDEN"}),  # already joined
        )
        await self._call("POST", "rooms", room.local_id, "join", as_user=local_user)
        await self._mapping.put_member(room.local_id, local_user)
        self._members[key] = True

    async def send(
        self, local_room: str, sender: str, event_type: str, content: dict[str, Any], txn_id: str
    ) -> str:
        """Write one event as ``sender``. Idempotent on ``txn_id``."""
        sent = await self._call(
            "PUT",
            "rooms",
            local_room,
            "send",
            event_type,
            txn_id,
            as_user=sender,
            body=content,
        )
        return str(sent["event_id"])

    async def redact(self, local_room: str, sender: str, event_id: str, txn_id: str) -> None:
        await self._call(
            "PUT",
            "rooms",
            local_room,
            "redact",
            event_id,
            txn_id,
            as_user=sender,
        )

    async def notice(self, room: Room, body: str, txn_id: str) -> str:
        """A message from the gateway itself, sent by the room's owner."""
        return await self.send(
            room.local_id,
            self.actor(room),
            "m.room.message",
            {"msgtype": "m.notice", "body": body},
            txn_id,
        )
