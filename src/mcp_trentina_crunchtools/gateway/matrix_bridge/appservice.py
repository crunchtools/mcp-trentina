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

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from .mapping import Room
from .rewrite import escape_localpart

if TYPE_CHECKING:
    from .mapping import BridgeMapping

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)


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
        # The mapping's rooms, names and memberships, read once each. Bounded
        # by the conversations the account is in, so held for the process.
        self._rooms: dict[str, Room] = {}
        self._names: dict[str, str] = {}
        self._members: set[tuple[str, str]] = set()
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

    async def ensure_room(self, remote_room: str, *, name: str, topic: str, is_direct: bool) -> str:
        """The local room mirroring ``remote_room``, created on first use and
        renamed when the remote name or topic moved."""
        room = self._rooms.get(remote_room) or await self._mapping.room_by_remote(remote_room)
        if room is None:
            await self._ensure_bot()
            created = await self._call(
                "POST",
                "createRoom",
                as_user=self.bot_id,
                body={
                    "preset": "private_chat",
                    "name": name,
                    "topic": topic,
                    "invite": [self.agent_id],
                    "is_direct": is_direct,
                },
            )
            local_id = str(created["room_id"])
            await self._mapping.put_room(remote_room, local_id, name, topic)
            self._rooms[remote_room] = Room(remote_room, local_id, name, topic)
            logger.info("matrix_bridge: mapped a new room for %s", self.agent_id)
            return local_id
        await self._sync_metadata(room, name=name, topic=topic)
        self._rooms[remote_room] = Room(remote_room, room.local_id, name, topic)
        return room.local_id

    async def _ensure_bot(self) -> None:
        """Register the appservice's own user, which creates every room.

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

    async def _sync_metadata(self, room: Room, *, name: str, topic: str) -> None:
        if name != room.name:
            await self._call(
                "PUT",
                "rooms",
                room.local_id,
                "state",
                "m.room.name",
                "",
                as_user=self.bot_id,
                body={"name": name},
            )
        if topic != room.topic:
            await self._call(
                "PUT",
                "rooms",
                room.local_id,
                "state",
                "m.room.topic",
                "",
                as_user=self.bot_id,
                body={"topic": topic},
            )
        if (name, topic) != (room.name, room.topic):
            await self._mapping.put_room(room.remote_id, room.local_id, name, topic)

    async def ensure_member(self, local_room: str, local_user: str) -> None:
        """Put a stand-in in a room: the bot invites, the stand-in joins."""
        if (local_room, local_user) in self._members:
            return
        if await self._mapping.is_member(local_room, local_user):
            self._members.add((local_room, local_user))
            return
        await self._call(
            "POST",
            "rooms",
            local_room,
            "invite",
            as_user=self.bot_id,
            body={"user_id": local_user},
            ok_errcodes=frozenset({"M_FORBIDDEN"}),  # already joined
        )
        await self._call("POST", "rooms", local_room, "join", as_user=local_user)
        await self._mapping.put_member(local_room, local_user)
        self._members.add((local_room, local_user))

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

    async def notice(self, local_room: str, body: str, txn_id: str) -> str:
        """A message from the gateway itself, as the appservice bot."""
        return await self.send(
            local_room, self.bot_id, "m.room.message", {"msgtype": "m.notice", "body": body}, txn_id
        )
