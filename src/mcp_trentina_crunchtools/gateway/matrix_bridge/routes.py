"""HTTP surface of the bridge on the gateway.

* ``POST /bridge/{profile}/event`` — the bridge process hands over one
  decrypted upstream event. Bearer ``ingress_token``. Answers 200 only once
  the event is in the agent's Conduit (or deliberately withheld or skipped),
  so the bridge advances its sync position only past what landed.
* ``/bridge/as/{profile}/...`` — the appservice API Conduit calls. Bearer
  ``hs_token``. Transactions carry the agent's events outbound.

Tokens are accepted in the ``Authorization`` header only. Conduit sends
the ``hs_token`` both ways (``conduit/src/api/appservice_server.rs``: ruma's
``SendAccessToken::IfRequired`` sets the header, and the query string is
appended after); the query copy is ignored rather than honoured, so nothing
here depends on a credential that access logs record.
"""

from __future__ import annotations

import hmac
import logging
from http import HTTPStatus
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.responses import JSONResponse, Response

from ...httpbody import TooLargeError, read_capped, where_invalid
from ...logsafe import exc_kind
from .appservice import AppService, ConduitError
from .core import BridgeUnavailableError, ProfileBridge
from .mapping import BridgeMapping

if TYPE_CHECKING:
    from pathlib import Path

    from pydantic import SecretStr
    from starlette.requests import Request

    from ..profile import Profile

logger = logging.getLogger(__name__)


class RoomInfo(BaseModel):
    """What the bridge knows about the room an event arrived in."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = ""
    topic: str = ""
    is_direct: bool = False
    # In a direct message, the other member, so the local DM can be theirs.
    peer: str = ""
    peer_displayname: str = ""
    # On a room announcement only: every member but the bridge's own user,
    # joined or invited (#264). None from a bridge that reports none.
    members: list[str] | None = None


class BridgeEvent(BaseModel):
    """One upstream event, as the bridge process hands it over. Our own wire
    format, so anything unexpected in it is refused."""

    model_config = ConfigDict(extra="forbid", strict=True)

    room_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    sender: str = Field(min_length=1)
    sender_displayname: str = ""
    type: str = Field(min_length=1)
    content: dict[str, Any] = Field(default_factory=dict)
    redacts: str | None = None
    room: RoomInfo = Field(default_factory=RoomInfo)


class AgentEvent(BaseModel):
    """A client-format event as Conduit pushes it: every field the spec
    defines (plus the two legacy ones homeservers still send), so an event
    carrying anything else is refused. Only the first six are read."""

    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: str
    room_id: str
    sender: str
    type: str
    content: dict[str, Any] = Field(default_factory=dict)
    redacts: str | None = None
    origin_server_ts: int | None = None
    state_key: str | None = None
    unsigned: dict[str, Any] | None = None
    age: int | None = None
    user_id: str | None = None


class Transaction(BaseModel):
    """An appservice transaction: the spec's sections, stable and MSC2409's
    unstable spelling. Only ``events`` is carried; the bridge moves timeline
    events, not presence, receipts or to-device traffic."""

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)

    events: list[AgentEvent] = Field(default_factory=list)
    ephemeral: list[dict[str, Any]] | None = None
    to_device: list[dict[str, Any]] | None = None
    unstable_ephemeral: list[dict[str, Any]] | None = Field(
        default=None, alias="de.sorunome.msc2409.ephemeral"
    )
    unstable_to_device: list[dict[str, Any]] | None = Field(
        default=None, alias="de.sorunome.msc2409.to_device"
    )


def bridged_agents(profiles: dict[str, Profile]) -> frozenset[str]:
    """The upstream user of every profile with a ``matrix_bridge`` block (#264).

    Enabled or not: a block that is switched off still names an agent's
    upstream identity, and another bridge talking to it is the same channel.
    ``public_user_id`` is the only upstream ID a profile carries; the bridge
    process logs in as it (``BRIDGE_USER_ID``).
    """
    return frozenset(
        p.matrix_bridge.public_user_id for p in profiles.values() if p.matrix_bridge is not None
    )


def build_bridges(
    profiles: dict[str, Profile], data_dir: Path, other_agents: frozenset[str] = frozenset()
) -> dict[str, ProfileBridge]:
    """Build the gateway half of every enabled bridge.

    Args:
        profiles: the loaded profiles; only those whose ``matrix_bridge`` is
            enabled (and so has resolved tokens) get a bridge.
        data_dir: where each profile's mapping store goes, as
            ``bridge-<profile>.db``. Created if absent.
        other_agents: agents' Matrix IDs that no profile bridges
            (``matrix.other_agent_user_ids``), refused like a bridged one.

    Returns:
        ``{profile name: ProfileBridge}``, empty when no bridge is enabled.
        Each owns HTTP clients and a SQLite store; ``close_bridges`` closes
        the ones registered at startup.
    """
    out: dict[str, ProfileBridge] = {}
    agents = bridged_agents(profiles) | other_agents
    for name, profile in profiles.items():
        cfg = profile.matrix_bridge
        if cfg is None or not cfg.enabled or cfg.local.as_token is None:
            continue
        mapping = BridgeMapping(data_dir / f"bridge-{name}.db")
        appservice = AppService(
            homeserver=cfg.local.homeserver,
            server_name=cfg.local.server_name,
            as_token=cfg.local.as_token.get_secret_value(),
            sender_localpart=cfg.local.sender_localpart,
            user_prefix=cfg.local.user_prefix,
            agent_localpart=cfg.local.agent_localpart,
            mapping=mapping,
        )
        out[name] = ProfileBridge(
            profile, mapping=mapping, appservice=appservice, other_agents=agents
        )
    return out


def _presented(request: Request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else ""


def _matches(presented: str, expected: SecretStr | None) -> bool:
    if expected is None or not presented:
        return False
    return hmac.compare_digest(
        presented.encode("utf-8"), expected.get_secret_value().encode("utf-8")
    )


def _refused(status: int, errcode: str, error: str) -> JSONResponse:
    return JSONResponse({"errcode": errcode, "error": error}, status_code=status)


# The bridges registered at startup, so the gateway's lifespan can close them.
_registered: list[ProfileBridge] = []


async def close_bridges() -> None:
    """Close every registered bridge's clients and store. Called on shutdown."""
    while _registered:
        await _registered.pop().aclose()


class BridgeRoutes:
    """The endpoints, bound to the bridges built at startup."""

    def __init__(self, bridges: dict[str, ProfileBridge]) -> None:
        self._bridges = bridges

    def _for_ingress(self, request: Request) -> ProfileBridge | None:
        bridge = self._bridges.get(request.path_params.get("profile", ""))
        if bridge is None or not _matches(_presented(request), bridge.cfg.ingress_token):
            return None
        return bridge

    def _for_homeserver(self, request: Request) -> ProfileBridge | None:
        bridge = self._bridges.get(request.path_params.get("profile", ""))
        if bridge is None or not _matches(_presented(request), bridge.cfg.local.hs_token):
            return None
        return bridge

    async def event(self, request: Request) -> Response:
        bridge = self._for_ingress(request)
        if bridge is None:
            return _refused(401, "M_UNKNOWN_TOKEN", "unauthorized")
        try:
            event = BridgeEvent.model_validate_json(await read_capped(request))
        except TooLargeError:
            return _refused(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "M_TOO_LARGE", "event too large")
        except ValidationError as exc:
            logger.warning(
                "matrix_bridge: malformed event for %s at %s",
                bridge.profile.name,
                where_invalid(exc),
            )
            return _refused(400, "M_BAD_JSON", "malformed event")
        try:
            outcome = await bridge.inbound(event.model_dump())
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "matrix_bridge: event for %s refused by the bridge core: %s",
                bridge.profile.name,
                exc_kind(exc),
            )
            return _refused(400, "M_BAD_JSON", "malformed event")
        except (ConduitError, OSError) as exc:
            logger.warning(
                "matrix_bridge: could not deliver for %s: %s", bridge.profile.name, exc_kind(exc)
            )
            return _refused(503, "M_UNKNOWN", "delivery failed, retry")
        return JSONResponse({"outcome": outcome})

    async def transaction(self, request: Request) -> Response:
        bridge = self._for_homeserver(request)
        if bridge is None:
            return _refused(403, "M_FORBIDDEN", "bad hs_token")
        try:
            txn = Transaction.model_validate_json(await read_capped(request))
        except TooLargeError:
            return _refused(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "M_TOO_LARGE", "transaction too large"
            )
        except ValidationError as exc:
            logger.warning(
                "matrix_bridge: malformed transaction for %s at %s",
                bridge.profile.name,
                where_invalid(exc),
            )
            return _refused(400, "M_BAD_JSON", "malformed transaction")
        try:
            await bridge.outbound(
                str(request.path_params["txn"]), [e.model_dump() for e in txn.events]
            )
        except (BridgeUnavailableError, ConduitError, OSError) as exc:
            logger.warning(
                "matrix_bridge: outbound failed for %s: %s", bridge.profile.name, exc_kind(exc)
            )
            return _refused(503, "M_UNKNOWN", "bridge unavailable, retry")
        return JSONResponse({})

    async def query(self, request: Request) -> Response:
        """User and alias queries: nothing is created on demand."""
        if self._for_homeserver(request) is None:
            return _refused(403, "M_FORBIDDEN", "bad hs_token")
        return _refused(404, "M_NOT_FOUND", "not provisioned on demand")

    async def ping(self, request: Request) -> Response:
        if self._for_homeserver(request) is None:
            return _refused(403, "M_FORBIDDEN", "bad hs_token")
        return JSONResponse({})


def register_bridge_routes(
    mcp_server: Any,
    profiles: dict[str, Profile],
    data_dir: Path,
    *,
    other_agents: frozenset[str] = frozenset(),
) -> BridgeRoutes | None:
    """Wire the bridge endpoints for every enabled bridge. Bound at startup.

    Args:
        mcp_server: the FastMCP server; routes go on via ``custom_route``.
        profiles: the loaded profiles (see ``build_bridges``).
        data_dir: where the mapping stores live.
        other_agents: see ``build_bridges``.

    Returns:
        The bound handlers, or None when no profile has an enabled bridge,
        in which case no route is registered at all.
    """
    bridges = build_bridges(profiles, data_dir, other_agents)
    if not bridges:
        return None
    _registered.extend(bridges.values())
    handlers = BridgeRoutes(bridges)
    route = mcp_server.custom_route
    route("/bridge/{profile}/event", methods=["POST"])(handlers.event)
    # The spec's prefixed paths, and the unprefixed ones older homeservers use.
    for prefix in ("/bridge/as/{profile}/_matrix/app/v1", "/bridge/as/{profile}"):
        route("/".join((prefix, "transactions", "{txn}")), methods=["PUT"])(handlers.transaction)
        for kind, param in (("users", "{user}"), ("rooms", "{alias}")):
            route("/".join((prefix, kind, param)), methods=["GET"])(handlers.query)
    route("/bridge/as/{profile}/_matrix/app/v1/ping", methods=["POST"])(handlers.ping)
    logger.warning("matrix_bridge: serving %s", ", ".join(sorted(bridges)))
    return handlers
