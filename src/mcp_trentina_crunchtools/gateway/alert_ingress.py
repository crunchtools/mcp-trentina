"""Alert webhook ingress for agent profiles.

Receives POST requests at ``/alert/{token}``, validates the token
against profile ``alert_ingress`` configurations (constant-time),
and forwards the JSON payload to the profile's ``forward_url``.

The token embedded in the URL is the sole authentication — no
headers required.  Designed for monitoring systems (Nagios, Zabbix)
that need to page an agent (Hermes/Kagetora) through Trentina.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import TYPE_CHECKING, Any

import httpx
from starlette.responses import Response

from .profile import Profile

if TYPE_CHECKING:
    from starlette.requests import Request

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
_alert_client: httpx.AsyncClient | None = None


def _get_alert_client() -> httpx.AsyncClient:
    global _alert_client
    if _alert_client is None:
        _alert_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _alert_client


async def close_alert_client() -> None:
    """Shut down the httpx client.  Called on application shutdown."""
    global _alert_client
    if _alert_client is not None:
        await _alert_client.aclose()
        _alert_client = None


def _resolve_profile_by_alert_token(
    token: str, profiles: dict[str, Profile],
) -> Profile | None:
    token_bytes = token.encode("utf-8")
    match: Profile | None = None
    for profile in profiles.values():
        if profile.alert_ingress is None or profile.alert_ingress.token is None:
            continue
        expected = profile.alert_ingress.token.get_secret_value().encode("utf-8")
        if hmac.compare_digest(token_bytes, expected) and match is None:
            match = profile
    return match


def register_alert_routes(
    mcp_server: Any, profiles: dict[str, Profile],
) -> None:
    """Wire ``POST /alert/{token}`` onto the FastMCP server."""
    alert_profiles = [
        name for name, p in profiles.items() if p.alert_ingress is not None
    ]
    if not alert_profiles:
        logger.info("alert_ingress: no profiles configured, skipping")
        return

    async def alert_endpoint(request: Request) -> Response:
        return await _handle_alert(request, profiles)

    mcp_server.custom_route("/alert/{token}", methods=["POST"])(alert_endpoint)

    logger.info(
        "alert_ingress: registered /alert/{token} for %d profile(s): %s",
        len(alert_profiles), ", ".join(alert_profiles),
    )


async def _handle_alert(
    request: Request, profiles: dict[str, Profile],
) -> Response:
    token = request.path_params.get("token", "")
    if not token:
        return Response(
            content="missing token", status_code=400, media_type="text/plain",
        )

    profile = _resolve_profile_by_alert_token(token, profiles)
    if profile is None:
        return Response(
            content="unauthorized", status_code=401, media_type="text/plain",
        )

    assert profile.alert_ingress is not None
    forward_url = profile.alert_ingress.forward_url

    try:
        body = await request.body()
    except Exception:
        return Response(
            content="bad request body", status_code=400, media_type="text/plain",
        )

    fwd_headers: dict[str, str] = {"Content-Type": "application/json"}
    if profile.alert_ingress.forward_secret is not None:
        secret = profile.alert_ingress.forward_secret.get_secret_value()
        sig = hmac.new(
            secret.encode("utf-8"), body, hashlib.sha256,
        ).hexdigest()
        fwd_headers["X-Hub-Signature-256"] = f"sha256={sig}"

    client = _get_alert_client()
    try:
        resp = await client.post(
            forward_url,
            content=body,
            headers=fwd_headers,
        )
    except httpx.TimeoutException:
        logger.warning("alert_ingress: timeout forwarding to %s", forward_url)
        return Response(
            content="forward timeout", status_code=504, media_type="text/plain",
        )
    except httpx.ConnectError as exc:
        logger.warning("alert_ingress: connect error to %s: %s", forward_url, exc)
        return Response(
            content="forward unreachable", status_code=502, media_type="text/plain",
        )

    logger.info(
        "alert_ingress: forwarded to %s for profile %s (status=%d)",
        forward_url, profile.name, resp.status_code,
    )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )
