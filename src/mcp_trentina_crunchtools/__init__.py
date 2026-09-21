"""mcp-trentina-crunchtools: Quarantined web content extraction + MCP gateway."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .gateway.app import OAuthContext
    from .gateway.circuit import CircuitBreaker
    from .gateway.loader import GatewayConfig
    from .gateway.profile import Profile
    from .gateway.sessions import SessionRegistry

__version__ = "0.11.0"

DEFAULT_PORT = 8019
_TRUTHY = {"1", "true", "yes", "on"}
_LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from fastmcp import FastMCP


def _configure_logging() -> str:
    """Send application logs to stderr at ``TRENTINA_LOG_LEVEL`` (default INFO).

    Without this the root logger sits at WARNING and every ``logger.info`` in
    the gateway — session lifecycle above all — is silently discarded, leaving
    only uvicorn's access log to diagnose from.

    Returns the resolved level name so callers can forward it to
    ``mcp.run(log_level=...)``. FastMCP defaults uvicorn's own log level
    independently of the root logger, and uvicorn re-applies that level to
    ``uvicorn.access``/``uvicorn.error`` *after* its own dictConfig runs — so
    setting the root logger alone never quiets uvicorn's access log. httpx's
    logger is clamped here directly since it sits outside uvicorn's logging
    config entirely.

    The returned name is always one of ``_LOG_LEVELS``' five known keys, all
    of which uvicorn's ``Config(log_level=...)`` recognizes. Anything else —
    typos, or names that happen to collide with an unrelated attribute of the
    ``logging`` module (e.g. ``NOTSET``, or internals like ``_STYLES``) —
    falls back to ``INFO`` instead of being forwarded and crashing server
    startup. Deliberately does not use ``getattr(logging, level_name, ...)``:
    that resolves *any* uppercase module attribute, not just level constants.
    """
    level_name = os.environ.get("TRENTINA_LOG_LEVEL", "INFO").strip().upper()
    if level_name not in _LOG_LEVELS:
        level_name = "INFO"
    level = _LOG_LEVELS[level_name]
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(level)
    return level_name


def main() -> None:
    """Entry point for mcp-trentina-crunchtools."""
    log_level = _configure_logging()
    parser = argparse.ArgumentParser(
        prog="mcp-trentina-crunchtools",
        description="MCP server for quarantined web content extraction and gateway",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--no-dbus",
        action="store_true",
        help="Disable D-Bus interface registration",
    )

    args = parser.parse_args()

    from .database import get_db
    from .server import mcp

    get_db()

    if not args.no_dbus:
        from .dbus_interface import start_dbus

        loop = asyncio.new_event_loop()
        loop.run_until_complete(start_dbus())
        loop.close()

    gateway_enabled = os.environ.get("TRENTINA_GATEWAY_ENABLED", "").strip().lower() in _TRUTHY

    match args.transport:
        case "stdio":
            mcp.run(transport="stdio")
        case "sse":
            mcp.run(transport="sse", host=args.host, port=args.port, log_level=log_level)
        case _:
            if gateway_enabled:
                _run_with_gateway(mcp, host=args.host, port=args.port, log_level=log_level)
            else:
                mcp.run(
                    transport="streamable-http",
                    host=args.host,
                    port=args.port,
                    log_level=log_level,
                )


def _run_with_gateway(mcp_server: FastMCP, *, host: str, port: int, log_level: str) -> None:
    """Run trentina with gateway routes wired in via FastMCP's custom_route API.

    Loads profiles from TRENTINA_PROFILES_PATH and registers
    POST /gateway/{profile}/mcp endpoints on the FastMCP app. Trentina's own
    tools are bound as the in-process internal backend so profiles can surface
    them (via an ``internal://<label>`` backend) through the same gateway
    endpoint as the remote MCP backends.

    The legacy /mcp endpoint with the web-tools surface is still registered by
    mcp.run() at the same port, but Option C treats it as deprecated — consumers
    talk to the gateway only.

    Failure to load profiles is fatal — we fail closed rather than serve with
    no gateway when the operator asked for one.

    ``log_level`` is forwarded to ``mcp.run()`` so uvicorn's access/error
    loggers pick up the resolved ``TRENTINA_LOG_LEVEL``.
    """
    from .gateway import load_profiles, register_internal_server, register_with_fastmcp
    from .gateway.circuit import breaker
    from .gateway.compress import load_compression_cache, set_profiles
    from .gateway.llm_proxy import load_llm_providers, register_llm_routes
    from .gateway.loader import register_active_config
    from .gateway.matrix_proxy import register_matrix_routes
    from .gateway.sessions import session_registry

    profiles_path = Path(
        os.environ.get("TRENTINA_PROFILES_PATH", "/etc/trentina/profiles.yaml")
    )
    logger.info("gateway: loading profiles from %s", profiles_path)
    gateway_config = load_profiles(profiles_path)

    session_registry.session_ttl = gateway_config.session_ttl_seconds
    session_registry.max_sessions_per_profile = gateway_config.max_sessions_per_profile
    logger.info(
        "gateway: session_ttl=%.0fs max_sessions_per_profile=%d "
        "(set gateway.session_ttl_seconds / gateway.max_sessions_per_profile "
        "in %s to change)",
        gateway_config.session_ttl_seconds,
        gateway_config.max_sessions_per_profile,
        profiles_path,
    )

    oauth_context = _build_oauth_context(gateway_config)
    if oauth_context is not None:
        # http_app() reads mcp_server.auth at run() time, so setting it here —
        # before run() below — is what mounts Google's authorize/token/register
        # and the .well-known authorization-server metadata at the root.
        mcp_server.auth = oauth_context.provider

    register_internal_server(mcp_server)
    register_with_fastmcp(
        mcp_server, gateway_config.profiles, session_registry, oauth_context,
    )

    _wire_circuit_notifications(breaker, session_registry, gateway_config.profiles)

    logger.info(
        "gateway: registered %d profile(s) at /gateway/<profile>/mcp",
        len(gateway_config.profiles),
    )

    llm_providers = load_llm_providers(gateway_config.llm_providers)
    register_llm_routes(mcp_server, llm_providers, gateway_config.profiles)

    if gateway_config.matrix.get("enabled"):
        matrix_upstream = gateway_config.matrix.get(
            "upstream", "https://matrix-client.matrix.org",
        )
        register_matrix_routes(
            mcp_server, gateway_config.profiles, upstream=matrix_upstream,
        )

    from .gateway.alert_ingress import register_alert_routes

    register_alert_routes(mcp_server, gateway_config.profiles)

    from .gateway.backend import load_tool_list_cache
    from .gateway.ingress_defense import load_verdict_cache

    compressions = load_compression_cache()
    tool_lists = load_tool_list_cache()
    # Perimeter verdicts survive the restart that produced them. Without
    # this the first tools/list after a restart re-judges every description
    # through all three layers and times the client out.
    verdicts = load_verdict_cache()

    # WARNING, not INFO, and not because anything is wrong. Production runs
    # at TRENTINA_LOG_LEVEL=WARNING, so INFO is discarded — which meant the
    # one line that answers "did the caches load?" was invisible on the only
    # box where the question gets asked. A cold verdict cache PREDICTS a slow
    # first tools/list, and that prediction belongs in the journal before the
    # timeout, not in an SSH session after it.
    logger.warning(
        "startup: caches loaded — %d tool list(s), %d compression(s), "
        "%d perimeter verdict(s)%s",
        tool_lists, compressions, verdicts,
        "" if verdicts else " (COLD: the first tools/list will judge every "
                            "tool description and may take minutes)",
    )
    set_profiles(gateway_config.profiles)
    # Last, and after every route is wired: this records both the config and
    # the facts about what got wired that a later reload has to respect. See
    # tools/reload.py — without it, an edit to profiles.yaml costs a restart,
    # and a restart costs 40 minutes of re-judged tool descriptions.
    register_active_config(
        profiles_path,
        gateway_config,
        llm_providers,
        oauth_route_registered=oauth_context is not None,
    )

    _warm_classifier()

    legacy_mcp = os.environ.get("TRENTINA_LEGACY_MCP", "").strip().lower() in _TRUTHY
    if legacy_mcp:
        logger.warning(
            "gateway: legacy /mcp endpoint ENABLED (TRENTINA_LEGACY_MCP) — it "
            "bypasses gateway auth, allowlists, and audit; migrate consumers "
            "to /gateway/<profile>/mcp and unset the variable",
        )
        mcp_path = "/mcp"
    else:
        # The legacy endpoint served Trentina's full tool surface with no
        # bearer, no allowlist, and no audit — a bypass of everything the
        # gateway enforces. FastMCP must still mount its own MCP app
        # somewhere, so it goes to a per-boot unguessable path that nothing
        # is told about, and /mcp itself answers 410 with directions.
        mcp_path = f"/mcp-internal-{secrets.token_hex(16)}"

        from starlette.responses import Response as _Response

        async def legacy_mcp_tombstone(_request: object) -> _Response:
            return _Response(
                content=(
                    "The unauthenticated /mcp endpoint is closed. Use "
                    "/gateway/<profile>/mcp with your profile's bearer token."
                ),
                status_code=410,
                media_type="text/plain",
            )

        mcp_server.custom_route("/mcp", methods=["GET", "POST", "DELETE"])(
            legacy_mcp_tombstone
        )
        logger.info("gateway: legacy /mcp closed (410); MCP app mounted internally")

    mcp_server.run(
        transport="streamable-http",
        host=host,
        port=port,
        log_level=log_level,
        path=mcp_path,
    )


_AS_METADATA_PREFIX = "/.well-known/oauth-authorization-server"

#: The one client-auth method this proxy enforces beyond "none". Named
#: rather than repeated as a literal so the advertisement in the metadata
#: and the method stored on the client can never drift apart.
_AUTH_METHOD_POST = "client_secret_post"


class _AdvertiseSecretPost:
    """ASGI wrapper that adds client_secret_post to the AS metadata document.

    FastMCP wraps the metadata handler in CORS middleware, so the route's
    endpoint is a full ASGI app rather than a request/response function — the
    body has to be intercepted on the way out. Buffering is safe here: the
    document is a few hundred bytes and is not streamed.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        start_message: dict[str, Any] | None = None
        chunks: list[bytes] = []

        async def capture(message: dict[str, Any]) -> None:
            nonlocal start_message
            if message["type"] == "http.response.start":
                start_message = message
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body"):
                return
            await self._flush(start_message, b"".join(chunks), send)

        await self._inner(scope, receive, capture)

    async def _flush(
        self, start: dict[str, Any] | None, body: bytes, send: Any
    ) -> None:
        """Emit the patched document, or the original when it is not ours."""
        if start is None:
            return
        try:
            document = json.loads(body)
            methods = list(document.get("token_endpoint_auth_methods_supported") or [])
            if _AUTH_METHOD_POST not in methods:
                methods.append(_AUTH_METHOD_POST)
            document["token_endpoint_auth_methods_supported"] = methods
            body = json.dumps(document).encode()
        except (ValueError, AttributeError):
            # A non-JSON body here means CORS answered a preflight or the route
            # errored; pass it through rather than turning it into a 500.
            pass

        headers = [
            (name, value)
            for name, value in start.get("headers", [])
            if name.lower() != b"content-length"
        ]
        headers.append((b"content-length", str(len(body)).encode()))
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": body})


def _advertise_secret_post(route: Any) -> Any:
    """Wrap one authorization-server metadata route; pass anything else through.

    The document is edited on the way out rather than rebuilt: FastMCP composes
    it from several options objects inside get_routes, and duplicating that
    construction here would be a second copy to keep in step on every upgrade.
    """
    from starlette.routing import Route

    if not isinstance(route, Route) or not route.path.startswith(_AS_METADATA_PREFIX):
        return route

    return Route(
        path=route.path,
        endpoint=_AdvertiseSecretPost(route.app),
        methods=list(route.methods or ["GET", "OPTIONS"]),
        name=route.name,
    )


def _provisioned_clients(
    profiles: Mapping[str, Profile], scope: str
) -> dict[str, Any]:
    """Build the confidential clients declared across the OAuth profiles.

    OAuthConfig refuses a half-declared client and the loader fails closed on an
    unresolved secret, so every entry reaching here has an id, a secret and at
    least one redirect URI. Redirect URIs are registered verbatim and
    ``allowed_redirect_uri_patterns`` is pinned to that same list: a client the
    operator provisioned by hand has one known callback, and pattern widening
    exists for DCR clients on unpredictable localhost ports, not for this.

    ``scope`` is the provider's own normalized scope string, and registering the
    client with it is load-bearing: the SDK checks every requested scope against
    the client's registered scope, so a provisioned client left with none has
    every ``/authorize`` refused as ``invalid_scope`` before the flow reaches
    consent. FastMCP's DCR path gets this from ``_default_scope_str``; a
    provisioned client has to be handed the same value.
    """
    from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
    from pydantic import AnyUrl

    from .gateway.errors import ProfileConfigError

    clients: dict[str, Any] = {}
    for name, profile in sorted(profiles.items()):
        oauth = profile.oauth
        if oauth is None or oauth.client_id is None:
            continue
        secret = oauth.client_secret
        if secret is None:
            raise ProfileConfigError(
                f"profile {name!r}: oauth.client_id is set but the client "
                "secret did not resolve — refusing to serve a provisioned "
                "client whose secret would never be checked"
            )
        if oauth.client_id in clients:
            raise ProfileConfigError(
                f"profile {name!r}: oauth.client_id {oauth.client_id!r} is "
                "already provisioned by another profile — one client id cannot "
                "carry two secrets or two redirect sets"
            )
        clients[oauth.client_id] = ProxyDCRClient(
            client_id=oauth.client_id,
            client_secret=secret.get_secret_value(),
            redirect_uris=[AnyUrl(uri) for uri in oauth.client_redirect_uris],
            grant_types=["authorization_code", "refresh_token"],
            scope=scope,
            token_endpoint_auth_method=_AUTH_METHOD_POST,
            allowed_redirect_uri_patterns=list(oauth.client_redirect_uris),
            client_name=f"provisioned:{name}",
        )
    return clients


def _build_oauth_context(gateway_config: GatewayConfig) -> OAuthContext | None:
    """Construct the gateway's Google-backed OAuth context, or None.

    Returns None when no profile opts into OAuth — the common case, and the
    gateway behaves exactly as before. When at least one profile sets
    ``oauth.enabled`` this builds one ``GoogleProvider`` for the whole gateway
    (the human-facing authorization server that proxies login to Google) and
    fails closed if the client credentials are absent: an enabled profile with
    no provider is a misconfiguration, not a reason to serve it unprotected.

    Env:
        TRENTINA_OAUTH_GOOGLE_CLIENT_ID / _CLIENT_SECRET — the one Google OAuth
            client registered for this deployment (required when any profile
            enables OAuth).
        TRENTINA_OAUTH_BASE_URL — public origin clients reach (default
            https://mcp.crunchtools.com); the OAuth endpoints and the RFC 9728
            resource metadata are advertised under it.
        TRENTINA_OAUTH_JWT_SIGNING_KEY — optional. Pins the key that signs
            FastMCP tokens and derives the on-disk storage location. Set it so
            issued tokens and stored registrations survive a Google client
            secret rotation; if unset, the key derives from the secret.
    """
    from .gateway.app import OAuthContext
    from .gateway.errors import ProfileConfigError

    profiles = gateway_config.profiles
    enabled = [
        name
        for name, p in profiles.items()
        if p.oauth is not None and p.oauth.enabled
    ]
    if not enabled:
        return None

    client_id = os.environ.get("TRENTINA_OAUTH_GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET", "").strip()
    base_url = os.environ.get(
        "TRENTINA_OAUTH_BASE_URL", "https://mcp.crunchtools.com"
    ).strip().rstrip("/")
    signing_key = os.environ.get("TRENTINA_OAUTH_JWT_SIGNING_KEY", "").strip() or None

    if not client_id or not client_secret:
        raise ProfileConfigError(
            "profile(s) "
            f"{', '.join(sorted(enabled))} set oauth.enabled but "
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID / _CLIENT_SECRET are not set — "
            "refusing to start an OAuth seat with no provider"
        )

    from fastmcp.server.auth.providers.google import GoogleProvider

    class _GatewayGoogleProvider(GoogleProvider):
        """GoogleProvider whose protected-resource URL is the gateway endpoint.

        FastMCP derives the RFC 8707 resource (the audience of issued tokens and
        the value OAuthProxy's /authorize resource-indicator check compares
        against) from base_url + the path FastMCP mounts its OWN MCP app at.
        Trentina serves MCP from custom routes (/gateway/<profile>/mcp) and
        tombstones FastMCP's mount at a per-boot random internal path, so that
        derived resource is an unadvertisable internal URL that never matches the
        indicator a client takes from our RFC 9728 metadata (the gateway URL).
        gemini.google.com sends it and OAuthProxy rejected /authorize with
        invalid_target before ever reaching Google. Passing no path to the base
        set_mcp_path makes _get_resource_url return resource_base_url verbatim,
        and OAuthProxy.set_mcp_path then binds the JWT audience to it.
        """

        #: Statically provisioned confidential clients, by client_id.
        provisioned: ClassVar[dict[str, Any]] = {}

        def set_mcp_path(self, mcp_path: str | None) -> None:
            logger.debug(
                "gateway: ignoring FastMCP mount path %s; OAuth resource stays "
                "pinned to the advertised gateway endpoint",
                mcp_path,
            )
            super().set_mcp_path(None)

        async def get_client(self, client_id: str) -> Any:
            """Resolve a provisioned confidential client ahead of the DCR store.

            Both `/authorize` and the SDK's ClientAuthenticator at `/token` go
            through here, so returning the provisioned record is what makes the
            secret actually checked rather than merely advertised. Answering
            before the store also means DCR can never overwrite a provisioned
            client by registering the same id.
            """
            client = self.provisioned.get(client_id)
            if client is not None:
                return client
            return await super().get_client(client_id)

        def get_routes(self, mcp_path: str | None = None) -> list[Any]:
            """Advertise the client-auth methods this proxy genuinely enforces.

            OAuthProxy hardcodes `token_endpoint_auth_methods_supported` to
            `["none"]` because it never enforces a downstream client secret.
            With a provisioned client the SDK's ClientAuthenticator does enforce
            one (hmac-compared, expiry-checked), so `client_secret_post` becomes
            true rather than decorative — and a client holding credentials, like
            gemini.google.com Custom Apps, needs to be told it may present them
            or it abandons the flow before calling `/token` at all.

            The metadata route is rebuilt deep inside the base `get_routes`, so
            the advertised document is patched on the way out instead of
            reimplementing that construction. See CHANGELOG 0.9.0, RT #1502.
            """
            routes = super().get_routes(mcp_path)
            if not self.provisioned:
                return routes
            return [_advertise_secret_post(route) for route in routes]

    # Pin the OAuth resource to the OAuth profile's gateway endpoint (see
    # _GatewayGoogleProvider). FastMCP's OAuthProxy holds one resource per proxy,
    # so with more than one OAuth profile only the pinned one authorizes; warn
    # when that happens. See CHANGELOG 0.8.3.
    resource_profile = sorted(enabled)[0]
    resource_url = f"{base_url}/gateway/{resource_profile}/mcp"
    if len(enabled) > 1:
        logger.warning(
            "gateway: OAuth enabled on %d profiles %s but FastMCP's OAuthProxy "
            "holds one resource URL; pinned to %s — others fail /authorize "
            "with invalid_target",
            len(enabled), sorted(enabled), resource_url,
        )

    # Provisioned confidential clients are resolved by get_client ahead of the
    # DCR store, and their presence is what turns on the client_secret_post
    # advertisement in get_routes. Built before the provider so the class
    # attribute is populated by the time FastMCP asks for routes.
    provider = _GatewayGoogleProvider(
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        resource_base_url=resource_url,
        required_scopes=["openid", "email", "profile"],
        jwt_signing_key=signing_key,
        # CIMD off deliberately: OAuthProxy advertises client_id_metadata_
        # document_supported=true but never implements server-side CIMD. The MCP
        # spec makes clients try CIMD before DCR whenever that flag is set, so
        # gemini.google.com took the CIMD branch, found nothing, and reported
        # "automatic registration failed" without ever POSTing /register.
        # Disabling it drops the flag and its private_key_jwt method, so clients
        # fall through to DCR, which the proxy does implement. See CHANGELOG 0.8.2.
        enable_cimd=False,
    )
    # Provisioned confidential clients are resolved by get_client ahead of the
    # DCR store, and their presence is what turns on the client_secret_post
    # advertisement in get_routes. Built AFTER the provider so they can carry
    # its normalized scope string — registering them without it refuses every
    # /authorize as invalid_scope. Assigned before run(), which is when FastMCP
    # first asks for routes.
    provisioned = _provisioned_clients(profiles, " ".join(provider.required_scopes or []))
    _GatewayGoogleProvider.provisioned = provisioned
    if provisioned:
        logger.info(
            "gateway: %d provisioned OAuth client(s): %s "
            "(confidential, client_secret_post enforced)",
            len(provisioned), ", ".join(sorted(provisioned)),
        )

    # The issuer FastMCP will advertise in its own authorization-server metadata.
    # Sourced from the provider (not rebuilt from base_url) so our protected-
    # resource metadata names the AS with the identical string — a pydantic
    # AnyHttpUrl appends a trailing slash to a bare origin, and RFC 8414 §3.3
    # rejects any mismatch. See OAuthContext.
    issuer = str(provider.issuer_url)
    # The scopes the provider advertises as scopes_supported in its AS metadata,
    # normalized (email/profile -> full googleapis URIs). Captured so our
    # protected-resource document names the identical list. See OAuthContext.
    scopes = tuple(provider.required_scopes or [])
    logger.info(
        "gateway: Google OAuth provider built for %d profile(s): %s "
        "(base_url=%s issuer=%s scopes=%s)",
        len(enabled), ", ".join(sorted(enabled)), base_url, issuer, " ".join(scopes),
    )
    return OAuthContext(
        provider=provider, base_url=base_url, issuer=issuer, scopes=scopes
    )


def _warm_classifier() -> None:
    """Load L2 at startup instead of on first scan, and say so out loud.

    The classifier lazy-loads on first use. In production on 2026-09-09 that
    first use arrived eight hours after the container started — so for eight
    hours the gateway was serving traffic with L2 unavailable, and nothing
    said so. `classify()` returns None when the model is absent and every
    caller proceeds, which means an absent layer is indistinguishable from a
    layer that looked and found nothing.

    Loading here converts a silent gap into a startup log line and a /health
    field that is true from the first request. It does not make the gateway
    refuse to start: a box with no model should still proxy, still sanitize,
    and still be obviously degraded rather than quietly so.
    """
    from .quarantine.classifier import classifier_status, is_classifier_available

    log = logging.getLogger(__name__)
    if is_classifier_available():
        log.info("gateway: L2 classifier loaded at startup (%s)", classifier_status())
    else:
        log.warning(
            "gateway: L2 classifier UNAVAILABLE (%s) — L1 only. /health reports "
            "this; alert on it rather than assuming the layer is running.",
            classifier_status(),
        )


def _wire_circuit_notifications(
    circuit_breaker: CircuitBreaker,
    sessions: SessionRegistry,
    profiles: Mapping[str, Profile],
) -> None:
    """Connect circuit breaker state changes to session notification broadcast.

    When a circuit opens or closes, determines which profiles use the
    affected backend URL and broadcasts ``tools/listChanged`` to all
    active sessions for those profiles.
    """
    from .gateway.circuit import State
    from .gateway.router import reset_profile_tools_cache

    pending_tasks: set[asyncio.Task[int]] = set()

    def on_circuit_change(url: str, old_state: State, new_state: State) -> None:
        if old_state == new_state:
            return

        should_notify = (
            (old_state is State.CLOSED and new_state is State.OPEN)
            or (old_state is State.HALF_OPEN and new_state is State.CLOSED)
            or (old_state is State.HALF_OPEN and new_state is State.OPEN)
        )
        if not should_notify:
            return

        reset_profile_tools_cache()

        affected = sessions.profiles_for_backend_url(url, dict(profiles))
        for profile_name in affected:
            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(
                    sessions.broadcast_tools_changed(profile_name)
                )
                pending_tasks.add(task)
                task.add_done_callback(pending_tasks.discard)
            except RuntimeError:
                logger.debug(
                    "gateway: no event loop for notification broadcast "
                    "(url=%s profile=%s)",
                    url,
                    profile_name,
                )

    circuit_breaker.on_state_change(on_circuit_change)
    logger.info("gateway: circuit breaker → session notification wired")
