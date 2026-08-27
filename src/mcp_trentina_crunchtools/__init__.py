"""mcp-trentina-crunchtools: Quarantined web content extraction + MCP gateway."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .gateway.circuit import CircuitBreaker
    from .gateway.profile import Profile
    from .gateway.sessions import SessionRegistry

__version__ = "0.5.0"

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
    POST /gateway/{profile}/mcp endpoints on the FastMCP app. Airlock's own
    tools are bound as the in-process internal backend so profiles can surface
    them (via an ``internal://<label>`` backend) through the same gateway
    endpoint as the remote MCP backends.

    The legacy /mcp endpoint with the web-tools surface is still registered by
    mcp.run() at the same port, but Option C treats it as deprecated — consumers
    talk to the gateway only.

    Failure to load profiles is fatal — we fail closed rather than serve with
    no gateway when the operator asked for one.
    """
    from .gateway import load_profiles, register_internal_server, register_with_fastmcp
    from .gateway.circuit import breaker
    from .gateway.compress import load_compression_cache, set_profiles
    from .gateway.llm_proxy import load_llm_providers, register_llm_routes
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

    register_internal_server(mcp_server)
    register_with_fastmcp(mcp_server, gateway_config.profiles, session_registry)

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
        register_matrix_routes(mcp_server, upstream=matrix_upstream)

    from .gateway.alert_ingress import register_alert_routes

    register_alert_routes(mcp_server, gateway_config.profiles)

    from .gateway.backend import load_tool_list_cache

    load_compression_cache()
    load_tool_list_cache()
    set_profiles(gateway_config.profiles)

    mcp_server.run(transport="streamable-http", host=host, port=port, log_level=log_level)


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
    import asyncio

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
