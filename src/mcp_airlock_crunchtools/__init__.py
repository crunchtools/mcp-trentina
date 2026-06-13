"""mcp-airlock-crunchtools: Quarantined web content extraction + MCP gateway."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

__version__ = "0.3.0"

DEFAULT_PORT = 8019
_TRUTHY = {"1", "true", "yes", "on"}

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from fastmcp import FastMCP


def main() -> None:
    """Entry point for mcp-airlock-crunchtools."""
    parser = argparse.ArgumentParser(
        prog="mcp-airlock-crunchtools",
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

    gateway_enabled = os.environ.get("AIRLOCK_GATEWAY_ENABLED", "").strip().lower() in _TRUTHY

    match args.transport:
        case "stdio":
            mcp.run(transport="stdio")
        case "sse":
            mcp.run(transport="sse", host=args.host, port=args.port)
        case _:
            if gateway_enabled:
                _run_with_gateway(mcp, host=args.host, port=args.port)
            else:
                mcp.run(transport="streamable-http", host=args.host, port=args.port)


def _run_with_gateway(mcp_server: FastMCP, *, host: str, port: int) -> None:
    """Run airlock with the gateway routes mounted alongside the FastMCP app.

    Loads profiles from AIRLOCK_PROFILES_PATH and exposes
    POST /gateway/{profile}/mcp endpoints. The existing /mcp endpoint with
    the web-tools surface remains unchanged at the same port.

    Failure to load profiles is fatal — we fail closed rather than serve with
    no gateway when the operator asked for one.
    """
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount

    from .gateway import gateway_app, load_profiles

    profiles_path = Path(
        os.environ.get("AIRLOCK_PROFILES_PATH", "/etc/airlock/profiles.yaml")
    )
    logger.info("gateway: loading profiles from %s", profiles_path)
    registry = load_profiles(profiles_path)

    fastmcp_app = mcp_server.http_app(transport="streamable-http")
    gw_app = gateway_app(registry)

    parent = Starlette(
        routes=[
            Mount("/", app=gw_app),
            Mount("/", app=fastmcp_app),
        ]
    )

    logger.info(
        "gateway: mounted %d profile(s); listening on %s:%d",
        len(registry),
        host,
        port,
    )
    uvicorn.run(parent, host=host, port=port, log_config=None)
