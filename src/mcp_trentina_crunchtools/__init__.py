"""mcp-trentina-crunchtools: Quarantined web content extraction + MCP gateway."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

__version__ = "0.5.0"

DEFAULT_PORT = 8019
_TRUTHY = {"1", "true", "yes", "on"}

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from fastmcp import FastMCP


def main() -> None:
    """Entry point for mcp-trentina-crunchtools."""
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
            mcp.run(transport="sse", host=args.host, port=args.port)
        case _:
            if gateway_enabled:
                _run_with_gateway(mcp, host=args.host, port=args.port)
            else:
                mcp.run(transport="streamable-http", host=args.host, port=args.port)


def _run_with_gateway(mcp_server: FastMCP, *, host: str, port: int) -> None:
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
    from .gateway.compress import load_compression_cache, precompress_all

    profiles_path = Path(
        os.environ.get("TRENTINA_PROFILES_PATH", "/etc/trentina/profiles.yaml")
    )
    logger.info("gateway: loading profiles from %s", profiles_path)
    registry = load_profiles(profiles_path)

    register_internal_server(mcp_server)
    register_with_fastmcp(mcp_server, registry)
    logger.info(
        "gateway: registered %d profile(s) at /gateway/<profile>/mcp",
        len(registry),
    )

    load_compression_cache()

    import threading

    def _bg_compress_thread() -> None:
        loop = asyncio.new_event_loop()
        try:
            stats = loop.run_until_complete(precompress_all(registry))
            if stats:
                logger.info("gateway: pre-compressed tools: %s", stats)
        except Exception:
            logger.warning("gateway: pre-compression failed", exc_info=True)
        finally:
            loop.close()

    threading.Thread(target=_bg_compress_thread, daemon=True).start()

    mcp_server.run(transport="streamable-http", host=host, port=port)
