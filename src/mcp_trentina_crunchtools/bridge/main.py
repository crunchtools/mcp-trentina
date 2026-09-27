"""``mcp-trentina-bridge``: run one profile's bridge, or prepare its store.

    mcp-trentina-bridge run
    mcp-trentina-bridge import-mautrix --crypto-db /import/crypto.db
    mcp-trentina-bridge delete-devices DEVICE [DEVICE ...]

``delete-devices`` exists for cutover: once the bridge holds an account, the
agent's old devices are pruned, which is what leaves the agent with no
upstream credential and makes the perimeter mandatory rather than optional.
It needs BRIDGE_PASSWORD, because the homeserver gates device deletion on
user-interactive auth.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

import uvicorn
from nio import DeleteDevicesResponse

from ..gateway.loader import read_secret_env
from .api import build_app
from .client import Bridge
from .import_mautrix import import_mautrix
from .settings import BridgeSettings

logger = logging.getLogger("mcp_trentina_crunchtools.bridge")


async def _run(settings: BridgeSettings) -> None:
    bridge = Bridge(settings)
    await bridge.login()
    server = uvicorn.Server(
        uvicorn.Config(
            build_app(bridge),
            host=settings.listen_host,
            port=settings.listen_port,
            log_level="warning",
        )
    )
    tasks = [
        asyncio.create_task(bridge.run(), name="sync"),
        asyncio.create_task(server.serve(), name="api"),
    ]
    try:
        # Either one ending ends the bridge: a sync loop with no API cannot
        # send, and an API with no sync loop sends into rooms it never reads.
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            task.result()
    finally:
        await bridge.aclose()


async def _delete_devices(settings: BridgeSettings, devices: list[str]) -> None:
    if not settings.password:
        raise SystemExit("delete-devices needs BRIDGE_PASSWORD")
    bridge = Bridge(settings)
    try:
        await delete_devices(bridge, devices)
    finally:
        await bridge.aclose()


async def delete_devices(bridge: Bridge, devices: list[str]) -> Any:
    """Delete other devices of the bridge's account, through password UIA.

    The first call asks the homeserver which auth it wants and returns a UIA
    session; the second answers it with the password.
    """
    settings = bridge.settings
    await bridge.login()
    if bridge.client.device_id in devices:
        raise SystemExit("refusing to delete the bridge's own device")
    first = await bridge.client.delete_devices(devices)
    auth: dict[str, Any] = {
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": settings.user_id},
        "password": settings.password,
    }
    session = getattr(first, "session", None)
    if session:
        auth["session"] = session
    result = await bridge.client.delete_devices(devices, auth)
    if not isinstance(result, DeleteDevicesResponse):
        raise SystemExit(f"delete failed: {result}")
    logger.warning("bridge[%s]: deleted %s", settings.profile, devices)
    return result


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(
        level=os.environ.get("BRIDGE_LOG_LEVEL", "WARNING"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser(prog="mcp-trentina-bridge")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the bridge")
    imp = sub.add_parser("import-mautrix", help="adopt a mautrix device into the store")
    imp.add_argument("--crypto-db", type=Path, required=True)
    rm = sub.add_parser("delete-devices", help="delete the account's other devices")
    rm.add_argument("devices", nargs="+")
    args = parser.parse_args(argv)

    if args.command == "import-mautrix":
        pickle_key = read_secret_env("BRIDGE_PICKLE_KEY")
        if not pickle_key:
            raise SystemExit("BRIDGE_PICKLE_KEY is required")
        store_dir = Path(os.environ.get("BRIDGE_STORE_DIR", "/data"))
        result = import_mautrix(args.crypto_db, store_dir, pickle_key)
        sys.stdout.write(f"{result}\n")
        return
    settings = BridgeSettings.from_env()
    if args.command == "delete-devices":
        asyncio.run(_delete_devices(settings, args.devices))
        return
    asyncio.run(_run(settings))


if __name__ == "__main__":
    main()
