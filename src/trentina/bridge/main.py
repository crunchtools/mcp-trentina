"""``trentina-bridge``: run one profile's bridge, or prepare its store.

    trentina-bridge run
    trentina-bridge import-mautrix --crypto-db /import/crypto.db
    trentina-bridge logout-device        # BRIDGE_OLD_ACCESS_TOKEN
    trentina-bridge sign-device          # BRIDGE_RECOVERY_KEY
    trentina-bridge reset-identity       # recovery key lost

``logout-device`` exists for cutover: once the bridge holds an account, the
agent's old device is pruned, which is what leaves the agent with no upstream
credential and makes the perimeter mandatory rather than optional. It logs the
old device out with that device's own token: a homeserver behind MAS
serves neither ``/delete_devices`` nor ``DELETE /devices``.

``sign-device`` cross-signs the bridge's own device with the account's
self-signing key from secret storage, so a device the bridge logged in fresh
does not show as unverified. ``reset-identity`` is for an account whose
recovery key is lost: new cross-signing keys, approved by the account owner
in a browser, and a new recovery key printed once.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import httpx
import uvicorn
from nio.store import SqliteStore

from .. import logsafe
from ..gateway.loader import read_secret_env
from ..matrix.recovery_key import RecoveryKeyError
from .api import build_app
from .client import Bridge
from .crosssign import CrossSignError, reset_identity, sign_own_device
from .import_mautrix import import_mautrix
from .settings import BridgeSettings

logger = logging.getLogger("trentina.bridge")

# Seconds for each request of a one-shot command against the homeserver.
_ONE_SHOT_TIMEOUT = 30.0


async def _run(settings: BridgeSettings) -> None:
    """Run the sync loop and the API until either one ends; always close."""
    bridge = Bridge(settings)
    try:
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
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            # Also on cancellation of _run itself: no task outlives the clients.
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await bridge.aclose()


async def _logout_device(settings: BridgeSettings) -> None:
    """Log out the agent's old device with its own access token."""
    old = read_secret_env("BRIDGE_OLD_ACCESS_TOKEN")
    if not old:
        raise SystemExit("logout-device needs BRIDGE_OLD_ACCESS_TOKEN")
    if old == _session(settings)["access_token"]:
        raise SystemExit("refusing to log out the bridge's own device")
    # nosemgrep: trentina-httpx-client-outside-egress -- operator env URL
    async with httpx.AsyncClient(timeout=_ONE_SHOT_TIMEOUT) as client:
        try:
            resp = await client.post(
                f"{settings.homeserver}/_matrix/client/v3/logout",
                headers={"Authorization": f"Bearer {old}"},
                json={},
            )
        except httpx.HTTPError as exc:
            raise SystemExit(f"logout-device: {exc}") from exc
    if resp.status_code != 200:
        raise SystemExit(f"logout-device: {resp.status_code} {resp.text[:200]}")
    logger.warning("bridge[%s]: old device logged out", settings.profile)


async def _sign_device(settings: BridgeSettings) -> None:
    """Cross-sign the bridge's device from the account's secret storage."""
    recovery_key = read_secret_env("BRIDGE_RECOVERY_KEY")
    if not recovery_key:
        raise SystemExit("sign-device needs BRIDGE_RECOVERY_KEY")
    # nosemgrep: trentina-httpx-client-outside-egress -- operator env URL
    async with httpx.AsyncClient(timeout=_ONE_SHOT_TIMEOUT) as client:
        try:
            session = _session(settings)
            result = await sign_own_device(
                client, settings.homeserver, session, _device_keys(settings, session), recovery_key
            )
        except (CrossSignError, RecoveryKeyError, httpx.HTTPError) as exc:
            raise SystemExit(f"sign-device: {exc}") from exc
    verb = "was already signed" if result.already else "signed"
    logger.warning("bridge[%s]: device %s %s", settings.profile, result.device_id, verb)


async def _reset_identity(settings: BridgeSettings) -> None:
    """New cross-signing identity; the recovery key goes to stdout only."""

    def ask(url: str) -> None:
        sys.stderr.write(
            f"\nApprove the reset as {settings.user_id}, within 10 minutes:\n  {url}\n\n"
        )
        sys.stderr.flush()

    def keep(recovery_key: str) -> None:
        sys.stdout.write(f"Recovery key (keep it; shown once): {recovery_key}\n")
        sys.stdout.flush()

    # nosemgrep: trentina-httpx-client-outside-egress -- operator env URL
    async with httpx.AsyncClient(timeout=_ONE_SHOT_TIMEOUT) as client:
        try:
            session = _session(settings)
            result = await reset_identity(
                client, settings.homeserver, session, _device_keys(settings, session), ask, keep
            )
        except (CrossSignError, httpx.HTTPError) as exc:
            raise SystemExit(f"reset-identity: {exc}") from exc
    logger.warning(
        "bridge[%s]: new identity %s; device %s signed",
        settings.profile,
        result.master_key,
        result.device_id,
    )


def _session(settings: BridgeSettings) -> dict[str, str]:
    """The session the bridge saved on its first start."""
    path = settings.store_dir / "session.json"
    if not path.exists():
        raise SystemExit(f"{path} does not exist: run the bridge once first")
    try:
        saved: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path} is not valid JSON ({exc}): restore it or log in again") from exc
    return saved


def _device_keys(settings: BridgeSettings, session: dict[str, str]) -> dict[str, str]:
    """The device's identity keys from the bridge's own crypto store: what
    its homeserver's copy must match before anything signs it."""
    user_id, device_id = session["user_id"], session["device_id"]
    store = SqliteStore(user_id, device_id, str(settings.store_dir), settings.pickle_key)
    account = store.load_account()
    if account is None:
        raise SystemExit(f"no crypto account for {device_id} in {settings.store_dir}")
    return {f"{algorithm}:{device_id}": key for algorithm, key in account.identity_keys.items()}


def main(argv: list[str] | None = None) -> None:
    logsafe.configure("BRIDGE_LOG_LEVEL", default="WARNING")
    parser = argparse.ArgumentParser(prog="trentina-bridge")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the bridge")
    imp = sub.add_parser("import-mautrix", help="adopt a mautrix device into the store")
    imp.add_argument("--crypto-db", type=Path, required=True)
    sub.add_parser("logout-device", help="log out the old device (BRIDGE_OLD_ACCESS_TOKEN)")
    sub.add_parser("sign-device", help="cross-sign the bridge's device (BRIDGE_RECOVERY_KEY)")
    sub.add_parser("reset-identity", help="new cross-signing identity (recovery key lost)")
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
    if args.command == "run":
        from ..gateway.loader import secret_env_names
        from ..posture import check_secret_sources, check_startup_posture

        check_startup_posture()
        check_secret_sources(secret_env_names())
    if args.command == "logout-device":
        asyncio.run(_logout_device(settings))
        return
    if args.command == "sign-device":
        asyncio.run(_sign_device(settings))
        return
    if args.command == "reset-identity":
        asyncio.run(_reset_identity(settings))
        return
    asyncio.run(_run(settings))


if __name__ == "__main__":
    main()
