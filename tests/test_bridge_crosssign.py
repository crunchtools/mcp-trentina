"""Cross-signing the bridge's device from secret storage, and pruning the old one.

The account, its secret storage and its published keys are built here with
the same primitives a client uses, so the test proves the round trip: a key
stored the way Element stores it is read back, and the signature uploaded
verifies against the published self-signing key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa

from mcp_trentina_crunchtools.bridge import main as main_mod
from mcp_trentina_crunchtools.bridge.crosssign import (
    CrossSignError,
    _hkdf,
    canonical_json,
    sign_own_device,
)
from mcp_trentina_crunchtools.bridge.settings import BridgeSettings
from mcp_trentina_crunchtools.matrix.recovery_key import PREFIX

USER = "@agent2-bot:matrix.org"
DEVICE = "NEWDEV"
KEY_ID = "ssss1"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode().rstrip("=")


def recovery_key(key: bytes) -> str:
    raw = bytes(PREFIX) + key
    parity = 0
    for byte in raw:
        parity ^= byte
    raw += bytes([parity])
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = B58[rem] + out
    return out


def encrypt(key: bytes, name: str, plaintext: bytes) -> dict[str, str]:
    aes_key, mac_key = _hkdf(key, name.encode())
    iv = bytearray(os.urandom(16))
    iv[8] &= 0x7F
    ciphertext = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=bytes(iv)).encrypt(
        plaintext
    )
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    return {"iv": b64(bytes(iv)), "ciphertext": b64(ciphertext), "mac": b64(mac)}


class Account:
    """An account with secret storage, a self-signing key and one device."""

    def __init__(self) -> None:
        self.key = os.urandom(32)
        self.seed = os.urandom(32)
        signer = ECC.construct(curve="Ed25519", seed=self.seed)
        self.ssk_public = b64(signer.public_key().export_key(format="raw"))
        check = encrypt(self.key, "", b"\0" * 32)
        self.data = {
            "m.secret_storage.default_key": {"key": KEY_ID},
            f"m.secret_storage.key.{KEY_ID}": {
                "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
                "iv": check["iv"],
                "mac": check["mac"],
            },
            "m.cross_signing.self_signing": {
                "encrypted": {
                    KEY_ID: encrypt(
                        self.key, "m.cross_signing.self_signing", b64(self.seed).encode()
                    )
                }
            },
        }
        self.device = {
            "user_id": USER,
            "device_id": DEVICE,
            "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
            "keys": {f"ed25519:{DEVICE}": "devkey"},
            "signatures": {USER: {f"ed25519:{DEVICE}": "selfsig"}},
            "unsigned": {"device_display_name": "bridge"},
        }
        self.uploads: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/account_data/" in path:
            kind = path.rsplit("/", 1)[1]
            return (
                httpx.Response(200, json=self.data[kind])
                if kind in self.data
                else httpx.Response(404)
            )
        if path.endswith("/keys/query"):
            return httpx.Response(
                200,
                json={
                    "device_keys": {USER: {DEVICE: self.device}},
                    "self_signing_keys": {
                        USER: {"keys": {f"ed25519:{self.ssk_public}": self.ssk_public}}
                    },
                },
            )
        if path.endswith("/keys/signatures/upload"):
            self.uploads.append(json.loads(request.content))
            return httpx.Response(200, json={"failures": {}})
        return httpx.Response(404)


SESSION = {"user_id": USER, "device_id": DEVICE, "access_token": "tok"}


async def test_the_device_is_signed_with_the_stored_key() -> None:
    account = Account()
    async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
        result = await sign_own_device(client, "https://hs", SESSION, recovery_key(account.key))
    assert not result.already
    [upload] = account.uploads
    signed = upload[USER][DEVICE]
    signature = signed["signatures"][USER][f"ed25519:{account.ssk_public}"]
    body = {k: v for k, v in signed.items() if k not in ("signatures", "unsigned")}
    public = ECC.construct(curve="Ed25519", seed=account.seed).public_key()
    eddsa.new(public, "rfc8032").verify(
        canonical_json(body), base64.b64decode(signature + "=" * (-len(signature) % 4))
    )


async def test_a_signed_device_is_left_alone() -> None:
    account = Account()
    async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
        await sign_own_device(client, "https://hs", SESSION, recovery_key(account.key))
        account.device["signatures"][USER].update(
            account.uploads[0][USER][DEVICE]["signatures"][USER]
        )
        again = await sign_own_device(client, "https://hs", SESSION, recovery_key(account.key))
    assert again.already
    assert len(account.uploads) == 1


async def test_the_wrong_recovery_key_uploads_nothing() -> None:
    account = Account()
    async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
        with pytest.raises(CrossSignError, match="does not open"):
            await sign_own_device(client, "https://hs", SESSION, recovery_key(os.urandom(32)))
    assert account.uploads == []


async def test_a_stored_key_that_is_not_the_published_one_uploads_nothing() -> None:
    account = Account()
    account.ssk_public = b64(os.urandom(32))
    async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
        with pytest.raises(CrossSignError, match="not the published one"):
            await sign_own_device(client, "https://hs", SESSION, recovery_key(account.key))
    assert account.uploads == []


def _settings(tmp_path: Path) -> BridgeSettings:
    (tmp_path / "session.json").write_text(json.dumps(SESSION))
    return BridgeSettings(
        profile="agent2",
        homeserver="https://hs",
        user_id=USER,
        store_dir=tmp_path,
        pickle_key="pk",
        gateway_url="http://mcp-trentina:8019",
        ingress_token="i",
        bridge_token="b",
        listen_host="127.0.0.1",
        listen_port=8471,
        device_name="d",
        device_id="",
        access_token="",
        password="",
    )


class TestLogoutDevice:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, calls: list[httpx.Request]) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(200, json={})

        real = httpx.AsyncClient
        monkeypatch.setattr(
            main_mod.httpx,
            "AsyncClient",
            lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
        )

    async def test_the_old_device_logs_out_with_its_own_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[httpx.Request] = []
        self._patch(monkeypatch, calls)
        monkeypatch.setenv("BRIDGE_OLD_ACCESS_TOKEN", "old-token")
        await main_mod._logout_device(_settings(tmp_path))
        [call] = calls
        assert call.url.path == "/_matrix/client/v3/logout"
        assert call.headers["authorization"] == "Bearer old-token"

    async def test_the_bridges_own_session_is_never_logged_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[httpx.Request] = []
        self._patch(monkeypatch, calls)
        monkeypatch.setenv("BRIDGE_OLD_ACCESS_TOKEN", "tok")
        with pytest.raises(SystemExit, match="own device"):
            await main_mod._logout_device(_settings(tmp_path))
        assert calls == []
