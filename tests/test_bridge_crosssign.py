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

from mcp_trentina_crunchtools.bridge import crosssign
from mcp_trentina_crunchtools.bridge import main as main_mod
from mcp_trentina_crunchtools.bridge.crosssign import (
    CrossSignError,
    _hkdf,
    canonical_json,
    reset_identity,
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
        # A path marker whose request fails with this answer instead.
        self.failing: dict[str, httpx.Response] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        failure = next((r for marker, r in self.failing.items() if marker in path), None)
        if failure is not None:
            return failure
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


async def test_a_tampered_secret_is_refused_before_anything_is_signed() -> None:
    account = Account()
    secret = account.data["m.cross_signing.self_signing"]["encrypted"][KEY_ID]
    secret["ciphertext"] = b64(os.urandom(32))
    async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
        with pytest.raises(CrossSignError, match="MAC mismatch"):
            await sign_own_device(client, "https://hs", SESSION, recovery_key(account.key))
    assert account.uploads == []


@pytest.mark.parametrize(
    ("marker", "answer", "match"),
    [
        ("/account_data/", httpx.Response(500, json={"errcode": "M_UNKNOWN"}), "account data"),
        ("/keys/query", httpx.Response(401, json={"errcode": "M_UNKNOWN_TOKEN"}), "keys query"),
        ("/keys/query", httpx.Response(502, text="<html>bad gateway</html>"), "keys query: 502"),
        ("/keys/query", httpx.Response(200, json={"device_keys": {}}), "no"),
        (
            "/keys/signatures/upload",
            httpx.Response(200, json={"failures": {USER: {DEVICE: {"errcode": "M_INVALID"}}}}),
            "signature upload",
        ),
        ("/keys/signatures/upload", httpx.Response(502, text="<html/>"), "signature upload: 502"),
    ],
)
async def test_a_failed_homeserver_call_is_reported_not_taken_for_success(
    marker: str, answer: httpx.Response, match: str
) -> None:
    account = Account()
    account.failing[marker] = answer
    async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
        with pytest.raises(CrossSignError, match=match):
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
    def _patch(
        self,
        monkeypatch: pytest.MonkeyPatch,
        calls: list[httpx.Request],
        answer: httpx.Response | None = None,
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return answer or httpx.Response(200, json={})

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

    async def test_a_refused_logout_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[httpx.Request] = []
        self._patch(monkeypatch, calls, httpx.Response(401, json={"errcode": "M_UNKNOWN_TOKEN"}))
        monkeypatch.setenv("BRIDGE_OLD_ACCESS_TOKEN", "old-token")
        with pytest.raises(SystemExit, match=r"logout-device: 401 .*M_UNKNOWN_TOKEN"):
            await main_mod._logout_device(_settings(tmp_path))

    async def test_an_unreachable_homeserver_fails_the_logout_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        _route_clients(monkeypatch, down)
        monkeypatch.setenv("BRIDGE_OLD_ACCESS_TOKEN", "old-token")
        with pytest.raises(SystemExit, match="logout-device: refused"):
            await main_mod._logout_device(_settings(tmp_path))


class ResettableAccount:
    """A homeserver that wants the reset approved in a browser first."""

    def __init__(self, approvals_needed: int = 1, challenge: httpx.Response | None = None) -> None:
        self.data: dict[str, Any] = {}
        self.challenge = challenge
        self.refused_writes: set[str] = set()
        self.refused_signatures = False
        self.uploaded: dict[str, Any] = {}
        self.signatures: list[dict[str, Any]] = []
        self.pending = approvals_needed
        self.device = {
            "user_id": USER,
            "device_id": DEVICE,
            "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
            "keys": {f"ed25519:{DEVICE}": "devkey"},
            "signatures": {USER: {f"ed25519:{DEVICE}": "selfsig"}},
        }

    def _upload(self, request: httpx.Request) -> httpx.Response:
        """Challenge while approvals are pending, then accept."""
        body = json.loads(request.content)
        if self.challenge is not None:
            return self.challenge
        self.pending -= 1
        if self.pending >= 0:
            return httpx.Response(
                401,
                json={
                    "session": "uia1",
                    "flows": [{"stages": ["org.matrix.cross_signing_reset"]}],
                    "params": {"org.matrix.cross_signing_reset": {"url": "https://account/reset"}},
                },
            )
        if "auth" in body:
            assert body["auth"] == {"type": "org.matrix.cross_signing_reset", "session": "uia1"}
        self.uploaded = body
        return httpx.Response(200, json={})

    def _account_data(self, request: httpx.Request) -> httpx.Response:
        kind = request.url.path.rsplit("/", 1)[1]
        if request.method == "PUT" and kind in self.refused_writes:
            return httpx.Response(500, json={"errcode": "M_UNKNOWN"})
        if request.method == "PUT":
            self.data[kind] = json.loads(request.content)
            return httpx.Response(200, json={})
        found = self.data.get(kind)
        return httpx.Response(200, json=found) if found is not None else httpx.Response(404)

    def _query(self, _request: httpx.Request) -> httpx.Response:
        ssk = self.uploaded["self_signing_key"]
        return httpx.Response(
            200,
            json={"device_keys": {USER: {DEVICE: self.device}}, "self_signing_keys": {USER: ssk}},
        )

    def _signatures(self, request: httpx.Request) -> httpx.Response:
        uploaded = json.loads(request.content)
        if self.refused_signatures:
            return httpx.Response(403, json={"errcode": "M_FORBIDDEN"})
        self.signatures.append(uploaded)
        return httpx.Response(200, json={"failures": {}})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        routes = (
            ("/keys/device_signing/upload", self._upload),
            ("/account_data/", self._account_data),
            ("/keys/query", self._query),
            ("/keys/signatures/upload", self._signatures),
        )
        handler = next((h for marker, h in routes if marker in request.url.path), None)
        return handler(request) if handler else httpx.Response(404)


class TestResetIdentity:
    async def test_reset_waits_for_approval_then_signs_and_stores(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(crosssign, "_APPROVAL_POLL", 0.0)
        account = ResettableAccount()
        asked: list[str] = []
        async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
            kept: list[str] = []
            reset = await reset_identity(client, "https://hs", SESSION, asked.append, kept.append)
            assert kept == [reset.recovery_key], "the key is surfaced before anything can fail"
            assert asked == ["https://account/reset"]
            # The key handed back opens the new storage and the device is signed.
            account.device["signatures"][USER].update(
                account.signatures[0][USER][DEVICE]["signatures"][USER]
            )
            again = await sign_own_device(client, "https://hs", SESSION, reset.recovery_key)
        assert again.already
        master = account.uploaded["master_key"]
        assert reset.master_key in master["keys"]
        for usage in ("self_signing_key", "user_signing_key"):
            signatures = account.uploaded[usage]["signatures"][USER]
            assert reset.master_key in signatures, f"{usage} is signed by the master key"
        for secret in (
            "m.cross_signing.master",
            "m.cross_signing.self_signing",
            "m.cross_signing.user_signing",
        ):
            assert secret in account.data

    async def test_nothing_is_published_when_the_reset_is_never_approved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(crosssign, "_APPROVAL_POLL", 0.0)
        monkeypatch.setattr(crosssign, "_APPROVAL_WINDOW", 0.0)
        account = ResettableAccount(approvals_needed=99)
        async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
            with pytest.raises(CrossSignError, match="not approved"):
                await reset_identity(client, "https://hs", SESSION, print, print)
        assert account.uploaded == {}, "no identity was published"
        assert account.signatures == []
        assert "m.secret_storage.default_key" in account.data, (
            "the stored keys match no published identity; a rerun replaces them"
        )

    async def test_a_failed_store_hands_out_no_key_and_publishes_nothing(self) -> None:
        account = ResettableAccount()
        account.refused_writes.add("m.cross_signing.self_signing")
        kept: list[str] = []
        async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
            with pytest.raises(
                CrossSignError, match=r"storing m\.cross_signing\.self_signing: 500"
            ):
                await reset_identity(client, "https://hs", SESSION, print, kept.append)
        assert kept == []
        assert account.uploaded == {}
        assert "m.secret_storage.default_key" not in account.data

    @pytest.mark.parametrize(
        ("challenge", "match"),
        [
            (httpx.Response(403, json={"errcode": "M_FORBIDDEN"}), "refused: 403 M_FORBIDDEN"),
            (httpx.Response(401, json={"flows": []}), "refused: 401"),
            (httpx.Response(502, text="<html>bad gateway</html>"), "refused: 502"),
            (
                httpx.Response(
                    401, json={"session": "s", "flows": [{"stages": ["m.login.password"]}]}
                ),
                "cannot answer",
            ),
        ],
    )
    async def test_a_challenge_it_cannot_answer_publishes_nothing(
        self, challenge: httpx.Response, match: str
    ) -> None:
        account = ResettableAccount(challenge=challenge)
        asked: list[str] = []
        async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
            with pytest.raises(CrossSignError, match=match):
                await reset_identity(client, "https://hs", SESSION, asked.append, print)
        assert asked == []
        assert account.uploaded == {}
        assert account.signatures == []

    async def test_an_upload_accepted_at_once_needs_no_approval(self) -> None:
        account = ResettableAccount(approvals_needed=0)
        asked: list[str] = []
        async with httpx.AsyncClient(transport=httpx.MockTransport(account)) as client:
            reset = await reset_identity(client, "https://hs", SESSION, asked.append, print)
        assert asked == []
        assert reset.master_key in account.uploaded["master_key"]["keys"]
        assert "auth" not in account.uploaded
        assert len(account.signatures) == 1


def _route_clients(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Every client the one-shot commands open talks to ``handler``."""
    real = httpx.AsyncClient
    monkeypatch.setattr(
        main_mod.httpx,
        "AsyncClient",
        lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
    )


class TestCommands:
    """The sign-device and reset-identity wrappers around the functions above."""

    async def test_sign_device_needs_the_recovery_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("BRIDGE_RECOVERY_KEY", raising=False)
        with pytest.raises(SystemExit, match="needs BRIDGE_RECOVERY_KEY"):
            await main_mod._sign_device(_settings(tmp_path))

    async def test_sign_device_reports_a_wrong_key_as_an_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        account = Account()
        _route_clients(monkeypatch, account)
        monkeypatch.setenv("BRIDGE_RECOVERY_KEY", recovery_key(os.urandom(32)))
        with pytest.raises(SystemExit, match=r"sign-device: .*does not open"):
            await main_mod._sign_device(_settings(tmp_path))
        assert account.uploads == []

    async def test_sign_device_signs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        account = Account()
        _route_clients(monkeypatch, account)
        monkeypatch.setenv("BRIDGE_RECOVERY_KEY", recovery_key(account.key))
        await main_mod._sign_device(_settings(tmp_path))
        assert len(account.uploads) == 1

    async def test_reset_prints_the_link_to_stderr_and_the_key_once_to_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(crosssign, "_APPROVAL_POLL", 0.0)
        _route_clients(monkeypatch, ResettableAccount())
        await main_mod._reset_identity(_settings(tmp_path))
        out, err = capsys.readouterr()
        assert "https://account/reset" in err
        assert "https://account/reset" not in out
        assert out.count("Recovery key") == 1
        assert "Recovery key" not in err

    async def test_a_failed_reset_exits_and_points_at_sign_device(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _route_clients(
            monkeypatch, ResettableAccount(challenge=httpx.Response(403, json={"errcode": "X"}))
        )
        with pytest.raises(SystemExit, match="finish with sign-device"):
            await main_mod._reset_identity(_settings(tmp_path))

    async def test_a_signing_failure_after_publishing_keeps_the_key_shown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        account = ResettableAccount(approvals_needed=0)
        account.refused_signatures = True
        _route_clients(monkeypatch, account)
        with pytest.raises(SystemExit, match="finish with sign-device"):
            await main_mod._reset_identity(_settings(tmp_path))
        assert account.uploaded, "the identity was published"
        assert capsys.readouterr().out.count("Recovery key") == 1

    async def test_an_unreachable_homeserver_is_an_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        _route_clients(monkeypatch, down)
        monkeypatch.setenv("BRIDGE_RECOVERY_KEY", recovery_key(os.urandom(32)))
        with pytest.raises(SystemExit, match="sign-device: refused"):
            await main_mod._sign_device(_settings(tmp_path))
