"""Sign the bridge's own device with the account's self-signing key.

A device nobody has signed shows as unverified: clients mark its messages,
and some users' clients refuse to send it room keys at all. An adopted device
is usually signed already; a device the bridge logged in fresh is not.

The self-signing key's private half lives in the account's secret storage
(SSSS), encrypted under the recovery key. This reads it with that key, checks
it against the published public key, signs the bridge's device keys, and
uploads the signature. No identity is reset, so nobody who already verified
the account has to verify it again.

Run once, by an operator, with the recovery key supplied for that run only.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from unpaddedbase64 import decode_base64, encode_base64

from ..matrix.recovery_key import decode_recovery_key, encode_recovery_key

if TYPE_CHECKING:
    from collections.abc import Callable

    import httpx

logger = logging.getLogger(__name__)

SSSS_ALGORITHM = "m.secret_storage.v1.aes-hmac-sha2"
SELF_SIGNING = "m.cross_signing.self_signing"


class CrossSignError(RuntimeError):
    """The account cannot be read, reset or signed as needed.

    From ``sign_own_device`` nothing was uploaded. From ``reset_identity`` it
    depends on the step, which its docstring lists."""


def _hkdf(key: bytes, info: bytes) -> tuple[bytes, bytes]:
    """HKDF-SHA256 with a zero salt, as SSSS specifies: 32 bytes of AES key,
    32 of HMAC key."""
    prk = hmac.new(b"\0" * 32, key, hashlib.sha256).digest()
    first = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    second = hmac.new(prk, first + info + b"\x02", hashlib.sha256).digest()
    return first, second


def decrypt_secret(key: bytes, name: str, encrypted: dict[str, str]) -> str:
    """One SSSS secret, authenticated before it is decrypted."""
    aes_key, mac_key = _hkdf(key, name.encode())
    ciphertext = decode_base64(encrypted["ciphertext"])
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, decode_base64(encrypted["mac"])):
        raise CrossSignError(f"{name}: MAC mismatch, so the recovery key is not this account's")
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=decode_base64(encrypted["iv"]))
    return cipher.decrypt(ciphertext).decode()


def check_key(key: bytes, description: dict[str, Any]) -> None:
    """The recovery key opens this secret-storage key: it encrypts 32 zero
    bytes under the empty name to the MAC the description publishes."""
    if description.get("algorithm") != SSSS_ALGORITHM:
        raise CrossSignError(f"unsupported secret storage algorithm {description.get('algorithm')}")
    aes_key, mac_key = _hkdf(key, b"")
    cipher = AES.new(
        aes_key, AES.MODE_CTR, nonce=b"", initial_value=decode_base64(description["iv"])
    )
    ciphertext = cipher.encrypt(b"\0" * 32)
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, decode_base64(description["mac"])):
        raise CrossSignError("the recovery key does not open this account's secret storage")


def canonical_json(value: Any) -> bytes:
    """Matrix canonical JSON: sorted keys, no whitespace, UTF-8. What a
    signature covers, so any other encoding verifies nowhere."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _signing_key(seed: bytes) -> Any:
    # pycryptodome takes the 32-byte seed as bytes; its typing says str or int.
    return ECC.construct(curve="Ed25519", seed=cast("Any", seed))


def public_key(seed: bytes) -> str:
    """The unpadded-base64 Ed25519 public key for a seed."""
    return encode_base64(_signing_key(seed).public_key().export_key(format="raw"))


def sign(value: dict[str, Any], seed: bytes) -> tuple[str, str]:
    """``(key id, signature)`` over ``value`` minus signatures and unsigned."""
    key = _signing_key(seed)
    public = public_key(seed)
    body = {k: v for k, v in value.items() if k not in ("signatures", "unsigned")}
    signature = encode_base64(eddsa.new(key, "rfc8032").sign(canonical_json(body)))
    return f"ed25519:{public}", signature


def _json(resp: httpx.Response) -> dict[str, Any]:
    """A response's JSON object, or ``{}`` for any other body: an error from
    a proxy is often an HTML page, and that must not escape as a
    ``JSONDecodeError`` in place of the homeserver's answer."""
    try:
        body = resp.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _require(resp: httpx.Response, what: str) -> dict[str, Any]:
    """The JSON object of a 200, else ``CrossSignError`` naming the call."""
    body = _json(resp)
    if resp.status_code != 200:
        raise CrossSignError(f"{what}: {resp.status_code} {body.get('errcode', '')}".rstrip())
    return body


@dataclass(frozen=True)
class Signed:
    """What ``sign_own_device`` did."""

    device_id: str
    key_id: str
    already: bool


async def sign_own_device(
    client: httpx.AsyncClient,
    homeserver: str,
    session: dict[str, str],
    recovery_key: str,
) -> Signed:
    """Sign the session's device with the account's self-signing key.

    Args:
        client: the HTTP client for the upstream homeserver; not closed here.
        homeserver: its base URL.
        session: the bridge's saved session: ``user_id``, ``device_id`` and
            ``access_token``. The device signed is that one, never another.
        recovery_key: the account's secret-storage recovery key, as a client
            displays it. It decrypts the self-signing key and is used for
            nothing else.

    Returns:
        ``Signed``: the device, the self-signing key ID, and ``already`` when
        the device carried that signature before, in which case nothing was
        uploaded.

    Raises:
        RecoveryKeyError: the recovery key is malformed.
        CrossSignError: it does not open this account's secret storage, the
            storage uses an unsupported algorithm, the stored key is not the
            published one, or the upload failed. Nothing is uploaded unless
            every check passed.
    """
    user_id, device_id = session["user_id"], session["device_id"]
    auth = {"Authorization": f"Bearer {session['access_token']}"}
    base = f"{homeserver}/_matrix/client/v3"

    async def account_data(kind: str) -> dict[str, Any]:
        resp = await client.get(
            f"{base}/user/{quote(user_id, safe='')}/account_data/{quote(kind, safe='')}",
            headers=auth,
        )
        return _require(resp, f"account data {kind}")

    key = decode_recovery_key(recovery_key)
    query = await client.post(
        f"{base}/keys/query", headers=auth, json={"device_keys": {user_id: [device_id]}}
    )
    try:
        key_id = (await account_data("m.secret_storage.default_key"))["key"]
        check_key(key, await account_data(f"m.secret_storage.key.{key_id}"))
        encrypted = (await account_data(SELF_SIGNING))["encrypted"][key_id]
        keys = _require(query, "keys query")
        published = keys["self_signing_keys"][user_id]["keys"]
        device = keys["device_keys"][user_id][device_id]
    except (KeyError, TypeError) as exc:
        raise CrossSignError(f"the account has no {exc} where its keys should be") from exc
    seed = decode_base64(decrypt_secret(key, SELF_SIGNING, encrypted))
    signer, signature = sign(device, seed)
    if signer not in published:
        raise CrossSignError("the stored self-signing key is not the published one")
    if signer in device.get("signatures", {}).get(user_id, {}):
        return Signed(device_id, signer, already=True)

    signed = {k: v for k, v in device.items() if k != "unsigned"}
    signed["signatures"] = {user_id: {signer: signature}}
    upload = await client.post(
        f"{base}/keys/signatures/upload", headers=auth, json={user_id: {device_id: signed}}
    )
    failures = _require(upload, "signature upload").get("failures")
    if failures:
        raise CrossSignError(f"signature upload: {failures}")
    return Signed(device_id, signer, already=False)


# How long to keep retrying the upload while the account owner approves the
# reset in the browser, and how often.
_APPROVAL_WINDOW = 600.0
_APPROVAL_POLL = 10.0
_CROSS_SIGNING = ("master", "self_signing", "user_signing")
# Clear bit 63 of the IV, as clients do, so the CTR counter cannot overflow
# into the upper half; and the random bytes behind a new storage key's ID.
_COUNTER_HEADROOM = 0x7F
_KEY_ID_BYTES = 24


def _encrypt_secret(key: bytes, name: str, secret: str) -> dict[str, str]:
    """One SSSS secret, as ``decrypt_secret`` reads it."""
    aes_key, mac_key = _hkdf(key, name.encode())
    iv = bytearray(os.urandom(16))
    iv[8] &= _COUNTER_HEADROOM
    ciphertext = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=bytes(iv)).encrypt(
        secret.encode()
    )
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    return {
        "iv": encode_base64(bytes(iv)),
        "ciphertext": encode_base64(ciphertext),
        "mac": encode_base64(mac),
    }


def _key_object(user_id: str, usage: str, seed: bytes) -> dict[str, Any]:
    public = public_key(seed)
    return {"user_id": user_id, "usage": [usage], "keys": {f"ed25519:{public}": public}}


@dataclass(frozen=True)
class Reset:
    """What ``reset_identity`` did. ``recovery_key`` is shown once."""

    device_id: str
    master_key: str
    recovery_key: str


async def reset_identity(
    client: httpx.AsyncClient,
    homeserver: str,
    session: dict[str, str],
    on_approval: Callable[[str], None],
    on_recovery_key: Callable[[str], None],
) -> Reset:
    """Give the account a new cross-signing identity, and sign the bridge.

    For an account whose recovery key is lost, so its self-signing key can no
    longer be read. Everyone who verified the account will see its identity
    change once and must verify it again; ``sign_own_device`` is the path
    that avoids that, whenever the recovery key exists.

    New master, self-signing and user-signing keys are generated, stored in
    new secret storage under a new recovery key for the operator to keep,
    then uploaded. A homeserver behind MAS gates the upload on the account owner
    approving it in a browser; ``on_approval`` is handed that URL, and the
    upload is retried until approved or ``_APPROVAL_WINDOW`` runs out.

    Args:
        client: the HTTP client for the upstream homeserver; not closed here.
        homeserver: its base URL.
        session: the bridge's saved session: ``user_id``, ``device_id`` and
            ``access_token``. That device is the one signed.
        on_approval: called with the approval URL when the homeserver asks
            the account owner to approve the reset.
        on_recovery_key: called with the new recovery key once the new keys
            are in secret storage and before the identity is uploaded, so the
            key is never lost to a later error. A failed signing step can be
            finished with ``sign-device`` and that key.

    Returns:
        ``Reset``: the device signed, the new master key ID, and the
        recovery key (also already handed to ``on_recovery_key``).

    Raises:
        CrossSignError: storing the secrets failed (nothing was published),
            the upload was refused or never approved (the stored keys match no
            published identity and are replaced by a rerun), or signing
            failed (finish with ``sign-device``).
    """
    user_id, device_id = session["user_id"], session["device_id"]
    auth = {"Authorization": f"Bearer {session['access_token']}"}
    base = f"{homeserver}/_matrix/client/v3"
    seeds = {usage: os.urandom(32) for usage in _CROSS_SIGNING}
    keys = {usage: _key_object(user_id, usage, seed) for usage, seed in seeds.items()}
    master_id = next(iter(keys["master"]["keys"]))
    for usage in ("self_signing", "user_signing"):
        signer, signature = sign(keys[usage], seeds["master"])
        keys[usage]["signatures"] = {user_id: {signer: signature}}

    body: dict[str, Any] = {
        "master_key": keys["master"],
        "self_signing_key": keys["self_signing"],
        "user_signing_key": keys["user_signing"],
    }
    # Stored before anything is published, so the printed key and the
    # account's secret storage always agree: if the upload then fails or is
    # never approved, the stored keys match no published identity,
    # sign-device refuses them, and a rerun replaces them.
    storage_key = os.urandom(32)
    recovery_key = encode_recovery_key(storage_key)
    key_id = encode_base64(os.urandom(_KEY_ID_BYTES))
    check = _encrypt_secret(storage_key, "", "\0" * 32)

    async def put(kind: str, content: dict[str, Any]) -> None:
        resp = await client.put(
            f"{base}/user/{quote(user_id, safe='')}/account_data/{quote(kind, safe='')}",
            headers=auth,
            json=content,
        )
        _require(resp, f"storing {kind}")

    await put(
        f"m.secret_storage.key.{key_id}",
        {"algorithm": SSSS_ALGORITHM, "iv": check["iv"], "mac": check["mac"]},
    )
    for usage, seed in seeds.items():
        name = f"m.cross_signing.{usage}"
        await put(
            name, {"encrypted": {key_id: _encrypt_secret(storage_key, name, encode_base64(seed))}}
        )
    await put("m.secret_storage.default_key", {"key": key_id})
    on_recovery_key(recovery_key)

    await _upload_with_approval(
        client, f"{base}/keys/device_signing/upload", auth, body, on_approval
    )
    await sign_own_device(client, homeserver, session, recovery_key)
    return Reset(device_id, master_id, recovery_key)


async def _upload_with_approval(
    client: httpx.AsyncClient,
    url: str,
    auth: dict[str, str],
    body: dict[str, Any],
    on_approval: Callable[[str], None],
) -> None:
    """POST ``body``, answering a user-interactive-auth challenge by waiting
    for browser approval (MAS's ``org.matrix.cross_signing_reset``)."""
    resp = await client.post(url, headers=auth, json=body)
    if resp.status_code == 200:
        return
    challenge = _json(resp)
    if resp.status_code != 401 or "session" not in challenge:
        raise CrossSignError(f"key upload refused: {resp.status_code} {challenge.get('errcode')}")
    stage = next((s for f in challenge.get("flows", []) for s in f.get("stages", [])), "")
    approve_url = (challenge.get("params", {}).get(stage) or {}).get("url", "")
    if not approve_url:
        raise CrossSignError(f"the homeserver wants {stage or 'an auth stage'} this cannot answer")
    on_approval(approve_url)
    retry = {**body, "auth": {"type": stage, "session": challenge["session"]}}
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _APPROVAL_WINDOW
    last = ""
    while loop.time() < deadline:
        await asyncio.sleep(_APPROVAL_POLL)
        resp = await client.post(url, headers=auth, json=retry)
        if resp.status_code == 200:
            return
        answer = f"{resp.status_code} {_json(resp).get('errcode', '')}".rstrip()
        if answer != last:
            logger.warning("cross-signing reset not accepted yet: %s", answer)
            last = answer
    raise CrossSignError(
        f"the reset was not approved in time (last answer: {last}); no identity was published"
    )
