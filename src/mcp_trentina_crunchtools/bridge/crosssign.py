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

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote

from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from unpaddedbase64 import decode_base64, encode_base64

from ..matrix.recovery_key import decode_recovery_key

if TYPE_CHECKING:
    import httpx

SSSS_ALGORITHM = "m.secret_storage.v1.aes-hmac-sha2"
SELF_SIGNING = "m.cross_signing.self_signing"


class CrossSignError(RuntimeError):
    """The account cannot be read or signed as needed. Nothing was uploaded."""


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
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(value: dict[str, Any], seed: bytes) -> tuple[str, str]:
    """``(key id, signature)`` over ``value`` minus signatures and unsigned."""
    # pycryptodome takes the 32-byte seed as bytes; its typing says str or int.
    key = ECC.construct(curve="Ed25519", seed=cast("Any", seed))
    public = encode_base64(key.public_key().export_key(format="raw"))
    body = {k: v for k, v in value.items() if k not in ("signatures", "unsigned")}
    signature = encode_base64(eddsa.new(key, "rfc8032").sign(canonical_json(body)))
    return f"ed25519:{public}", signature


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
        if resp.status_code != 200:
            raise CrossSignError(f"account data {kind}: {resp.status_code}")
        content: dict[str, Any] = resp.json()
        return content

    key = decode_recovery_key(recovery_key)
    key_id = (await account_data("m.secret_storage.default_key"))["key"]
    check_key(key, await account_data(f"m.secret_storage.key.{key_id}"))
    encrypted = (await account_data(SELF_SIGNING))["encrypted"][key_id]
    seed = decode_base64(decrypt_secret(key, SELF_SIGNING, encrypted))

    query = await client.post(
        f"{base}/keys/query", headers=auth, json={"device_keys": {user_id: [device_id]}}
    )
    keys = query.json()
    published = keys["self_signing_keys"][user_id]["keys"]
    device = keys["device_keys"][user_id][device_id]
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
    failures = upload.json().get("failures") or {}
    if upload.status_code != 200 or failures:
        raise CrossSignError(f"signature upload: {upload.status_code} {failures}")
    return Signed(device_id, signer, already=False)
