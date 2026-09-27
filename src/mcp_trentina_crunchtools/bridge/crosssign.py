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
import secrets
import string
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
_SEED_BYTES = 32
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
    """One SSSS secret, authenticated before it is decrypted.

    Args:
        key: the 32-byte secret-storage key the recovery key decodes to.
        name: the secret's account-data type, e.g. ``m.cross_signing.self_signing``;
            it is the HKDF info, so a secret stored under another name fails.
        encrypted: the stored object for this key: unpadded-base64 ``iv``,
            ``ciphertext`` and ``mac``.

    Returns:
        The plaintext secret, itself unpadded base64 for a cross-signing seed.

    Raises:
        CrossSignError: the MAC does not match, so the key or the data is wrong.
        KeyError, ValueError: a field is missing or not base64.
    """
    aes_key, mac_key = _hkdf(key, name.encode())
    ciphertext = decode_base64(encrypted["ciphertext"])
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, decode_base64(encrypted["mac"])):
        raise CrossSignError(f"{name}: MAC mismatch, so the recovery key is not this account's")
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=decode_base64(encrypted["iv"]))
    return cipher.decrypt(ciphertext).decode()


def check_key(key: bytes, description: dict[str, Any]) -> None:
    """The recovery key opens this secret-storage key: it encrypts 32 zero
    bytes under the empty name to the MAC the description publishes.

    Args:
        key: the 32-byte secret-storage key the recovery key decodes to.
        description: the ``m.secret_storage.key.<id>`` account data:
            ``algorithm``, and unpadded-base64 ``iv`` and ``mac``.

    Returns:
        Nothing; returning at all means the key opens this storage.

    Raises:
        CrossSignError: the algorithm is not ``SSSS_ALGORITHM``, or the MAC
            does not match (the key belongs to other storage).
        KeyError, ValueError: a field is missing or not base64.
    """
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


def _public(key: Any) -> str:
    return encode_base64(key.public_key().export_key(format="raw"))


def public_key(seed: bytes) -> str:
    """The unpadded-base64 Ed25519 public key for a seed."""
    return _public(_signing_key(seed))


def sign(value: dict[str, Any], seed: bytes) -> tuple[str, str]:
    """Sign a Matrix object with an Ed25519 key.

    Args:
        value: the JSON object to sign, e.g. device keys or a cross-signing
            key. Its ``signatures`` and ``unsigned`` are left out of what is
            signed, as the spec requires; ``value`` itself is not changed.
        seed: the key's 32-byte Ed25519 seed (the private key as stored).

    Returns:
        ``(key id, signature)``: ``ed25519:<unpadded-base64 public key>``,
        the ID a signature is filed under, and the unpadded-base64 signature
        over the canonical JSON.
    """
    key = _signing_key(seed)
    public = _public(key)
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
    device_keys: dict[str, str],
    recovery_key: str,
) -> Signed:
    """Sign the session's device with the account's self-signing key.

    Args:
        client: the HTTP client for the upstream homeserver; not closed here.
        homeserver: its base URL.
        session: the bridge's saved session: ``user_id``, ``device_id`` and
            ``access_token``. The device signed is that one, never another.
        device_keys: the device's identity keys as the bridge holds them
            (``ed25519:<device>``, ``curve25519:<device>``), from its own
            crypto store. The homeserver's copy is signed only if it is
            exactly these: signing whatever it returned would let it have
            keys of its choosing cross-signed as this device.
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
            published one, the homeserver's device keys are not
            ``device_keys``, or the upload failed. Nothing is uploaded unless
            every check passed.
        httpx.HTTPError: the homeserver could not be reached; propagated.
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
        seed = decode_base64(decrypt_secret(key, SELF_SIGNING, encrypted))
    except (KeyError, TypeError) as exc:
        raise CrossSignError(f"the account has no {exc} where its keys should be") from exc
    except ValueError as exc:
        raise CrossSignError(f"the account's secret storage is malformed: {exc}") from exc
    if device.get("user_id") != user_id or device.get("device_id") != device_id:
        raise CrossSignError("the homeserver returned another device's keys")
    if device.get("keys") != device_keys:
        raise CrossSignError("the homeserver's keys for this device are not the bridge's own")
    if len(seed) != _SEED_BYTES:
        raise CrossSignError("the stored self-signing key is not an Ed25519 seed")
    signer, signature = sign(device, seed)
    if signer not in published:
        raise CrossSignError("the stored self-signing key is not the published one")
    # Ed25519 signatures are deterministic: the same key over the same keys
    # makes the same signature, so an equal one is a valid one.
    if device.get("signatures", {}).get(user_id, {}).get(signer) == signature:
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
# into the upper half.
_COUNTER_HEADROOM = 0x7F
# A new storage key's ID: letters and digits only, as clients make them. It
# is part of an account-data type in a URL path, where base64's "/" and "+"
# do not survive every homeserver's decoding.
_KEY_ID_LENGTH = 32
_KEY_ID_ALPHABET = string.ascii_letters + string.digits


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
    device_keys: dict[str, str],
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
        device_keys: its identity keys as the bridge holds them; see
            ``sign_own_device``.
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
        CrossSignError: storing the secrets failed, or the upload was
            refused or never approved: then nothing was published and the
            account's default storage is untouched, the new copies sitting
            unused beside it. Or the default could not be switched after
            publishing (rerun the reset), or signing failed (finish with
            ``sign-device``).
        httpx.HTTPError: the homeserver could not be reached, at any step;
            propagated, and the step it stopped at is as for CrossSignError.
    """
    user_id, device_id = session["user_id"], session["device_id"]
    auth = {"Authorization": f"Bearer {session['access_token']}"}
    base = f"{homeserver}/_matrix/client/v3"
    seeds = {usage: os.urandom(_SEED_BYTES) for usage in _CROSS_SIGNING}
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
    # Stored before anything is published, so the printed key always opens
    # what gets published; made the default only after, so a reset that is
    # refused or never approved leaves the account exactly as it was.
    storage_key = os.urandom(32)
    recovery_key = encode_recovery_key(storage_key)
    key_id = "".join(secrets.choice(_KEY_ID_ALPHABET) for _ in range(_KEY_ID_LENGTH))
    check = _encrypt_secret(storage_key, "", "\0" * 32)

    def data_url(kind: str) -> str:
        return f"{base}/user/{quote(user_id, safe='')}/account_data/{quote(kind, safe='')}"

    async def put(kind: str, content: dict[str, Any]) -> None:
        _require(await client.put(data_url(kind), headers=auth, json=content), f"storing {kind}")

    await put(
        f"m.secret_storage.key.{key_id}",
        {"algorithm": SSSS_ALGORITHM, "iv": check["iv"], "mac": check["mac"]},
    )
    # Added beside the copies under other storage keys, never over them:
    # until default_key moves, the old key's copies are what is in use.
    for usage, seed in seeds.items():
        name = f"m.cross_signing.{usage}"
        current = await client.get(data_url(name), headers=auth)
        # 404 is "never stored"; any other failure must not be taken for it.
        stored = {} if current.status_code == 404 else _require(current, f"reading {name}")
        copies = stored.get("encrypted", {})
        if not isinstance(copies, dict):
            raise CrossSignError(f"{name} is malformed; not replacing it")
        copies = dict(copies)
        copies[key_id] = _encrypt_secret(storage_key, name, encode_base64(seed))
        await put(name, {"encrypted": copies})
    on_recovery_key(recovery_key)

    await _upload_with_approval(
        client, f"{base}/keys/device_signing/upload", auth, body, on_approval
    )
    try:
        await put("m.secret_storage.default_key", {"key": key_id})
    except CrossSignError as exc:
        raise CrossSignError(
            f"{exc}: the identity is published but its storage is not the default;"
            " rerun reset-identity"
        ) from exc
    try:
        await sign_own_device(client, homeserver, session, device_keys, recovery_key)
    except CrossSignError as exc:
        raise CrossSignError(
            f"{exc}; finish with sign-device and the recovery key printed above"
        ) from exc
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
    while (remaining := deadline - loop.time()) > 0:
        await asyncio.sleep(min(_APPROVAL_POLL, remaining))
        if loop.time() >= deadline:
            break
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
