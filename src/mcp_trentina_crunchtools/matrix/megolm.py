"""The vodozemac surface, behind an availability guard.

Every call into the crypto library goes through here, for two reasons.

The dependency is optional. It ships as an extra so the gateway installs and
runs without it, and a deployment that asks for decryption on a platform with
no wheel fails at CONFIG LOAD with a clear message rather than at request time
with a 100% undecryptable rate. This mirrors
``quarantine.classifier.is_classifier_available()``, which exists for the same
reason and is the pattern an operator here already knows.

It also keeps the blast radius of a crypto library small and greppable. One
module imports vodozemac; everything else asks this module. Trentina only ever
READS keys -- there is no encrypt path, no device identity, and nothing here
can write to a homeserver.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_vodozemac: Any = None
_checked = False


def megolm_available() -> bool:
    """True when the crypto library is importable. Cached after the first call."""
    global _vodozemac, _checked
    if _checked:
        return _vodozemac is not None
    _checked = True
    try:
        import vodozemac
    except ImportError:
        logger.info(
            "vodozemac not installed — Matrix decryption unavailable. Install "
            "the 'matrix' extra to enable it."
        )
        return False
    _vodozemac = vodozemac
    return True


def reset_megolm() -> None:
    """Drop the cached import. For tests."""
    global _vodozemac, _checked
    _vodozemac = None
    _checked = False


def backup_decryptor(private_key: bytes) -> Any:
    """Build the object that unwraps backed-up room keys.

    Also the only way to learn the backup's PUBLIC key, which the provider
    compares against the homeserver's ``auth_data`` at startup. That
    comparison turns "wrong recovery key" from a silent production failure
    into a refused start.
    """
    v = _require()
    return v.PkDecryption.from_key(v.Curve25519SecretKey.from_bytes(private_key))


def backup_public_key(decryptor: Any) -> str:
    return str(decryptor.public_key.to_base64())


def unwrap_session_data(decryptor: Any, session_data: dict[str, Any]) -> dict[str, Any]:
    """Decrypt one ``session_data`` blob from ``GET /room_keys/keys``.

    The three fields map onto the library's Message exactly. Note they are
    passed BY NAME: the tuple ``Message.to_base64()`` returns is not in the
    constructor's order, and getting it wrong fails with a key-size error
    that points nowhere near the mistake.
    """
    v = _require()
    message = v.Message.from_base64(
        session_data["ciphertext"],
        session_data["mac"],
        session_data["ephemeral"],
    )
    decoded: dict[str, Any] = json.loads(decryptor.decrypt(message))
    return decoded


def import_session(session_key_base64: str) -> Any:
    """Turn an exported room key into something that can decrypt events."""
    v = _require()
    return v.InboundGroupSession.import_session(v.ExportedSessionKey(session_key_base64))


def decrypt_event(session: Any, ciphertext_base64: str) -> bytes:
    """Decrypt one ``m.room.encrypted`` payload. Returns the plaintext bytes."""
    v = _require()
    result = session.decrypt(v.MegolmMessage.from_base64(ciphertext_base64))
    return bytes(result.plaintext)


def _require() -> Any:
    if not megolm_available() or _vodozemac is None:
        raise RuntimeError("vodozemac is not installed; callers must check megolm_available()")
    return _vodozemac
