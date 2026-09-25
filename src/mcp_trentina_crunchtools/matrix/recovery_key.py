"""Decode a Matrix recovery key. Pure arithmetic, no crypto library.

The recovery key an operator is shown once at bootstrap is the private half of
the room-key backup. Its format is fixed by the spec: base58 of a two-byte
prefix, 32 key bytes, and a parity byte chosen so the XOR of the whole string
is zero.

This lives apart from ``megolm.py`` on purpose. It is the one piece of the
decryption path that is decidable without vodozemac, so it can be tested
exhaustively wherever the tests run, including on a platform with no wheel.
Getting it wrong is also the most likely operator error -- a mistyped or
truncated key -- and the parity byte exists precisely so that is caught here,
at config load, rather than surfacing later as a 100% undecryptable rate.
"""

from __future__ import annotations

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
"""Bitcoin base58. Excludes 0, O, I and l, which are the characters an
operator transcribing a key by hand is most likely to confuse."""

_INDEX = {c: i for i, c in enumerate(_ALPHABET)}
_BASE = len(_ALPHABET)

PREFIX = (0x8B, 0x01)
"""Version prefix for ``m.megolm_backup.v1`` recovery keys."""

KEY_BYTES = 32
EXPECTED_LEN = len(PREFIX) + KEY_BYTES + 1  # prefix + key + parity


class RecoveryKeyError(ValueError):
    """The supplied recovery key is not a usable one."""


def _b58decode(text: str) -> bytes:
    value = 0
    for char in text:
        digit = _INDEX.get(char)
        if digit is None:
            raise RecoveryKeyError(
                f"invalid character {char!r} — a recovery key is base58 and "
                f"never contains 0, O, I or l"
            )
        value = value * _BASE + digit
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    # Leading '1's encode leading zero bytes and are lost by the integer math.
    leading = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading + body


def decode_recovery_key(text: str) -> bytes:
    """Return the 32 raw private-key bytes, or raise.

    Whitespace is stripped anywhere, not just at the ends: the key is
    displayed to humans in space-separated groups and will be pasted that way.
    """
    cleaned = "".join(text.split())
    if not cleaned:
        raise RecoveryKeyError("empty recovery key")

    raw = _b58decode(cleaned)
    if len(raw) != EXPECTED_LEN:
        raise RecoveryKeyError(
            f"decodes to {len(raw)} bytes, expected {EXPECTED_LEN} — the key "
            f"is truncated or has extra characters"
        )
    if tuple(raw[: len(PREFIX)]) != PREFIX:
        raise RecoveryKeyError(
            "wrong version prefix — this is not an m.megolm_backup.v1 "
            "recovery key"
        )

    parity = 0
    for byte in raw:
        parity ^= byte
    if parity != 0:
        raise RecoveryKeyError(
            "parity check failed — the key is mistyped. This check exists so "
            "a bad key is caught at load instead of as a silent inability to "
            "decrypt anything."
        )

    return raw[len(PREFIX) : len(PREFIX) + KEY_BYTES]
