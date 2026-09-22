"""Recovery-key decoding. Pure arithmetic, provable without vodozemac.

This is the most likely operator error in the whole decryption path — a key
mistyped or truncated while being transcribed from the one time it was shown.
The format carries a parity byte precisely so that is catchable, and these
tests are what make sure we actually catch it instead of starting up and
decrypting nothing.
"""

from __future__ import annotations

import pytest

from mcp_trentina_crunchtools.matrix.recovery_key import (
    KEY_BYTES,
    PREFIX,
    RecoveryKeyError,
    decode_recovery_key,
)

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _ALPHABET[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def _make(key: bytes, *, prefix: tuple[int, int] = PREFIX, parity: int | None = None) -> str:
    payload = bytes(prefix) + key
    if parity is None:
        parity = 0
        for b in payload:
            parity ^= b
    return _b58(payload + bytes([parity]))


KEY = bytes(range(KEY_BYTES))


class TestHappyPath:
    def test_round_trip(self) -> None:
        assert decode_recovery_key(_make(KEY)) == KEY

    def test_spaces_are_stripped_anywhere(self) -> None:
        """The key is shown to humans in groups and will be pasted that way."""
        text = _make(KEY)
        spaced = " ".join(text[i : i + 4] for i in range(0, len(text), 4))
        assert decode_recovery_key(spaced) == KEY
        assert decode_recovery_key(f"  {text}\n") == KEY

    def test_all_zero_key_survives_leading_zeros(self) -> None:
        """Leading zero bytes encode as '1's and are lost by naive base58."""
        assert decode_recovery_key(_make(bytes(KEY_BYTES))) == bytes(KEY_BYTES)


class TestRejections:
    def test_empty(self) -> None:
        with pytest.raises(RecoveryKeyError, match="empty"):
            decode_recovery_key("   ")

    def test_bad_character(self) -> None:
        """0, O, I and l are excluded from base58 exactly because they are
        the characters a human transcribing a key confuses."""
        with pytest.raises(RecoveryKeyError, match="base58"):
            decode_recovery_key(_make(KEY)[:-1] + "0")

    def test_wrong_prefix(self) -> None:
        with pytest.raises(RecoveryKeyError, match="version prefix"):
            decode_recovery_key(_make(KEY, prefix=(0x00, 0x01)))

    def test_bad_parity_is_caught(self) -> None:
        """The whole reason the format carries a parity byte."""
        good = 0
        for b in bytes(PREFIX) + KEY:
            good ^= b
        with pytest.raises(RecoveryKeyError, match="parity"):
            decode_recovery_key(_make(KEY, parity=good ^ 0x01))

    def test_truncated(self) -> None:
        with pytest.raises(RecoveryKeyError, match="expected"):
            decode_recovery_key(_make(KEY)[:20])

    @pytest.mark.parametrize("flip", [0, 7, 31])
    def test_a_single_flipped_key_byte_is_caught(self, flip: int) -> None:
        """A one-character typo must not produce a key that silently decrypts
        nothing. Parity over the whole string is what buys this."""
        mangled = bytearray(KEY)
        mangled[flip] ^= 0x01
        payload = bytes(PREFIX) + bytes(mangled)
        parity = 0
        for b in payload:
            parity ^= b
        # Keep the ORIGINAL parity byte, as a typo in the key would.
        original = 0
        for b in bytes(PREFIX) + KEY:
            original ^= b
        assert parity != original
        with pytest.raises(RecoveryKeyError, match="parity"):
            decode_recovery_key(_b58(payload + bytes([original])))
