"""What a run of decoded bytes is, from its first bytes (#367).

The layers cannot read binary, so the unpack stage labels it instead. A
label says what the bytes are, which is what L2 needs in order to stop
reacting to a blob, and it says whether an agent could pull text out of
them. That second answer decides the gap: an image, a PDF or an archive is
something an agent's tools can open and a layer cannot yet read
(``binary_unread``); a key, an executable or random bytes is not.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Kind:
    """One kind of binary.

    Attributes:
        name: What the label calls it, a media type where one exists.
        extractable: An agent's tools can pull text out of it, so until a
            layer can too, delivering it unread is a gap.
    """

    name: str
    extractable: bool


OPAQUE = Kind("binary", extractable=False)

_SIGNATURES: tuple[tuple[bytes, Kind], ...] = (
    (b"\x89PNG\r\n\x1a\n", Kind("image/png", extractable=True)),
    (b"\xff\xd8\xff", Kind("image/jpeg", extractable=True)),
    (b"GIF87a", Kind("image/gif", extractable=True)),
    (b"GIF89a", Kind("image/gif", extractable=True)),
    (b"BM", Kind("image/bmp", extractable=True)),
    (b"II*\x00", Kind("image/tiff", extractable=True)),
    (b"MM\x00*", Kind("image/tiff", extractable=True)),
    (b"%PDF-", Kind("application/pdf", extractable=True)),
    (b"PK\x03\x04", Kind("zip archive or office file", extractable=True)),
    (b"\x1f\x8b", Kind("gzip", extractable=True)),
    (b"BZh", Kind("bzip2", extractable=True)),
    (b"7z\xbc\xaf\x27\x1c", Kind("7z archive", extractable=True)),
    (b"Rar!\x1a\x07", Kind("rar archive", extractable=True)),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", Kind("legacy office file", extractable=True)),
    (b"SQLite format 3\x00", Kind("SQLite database", extractable=True)),
    (b"\x00asm", Kind("WebAssembly module", extractable=True)),
    (b"\x00\x00\x01\x00", Kind("image/x-icon", extractable=True)),
    (b"ID3", Kind("audio", extractable=True)),
    (b"\xff\xfb", Kind("audio", extractable=True)),
    (b"\xff\xf3", Kind("audio", extractable=True)),
    (b"\xff\xf2", Kind("audio", extractable=True)),
    (b"OggS", Kind("audio or video", extractable=True)),
    (b"fLaC", Kind("audio", extractable=True)),
    (b"\x1a\x45\xdf\xa3", Kind("video", extractable=True)),
    (b"\x7fELF", Kind("ELF executable", extractable=False)),
    (b"\x00\x00\x00\x07ssh-rsa", Kind("SSH public key", extractable=False)),
    (b"\x00\x00\x00\x0bssh-ed25519", Kind("SSH public key", extractable=False)),
    (b"\x00\x00\x00\x13ecdsa-sha2-", Kind("SSH public key", extractable=False)),
    (b"\x30\x82", Kind("DER certificate or key", extractable=False)),
)


STRONG_PREFIX = 4
"""Signature bytes a short token must match. Two-byte prefixes (``BM``, an
MP3 frame's ``\\xff\\xfb``) occur by chance: ``//static`` in a URL decodes to
one. Short tokens are matched only on four bytes or more."""


def identify(decoded: bytes, *, short: bool = False) -> Kind:
    """The kind ``decoded`` starts as, or ``OPAQUE``.

    RIFF (WebP, WAV, AVI) and ISO media (MP4, MOV, HEIC) carry their tag at
    an offset, so they are checked apart from the prefix table. Audio and
    video count as openable: an agent with a transcription tool reads them.
    ``short`` skips prefixes under ``STRONG_PREFIX`` bytes. ``OPAQUE`` means
    no signature here matched. It is not proof that nothing
    could open the bytes, which is a known gap (docs/defense-pipeline.md).
    """
    if decoded[:4] == b"RIFF":
        riff = {b"WEBP": "image/webp", b"WAVE": "audio", b"AVI ": "video"}
        return Kind(riff.get(decoded[8:12], "audio or video"), extractable=True)
    if decoded[4:8] == b"ftyp":  # MP4, MOV, HEIC
        return Kind("video or image", extractable=True)
    for prefix, kind in _SIGNATURES:
        if decoded.startswith(prefix) and not (short and len(prefix) < STRONG_PREFIX):
            return kind
    return _embedded(decoded)


ZIP_TAIL = 65_557
"""Bytes from the end that may hold a ZIP's end-of-directory record: the
22-byte record plus the longest comment (65,535)."""

PDF_HEADER_REACH = 1024
"""Readers accept a PDF header anywhere in the first kilobyte."""


def _embedded(decoded: bytes) -> Kind:
    """A container whose signature need not open the bytes.

    A ZIP is read from its end, so a self-extracting stub or any other
    prefix can stand in front of it; a PDF header may sit anywhere in the
    first kilobyte. Either behind noise is still something an agent can open.
    """
    if b"PK\x05\x06" in decoded[-ZIP_TAIL:]:
        return Kind("zip archive or office file", extractable=True)
    if b"%PDF-" in decoded[:PDF_HEADER_REACH]:
        return Kind("application/pdf", extractable=True)
    return OPAQUE


def from_media_type(media_type: str) -> Kind:
    """A data URI's declared type, for bytes too short to carry a signature.

    Mapped onto fixed names, never echoed: the type is the payload author's
    text, and a kind's name reaches the warning, which carries only values
    from a closed set.
    """
    media_type = media_type.lower()
    if media_type.startswith("image/"):
        return Kind("image", extractable=True)
    return _DECLARED.get(media_type, OPAQUE)


_DECLARED = {
    "application/pdf": Kind("application/pdf", extractable=True),
    "application/zip": Kind("zip archive or office file", extractable=True),
    "application/gzip": Kind("gzip", extractable=True),
}
