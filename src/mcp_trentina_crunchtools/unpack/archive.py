"""Open an archive in memory, within limits, and hand back its files (#368).

Zip, tar, gzip, bzip2 and xz, with the standard library and nothing written
to disk. This module only opens: ``scan.py`` decides what each file's bytes
are and what the layers read for them, so a file inside an archive is
unpacked by the same rules as a token in the text.

Three things can be said about an archive, and only the first reads it:

* **It opened inside the limits.** Its files come back as ``Entry`` rows.
* **One file in it cannot be read** (encrypted, a compression method not
  opened here). That entry comes back with ``content`` None and the reason;
  the rest of the archive is still read, and ``scan.py`` counts the entry
  as unread.
* **It did not open, or it broke a limit.** ``open_archive`` returns None
  and the whole archive stays the ``binary_unread`` gap. A bomb is refused
  the same way a corrupt file is: fail closed, with no partial read.

The limits are on WORK, so they hold whatever a header claims: every read
is bounded by the bytes left in the ``Budget``, and declared sizes are only
ever used to refuse early.
"""

from __future__ import annotations

import bz2
import io
import lzma
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

MAX_BYTES = 1024 * 1024
"""Uncompressed bytes read from one token's archives, nested ones included.
What the layers read counts against admission, which is far below this; the
cap bounds the work done before admission can refuse."""

MAX_ENTRIES = 256
"""Files read from one token's archives, nested ones included."""

MAX_RATIO = 200
"""Uncompressed over compressed size, past ``RATIO_FLOOR`` bytes out. Office
XML compresses 10 to 30 times; a bomb compresses by thousands."""

RATIO_FLOOR = 64 * 1024
"""Output below this is never refused on ratio: a kilobyte of repeated text
compresses a hundredfold and is not a bomb."""

MAX_NAME = 200
"""Characters of a file name the layers read."""

XZ_MEMORY = 64 * 1024 * 1024
"""Decoder memory an xz stream may ask for. Its header names a dictionary of
up to 4 GiB, which the decoder would otherwise allocate."""

TAR_MAGIC_AT = 257

ZIP = "zip archive or office file"
GZIP = "gzip"
BZIP2 = "bzip2"
XZ = "xz"
TAR = "tar archive"
OPENABLE = frozenset({ZIP, GZIP, BZIP2, XZ, TAR})
"""Kind names (``signatures.py``) this module opens."""

_ZIP_METHODS = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2})
"""Zip compression methods read here. LZMA is left out: ``zipfile`` gives its
decoder no memory limit. An entry using another method is unread."""

_ENCRYPTED = 0x1
_HAS_DESCRIPTOR = 0x8
_LOCAL_HEADER = 30
_MAX_DESCRIPTOR = 24
"""A data descriptor: an optional signature, a CRC and two sizes, 8 bytes each under zip64."""
_GZIP_WBITS = 31
"""zlib's window setting for a gzip wrapper."""
_BROKEN = (
    zipfile.BadZipFile,
    tarfile.TarError,
    lzma.LZMAError,
    zlib.error,
    struct.error,
    OSError,
    EOFError,
    ValueError,
    RuntimeError,
    NotImplementedError,
    KeyError,
    IndexError,
    OverflowError,
)
"""What the standard library's readers raise on hostile bytes."""


class Entry(NamedTuple):
    """One file of an archive.

    Attributes:
        name: Its path as the archive gives it, single-line and capped. The
            archive author's text: the layers read it, and nothing uses it
            as a path.
        content: Its bytes, or None when it could not be read.
        unread: Why not, when ``content`` is None: a fixed phrase, never text
            from the archive.
    """

    name: str
    content: bytes | None
    unread: str = ""


@dataclass
class Budget:
    """What is left to read across one token's archives, nested ones included."""

    bytes_left: int = MAX_BYTES
    entries_left: int = MAX_ENTRIES

    def take(self, content: bytes) -> bool:
        """Charge ``content`` to the budget. False when it does not fit."""
        if len(content) > self.bytes_left or self.entries_left <= 0:
            return False
        self.bytes_left -= len(content)
        self.entries_left -= 1
        return True


class _OverLimitError(Exception):
    """A limit was reached: the archive is refused whole."""


def is_tar(packed: bytes) -> bool:
    """Whether ``packed`` carries the ``ustar`` magic of a POSIX or GNU tar."""
    return packed[TAR_MAGIC_AT : TAR_MAGIC_AT + 5] == b"ustar"


def open_archive(packed: bytes, kind: str, budget: Budget) -> list[Entry] | None:
    """The files of ``packed``, an archive of ``kind``, or None if it stays unread.

    A compressed stream (gzip, bzip2, xz) is one file named ``(contents)``;
    when what it holds is a tar, that tar's files are returned in its place.

    Args:
        packed: The archive's bytes.
        kind: A kind name from ``signatures.py``; anything outside
            ``OPENABLE`` returns None.
        budget: Shared by every archive opened for one token. It is charged
            only for an archive that is returned: a refused one costs the
            caller nothing it can read.

    Returns:
        The entries in archive order, or None when the archive is corrupt,
        of a kind not opened here, or over a limit.
    """
    # TRUST: decompressing bytes nobody has judged yet
    #   untrusted: all of `packed`, chosen by whoever wrote the payload
    #   judged-by: nothing here; scan.py hands every returned byte to the layers
    #   on-failure: fail-closed: None, and the caller counts the archive unread
    #   owner: unpack.archive.open_archive
    #   evidence: T1 every read is `read(bytes_left + 1)`, so a header's size is
    #     never trusted; T1 xz memlimit; T1 zip LZMA entries are not opened;
    #     T4 tests/test_unpack_archive.py bombs; T2 nothing is written to disk
    reader = _READERS.get(kind)
    trial = Budget(budget.bytes_left, budget.entries_left)
    try:
        entries = None if reader is None else reader(packed, trial)
    except (_OverLimitError, *_BROKEN):
        entries = None
    if entries is None:
        return None
    read = sum(len(e.content) for e in entries if e.content is not None)
    if read > RATIO_FLOOR and read > MAX_RATIO * max(len(packed), 1):
        return None
    budget.bytes_left, budget.entries_left = trial.bytes_left, trial.entries_left
    return entries


def _stream(new_decoder: Callable[[], Any], packed: bytes, budget: Budget) -> list[Entry]:
    """Every stream in ``packed``, decompressed within the budget.

    Streams may be concatenated, as ``cat a.gz b.gz`` writes them. Whatever
    follows the last one must be zero padding: the library's own file readers
    stop at the first stream and ignore the rest, and bytes a layer never saw
    are exactly what this stage exists to refuse. A stream that holds a tar
    is returned as that tar's files.
    """
    limit = budget.bytes_left
    out = bytearray()
    rest = packed
    while rest.strip(b"\0"):
        decoder = new_decoder()
        out += decoder.decompress(rest, limit + 1 - len(out))
        if len(out) > limit:
            raise _OverLimitError
        if not decoder.eof:
            raise EOFError("truncated stream")
        rest = decoder.unused_data
    inner = bytes(out)
    return _tar(inner, budget) if is_tar(inner) else [_charged(Entry("(contents)", inner), budget)]


def _charged(entry: Entry, budget: Budget) -> Entry:
    """``entry``, once its bytes fit the budget."""
    if entry.content is not None and not budget.take(entry.content):
        raise _OverLimitError
    return entry


def _zip(packed: bytes, budget: Budget) -> list[Entry]:
    entries: list[Entry] = []
    with zipfile.ZipFile(io.BytesIO(packed)) as archive:
        members = [m for m in archive.infolist() if not (m.is_dir() and not m.compress_size)]
        over = len(members) > budget.entries_left
        over = over or sum(m.file_size for m in members) > budget.bytes_left
        if over or _unlisted_bytes(packed, archive) > 0:
            raise _OverLimitError
        for member in members:
            entries.extend(_zip_member(archive, member, budget))
        if archive.comment:
            entries.append(_charged(Entry("(archive comment)", archive.comment), budget))
    return entries


def _zip_member(
    archive: zipfile.ZipFile, member: zipfile.ZipInfo, budget: Budget
) -> Iterator[Entry]:
    """One listed file, then its comment if it has one: a comment is text too."""
    name = _name(member.filename)
    if member.flag_bits & _ENCRYPTED:
        yield Entry(name, None, "encrypted")
        return
    if member.compress_type not in _ZIP_METHODS:
        yield Entry(name, None, "compressed by a method not opened")
        return
    with archive.open(member) as handle:
        content = handle.read(budget.bytes_left + 1)
    yield _charged(Entry(name, content), budget)
    if member.comment:
        yield _charged(Entry(f"{name} (comment)", member.comment), budget)


def _unlisted_bytes(packed: bytes, archive: zipfile.ZipFile) -> int:
    """Bytes ahead of the central directory that no listed file accounts for.

    A zip is read from its directory, at the end. Bytes the directory does
    not list are invisible to this reader and plain to others: a stream
    reader walks the local headers from the front, ``strings`` reads a stub,
    a recovery tool finds a file the directory left out. So every byte before
    the directory must belong to a listed file's header, its data, or the
    optional descriptor after it. Anything more refuses the archive, which
    costs a self-extracting stub its reading and closes the differential.
    """
    spans: list[tuple[int, int]] = []
    allowed = 0
    for member in archive.infolist():
        header = packed[member.header_offset : member.header_offset + _LOCAL_HEADER]
        if len(header) < _LOCAL_HEADER or header[:4] != b"PK\x03\x04":
            raise zipfile.BadZipFile("missing local header")
        name_len, extra_len = struct.unpack("<HH", header[26:30])
        start = member.header_offset
        spans.append((start, start + _LOCAL_HEADER + name_len + extra_len + member.compress_size))
        if member.flag_bits & _HAS_DESCRIPTOR:
            allowed += _MAX_DESCRIPTOR
    covered = 0
    reach = 0
    for start, end in sorted(spans):
        covered += max(0, end - max(start, reach))
        reach = max(reach, end)
    directory: int = archive.start_dir
    return directory - covered - allowed


def _tar(packed: bytes, budget: Budget) -> list[Entry]:
    entries: list[Entry] = []
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:") as archive:
        for member in archive:
            if not member.isfile():
                continue  # directories, links and devices hold no text
            handle = archive.extractfile(member)
            content = b"" if handle is None else handle.read(budget.bytes_left + 1)
            entries.append(_charged(Entry(_name(member.name), content), budget))
        # tarfile stops at the end-of-archive marker; `tar -i` does not. What
        # follows the last header it read must be padding and nothing else.
        if packed[archive.offset :].strip(b"\0"):
            raise _OverLimitError
    return entries


def _name(raw: str) -> str:
    """A file name on one line, capped: it is read by the layers, never opened."""
    return " ".join(raw.split())[:MAX_NAME] or "(unnamed)"


_READERS: dict[str, Callable[[bytes, Budget], list[Entry]]] = {
    ZIP: _zip,
    TAR: _tar,
    GZIP: partial(_stream, lambda: zlib.decompressobj(wbits=_GZIP_WBITS)),
    BZIP2: partial(_stream, bz2.BZ2Decompressor),
    XZ: partial(_stream, lambda: lzma.LZMADecompressor(memlimit=XZ_MEMORY)),
}
"""How each openable kind is read. ``OPENABLE`` is this table's keys."""
