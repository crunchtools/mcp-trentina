"""What a PDF says, read in a child process (#369).

``read_pdf`` hands the bytes to ``pdf_worker`` and checks what comes back.
The worker's module docstring says what is read and why it is a process.
This side owns the deadline and the shape of the answer: the worker read a
hostile file, so its output is checked field by field and anything that
does not fit is no answer at all.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass, field

from .archive import Entry

WORKER = "mcp_trentina_crunchtools.unpack.pdf_worker"
DEADLINE = 30.0
"""Wall-clock seconds for one PDF. The worker limits its own CPU to 20."""

CONCURRENCY = 2
"""PDFs being read at once. Each is a process with up to a gigabyte to use."""

SLOT_WAIT = 10.0
"""Seconds a PDF waits for one of those slots before it is given up as unread.
Callers are worker threads of the gateway's one pool: a thread waiting here is
a thread L1 and the tokenizer cannot have, so the wait is short."""

MAX_OUTPUT = 16 * 1024 * 1024
"""Bytes of worker output accepted. Its own text cap is far below this."""

TOO_LARGE = "too large to read"
"""Why an embedded file past the worker's byte cap has no content."""

_slots = threading.BoundedSemaphore(CONCURRENCY)

SECTIONS = (
    "note",
    "field",
    "link",
    "javascript",
    "title",
    "information",
    "alternate text",
    "file",
    "metadata",
)
"""The worker's section names, in the order the layers read them."""


@dataclass
class PdfReading:
    """One PDF, as text.

    Attributes:
        pages: ``(visible, hidden)`` text for each page, in order.
        hidden: Runs of text drawn so a reader does not see them.
        scanned: Pages that draw an image and have no text: pictures of
            pages, which only OCR reads.
        text_layers: Pages that are an image with an invisible text layer
            over it, read as the page's text.
        fields: Text entries by section name (``SECTIONS``).
        attachments: Embedded files, for the archive rules to read.
    """

    pages: list[tuple[str, str]] = field(default_factory=list)
    hidden: int = 0
    scanned: int = 0
    text_layers: int = 0
    fields: dict[str, list[str]] = field(default_factory=dict)
    attachments: list[Entry] = field(default_factory=list)

    def markdown(self) -> str:
        """The visible text of the pages, for stage 1 to deliver."""
        return "\n\n".join(visible for visible, _ in self.pages if visible)


def _environment() -> dict[str, str]:
    """What the worker starts with: the import path, and no credential."""
    return {
        "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def read_pdf(packed: bytes) -> PdfReading | None:
    """Read ``packed`` as a PDF, or None when it stays unread.

    None for a file the worker could not read to the end: corrupt,
    encrypted with a password, over a size cap, still running at the
    deadline, or one that found every slot busy for ``SLOT_WAIT`` seconds.
    The caller counts it as ``binary_unread``.
    """
    # TRUST: parsing a PDF nobody has judged yet
    #   untrusted: all of `packed`, and therefore everything the worker prints
    #   judged-by: nothing here; every string returned is read by the layers
    #   on-failure: fail-closed: None, and the caller counts the PDF unread
    #   owner: unpack.pdf.read_pdf
    #   evidence: T1 the child has RLIMIT_CPU, RLIMIT_AS, a wall-clock kill and
    #     no secret in its environment; T1 argv is this interpreter and a constant
    #     module; T1 _checked() accepts only its shapes; T4 tests/test_unpack_pdf.py
    if not _slots.acquire(timeout=SLOT_WAIT):
        return None
    try:
        done = subprocess.run(
            [sys.executable, "-m", WORKER],
            input=packed,
            capture_output=True,
            timeout=DEADLINE,
            env=_environment(),
            cwd="/",
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    finally:
        _slots.release()
    if done.returncode != 0 or len(done.stdout) > MAX_OUTPUT:
        return None
    try:
        return _checked(json.loads(done.stdout))
    except (ValueError, TypeError, KeyError, RecursionError, binascii.Error):
        return None


def _strings(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError("not a list of strings")
    return value


def _count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TypeError("not a count")
    return value


def _checked(raw: object) -> PdfReading | None:
    """The worker's JSON as a ``PdfReading``. Raises on any other shape."""
    if not isinstance(raw, dict) or raw.get("encrypted"):
        return None
    reading = PdfReading(
        hidden=_count(raw["hidden"]),
        scanned=_count(raw["scanned"]),
        text_layers=_count(raw["text_layers"]),
    )
    for page in raw["pages"]:
        visible, unseen = _strings(page)
        reading.pages.append((visible, unseen))
    fields = raw["fields"]
    if not isinstance(fields, dict):
        raise TypeError("fields is not an object")
    reading.fields = {name: _strings(fields[name]) for name in SECTIONS if name in fields}
    for name, encoded in raw["attachments"]:
        if not isinstance(name, str) or not isinstance(encoded, (str, type(None))):
            raise TypeError("not an attachment")
        reading.attachments.append(
            Entry(name, None, TOO_LARGE)
            if encoded is None
            else Entry(name, base64.b64decode(encoded, validate=True))
        )
    return reading
