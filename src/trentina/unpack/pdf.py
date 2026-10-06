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
import logging
import threading
from dataclasses import dataclass, field

from .archive import Entry
from .child import ask

logger = logging.getLogger(__name__)

WORKER = "trentina.unpack.pdf_worker"
DEADLINE = 30.0
"""Wall-clock seconds for one PDF. The worker limits its own CPU to 20."""

CONCURRENCY = 2
"""PDFs being read at once. Each is a process with up to a gigabyte to use."""

MALFORMED = "answer malformed"
UNREADABLE = "needs a password"
"""Why a PDF is unread when the worker answered and the answer was no reading."""

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
            over it. The layer is read as the page's text; the picture under
            it is unread, and nothing has checked the two agree.
        fields: Text entries by section name (``SECTIONS``).
        attachments: Embedded files, for the archive rules to read.
        pictures: ``(page number, image)`` for pages that are pictures,
            scanned or under a text layer, for OCR to read (#370). A page
            counted in ``scanned`` or ``text_layers`` with no picture here
            stays unread.
    """

    pages: list[tuple[str, str]] = field(default_factory=list)
    hidden: int = 0
    scanned: int = 0
    text_layers: int = 0
    fields: dict[str, list[str]] = field(default_factory=dict)
    attachments: list[Entry] = field(default_factory=list)
    pictures: list[tuple[int, bytes]] = field(default_factory=list)

    def markdown(self) -> str:
        """The visible text of the pages, for stage 1 to deliver."""
        return "\n\n".join(visible for visible, _ in self.pages if visible)


def read_pdf(packed: bytes) -> PdfReading | None:
    """Read ``packed`` as a PDF, or None when it stays unread.

    None for a file the worker could not read to the end: corrupt,
    encrypted with a password, over a size cap, still running at the
    deadline, or one that found every slot busy. The caller counts it as
    ``binary_unread``, and a log line says which.
    """
    # TRUST: parsing a PDF nobody has judged yet
    #   untrusted: all of `packed`, and therefore everything the worker prints
    #   judged-by: nothing here; every string returned is read by the layers
    #   on-failure: fail-closed: None, and the caller counts the PDF unread
    #   owner: unpack.pdf.read_pdf
    #   evidence: T1 child.ask: a child with RLIMIT_CPU, RLIMIT_AS, a wall-clock
    #     kill and no secret in its environment; T1 _checked() accepts only its
    #     shapes; T4 tests/test_unpack_pdf.py
    answer = ask(WORKER, packed, slots=_slots, deadline=DEADLINE, max_output=MAX_OUTPUT)
    reading = None
    if isinstance(answer, bytes):
        try:
            reading = _checked(json.loads(answer))
        except (ValueError, TypeError, KeyError, RecursionError, binascii.Error):
            answer = MALFORMED
    if reading is None:
        # `answer` is one of child.py's phrases or ours, never the file's text.
        logger.warning("pdf: unread, %s", answer if isinstance(answer, str) else UNREADABLE)
    return reading


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
    if not isinstance(raw, dict):
        raise TypeError("not an answer")
    if raw.get("encrypted"):
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
    for number, encoded in raw["pictures"]:
        if not isinstance(encoded, str):
            raise TypeError("not a picture")
        reading.pictures.append((_count(number), base64.b64decode(encoded, validate=True)))
    for name, encoded in raw["attachments"]:
        if not isinstance(name, str) or not isinstance(encoded, (str, type(None))):
            raise TypeError("not an attachment")
        reading.attachments.append(
            Entry(name, None, TOO_LARGE)
            if encoded is None
            else Entry(name, base64.b64decode(encoded, validate=True))
        )
    return reading
