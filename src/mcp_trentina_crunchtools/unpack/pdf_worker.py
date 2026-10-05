"""Read one PDF from stdin and print what it says as JSON (#369).

Run as a child process by ``pdf.read_pdf`` and by nothing else:

    python -m mcp_trentina_crunchtools.unpack.pdf_worker < file.pdf

A PDF is the most complicated thing this gateway opens, in a pure-Python
parser with a history of inputs that loop or allocate without end. A thread
cannot be stopped; a process can. So the parse happens here, under a CPU
limit and an address-space limit this process sets on itself, with no
credential in its environment, and the parent kills it at a wall-clock
deadline. Any exception is left to end the process: a PDF that cannot be
read to the end is not half read.

The output is everything a tool handed the file could show an agent:

* the text of each page, split by whether a reader would see it;
* every text-valued entry worth reading in every object of the file
  (annotation contents, form values, link targets, JavaScript, document
  information, alternate text), reached by walking the cross-reference
  table and not the page tree, so an object nothing points to is read too;
* the XMP metadata packet, the outline, and each embedded file's bytes.

Invisible means drawn so by a named operator: text render mode 3 or 7, a
white fill, a size under a point once the matrices are applied, or a
position outside the page. Text in a hidden optional-content layer, behind
an image or clipped away is read as visible (Known gaps).
"""

from __future__ import annotations

import base64
import io
import json
import math
import resource
import sys
from dataclasses import dataclass, field
from typing import Any

from pypdf import PdfReader, filters
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject

CPU_SECONDS = 20
MEMORY_BYTES = 1024 * 1024 * 1024
MAX_STREAM_BYTES = 32 * 1024 * 1024
"""What one compressed stream may inflate to. pypdf's own default is 75 MB."""

MAX_PAGES = 500
MAX_OBJECTS = 100_000
MAX_TEXT = 2_000_000
"""Characters of text collected before the file is given up as too large.
Admission refuses long before this; the cap bounds the work."""

MAX_ATTACHED = 1024 * 1024
"""Bytes of embedded files returned, the archive stage's own budget."""

INVISIBLE_MODES = frozenset({3, 7})
"""Text render modes that paint nothing: invisible, and clip-only."""

MIN_POINT_SIZE = 1.0
MARGIN = 2.0
"""Points outside the page box a text origin may sit before it is off the page."""

_SHOW = frozenset({b"Tj", b"TJ", b"'", b'"'})
_GRAY = frozenset({b"g"})
_RGB = frozenset({b"rg", b"sc", b"scn"})
_CMYK = frozenset({b"k"})
_INLINE_IMAGE = b"INLINE IMAGE"

FIELDS = {
    "/Contents": "note",
    "/RC": "note",
    "/T": "field",
    "/TU": "field",
    "/V": "field",
    "/DV": "field",
    "/URI": "link",
    "/JS": "javascript",
    "/Title": "title",
    "/Author": "information",
    "/Subject": "information",
    "/Keywords": "information",
    "/Alt": "alternate text",
    "/ActualText": "alternate text",
    "/E": "alternate text",
    "/Desc": "file",
    "/UF": "file",
}
"""Dictionary entries whose text a reader or an extraction tool shows, and
the fixed word each is reported under. The key is the PDF's; the word is
ours, so nothing from the file names a section."""


STREAM_KEYS = frozenset({"/JS", "/RC"})
"""Entries that may hold their text in a stream."""


class TooLargeError(Exception):
    """A cap was reached. The file is refused, not truncated."""


@dataclass
class _Painter:
    """The parts of the graphics state that decide whether text is seen."""

    box: tuple[float, float, float, float]
    mode: int = 0
    white: bool = False
    stack: list[tuple[int, bool]] = field(default_factory=list)
    shown_hidden: bool = False
    shown_visible: bool = False
    images: int = 0
    visible: list[str] = field(default_factory=list)
    hidden: list[str] = field(default_factory=list)
    hidden_chunks: int = 0

    def operand(self, operator: Any, operands: Any, _cm: Any, _tm: Any) -> None:
        if operator == b"Tr" and operands:
            self.mode = int(operands[0])
        elif operator in _GRAY:
            self.white = _all(operands, 1)
        elif operator in _RGB:
            self.white = len(operands) >= 3 and _all(operands, 1)
        elif operator in _CMYK:
            self.white = _all(operands, 0)
        elif operator == b"q":
            self.stack.append((self.mode, self.white))
        elif operator == b"Q" and self.stack:
            self.mode, self.white = self.stack.pop()
        elif operator == _INLINE_IMAGE:
            self.images += 1
        elif operator in _SHOW:
            unseen = self.mode in INVISIBLE_MODES or self.white
            self.shown_hidden = self.shown_hidden or unseen
            self.shown_visible = self.shown_visible or not unseen

    def text(self, chunk: str, cm: Any, tm: Any, _font: Any, size: float) -> None:
        """One run of text as pypdf hands it over, with the matrices in force.

        A run can hold several show operators. It is hidden when none of
        them painted visibly, or when the whole run is too small or off the
        page; it is COUNTED as hidden when any of them was, so text mixed
        into a visible line is still reported.
        """
        if not chunk.strip():
            (self.hidden if self.hidden and not self.visible else self.visible).append(chunk)
            return
        misplaced = _tiny(cm, tm, size) or self._off_page(cm, tm)
        unseen = misplaced or (self.shown_hidden and not self.shown_visible)
        if misplaced or self.shown_hidden:
            self.hidden_chunks += 1
        (self.hidden if unseen else self.visible).append(chunk)
        self.shown_hidden = self.shown_visible = False

    def _off_page(self, cm: Any, tm: Any) -> bool:
        x = tm[4] * cm[0] + tm[5] * cm[2] + cm[4]
        y = tm[4] * cm[1] + tm[5] * cm[3] + cm[5]
        left, bottom, right, top = self.box
        return not (left - MARGIN <= x <= right + MARGIN and bottom - MARGIN <= y <= top + MARGIN)


def _all(operands: Any, value: float) -> bool:
    try:
        return bool(operands) and all(abs(float(o) - value) < 1e-3 for o in operands)
    except (TypeError, ValueError):
        return False


def _tiny(cm: Any, tm: Any, size: float) -> bool:
    scale = math.sqrt(abs(tm[0] * tm[3] - tm[1] * tm[2]) * abs(cm[0] * cm[3] - cm[1] * cm[2]))
    return abs(float(size)) * scale < MIN_POINT_SIZE


def _has_image(resources: Any, depth: int = 0) -> bool:
    """Whether a page's resources draw an image, directly or inside a form."""
    xobjects = resources.get("/XObject") if isinstance(resources, DictionaryObject) else None
    if not isinstance(xobjects, DictionaryObject) or depth > 4:
        return False
    for ref in xobjects.values():
        xobject = ref.get_object()
        if not isinstance(xobject, DictionaryObject):
            continue
        if xobject.get("/Subtype") == "/Image":
            return True
        if xobject.get("/Subtype") == "/Form" and _has_image(xobject.get("/Resources"), depth + 1):
            return True
    return False


def _text_of(value: Any, *, stream: bool = False) -> str:
    """A dictionary entry as text, or empty when it is not text.

    A stream counts only where the key can hold one (``STREAM_KEYS``):
    ``/Contents`` on a page is its drawing operators, not a note.
    """
    value = value.get_object() if isinstance(value, IndirectObject) else value
    if isinstance(value, StreamObject):
        return value.get_data().decode("utf-8", "replace") if stream else ""
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return value if isinstance(value, str) and not str(value).startswith("/") else ""


@dataclass
class _Reading:
    reader: PdfReader
    size: int = 0
    out: dict[str, Any] = field(default_factory=dict)

    def spend(self, text: str) -> str:
        self.size += len(text)
        if self.size > MAX_TEXT:
            raise TooLargeError
        return text

    def pages(self) -> None:
        pages, hidden, scanned = [], 0, 0
        if len(self.reader.pages) > MAX_PAGES:
            raise TooLargeError
        for page in self.reader.pages:
            box = tuple(float(v) for v in page.mediabox)
            painter = _Painter((box[0], box[1], box[2], box[3]))
            page.extract_text(visitor_operand_before=painter.operand, visitor_text=painter.text)
            visible = self.spend("".join(painter.visible).strip())
            unseen = self.spend("".join(painter.hidden).strip())
            hidden += painter.hidden_chunks
            pictured = painter.images > 0 or _has_image(page.get("/Resources"))
            scanned += pictured and not (visible or unseen)
            pages.append([visible, unseen])
        self.out.update(pages=pages, hidden=hidden, scanned=scanned)

    def fields(self) -> None:
        """Every text entry in ``FIELDS``, from every object the file has."""
        count = int(self.reader.trailer.get("/Size", 0))
        if count > MAX_OBJECTS:
            raise TooLargeError
        found: dict[str, list[str]] = {}
        for number in range(1, count):
            target = self.reader.get_object(IndirectObject(number, 0, self.reader))
            for entry in _dictionaries(target):
                for key, section in FIELDS.items():
                    text = (
                        _text_of(entry.get(key), stream=key in STREAM_KEYS) if key in entry else ""
                    )
                    if text.strip() and text not in found.setdefault(section, []):
                        found[section].append(self.spend(text))
        packet = self.reader.root_object.get("/Metadata")
        if packet is not None:
            found.setdefault("metadata", []).append(self.spend(_text_of(packet, stream=True)))
        self.out["fields"] = found

    def attachments(self) -> None:
        attached, total = [], 0
        for name, contents in self.reader.attachments.items():
            for content in contents:
                total += len(content)
                if total > MAX_ATTACHED:
                    raise TooLargeError
                attached.append([str(name), base64.b64encode(content).decode("ascii")])
        self.out["attachments"] = attached


def _dictionaries(target: Any) -> list[DictionaryObject]:
    """``target`` and the dictionaries directly inside it, one level down."""
    if isinstance(target, DictionaryObject):
        inner = [v for v in target.values() if isinstance(v, DictionaryObject)]
        return [target, *inner]
    if isinstance(target, ArrayObject):
        return [v for v in target if isinstance(v, DictionaryObject)]
    return []


def main() -> int:
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    filters.ZLIB_MAX_OUTPUT_LENGTH = MAX_STREAM_BYTES
    filters.LZW_MAX_OUTPUT_LENGTH = MAX_STREAM_BYTES
    reader = PdfReader(io.BytesIO(sys.stdin.buffer.read()))
    if reader.is_encrypted and not reader.decrypt(""):
        json.dump({"encrypted": True}, sys.stdout)
        return 0
    reading = _Reading(reader)
    reading.pages()
    reading.fields()
    reading.attachments()
    json.dump(reading.out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
