"""Read the text of a Word, Excel or PowerPoint file (#368).

A docx, xlsx or pptx is a zip of XML parts. ``archive.py`` opens the zip;
this module turns each XML part into the text it holds, and says which of
that text the application would not show.

Two readers need two different answers, so both are kept:

* **The layers** read everything: every text node of every part, shown or
  hidden. A renderer decides what is visible; a model handed the file by an
  agent's tool reads all of it. Reading more than Word shows is the safe
  direction, so elements are matched by local name whatever their
  namespace prefix, and a part this module cannot parse is left for the
  caller to read as raw XML.
* **The delivery**, when stage 1 reduces the file (``preprocess/structured``),
  is the visible text of the content parts, as Markdown. Hidden text is
  dropped there and counted, as HTML conversion drops hidden elements.

Hidden means marked so by the format: Word's ``vanish``, ``webHidden`` and
``specVanish`` run properties, set on the run or inherited from a character
style, a paragraph style or the document defaults; a hidden or very hidden
sheet; a hidden row; a shared string no cell uses; a slide with
``show="0"``. White text, one-point type and shapes moved off the page are
not detected (Known gaps). They are still read by the layers.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET
from xml.parsers import expat

from .archive import ZIP, Budget, open_archive

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from .archive import Entry

DOCX = "docx"
XLSX = "xlsx"
PPTX = "pptx"
_MAIN_PARTS = {
    "word/document.xml": DOCX,
    "xl/workbook.xml": XLSX,
    "ppt/presentation.xml": PPTX,
}
CONTENT_TYPES = "[Content_Types].xml"

_VANISH = frozenset({"vanish", "webHidden", "specVanish"})
_OFF = frozenset({"0", "false", "off"})
_BREAKS = frozenset({"p", "br", "cr", "tr", "si", "row", "comment", "sheet", "definedName"})
_ALT_TEXT = frozenset({"descr", "title", "tooltip"})
_ALT_HOLDERS = frozenset({"docPr", "cNvPr", "hlinkClick", "hyperlink"})
_RUN_TEXT = frozenset({"t", "delText", "instrText"})
"""Elements whose text joins its neighbours' with no space: a word may be
split across runs."""
MAX_STYLE_HOPS = 20
"""``basedOn`` links followed before a style chain is given up as a loop."""

_SLIDE_NUMBER = re.compile(r"(\d+)\.xml$")
_DOCX_EXTRA = re.compile(r"word/(footnotes|endnotes|comments|header\d*|footer\d*)\.xml$")


class _ForbiddenError(Exception):
    """The part declares a DTD: no OOXML part has one, and entities are how
    an XML parser is made to expand a kilobyte into gigabytes."""


def _forbid(*_args: object) -> None:
    raise _ForbiddenError


def parse(data: bytes) -> ET.Element | None:
    """``data`` as an XML tree, or None when it is not well-formed or has a DTD."""
    # TRUST: parsing XML nobody has judged yet
    #   untrusted: all of `data`, a part of a file the payload's author wrote
    #   judged-by: nothing here; the text this yields is what the layers read
    #   on-failure: fail-closed: None, and the caller reads the part as raw text
    #   owner: unpack.office.parse
    #   evidence: T1 a DOCTYPE raises before any entity is declared, so nothing
    #     expands; T1 expat fetches no external entity; T4 tests/test_unpack_office.py
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    parser.StartDoctypeDeclHandler = _forbid
    parser.StartElementHandler = lambda name, attrs: builder.start(
        _qualified(name), {_qualified(key): value for key, value in attrs.items()}
    )
    parser.EndElementHandler = lambda name: builder.end(_qualified(name))
    parser.CharacterDataHandler = builder.data
    try:
        parser.Parse(data, True)
        return builder.close()
    except (expat.ExpatError, _ForbiddenError, ValueError, LookupError, AssertionError):
        return None


def _qualified(name: str) -> str:
    """expat's ``uri}local`` as ElementTree's ``{uri}local``."""
    return "{" + name if "}" in name else name


def local(tag: object) -> str:
    """An element's name without its namespace. Comments have no string tag."""
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def attr(element: ET.Element, name: str) -> str | None:
    """The attribute called ``name`` in any namespace."""
    for key, value in element.attrib.items():
        if local(key) == name:
            return value
    return None


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in element if local(c.tag) == name), None)


def _switch(properties: ET.Element | None) -> bool | None:
    """Whether run properties hide their text: True, False, or None for unsaid."""
    if properties is None:
        return None
    said: bool | None = None
    for prop in properties:
        if local(prop.tag) in _VANISH:
            on = (attr(prop, "val") or "true").lower() not in _OFF
            if on:
                return True
            said = False
    return said


@dataclass
class Text:
    """One part's text, split by whether the application shows it."""

    lines: list[tuple[str, bool]] = field(default_factory=list)  # (line, hidden)

    def add(self, line: str, *, hidden: bool) -> None:
        if line.strip():
            self.lines.append((" ".join(line.split()), hidden))

    def all(self) -> str:
        return "\n".join(line for line, _ in self.lines)

    def visible(self) -> str:
        return "\n".join(line for line, hidden in self.lines if not hidden)

    @property
    def hidden_count(self) -> int:
        return sum(1 for _, hidden in self.lines if hidden)


@dataclass
class _Styles:
    """Which Word styles hide their text, after ``basedOn`` inheritance."""

    default: bool = False
    hidden: frozenset[str] = frozenset()

    @classmethod
    def read(cls, root: ET.Element | None) -> _Styles:
        if root is None:
            return cls()
        own: dict[str, bool | None] = {}
        based: dict[str, str] = {}
        default = False
        for element in root.iter():
            name = local(element.tag)
            if name == "rPrDefault":
                default = _switch(_child(element, "rPr")) is True
            elif name == "style":
                style_id = attr(element, "styleId")
                if style_id is None:
                    continue
                own[style_id] = _switch(_child(element, "rPr"))
                parent = _child(element, "basedOn")
                if parent is not None:
                    based[style_id] = attr(parent, "val") or ""
        return cls(default, frozenset(s for s in own if _inherited(s, own, based)))


def _inherited(style: str, own: dict[str, bool | None], based: dict[str, str]) -> bool:
    for _ in range(MAX_STYLE_HOPS):
        said = own.get(style)
        if said is not None:
            return said
        if style not in based:
            return False
        style = based[style]
    return False


def _styled(element: ET.Element, properties: str, style: str) -> str | None:
    props = _child(element, properties)
    ref = None if props is None else _child(props, style)
    return None if ref is None else attr(ref, "val")


class _Flow:
    """Every text node under a root, a line per paragraph, in document order.

    Whether an element's text is hidden is settled top-down, which document
    order allows: a parent is always visited before its children. A run
    decides for itself when its properties say; otherwise its character
    style, its paragraph's style and the document default are asked in turn.
    """

    def __init__(self, styles: _Styles, *, forced: bool) -> None:
        self.styles = styles
        self.forced = forced or styles.default
        self.text = Text()
        self._line: list[str] = []
        self._line_hidden = False

    def read(self, root: ET.Element) -> Text:
        hides: dict[ET.Element, bool] = {root: self.forced}
        for element in root.iter():
            name = local(element.tag)
            hidden = self._hides(element, name, hides.get(element, False))
            for child in element:
                hides[child] = hidden
            if name in _BREAKS:
                self._flush()
            if name in _ALT_HOLDERS:
                self._alt_text(element, hidden)
            if element.text and element.text.strip() and name != "rPr":
                self._say(element.text, hidden)
                if name not in _RUN_TEXT:
                    self._line.append(" ")
        self._flush()
        return self.text

    def _hides(self, element: ET.Element, name: str, inherited: bool) -> bool:
        if name == "p":
            return self.forced or _styled(element, "pPr", "pStyle") in self.styles.hidden
        if name != "r":
            return inherited
        said = _switch(_child(element, "rPr"))
        if said is not None:
            return self.forced or said
        return inherited or _styled(element, "rPr", "rStyle") in self.styles.hidden

    def _alt_text(self, element: ET.Element, hidden: bool) -> None:
        for key in _ALT_TEXT:
            value = attr(element, key)
            if value and value.strip():
                self._flush()
                self.text.add(f"[{value}]", hidden=hidden)

    def _say(self, piece: str, hidden: bool) -> None:
        if self._line and self._line_hidden != hidden:
            self._flush()
        if not self._line:
            self._line_hidden = hidden
        self._line.append(piece)

    def _flush(self) -> None:
        self.text.add("".join(self._line), hidden=self._line_hidden)
        self._line.clear()
        self._line_hidden = False


def _flow(root: ET.Element, styles: _Styles, *, hidden: bool = False) -> Text:
    return _Flow(styles, forced=hidden).read(root)


def _cells(root: ET.Element, shared: list[str], used: set[int], *, hidden: bool) -> Text:
    """A worksheet as one line per row, cells joined by `` | ``."""
    text = Text()
    for row in root.iter():
        if local(row.tag) != "row":
            continue
        cells: list[str] = []
        for cell in row:
            if local(cell.tag) != "c":
                continue
            cells.append(_cell(cell, shared, used))
        row_hidden = hidden or (attr(row, "hidden") or "0").lower() not in _OFF
        text.add(" | ".join(c for c in cells if c), hidden=row_hidden)
    return text


def _cell(cell: ET.Element, shared: list[str], used: set[int]) -> str:
    kind = attr(cell, "t") or "n"
    value = ""
    formula = ""
    for child in cell:
        name = local(child.tag)
        if name == "v":
            value = child.text or ""
        elif name == "f":
            formula = child.text or ""
        elif name == "is":
            value = "".join(t.text or "" for t in child.iter() if local(t.tag) == "t")
    if kind == "s" and value.strip().isdigit():
        index = int(value)
        if index < len(shared):
            used.add(index)
            value = shared[index]
    return f"{value} (={formula})" if formula.strip() else value


def _relationships(root: ET.Element | None, base: str) -> tuple[dict[str, str], list[str]]:
    """``(internal targets by id, external targets)`` of one ``.rels`` part."""
    internal: dict[str, str] = {}
    external: list[str] = []
    if root is None:
        return internal, external
    for rel in root.iter():
        if local(rel.tag) != "Relationship":
            continue
        target = attr(rel, "Target") or ""
        if (attr(rel, "TargetMode") or "").lower() == "external":
            external.append(target)
        else:
            path = target.lstrip("/") if target.startswith("/") else posixpath.join(base, target)
            internal[attr(rel, "Id") or ""] = posixpath.normpath(path)
    return internal, external


@dataclass
class Reading:
    """What one office file says.

    Attributes:
        kind: ``docx``, ``xlsx`` or ``pptx``.
        parts: The text of every XML part that parsed, by part name, in the
            archive's order. A part missing from here was not parsed, and
            the caller reads it as it would any other file.
        titles: Headings for the content parts, in reading order: what the
            Markdown delivery is built from.
    """

    kind: str
    parts: dict[str, Text] = field(default_factory=dict)
    titles: list[tuple[str, str]] = field(default_factory=list)  # (part name, heading)

    @property
    def hidden(self) -> int:
        """Lines the application would not show, across every part."""
        return sum(text.hidden_count for text in self.parts.values())

    def markdown(self) -> str:
        """The visible text of the content parts, for stage 1 to deliver."""
        sections: list[str] = []
        for name, heading in self.titles:
            body = self.parts[name].visible() if name in self.parts else ""
            if body:
                sections.append(f"{heading}\n\n{body}" if heading else body)
        return "\n\n".join(sections)


def kind_of(names: Iterable[str]) -> str | None:
    """Which office format a zip with these file names is, or None."""
    names = set(names)
    if CONTENT_TYPES not in names:
        return None
    return next((kind for part, kind in _MAIN_PARTS.items() if part in names), None)


def read(entries: list[Entry]) -> Reading | None:
    """Read an opened zip as an office file, or None if it is not one."""
    files = {e.name: e.data for e in entries if e.data is not None}
    kind = kind_of(files)
    if kind is None:
        return None
    trees = {
        name: tree
        for name, data in files.items()
        if name.endswith((".xml", ".rels")) and (tree := parse(data)) is not None
    }
    reading = Reading(kind)
    if kind == XLSX:
        _read_xlsx(trees, reading)
    else:
        styles = _Styles.read(trees.get("word/styles.xml"))
        for name, tree in trees.items():
            if name.endswith(".rels"):
                continue
            slide_off = kind == PPTX and (attr(tree, "show") or "1").lower() in _OFF
            reading.parts[name] = _flow(tree, styles, hidden=slide_off)
        reading.titles = list(_docx_titles(trees) if kind == DOCX else _pptx_titles(trees))
    for name, tree in trees.items():
        if not name.endswith(".rels"):
            continue
        _, external = _relationships(tree, "")
        links = Text()
        for target in external:
            links.add(f"link: {target}", hidden=False)
        reading.parts[name] = links
        if links.lines:
            reading.titles.append((name, "Links"))
    return reading


def _docx_titles(trees: dict[str, ET.Element]) -> Iterator[tuple[str, str]]:
    yield "word/document.xml", ""
    for name in sorted(trees):
        extra = _DOCX_EXTRA.match(name)
        if extra:
            yield name, f"## {extra.group(1).rstrip('0123456789').capitalize()}"


def _numbered(trees: dict[str, ET.Element], prefix: str) -> list[tuple[int, str]]:
    found = []
    for name in trees:
        number = _SLIDE_NUMBER.search(name)
        if name.startswith(prefix) and "/_rels/" not in name and number:
            found.append((int(number.group(1)), name))
    return sorted(found)


def _pptx_titles(trees: dict[str, ET.Element]) -> Iterator[tuple[str, str]]:
    for number, name in _numbered(trees, "ppt/slides/slide"):
        yield name, f"## Slide {number}"
    for number, name in _numbered(trees, "ppt/notesSlides/notesSlide"):
        yield name, f"## Notes {number}"


def _read_xlsx(trees: dict[str, ET.Element], reading: Reading) -> None:
    shared_tree = trees.get("xl/sharedStrings.xml")
    shared = (
        []
        if shared_tree is None
        else [
            "".join(t.text or "" for t in item.iter() if local(t.tag) == "t")
            for item in shared_tree.iter()
            if local(item.tag) == "si"
        ]
    )
    targets, _ = _relationships(trees.get("xl/_rels/workbook.xml.rels"), "xl")
    sheets: dict[str, tuple[str, bool]] = {}
    workbook = trees.get("xl/workbook.xml")
    for sheet in [] if workbook is None else workbook.iter():
        if local(sheet.tag) == "sheet":
            part = targets.get(attr(sheet, "id") or "", "")
            off = (attr(sheet, "state") or "visible").lower() != "visible"
            sheets[part] = (attr(sheet, "name") or "", off)
    used: set[int] = set()
    empty = _Styles()
    for name, tree in trees.items():
        if name.endswith(".rels") or name == "xl/sharedStrings.xml":
            continue
        if local(tree.tag) == "worksheet":
            title, off = sheets.get(name, ("", False))
            reading.parts[name] = _cells(tree, shared, used, hidden=off)
            reading.titles.append((name, f"## {' '.join(title.split())}" if title else "## Sheet"))
        else:
            reading.parts[name] = _flow(tree, empty)
    unused = Text()
    for index, value in enumerate(shared):
        if index not in used:
            unused.add(value, hidden=True)
    reading.parts["xl/sharedStrings.xml"] = unused


ZIP_BASE64_PREFIX = "UEsDB"
"""How canonical base64 of a zip's ``PK\\x03\\x04`` always starts."""


def reduce_base64(token: str, max_chars: int) -> tuple[str, str, int] | None:
    """A base64 office file as ``(kind, Markdown, hidden lines dropped)``.

    For stage 1 (``preprocess/structured``). None declines, and the token is
    then delivered as it arrived for the unpack stage to read: not canonical
    base64, not an office file, over a limit, a part that could not be read,
    or nothing visible to deliver.
    """
    if not token.startswith(ZIP_BASE64_PREFIX) or len(token) > max_chars or len(token) % 4:
        return None
    try:
        data = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    entries = open_archive(data, ZIP, Budget())
    if entries is None or any(entry.data is None for entry in entries):
        return None
    reading = read(entries)
    if reading is None:
        return None
    markdown = reading.markdown()
    return (reading.kind, markdown, reading.hidden) if markdown else None
