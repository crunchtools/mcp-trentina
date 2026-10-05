"""Small PDF files built in memory with pypdf, for the unpack tests.

A page is its content stream: the operators are written out by the test, so
what is invisible is invisible because of a named operator (``3 Tr``,
``1 1 1 rg``) and not because of a tool's choices.
"""

from __future__ import annotations

import io

from pypdf import PdfWriter
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    FloatObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

LETTER = (612, 792)
NOTE_BOX = (72, 600, 172, 620)
"""Where an annotation sits on the page: left, bottom, right, top."""


def show(text: str, x: float = 72, y: float = 700, size: float = 12, before: str = "") -> str:
    """One line of text at ``(x, y)``. ``before`` is operators inside ``BT``."""
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return f"BT /F1 {size} Tf {before} 1 0 0 1 {x} {y} Tm ({safe}) Tj ET\n"


def pdf(
    *pages: str,
    info: dict[str, str] | None = None,
    annotations: list[dict[str, str]] | None = None,
    attachments: dict[str, bytes] | None = None,
    javascript: str = "",
    image: bool = False,
) -> bytes:
    """A PDF with one page per content stream in ``pages``.

    ``annotations`` go on the first page, each a dict of text entries
    (``Contents``, ``T``, ``URI``). ``image`` adds a 1 by 1 image XObject to
    every page's resources and draws it.
    """
    writer = PdfWriter()
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    font_ref = writer._add_object(font)
    for drawn in pages:
        content = drawn
        page = writer.add_blank_page(*LETTER)
        resources = DictionaryObject(
            {NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})}
        )
        if image:
            pixel = DecodedStreamObject()
            pixel.set_data(b"\x00")
            pixel.update(
                {
                    NameObject("/Type"): NameObject("/XObject"),
                    NameObject("/Subtype"): NameObject("/Image"),
                    NameObject("/Width"): NumberObject(1),
                    NameObject("/Height"): NumberObject(1),
                    NameObject("/ColorSpace"): NameObject("/DeviceGray"),
                    NameObject("/BitsPerComponent"): NumberObject(8),
                }
            )
            resources[NameObject("/XObject")] = DictionaryObject(
                {NameObject("/Im1"): writer._add_object(pixel)}
            )
            content += "q 200 0 0 200 72 300 cm /Im1 Do Q\n"
        stream = DecodedStreamObject()
        stream.set_data(content.encode("latin-1"))
        page[NameObject("/Resources")] = resources
        page[NameObject("/Contents")] = writer._add_object(stream)
    if annotations:
        first = writer.pages[0]
        refs = ArrayObject()
        for fields in annotations:
            annotation = DictionaryObject(
                {
                    NameObject("/Type"): NameObject("/Annot"),
                    NameObject("/Subtype"): NameObject("/Link" if "URI" in fields else "/Text"),
                    NameObject("/Rect"): ArrayObject([FloatObject(v) for v in NOTE_BOX]),
                }
            )
            for key, value in fields.items():
                if key == "URI":
                    annotation[NameObject("/A")] = DictionaryObject(
                        {
                            NameObject("/S"): NameObject("/URI"),
                            NameObject("/URI"): TextStringObject(value),
                        }
                    )
                else:
                    annotation[NameObject(f"/{key}")] = TextStringObject(value)
            refs.append(writer._add_object(annotation))
        first[NameObject("/Annots")] = refs
    if info:
        writer.add_metadata({f"/{key}": value for key, value in info.items()})
    for name, content in (attachments or {}).items():
        writer.add_attachment(name, content)
    if javascript:
        writer.add_js(javascript)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()
