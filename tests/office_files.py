"""Small Word, Excel and PowerPoint files built in memory, for the unpack tests.

Real OOXML in the parts that matter (namespaces, run properties, shared
strings, relationships) and nothing else: no theme, no fonts, no app
properties. Every file is a zip written by ``zipfile``.
"""

from __future__ import annotations

import base64
import io
import zipfile

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CONTENT_TYPES = '<?xml version="1.0"?><Types/>'


def zipped(files: dict[str, bytes | str], *, comment: bytes = b"") -> bytes:
    """A deflated zip of ``files``, in the order given."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.comment = comment
    return buffer.getvalue()


def b64(data: bytes | str) -> str:
    return base64.b64encode(data.encode() if isinstance(data, str) else data).decode()


def run(text: str, properties: str = "") -> str:
    """One Word run. ``properties`` is the inside of its ``w:rPr``."""
    rpr = f"<w:rPr>{properties}</w:rPr>" if properties else ""
    return f'<w:r>{rpr}<w:t xml:space="preserve">{text}</w:t></w:r>'


def paragraph(*runs: str, style: str = "") -> str:
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f"<w:p>{ppr}{''.join(runs)}</w:p>"


def docx(
    *paragraphs: str,
    styles: str = "",
    extra: dict[str, bytes | str] | None = None,
    prefix: str = "w",
) -> bytes:
    """A Word file whose body is ``paragraphs``. ``prefix`` renames the
    namespace prefix, which a parser matching on ``w:`` would miss."""
    body = "".join(paragraphs)
    document = (
        f'<?xml version="1.0"?><w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>'
    )
    files: dict[str, bytes | str] = {
        "[Content_Types].xml": CONTENT_TYPES,
        "word/document.xml": document.replace("w:", f"{prefix}:").replace(
            "xmlns:w=", f"xmlns:{prefix}="
        ),
    }
    if styles:
        files["word/styles.xml"] = (
            f'<?xml version="1.0"?><w:styles xmlns:w="{W}">{styles}</w:styles>'
        )
    files.update(extra or {})
    return zipped(files)


def xlsx(
    sheets: dict[str, list[list[str]]],
    *,
    hidden: frozenset[str] = frozenset(),
    orphans: tuple[str, ...] = (),
) -> bytes:
    """An Excel file. Every cell is a shared string; ``orphans`` are shared
    strings no cell uses, and ``hidden`` names the sheets marked hidden."""
    strings: list[str] = []
    files: dict[str, bytes | str] = {"[Content_Types].xml": CONTENT_TYPES}
    entries, relationships = [], []
    for number, (name, rows) in enumerate(sheets.items(), start=1):
        xml_rows = []
        for row in rows:
            cells = []
            for value in row:
                strings.append(value)
                cells.append(f'<c t="s"><v>{len(strings) - 1}</v></c>')
            xml_rows.append(f"<row>{''.join(cells)}</row>")
        files[f"xl/worksheets/sheet{number}.xml"] = (
            f'<?xml version="1.0"?><worksheet xmlns="{S}"><sheetData>{"".join(xml_rows)}'
            "</sheetData></worksheet>"
        )
        state = ' state="hidden"' if name in hidden else ""
        entries.append(f'<sheet name="{name}" sheetId="{number}"{state} r:id="rId{number}"/>')
        relationships.append(
            f'<Relationship Id="rId{number}" Target="worksheets/sheet{number}.xml"/>'
        )
    strings.extend(orphans)
    files["xl/workbook.xml"] = (
        f'<?xml version="1.0"?><workbook xmlns="{S}" xmlns:r="{R}"><sheets>{"".join(entries)}'
        "</sheets></workbook>"
    )
    files["xl/_rels/workbook.xml.rels"] = f"<Relationships>{''.join(relationships)}</Relationships>"
    items = "".join(f"<si><t>{value}</t></si>" for value in strings)
    files["xl/sharedStrings.xml"] = f'<?xml version="1.0"?><sst xmlns="{S}">{items}</sst>'
    return zipped(files)


def pptx(slides: list[str], *, hidden: frozenset[int] = frozenset(), notes: str = "") -> bytes:
    """A PowerPoint file, one text box per slide. ``hidden`` holds the
    1-based numbers of slides with ``show="0"``."""
    files: dict[str, bytes | str] = {
        "[Content_Types].xml": CONTENT_TYPES,
        "ppt/presentation.xml": f'<?xml version="1.0"?><p:presentation xmlns:p="{P}"/>',
    }
    for number, text in enumerate(slides, start=1):
        show = ' show="0"' if number in hidden else ""
        files[f"ppt/slides/slide{number}.xml"] = (
            f'<?xml version="1.0"?><p:sld xmlns:p="{P}" xmlns:a="{A}"{show}><p:cSld><p:spTree>'
            f"<p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>"
            "</p:spTree></p:cSld></p:sld>"
        )
    if notes:
        files["ppt/notesSlides/notesSlide1.xml"] = (
            f'<?xml version="1.0"?><p:notes xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree><p:sp>'
            f"<p:txBody><a:p><a:r><a:t>{notes}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree>"
            "</p:cSld></p:notes>"
        )
    return zipped(files)
