"""L2 on what the unpack stage reads out of archives and office files (#368).

The unpack stage frames an opened archive with a header and a
``=== name ===`` line per file. A bracketed marker in front of decoded
base64 made L2 flag benign text (docs/benchmark.md, "Unpack stage"), so the
framing is measured here before it ships: every corpus text is packed into
each container, unpacked, and classified. A container reads like plain text
to L2 when its benign and attack counts match the plain row.

    CLASSIFIER_MODEL_PATH=<export> uv run python benchmarks/unpack_archives.py
"""

from __future__ import annotations

import gzip
import io
import sys
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mcp_trentina_crunchtools.l1.pipeline import run_l1
from mcp_trentina_crunchtools.quarantine.classifier import classify, is_classifier_available
from mcp_trentina_crunchtools.unpack.scan import unpack
from tests.adversarial_corpus import CORPUS
from tests.office_files import b64, docx, paragraph, pptx, run, xlsx, zipped

if TYPE_CHECKING:
    from collections.abc import Callable


def _tar_gz(text: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        data = text.encode()
        info = tarfile.TarInfo("notes/report.txt")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue())


def _lines(text: str) -> list[str]:
    return [escape(line) for line in text.splitlines() if line.strip()] or [escape(text)]


CONTAINERS: dict[str, Callable[[str], bytes]] = {
    "zip, one text file": lambda t: zipped({"notes/report.txt": t}),
    "zip, three text files": lambda t: zipped(
        {
            "README.md": "Build notes for the storage service.",
            "notes/report.txt": t,
            "VERSION": "1.4.2",
        }
    ),
    "tar.gz": _tar_gz,
    "docx": lambda t: docx(*(paragraph(run(line)) for line in _lines(t))),
    "xlsx": lambda t: xlsx({"Sheet1": [[line] for line in _lines(t)]}),
    "pptx": lambda t: pptx(_lines(t)),
}


def _flagged(text: str) -> bool:
    result = classify(text)
    return result is not None and result.label == "MALICIOUS"


def main() -> int:
    if not is_classifier_available():
        print("error: no L2 model loaded (set CLASSIFIER_MODEL_PATH)", file=sys.stderr)
        return 2
    benign = [c.payload for c in CORPUS if not c.expect_injection]
    attacks = [c.payload for c in CORPUS if c.expect_injection]
    print(f"{len(benign)} benign, {len(attacks)} attacks\n")
    print(
        "| container | benign flagged by L2 | attacks flagged by L2 | L1 refuses benign | unread |"
    )
    print("|---|---|---|---|---|")
    rows: dict[str, Callable[[str], str]] = {"plain text": lambda t: t}
    rows.update(
        {
            name: (lambda t, pack=pack: f"Attachment: {b64(pack(t))}")
            for name, pack in CONTAINERS.items()
        }
    )
    for name, build in rows.items():
        views = {text: unpack(build(text)) for text in (*benign, *attacks)}
        unread = sum(bool(view.unread) for view in views.values())
        l1 = sum(run_l1(views[t].text).stats.risk_level() in ("high", "critical") for t in benign)
        print(
            f"| {name} | {sum(_flagged(views[t].text) for t in benign)} "
            f"| {sum(_flagged(views[t].text) for t in attacks)} | {l1} | {unread} |"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
