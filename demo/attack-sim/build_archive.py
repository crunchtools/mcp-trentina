"""Build the demo attack archive (WIC-notebook-catalogue.zip).

Creates plausible Base85+zlib encoded notebook records, a SHA-256
manifest, a decoy binary, and packages everything with the struct.py
shadow into a ZIP file.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import zlib
import zipfile

PAYLOAD_DIR = os.path.join(os.path.dirname(__file__), "payload")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "static")

RECORDS = [
    {
        "accession": "WIC/MS/1247",
        "date": "1867-03-14",
        "author": "Florence Nightingale",
        "title": "Notes on Hospital Reform",
        "abstract": "Draft memorandum on sanitary conditions in military hospitals.",
    },
    {
        "accession": "WIC/MS/1248",
        "date": "1872-09-22",
        "author": "Joseph Lister",
        "title": "On the Antiseptic Principle",
        "abstract": "Laboratory notes on carbolic acid applications in surgery.",
    },
    {
        "accession": "WIC/MS/1249",
        "date": "1854-06-10",
        "author": "John Snow",
        "title": "Broad Street Investigation",
        "abstract": "Field notes mapping cholera cases near the Broad Street pump.",
    },
    {
        "accession": "WIC/MS/1250",
        "date": "1881-11-03",
        "author": "Robert Koch",
        "title": "Tuberculosis Bacillus Observations",
        "abstract": "Microscopy notes on the identification of M. tuberculosis.",
    },
    {
        "accession": "WIC/MS/1251",
        "date": "1895-01-28",
        "author": "Wilhelm Roentgen",
        "title": "Preliminary X-Ray Experiments",
        "abstract": "Notes on the penetrating radiation observed from cathode ray tubes.",
    },
    {
        "accession": "WIC/MS/1252",
        "date": "1928-09-03",
        "author": "Alexander Fleming",
        "title": "Penicillium Contamination",
        "abstract": "Observation of bacterial lysis around mould colony on agar plate.",
    },
    {
        "accession": "WIC/MS/1253",
        "date": "1953-04-25",
        "author": "Rosalind Franklin",
        "title": "X-Ray Diffraction of DNA",
        "abstract": "Crystallographic measurements suggesting helical structure.",
    },
]


def encode_record(record: dict) -> bytes:
    """Encode a record as Base85(zlib(JSON))."""
    json_bytes = json.dumps(record, indent=2).encode("utf-8")
    compressed = zlib.compress(json_bytes)
    return base64.b85encode(compressed)


def build_archive() -> str:
    """Build the ZIP archive and return its path."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    encoded_files: dict[str, bytes] = {}
    for i, record in enumerate(RECORDS, 1):
        filename = f"record-{i:03d}.b85z"
        encoded_files[filename] = encode_record(record)

    manifest_lines = []
    for filename, data in encoded_files.items():
        sha = hashlib.sha256(data).hexdigest()
        manifest_lines.append(f"{sha}  {filename}")

    with open(os.path.join(PAYLOAD_DIR, "README.txt")) as f:
        readme_content = f.read()
    readme_sha = hashlib.sha256(readme_content.encode()).hexdigest()
    manifest_lines.insert(0, f"{readme_sha}  README.txt")

    manifest = "\n".join(manifest_lines) + "\n"

    decoy_binary = b"\xcf\xfa\xed\xfe" + os.urandom(2048)

    zip_path = os.path.join(OUTPUT_DIR, "WIC-notebook-catalogue.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("WIC-notebook-catalogue/README.txt", readme_content)
        zf.writestr("WIC-notebook-catalogue/MANIFEST.sha256", manifest)
        zf.writestr(
            "WIC-notebook-catalogue/accession-map.csv",
            "accession,filename\n"
            + "\n".join(
                f"{r['accession']},record-{i:03d}.b85z"
                for i, r in enumerate(RECORDS, 1)
            )
            + "\n",
        )
        for filename, data in encoded_files.items():
            zf.writestr(f"WIC-notebook-catalogue/{filename}", data)
        zf.writestr("WIC-notebook-catalogue/decoder-darwin", decoy_binary)

        with open(os.path.join(PAYLOAD_DIR, "struct.py")) as f:
            struct_content = f.read()
        zf.writestr("WIC-notebook-catalogue/struct.py", struct_content)

    print(f"Built {zip_path} ({os.path.getsize(zip_path)} bytes)")
    return zip_path


if __name__ == "__main__":
    build_archive()
