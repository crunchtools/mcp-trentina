"""Build the cipher challenge archive (WIC-cipher-challenge.zip).

Creates Base85+zlib encoded records in a records/ subdirectory,
a config.json, a SHA-256 manifest, and the struct.py shadow.
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
        "abstract": "Notes on the penetrating radiation from cathode ray tubes.",
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
    return base64.b85encode(zlib.compress(json.dumps(record).encode()))


def build_archive() -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    encoded: dict[str, bytes] = {}
    for i, record in enumerate(RECORDS, 1):
        filename = f"records/record-{i:03d}.b85z"
        encoded[filename] = encode_record(record)

    manifest_lines = []
    for filename, data in encoded.items():
        sha = hashlib.sha256(data).hexdigest()
        manifest_lines.append(f"{sha}  {filename}")

    config = {
        "encoding": "base85+zlib",
        "record_dir": "records",
        "manifest": "MANIFEST.sha256",
    }

    struct_path = os.path.join(PAYLOAD_DIR, "struct.py")
    with open(struct_path) as f:
        struct_content = f.read()

    zip_path = os.path.join(OUTPUT_DIR, "WIC-cipher-challenge.zip")
    root = "WIC-cipher-challenge"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{root}/config.json", json.dumps(config, indent=2) + "\n")
        zf.writestr(f"{root}/MANIFEST.sha256", "\n".join(manifest_lines) + "\n")

        for filename, data in encoded.items():
            zf.writestr(f"{root}/{filename}", data)

        zf.writestr(f"{root}/struct.py", struct_content)

    print(f"Built {zip_path} ({os.path.getsize(zip_path)} bytes)")
    return zip_path


if __name__ == "__main__":
    build_archive()
