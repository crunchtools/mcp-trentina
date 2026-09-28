"""The external corpus: ``jackhhao/jailbreak-classification`` (issue #85).

A third-party labeled set, so the benchmark stops grading the defense only
against attacks its own author wrote, and so the FP rate has a denominator
in the hundreds instead of 9.

It is DIRECT jailbreak (user-to-model, DAN-style persona attacks), not
indirect injection in retrieved content, which is Trentina's threat model.
It measures L2 (Prompt Guard 2 is trained on exactly this syntax) and
over-triggering on benign roleplay. It says little about L3's semantic
gap; the internal corpus stays that measurement.

Pinned to one dataset revision and checked by SHA-256, so a result names
exactly what it was measured on. Downloaded on first use into
``benchmarks/data/`` (gitignored): the repo does not vendor 1.6 MB of
jailbreak prompts.
"""

from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from tests.adversarial_corpus import Case

if TYPE_CHECKING:
    from collections.abc import Callable

DATASET = "jackhhao/jailbreak-classification"
REVISION = "2f2ceeb39658696fd3f462403562b6eea5306287"
LICENSE = "Apache-2.0"

SPLIT_SHA256: dict[str, str] = {
    "test": "809ef0d7c82fa05c31e818e9c3ff68f769632ac6d11cc3b43254cada577869a9",
    "train": "e0c1460d229dc5d9162d5393a4e5e42382e862d04f400354bd4123b7d5257fff",
}
"""The balanced splits the dataset card declares (262 and 1,044 rows)."""

SPLITS = (*SPLIT_SHA256, "all")

CATEGORY_ATTACK = "external_jailbreak"
CATEGORY_BENIGN = "external_benign"
CATEGORY_PREFIX = "external_"

CACHE_DIR = Path(__file__).resolve().parent / "data"

_LABELS = {"jailbreak": True, "benign": False}
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024
"""The constitution's cap on a fetched response. The largest split is 1.3 MB."""
_CSV_FIELD_LIMIT = 1 << 20
"""Largest prompt is ~12 KB; the stdlib default of 128 KB is fine today, this
keeps a longer one from failing the parse instead of the benchmark."""


def url(split: str) -> str:
    """The pinned revision's CSV for ``test`` or ``train``."""
    return (
        f"https://huggingface.co/datasets/{DATASET}/resolve/{REVISION}"
        f"/balanced/jailbreak_dataset_{split}_balanced.csv"
    )


def _download(split: str, transport: httpx.BaseTransport | None = None) -> bytes:
    """Stream the split, refusing it past ``MAX_DOWNLOAD_BYTES``."""
    body = bytearray()
    with (
        httpx.Client(transport=transport, follow_redirects=True, timeout=60.0) as client,
        client.stream("GET", url(split)) as response,
    ):
        response.raise_for_status()
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"{url(split)} exceeds {MAX_DOWNLOAD_BYTES} bytes")
    return bytes(body)


def _split_bytes(split: str, cache_dir: Path, fetch: Callable[[str], bytes]) -> bytes:
    """The split's CSV, from cache when its hash still matches, else fetched.

    A fetched file that does not match the pinned hash is refused, never
    cached: a benchmark measured on different rows than it names is worse
    than one that does not run.
    """
    expected = SPLIT_SHA256[split]
    cached = cache_dir / f"jailbreak-classification-{split}-{REVISION[:12]}.csv"
    if cached.is_file():
        cached_csv = cached.read_bytes()
        if hashlib.sha256(cached_csv).hexdigest() == expected:
            return cached_csv
    fetched_csv = fetch(split)
    actual = hashlib.sha256(fetched_csv).hexdigest()
    if actual != expected:
        raise ValueError(
            f"{DATASET}@{REVISION[:12]} {split}: sha256 {actual} does not match "
            f"the pinned {expected}"
        )
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(fetched_csv)
    return fetched_csv


def _cases(split: str, csv_bytes: bytes) -> list[Case]:
    # field_size_limit is process-wide; restore it so no other reader inherits ours.
    previous = csv.field_size_limit(_CSV_FIELD_LIMIT)
    try:
        rows = list(csv.DictReader(io.StringIO(csv_bytes.decode("utf-8"), newline="")))
    finally:
        csv.field_size_limit(previous)
    cases = []
    for i, row in enumerate(rows):
        is_attack = _LABELS[row["type"]]
        cases.append(
            Case(
                id=f"ext-{split}-{i:04d}",
                category=CATEGORY_ATTACK if is_attack else CATEGORY_BENIGN,
                payload=row["prompt"],
                expect_injection=is_attack,
            )
        )
    return cases


def load(
    split: str = "test",
    *,
    cache_dir: Path = CACHE_DIR,
    fetch: Callable[[str], bytes] = _download,
) -> list[Case]:
    """The dataset as benchmark ``Case``s.

    ``split`` is ``test``, ``train``, or ``all`` (test then train).
    ``cache_dir`` holds the downloaded CSVs; ``fetch`` retrieves one split's
    bytes and is replaced in tests. ``min_risk`` stays empty: the dataset
    has no severity label, and the benchmark reports risk calibration as
    n/a rather than inventing one.

    Raises ValueError for an unknown split, or when a fetched file does not
    match its pinned SHA-256.
    """
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of {SPLITS}")
    names = list(SPLIT_SHA256) if split == "all" else [split]
    return [c for name in names for c in _cases(name, _split_bytes(name, cache_dir, fetch))]
