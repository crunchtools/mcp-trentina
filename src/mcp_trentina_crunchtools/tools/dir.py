"""Directory tools — block_dir, warn_dir and clean_dir.

A directory listing is a payload like any other: file names are text an
attacker chose, and a name can be an instruction. So the listing crosses all
three layers, and the mode decides what is delivered.

This replaces ``quarantine_scan_dir``, a diagnostic that ran L1 and L2 on
every ``.py`` file (up to 500 of them) and returned a bespoke
``recommendation`` string. Module shadowing — a ``struct.py`` that Python
imports instead of the real one — is now an L1 detector (``ShadowStats``)
whose any-hit risk is critical, so a shadowed directory is refused by block,
cleaned by clean and warned by warn through the same rule as everything
else. File CONTENTS are not read here; that is ``*_read``, one file at a
time, all three layers.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..config import get_config
from ..database import is_blocked
from ..errors import BlockedSourceError, FileReadError
from ..l1.pipeline import run_l1
from ..l1.shadows import ShadowStats, detect_module_shadows
from ..modes import Mode
from .judged import judge_and_deliver

MAX_DIR_ENTRIES = 500


def _entry(entry: os.DirEntry[str]) -> dict[str, Any]:
    if entry.is_symlink():
        kind = "symlink"
    elif entry.is_dir(follow_symlinks=False):
        kind = "dir"
    elif entry.is_file(follow_symlinks=False):
        kind = "file"
    else:
        kind = "other"
    size = entry.stat(follow_symlinks=False).st_size if kind == "file" else None
    return {"name": entry.name, "type": kind, "size": size}


async def _dir(path: str, mode: Mode, prompt: str | None = None) -> dict[str, Any]:
    resolved = str(Path(path).resolve())
    if not os.path.isdir(resolved):
        raise FileReadError(path, "Not a directory")
    with os.scandir(resolved) as it:
        found = list(it)
    if len(found) > MAX_DIR_ENTRIES:
        raise FileReadError(path, f"Too many entries ({len(found)}, max {MAX_DIR_ENTRIES})")
    entries = sorted((_entry(e) for e in found), key=lambda e: e["name"])

    blocked = is_blocked(resolved)
    if blocked and mode is not Mode.CLEAN:
        raise BlockedSourceError(resolved, blocked["detected_at"])

    listing = "\n".join(
        f"{e['name']}\t{e['type']}\t{e['size'] if e['size'] is not None else '-'}" for e in entries
    )
    shadows = detect_module_shadows(resolved)
    pipeline = run_l1(listing)
    pipeline.stats.shadows = ShadowStats.from_result(shadows)

    briefing = None
    if shadows.has_shadows:
        # Module names come from the stdlib list, not from the directory.
        modules = ", ".join(sorted({f.shadows_module for f in shadows.shadows_found}))
        briefing = (
            f"{len(shadows.shadows_found)} entr(ies) in this directory shadow "
            f"Python standard-library modules ({modules}). Python run from here "
            "would import them instead of the real modules."
        )

    shadow_fields = [
        {
            "file": f.filename,
            "shadows_module": f.shadows_module,
            "obfuscated": f.is_obfuscated,
        }
        for f in shadows.shadows_found
    ]
    return await judge_and_deliver(
        listing,
        mode=mode,
        family="dir",
        source=resolved,
        source_type="file",
        kind="dir",
        ref=resolved,
        prompt=prompt,
        allowlisted=get_config().is_trusted_path(resolved),
        blocklisted_at=blocked["detected_at"] if blocked else None,
        precomputed_l1=pipeline,
        l3_context=briefing,
        extras={"entries": entries, "shadows": shadow_fields},
    )


async def block_dir(path: str) -> dict[str, Any]:
    """Refuse a flagged or shadowed directory; otherwise its listing."""
    return await _dir(path, Mode.BLOCK)


async def warn_dir(path: str) -> dict[str, Any]:
    """The listing, with the verdict attached when there is one."""
    return await _dir(path, Mode.WARN)


async def clean_dir(path: str, prompt: str) -> dict[str, Any]:
    """A verified L3 extraction of the listing, never the names themselves."""
    return await _dir(path, Mode.CLEAN, prompt)
