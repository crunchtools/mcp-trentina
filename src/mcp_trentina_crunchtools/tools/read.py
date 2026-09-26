"""Read tools — block_read, flag_read and redact_read."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..config import get_config
from ..database import is_blocked
from ..errors import FileReadError
from ..models import ALLOWED_TEXT_EXTENSIONS
from ..modes import Mode
from ..preprocess.policy import INTERNAL_DEFAULTS
from .judged import blocklisted, judge_and_deliver
from .preprocess import prepare

MAX_FILE_SIZE = 2_000_000
BINARY_CHECK_BYTES = 8192

_EXTENSIONLESS_ALLOWED = frozenset(
    {
        "makefile",
        "dockerfile",
        "containerfile",
        "readme",
        "license",
        "changelog",
        "authors",
        "contributors",
    }
)


def _validate_file(path: str) -> str:
    """Validate file path and return resolved absolute path."""
    resolved = str(Path(path).resolve())

    if not os.path.isfile(resolved):
        raise FileReadError(path, "File does not exist")

    file_size = os.path.getsize(resolved)
    if file_size > MAX_FILE_SIZE:
        raise FileReadError(path, f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")

    suffix = Path(resolved).suffix.lower()
    name_lower = Path(resolved).name.lower()

    if suffix and suffix not in ALLOWED_TEXT_EXTENSIONS:
        raise FileReadError(path, f"Binary or unsupported file type: {suffix}")

    if not suffix and name_lower not in _EXTENSIONLESS_ALLOWED:
        raise FileReadError(path, "Unknown file type (no extension)")

    with open(resolved, "rb") as fh:
        chunk = fh.read(BINARY_CHECK_BYTES)
        if b"\x00" in chunk:
            raise FileReadError(path, "Binary file detected")

    return resolved


async def read_file(
    path: str, mode: Mode, prompt: str | None = None, preprocess: Any = None
) -> dict[str, Any]:
    """Read one text file, then hand it to the one judging path.

    ``preprocess`` is the agent's ``trentina_preprocess``. Omitted, nothing
    runs but the policy's floor: an agent that reads a file usually means to
    edit it, and needs the bytes on disk. A list names what to run, within the
    bound policy (``preprocess/policy.py``); a name outside it raises
    ``PreProcessNotPermittedError``.
    """
    resolved = _validate_file(path)

    blocked = is_blocked(resolved)
    if blocked and mode is not Mode.REDACT:
        raise blocklisted(resolved, mode, blocked["detected_at"])

    with open(resolved, encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    page = await prepare(
        content, requested=preprocess, default=INTERNAL_DEFAULTS["read_tool"], source=resolved
    )
    return await judge_and_deliver(
        page.content,
        mode=mode,
        family="read",
        source=resolved,
        source_type="file",
        kind="file",
        ref=resolved,
        prompt=prompt,
        allowlisted=get_config().is_trusted_path(resolved),
        blocklisted_at=blocked["detected_at"] if blocked else None,
        provenance=page.provenance,
        precomputed_l1=page.pipeline,
        l3_context=page.briefing,
        extras=page.extras,
        redact_extras=page.extras,
    )


async def block_read(path: str) -> dict[str, Any]:
    """Refuse a flagged or incompletely judged file; otherwise the exact bytes."""
    return await read_file(path, Mode.BLOCK)


async def flag_read(path: str) -> dict[str, Any]:
    """The bytes on disk, with the verdict attached when there is one."""
    return await read_file(path, Mode.FLAG)


async def redact_read(path: str, prompt: str) -> dict[str, Any]:
    """A verified L3 extraction instead of the file."""
    return await read_file(path, Mode.REDACT, prompt)
