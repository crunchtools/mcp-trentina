"""Module shadow detection for Python directories.

Detects Python files that shadow standard library modules — a supply chain
attack vector where a local file with the same name as a stdlib module is
loaded instead of the real one.  See wunderwuzzi's Claude Code Opus 5 bypass
(2026-08-26) for a real-world exploit chain using struct.py shadowing.

The scan reads a directory through a descriptor the caller already holds
(#287): ``dir_tool`` lists through the fd confinement checked, and hands the
same entries here, so the listing delivered and the shadows found come from
one read of one directory. Each candidate is opened relative to that fd with
``O_NOFOLLOW`` and must be a regular file. A shadow that is a symlink is
still a shadow, since Python would import through it, but it is reported as
``symlink`` and never read: its target may be anywhere.
"""

from __future__ import annotations

import logging
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass, field
from itertools import islice
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

log = logging.getLogger(__name__)

STDLIB_MODULES: frozenset[str] = sys.stdlib_module_names

_EXEC_RE = re.compile(r"\b(?:exec|eval|compile)\s*\(")
_PROCESS_RE = re.compile(r"\b(?:subprocess|os\.system|os\.popen|os\.exec\w*|Popen)\b")
_DYNAMIC_IMPORT_RE = re.compile(r"\b__import__\s*\(")
_CHR_RE = re.compile(r"chr\s*\(\s*\d+\s*\)")
_INTERNAL_IMPORT_RE = re.compile(r"(?:from\s+_\w+\s+import|import\s+_\w+)")
_NETWORK_RE = re.compile(r"\b(?:socket|urllib|http\.client|requests|httpx)\b")
_OBFUSCATION_RE = re.compile(
    r"(?:"
    r"\\x[0-9a-fA-F]{2}"
    r"|b(?:64|85|16)decode"
    r"|a85decode"
    r"|join\s*\(\s*\[.{0,200}?chr"
    r"|getattr\s*\(.{0,200}?,\s*[\"']__"
    r"|codecs\.decode"
    r"|bytes\.fromhex"
    r")"
)

MAX_FILE_SIZE = 500_000
MAX_SCAN_BYTES = 4_000_000
"""Bytes read across one directory's shadows. Past it a shadow is still
reported, with an ``unscanned`` indicator, so the scan's cost is bounded
without a shadow going unreported."""
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
_DIR_FLAGS = _OPEN_FLAGS | os.O_DIRECTORY


@dataclass
class ShadowStats:
    """Stdlib-shadowing files in a directory, as L1 counts.

    Unlike every other stage this one reads a DIRECTORY, not text, so the
    ``dir`` producer runs it and merges the counts into the listing's L1 stats.
    Both counts are suspicious, and any shadow at all makes L1's risk
    ``critical``: one ``struct.py`` beside the code an agent is about to run is
    the whole attack, so there is no count below which it is merely medium.
    """

    files: int = 0
    obfuscated: int = 0

    @classmethod
    def from_result(cls, result: ShadowScanResult) -> ShadowStats:
        return cls(
            files=len(result.shadows_found),
            obfuscated=sum(1 for f in result.shadows_found if f.is_obfuscated),
        )


@dataclass
class ObfuscationIndicator:
    """A single obfuscation signal found in a file."""

    category: str
    description: str
    line_number: int | None = None


@dataclass
class ShadowFinding:
    """A Python file that shadows a standard library module."""

    filename: str
    shadows_module: str
    path: str
    obfuscation_indicators: list[ObfuscationIndicator] = field(default_factory=list)
    risk_level: str = "high"

    @property
    def is_obfuscated(self) -> bool:
        return len(self.obfuscation_indicators) > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "filename": self.filename,
            "shadows_module": self.shadows_module,
            "path": self.path,
            "risk_level": self.risk_level,
            "is_obfuscated": self.is_obfuscated,
            "obfuscation_indicators": [asdict(i) for i in self.obfuscation_indicators],
        }


@dataclass
class ShadowScanResult:
    """Result of scanning a directory for module shadows."""

    directory: str
    shadows_found: list[ShadowFinding] = field(default_factory=list)
    files_scanned: int = 0
    entries_read: int = 0
    """Directory entries looked at, so a caller that bounded the scan can tell
    whether the bound cut it short."""

    @property
    def risk_level(self) -> str:
        has_obfuscated = any(f.is_obfuscated for f in self.shadows_found)
        return "critical" if has_obfuscated else "high" if self.shadows_found else "low"

    @property
    def has_shadows(self) -> bool:
        return len(self.shadows_found) > 0

    def to_dict(self) -> dict[str, object]:
        return {
            "directory": self.directory,
            "files_scanned": self.files_scanned,
            "risk_level": self.risk_level,
            "has_shadows": self.has_shadows,
            "shadows": [s.to_dict() for s in self.shadows_found],
        }


def _scan_for_obfuscation(content: str) -> list[ObfuscationIndicator]:
    """Scan Python source for obfuscation indicators."""
    indicators: list[ObfuscationIndicator] = []

    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if _EXEC_RE.search(stripped):
            indicators.append(ObfuscationIndicator("code_execution", "exec/eval/compile call", i))

        if _PROCESS_RE.search(stripped):
            indicators.append(ObfuscationIndicator("process_spawn", "subprocess/os.system call", i))

        if _DYNAMIC_IMPORT_RE.search(stripped):
            indicators.append(ObfuscationIndicator("dynamic_import", "__import__ call", i))

        chr_matches = _CHR_RE.findall(stripped)
        if len(chr_matches) >= 3:
            indicators.append(
                ObfuscationIndicator(
                    "char_building", f"{len(chr_matches)} chr() calls on one line", i
                )
            )

        if _INTERNAL_IMPORT_RE.search(stripped):
            indicators.append(
                ObfuscationIndicator(
                    "internal_import",
                    "imports from internal (_) module — re-exports real API while adding payload",
                    i,
                )
            )

        if _NETWORK_RE.search(stripped):
            indicators.append(
                ObfuscationIndicator("network_access", "network library reference", i)
            )

        if _OBFUSCATION_RE.search(stripped):
            indicators.append(ObfuscationIndicator("obfuscation", "encoding/decoding pattern", i))

    return indicators


def _read_shadow(fd: int, budget: list[int]) -> list[ObfuscationIndicator]:
    """Obfuscation indicators for the open regular file ``fd``, within ``budget``."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        return [ObfuscationIndicator("unreadable", "shadow changed type while being read")]
    size = st.st_size
    if size > MAX_FILE_SIZE:
        return [ObfuscationIndicator("size", f"unusually large for a stdlib shadow ({size} bytes)")]
    if size > budget[0]:
        return [ObfuscationIndicator("unscanned", "directory's shadow read budget spent")]
    with open(fd, "rb", closefd=False) as fh:
        # One byte past the cap, so a file that grew after fstat is caught too.
        raw = fh.read(MAX_FILE_SIZE + 1)
    budget[0] -= len(raw)
    if len(raw) > MAX_FILE_SIZE:
        return [ObfuscationIndicator("size", "unusually large for a stdlib shadow")]
    if b"\x00" in raw:
        return [ObfuscationIndicator("binary", "shadow is not text")]
    return _scan_for_obfuscation(raw.decode("utf-8", errors="replace"))


def _scan_at(dir_fd: int, name: str, budget: list[int]) -> list[ObfuscationIndicator] | None:
    """Indicators for ``name`` in ``dir_fd``, or None when it is no importable file.

    Opened relative to the descriptor and never through a symlink. A
    symlink is reported without being read; a FIFO, device or directory is
    not a module Python would import, so it is not a shadow.
    """
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode):
        return [ObfuscationIndicator("symlink", "shadow is a symlink; its target was not read")]
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        # TRUST: opening a caller-placed file inside a confined directory
        #   untrusted: `name`, and the file's bytes, chosen by whoever writes the root
        #   judged-by: confine.open_confined admitted `dir_fd`; O_NOFOLLOW keeps the
        #     open in it, and _read_shadow refuses anything but a regular file
        #   on-failure: fail-closed; an unreadable shadow is still a critical shadow
        #   owner: tools/dir._list_confined, which holds `dir_fd`
        #   evidence: T1 os.open dir_fd and O_NOFOLLOW; T3 #287; T4 S_ISREG above
        fd = os.open(name, _OPEN_FLAGS, dir_fd=dir_fd)
    except OSError:
        return [ObfuscationIndicator("unreadable", "shadow file exists but cannot be read")]
    try:
        return _read_shadow(fd, budget)
    except OSError:
        return [ObfuscationIndicator("unreadable", "shadow file exists but cannot be read")]
    finally:
        os.close(fd)


def _record(
    result: ShadowScanResult, filename: str, module: str, indicators: list[ObfuscationIndicator]
) -> None:
    """Count the shadow ``filename`` of stdlib ``module`` into ``result``."""
    result.files_scanned += 1
    result.shadows_found.append(
        ShadowFinding(
            filename=filename,
            shadows_module=module,
            path=filename,
            obfuscation_indicators=indicators,
            risk_level="critical" if indicators else "high",
        )
    )


def scan_shadows(
    dir_fd: int, entries: Iterable[os.DirEntry[str]], directory: str
) -> ShadowScanResult:
    """Shadows among ``entries``, as listed from the open directory ``dir_fd``.

    The caller lists and passes the entries, so what it delivers and what
    is scanned are the same read. ``directory`` is a label only; nothing is
    opened by path. Blocking: run it in the thread that holds ``dir_fd``.
    """
    result = ShadowScanResult(directory=directory)
    budget = [MAX_SCAN_BYTES]
    for entry in entries:
        result.entries_read += 1
        _scan_entry(dir_fd, entry, result, budget)
    return result


def detect_module_shadows(directory: str, *, max_entries: int | None = None) -> ShadowScanResult:
    """Scan a directory named by path for Python files that shadow stdlib modules.

    NOT confined: for an operator's own path only. A tool handling a
    caller's path opens it through ``tools/confine.py`` and calls
    ``scan_shadows`` on that descriptor (#287).

    ``max_entries`` stops the scan after that many directory entries, lazily.
    """
    try:
        fd = os.open(directory, _DIR_FLAGS)
    except OSError:
        return ShadowScanResult(directory=directory)
    try:
        with os.scandir(fd) as it:
            return scan_shadows(fd, islice(it, max_entries), directory)
    finally:
        os.close(fd)


def _scan_entry(
    dir_fd: int, entry: os.DirEntry[str], result: ShadowScanResult, budget: list[int]
) -> None:
    """Record ``entry`` in ``result`` if it shadows a stdlib module."""
    name = entry.name
    if name.endswith(".py"):
        module_name = name[:-3]
        if module_name not in STDLIB_MODULES:
            result.files_scanned += entry.is_file(follow_symlinks=False)
            return
        indicators = _scan_at(dir_fd, name, budget)
        if indicators is not None:
            _record(result, name, module_name, indicators)
        return
    if name in STDLIB_MODULES:
        _scan_package(dir_fd, name, result, budget)


def _scan_package(dir_fd: int, name: str, result: ShadowScanResult, budget: list[int]) -> None:
    """A stdlib-named directory with an ``__init__.py`` is a package shadow."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        # Whether its target holds an __init__.py is a read through the link.
        _record(result, name, name, [ObfuscationIndicator("symlink", "stdlib-named symlink")])
        return
    if not stat.S_ISDIR(st.st_mode):
        return
    try:
        pkg_fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError:
        return
    try:
        indicators = _scan_at(pkg_fd, "__init__.py", budget)
    finally:
        os.close(pkg_fd)
    if indicators is not None:
        _record(result, f"{name}/__init__.py", name, indicators)
