"""Module shadow detection for Python directories.

Detects Python files that shadow standard library modules — a supply chain
attack vector where a local file with the same name as a stdlib module is
loaded instead of the real one.  See wunderwuzzi's Claude Code Opus 5 bypass
(2026-08-26) for a real-world exploit chain using struct.py shadowing.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

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
    r"|join\s*\(\s*\[.*?chr"
    r"|getattr\s*\(.*?,\s*[\"']__"
    r"|codecs\.decode"
    r"|bytes\.fromhex"
    r")"
)

MAX_FILE_SIZE = 500_000


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

    @property
    def risk_level(self) -> str:
        has_obfuscated = any(f.is_obfuscated for f in self.shadows_found)
        return (
            "critical" if has_obfuscated
            else "high" if self.shadows_found
            else "low"
        )

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
            indicators.append(ObfuscationIndicator(
                "code_execution", "exec/eval/compile call", i
            ))

        if _PROCESS_RE.search(stripped):
            indicators.append(ObfuscationIndicator(
                "process_spawn", "subprocess/os.system call", i
            ))

        if _DYNAMIC_IMPORT_RE.search(stripped):
            indicators.append(ObfuscationIndicator(
                "dynamic_import", "__import__ call", i
            ))

        chr_matches = _CHR_RE.findall(stripped)
        if len(chr_matches) >= 3:
            indicators.append(ObfuscationIndicator(
                "char_building", f"{len(chr_matches)} chr() calls on one line", i
            ))

        if _INTERNAL_IMPORT_RE.search(stripped):
            indicators.append(ObfuscationIndicator(
                "internal_import",
                "imports from internal (_) module — re-exports real API "
                "while adding payload",
                i,
            ))

        if _NETWORK_RE.search(stripped):
            indicators.append(ObfuscationIndicator(
                "network_access", "network library reference", i
            ))

        if _OBFUSCATION_RE.search(stripped):
            indicators.append(ObfuscationIndicator(
                "obfuscation", "encoding/decoding pattern", i
            ))

    return indicators


def _scan_shadow_file(
    filename: str, module_name: str, path: str
) -> ShadowFinding:
    """Scan a shadow file for obfuscation and return the finding."""
    indicators: list[ObfuscationIndicator] = []
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE_SIZE:
            indicators.append(ObfuscationIndicator(
                "size", f"unusually large for a stdlib shadow ({size} bytes)", None
            ))
        else:
            with open(path, encoding="utf-8", errors="replace") as fh:
                indicators = _scan_for_obfuscation(fh.read())
    except OSError:
        log.debug("Could not read shadow file %s", path)

    return ShadowFinding(
        filename=filename,
        shadows_module=module_name,
        path=path,
        obfuscation_indicators=indicators,
        risk_level="critical" if indicators else "high",
    )


def detect_module_shadows(directory: str) -> ShadowScanResult:
    """Scan a directory for Python files that shadow stdlib modules.

    Checks both file-based modules (struct.py) and package-based modules
    (struct/__init__.py).  For each shadow, scans the source for obfuscation
    indicators that suggest the shadow is weaponized.
    """
    resolved = str(Path(directory).resolve())
    result = ShadowScanResult(directory=resolved)

    if not os.path.isdir(resolved):
        return result

    for entry in os.scandir(resolved):
        if entry.is_file() and entry.name.endswith(".py"):
            result.files_scanned += 1
            module_name = entry.name[:-3]
            if module_name in STDLIB_MODULES:
                result.shadows_found.append(
                    _scan_shadow_file(entry.name, module_name, entry.path)
                )

        if entry.is_dir():
            init_path = os.path.join(entry.path, "__init__.py")
            if os.path.isfile(init_path) and entry.name in STDLIB_MODULES:
                result.files_scanned += 1
                result.shadows_found.append(
                    _scan_shadow_file(
                        f"{entry.name}/__init__.py", entry.name, init_path
                    )
                )

    return result
