"""The tool surface a profile is served, against what its backends offer.

What a client pays for tools/list, measured at the three points where the
gateway changes it: as each backend OFFERS its tools, as the allowlist
ALLOWS them, and as the gateway SERVES them after compression, compaction,
its own inserted params and short names. The difference between the first
and last is the context Trentina saves a client that loads the whole list —
which not every client does: Claude Code defers MCP tools and pays only for
names, Gemini web loads every schema up front.

In memory only. Recorded when a profile's aggregate is cached and dropped
when it is invalidated, so it always describes the list a client would get.
The boot warm-up rebuilds every profile, so a restart repopulates it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

# The same estimate get_compression_stats uses. A real tokenizer is
# per-model; this is for comparing sizes, not for billing.
BYTES_PER_TOKEN = 4

TOKEN_NOTE = (
    f"Tokens are estimated as bytes/{BYTES_PER_TOKEN}. Whether the surface costs "
    "context depends on the client: one that defers MCP tools pays for names only."
)


def wire_bytes(obj: Any) -> int:
    """UTF-8 length of *obj* as compact JSON: what it costs on the wire.

    The unit every size in the audit and the surface report is counted in.
    ``default=str`` because a size estimate must never fail a call.
    """
    return len(
        json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    )


@dataclass
class Stage:
    """A tool count and its wire size at one point in the build."""

    tools: int = 0
    bytes: int = 0

    @classmethod
    def of(cls, tools: list[dict[str, Any]]) -> Stage:
        """Count *tools* and size them as one compact JSON array."""
        return cls(len(tools), wire_bytes(tools))

    def as_dict(self) -> dict[str, int]:
        """``tools``, ``bytes``, and ``est_tokens`` (bytes / BYTES_PER_TOKEN)."""
        return {
            "tools": self.tools,
            "bytes": self.bytes,
            "est_tokens": self.bytes // BYTES_PER_TOKEN,
        }


@dataclass
class BackendSurface:
    """One backend's list: offered, allowed, and shaped (before short names)."""

    offered: Stage
    allowed: Stage
    shaped: Stage


@dataclass
class Surface:
    """A profile's whole aggregate, and each backend's part of it."""

    backends: dict[str, BackendSurface]
    served: Stage
    built_at: float = field(default_factory=time.time)

    def report(self) -> dict[str, Any]:
        """Totals at each stage, and what each step saved, in bytes and tokens."""
        offered = Stage(
            sum(b.offered.tools for b in self.backends.values()),
            sum(b.offered.bytes for b in self.backends.values()),
        )
        allowed = Stage(
            sum(b.allowed.tools for b in self.backends.values()),
            sum(b.allowed.bytes for b in self.backends.values()),
        )
        shaped = sum(b.shaped.bytes for b in self.backends.values())

        def saved(before: int, after: int) -> dict[str, int]:
            return {"bytes": before - after, "est_tokens": (before - after) // BYTES_PER_TOKEN}

        return {
            "offered": offered.as_dict(),
            "allowed": allowed.as_dict(),
            "served": self.served.as_dict(),
            "saved": {
                "by_allowlist": saved(offered.bytes, allowed.bytes),
                # Compression and compaction, net of the params the gateway
                # inserts — so this can be negative for a small backend.
                "by_shaping": saved(allowed.bytes, shaped),
                "by_short_names": saved(shaped, self.served.bytes),
                "total": saved(offered.bytes, self.served.bytes),
            },
            "percent_of_offered": round(100 * self.served.bytes / offered.bytes)
            if offered.bytes
            else 100,
            "by_backend": {
                # "shaped", not "served": short names are assigned across the
                # whole aggregate, so no backend has a served size of its own.
                name: {
                    "offered": b.offered.as_dict(),
                    "allowed": b.allowed.as_dict(),
                    "shaped": b.shaped.as_dict(),
                }
                for name, b in sorted(
                    self.backends.items(), key=lambda kv: kv[1].offered.bytes, reverse=True
                )
            },
            "built_at": self.built_at,
        }


_surfaces: dict[str, Surface] = {}


def record_surface(profile_name: str, surface: Surface) -> None:
    """Keep *surface* as the profile's, replacing any earlier build's."""
    _surfaces[profile_name] = surface


def forget_surface(profile_name: str) -> None:
    """Drop the profile's surface with its aggregate; absent is fine."""
    _surfaces.pop(profile_name, None)


def surface_report(profile_name: str) -> dict[str, Any] | None:
    """The profile's surface, or None when its aggregate is not built yet."""
    surface = _surfaces.get(profile_name)
    return surface.report() if surface is not None else None


def surface_profiles() -> list[str]:
    """Names of the profiles with a surface recorded, sorted."""
    return sorted(_surfaces)
