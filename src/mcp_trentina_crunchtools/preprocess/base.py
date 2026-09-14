"""Pre-processor contract — token reduction OUTSIDE the security perimeter.

Trentina has two mandates: defend the primary model, and save it tokens.
They are served by two mechanisms in two places, deliberately:

* Pre-processors (this package) make payloads SMALLER. They run outside the
  perimeter, their output is exactly as untrusted as their input, and
  everything they emit crosses the defense pipeline on its way in.
* The defense pipeline (``defense.py``) makes verdicts. It never shrinks.

Three invariants, none negotiable:

1. A pre-processor never makes a security decision. It only reduces.
2. A pre-processor never bypasses ``defend()``. The composition layer hands
   back a reduced artifact; the caller scans THAT artifact and delivers THAT
   artifact. What reduction dropped never reaches the agent at all, which is
   what makes fingerprint-collision games pointless — colliding your payload
   into a collapsed group deletes it.
3. Every pre-processor accounts for itself. The sidecar (bytes in/out, ratio,
   what was collapsed) travels two places: the audit log, as evidence for the
   token mandate, and L3's briefing, because "this artifact is the 3% that
   survived reduction" is context a judge should have.

Pre-processors parse hostile bytes. Regexes here must be linear-time and
fingerprinting must cap the bytes it reads per line — an attacker choosing
the input must not be able to buy quadratic work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class Cost(str, Enum):
    """What running the processor spends.

    FREE is deterministic local compute. METERED calls an LLM — which is why
    the composition result tracks whether any METERED processor touched the
    payload: model output gets unconditional L3 (see ``defense.Provenance``),
    because a coerced summarizer emits exactly the fluent, syntax-free shape
    L2 is documented to miss.
    """

    FREE = "free"
    METERED = "metered"


@dataclass(frozen=True)
class PreProcessContext:
    """What the processor may know about the job. Not a policy channel."""

    source: str = ""
    # The size the caller is trying to get under, in bytes. None means
    # "smaller is better but nothing binds". auto-composition escalates to
    # METERED processors only while this is exceeded.
    target_bytes: int | None = None


@dataclass(frozen=True)
class PreProcessResult:
    """One processor's accounting — the sidecar, per invariant 3.

    ``applied`` is False when the processor looked and declined (content not
    log-shaped, reduction below its floor). Its ``content`` then echoes the
    input and downstream composition treats it as a no-op.
    """

    name: str
    cost: Cost
    content: str
    applied: bool
    bytes_in: int
    bytes_out: int
    # Processor-specific accounting: lines collapsed, groups formed, model
    # used, anything a human auditing token spend would want. Values stay
    # scalar so the whole thing serializes into an audit row.
    details: dict[str, int | float | str] = field(default_factory=dict)

    @property
    def ratio(self) -> float:
        """Output bytes per input byte. 1.0 means nothing happened."""
        if self.bytes_in == 0:
            return 1.0
        return self.bytes_out / self.bytes_in

    @classmethod
    def declined(
        cls,
        name: str,
        cost: Cost,
        payload: str,
        *,
        reason: str,
        details: dict[str, int | float | str] | None = None,
    ) -> PreProcessResult:
        """The no-op variant: the processor looked and passed the payload
        through unchanged. `reason` records why (too small, not log-shaped,
        worker error); downstream composition treats it as a skip."""
        size = len(payload.encode("utf-8"))
        merged: dict[str, int | float | str] = {"declined": reason}
        if details:
            merged.update(details)
        return cls(
            name=name,
            cost=cost,
            content=payload,
            applied=False,
            bytes_in=size,
            bytes_out=size,
            details=merged,
        )


@runtime_checkable
class PreProcessor(Protocol):
    """The shape of a pre-processor. Implementations are stateless."""

    name: str
    cost: Cost

    async def run(self, payload: str, ctx: PreProcessContext) -> PreProcessResult:
        """Reduce the payload. Must return the input unchanged (applied=False)
        rather than raise on content it cannot improve."""
        ...
