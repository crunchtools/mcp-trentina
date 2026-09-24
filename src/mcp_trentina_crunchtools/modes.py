"""The three modes, and the one rule for a layer that could not finish.

Every content tool and the gateway judge with the same three layers; the mode
decides only what is delivered:

* ``block`` — a flagged verdict is refused; the agent never sees it.
* ``warn`` — the bytes as they arrived, with the verdict attached. A
  researcher's grant: almost never the right mode for an assistant, a coding
  agent or a swarm.
* ``clean`` — an L3 extraction, verified, instead of the original.

Before 0.31.0 the modes ran different pipelines — clean spent L3 on
extraction and got no detection verdict, search never called L3 — and each
ingress decided on its own what to do about a layer that could not run. The
tools delivered through an L3 outage while the gateway refused; the tools
refused a truncated L2 scan while the gateway's warn raised on it. Those were
two answers to one question, so the question lives here once.

**block and clean require every layer to produce a verdict; warn does not.**
A layer that is ABSENT (no ONNX model, no provider) can be excused per layer
with ``TRENTINA_REQUIRE_L2`` / ``TRENTINA_REQUIRE_L3``. A layer that ran but
read only PART of the payload is never excused: that is the padding attack,
where the payload hides past the cap and the head reads clean.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from typing import TYPE_CHECKING, Any

from .config import get_config

if TYPE_CHECKING:
    from .defense import DefenseVerdict


class Mode(str, Enum):
    """What a caller does with a verdict. Never which layers run."""

    BLOCK = "block"
    WARN = "warn"
    CLEAN = "clean"


@dataclass(frozen=True)
class Gaps:
    """What the layers could not do, as distinct from what they found."""

    l2_unavailable: bool = False
    l2_truncated: bool = False
    l3_unavailable: bool = False
    l3_truncated: bool = False

    def any(self) -> bool:
        return self.l2_unavailable or self.l2_truncated or self.l3_unavailable or self.l3_truncated

    def blocking(self) -> bool:
        """Whether block and clean must refuse. warn never consults this."""
        config = get_config()
        return (
            self.l2_truncated
            or self.l3_truncated
            or (self.l2_unavailable and config.require_l2)
            or (self.l3_unavailable and config.require_l3)
        )

    def truncated_only(self) -> bool:
        """Every gap is a partial read, none an absent layer.

        The allowlist may send these to clean, which reads the whole payload
        through L3's own cap; an absent layer it may not excuse.
        """
        return (self.l2_truncated or self.l3_truncated) and not (
            self.l2_unavailable or self.l3_unavailable
        )


def gaps_of(verdict: DefenseVerdict) -> Gaps:
    """The one derivation of a verdict's gaps. warning, report and gateway read it."""
    has_text = bool(verdict.pipeline.content.strip())
    assessment = verdict.l3_assessment
    classification = verdict.classification
    l2_truncated = verdict.l2_truncated or bool(
        classification is not None and classification.truncated
    )
    return Gaps(
        l2_unavailable=has_text and classification is None and not l2_truncated,
        l2_truncated=l2_truncated,
        l3_unavailable=bool(has_text and (assessment is None or assessment.get("l3_unavailable"))),
        l3_truncated=verdict.l3_truncated,
    )


def warning_blocks(warning: dict[str, Any]) -> bool:
    """Whether a cached ``_trentina_warning`` describes a blocking gap.

    The gateway caches warnings, not verdicts. Each ``Gaps`` field is a
    boolean key of the same name in the warning, so a gap added later is read
    back without touching this; a key an older perimeter did not write reads
    as absent.
    """
    gaps = Gaps(**{f.name: bool(warning.get(f.name)) for f in fields(Gaps)})
    return gaps.blocking()
