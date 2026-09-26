"""The three modes, and the one rule for a layer that could not finish.

Every content tool and the gateway judge with the same three layers; the mode
decides only what is delivered:

* ``block`` — a flagged verdict is refused; the agent never sees it.
* ``flag`` — the bytes as they arrived, with the verdict attached. A
  researcher's grant: almost never the right mode for an assistant, a coding
  agent or a swarm.
* ``redact`` — an L3 extraction, verified, instead of the original.

The names are OpenRouter's guardrail actions (#200); until 0.35.0 flag was
``warn`` and redact was ``clean``, and 0.36.0 removed the old names. redact is NOT
OpenRouter's span substitution: L2 and L3 give verdicts, not spans, so there
is nothing to substitute. The whole payload is rewritten through L3 instead.

Before 0.31.0 the modes ran different pipelines — redact spent L3 on
extraction and got no detection verdict, search never called L3 — and each
ingress decided on its own what to do about a layer that could not run. The
tools delivered through an L3 outage while the gateway refused; the tools
refused a truncated L2 scan while the gateway's flag raised on it. Those were
two answers to one question, so the question lives here once.

**block and redact require every layer to produce a verdict; flag does not.**
A layer that is ABSENT (no ONNX model, no provider) can be excused per layer
with ``TRENTINA_REQUIRE_L2`` / ``TRENTINA_REQUIRE_L3``. A layer that ran but
read only PART of the payload is never excused: that is the padding attack,
where the payload hides past the cap and the head reads clean.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from enum import Enum
from typing import TYPE_CHECKING, Any

from .config import canonical_mode, get_config
from .errors import ModeNotPermittedError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .defense import DefenseVerdict


class Mode(str, Enum):
    """What a caller does with a verdict. Never which layers run.

    Declared strictest first, OpenRouter's precedence: block > redact > flag.
    """

    BLOCK = "block"
    REDACT = "redact"
    FLAG = "flag"

    @classmethod
    def _missing_(cls, value: object) -> Mode | None:
        """``Mode("BLOCK")`` is BLOCK; see ``canonical_mode``."""
        if isinstance(value, str) and (name := canonical_mode(value)) != value:
            return cls(name)
        return None


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
        """Whether block and redact must refuse. flag never consults this."""
        config = get_config()
        return (
            self.l2_truncated
            or self.l3_truncated
            or (self.l2_unavailable and config.require_l2)
            or (self.l3_unavailable and config.require_l3)
        )

    @classmethod
    def of_warning(cls, warning: dict[str, Any]) -> Gaps:
        """A cached ``_trentina_warning``'s gaps.

        The gateway caches warnings, not verdicts. Each field is a boolean key
        of the same name in the warning, so a gap added later is read back
        without touching this; a key an older perimeter did not write reads
        as absent.
        """
        return cls(**{f.name: bool(warning.get(f.name)) for f in fields(cls)})

    def truncated_only(self) -> bool:
        """Every gap is a partial read, none an absent layer.

        The allowlist may send these to redact, which reads the whole payload
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


def refusal_reason(flagged_by: str | None, gaps: Gaps) -> str | None:
    """Why block or redact may not deliver the original, or None.

    The reason names layers and gaps only. It is ours, never the payload's.
    """
    if flagged_by is not None:
        return f"flagged by {flagged_by}"
    if not gaps.blocking():
        return None
    missing = [
        name
        for name, present in (
            ("L2 unavailable", gaps.l2_unavailable),
            ("L2 read only part of the payload", gaps.l2_truncated),
            ("L3 unavailable", gaps.l3_unavailable),
            ("L3 read only part of the payload", gaps.l3_truncated),
        )
        if present
    ]
    return "not fully judged: " + ", ".join(missing)


# The per-call mode (#193). The agent asks through `trentina_mode`; a POLICY
# decides whether it may. Under the gateway the policy is the calling
# profile's `defense.modes`, bound here around an internal tool call; a
# standalone server reads TRENTINA_MODE / TRENTINA_MODES.


@dataclass(frozen=True)
class ModePolicy:
    """Which modes a caller may use, and what an omitted mode means."""

    allowed: tuple[Mode, ...]
    default: Mode

    @classmethod
    def of(cls, allowed: Iterable[str], default: str) -> ModePolicy:
        return cls(tuple(Mode(m) for m in allowed), Mode(default))

    def resolve(self, requested: str | None) -> Mode:
        """The mode this call runs in. Omission resolves BEFORE the check.

        Checking the requested value and then defaulting would let an omitted
        mode skip the policy entirely — the parameter-guard trap, where a
        missing argument is simply not checked.
        """
        name = self.default.value if requested is None else canonical_mode(str(requested))
        allowed = [m.value for m in self.allowed]
        if name not in allowed:
            raise ModeNotPermittedError(name, allowed)
        return Mode(name)

    def alternatives(self, current: Mode, cause: str | None) -> list[str]:
        """What a refused call may try next, under this policy.

        Flagged content is offered redact and NEVER flag: "retry with flag"
        would be the gateway itself steering the agent to the verbatim bytes
        the attacker wanted delivered. flag in the policy is a grant for
        deliberate reading, not the gateway's retry path. Only a refusal for
        an unfinished read, with nothing found, may point at flag — redact
        refuses on the same gaps. Whatever is suggested is also what the
        blocklist lets through: redact proceeds on a blocklisted source.

        ``cause`` is ``"flagged"``, ``"gaps"``, or None for anything else.
        """
        candidates = {"flagged": [Mode.REDACT], "gaps": [Mode.FLAG]}.get(cause or "", [])
        return [m.value for m in candidates if m in self.allowed and m is not current]


def current_policy() -> ModePolicy:
    """The gateway's policy for this call, else the standalone one from the environment."""
    from .gateway.context import get_current_policy

    bound = get_current_policy()
    if bound is not None:
        return bound
    config = get_config()
    return ModePolicy.of(config.allowed_modes, config.default_mode)


def refusal_body(
    reason: str,
    mode: Mode,
    *,
    flagged_by: str | None = None,
    gaps: Gaps | None = None,
    policy: ModePolicy | None = None,
) -> dict[str, Any]:
    """The structured refusal: gateway-authored fields, no payload, no L3 prose."""
    gap_names = [name for name, present in asdict(gaps).items() if present] if gaps else []
    cause = "flagged" if flagged_by is not None else "gaps" if gap_names else None
    policy = policy or current_policy()
    body: dict[str, Any] = {
        "reason": reason,
        "mode": mode.value,
        "alternatives": policy.alternatives(mode, cause),
    }
    if flagged_by is not None:
        body["flagged_by"] = flagged_by
    if gap_names:
        body["gaps"] = gap_names
    return body
