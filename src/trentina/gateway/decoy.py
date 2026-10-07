"""Decoy tools and planted credentials: alarms with no model behind them (#357).

A ``decoy://`` backend's tools are declared in the profile and answered by
nothing. An agent doing its job has no reason to call one, so a call is
evidence that something else is steering it. A honeytoken is a fake
credential planted where only an attacker's instructions lead; one appearing
in the arguments of any call, to any backend, is the same evidence.

Both checks are exact and deterministic: a tool name, a substring. Neither
reads the content that caused the call. The audit's ``session`` and
``call_ref`` columns are what lead back to that.

What this does not see: a planted credential the agent encoded, split or
paraphrased before sending it (``tests/test_coverage_gaps.py`` holds that
open), and anything an agent does without a tool call through the gateway.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..database import record_detection
from ..dbus_interface import emit_detection_event
from ..logsafe import exc_kind
from .context import current_call
from .profile import HONEYTOKEN_REF_RE

if TYPE_CHECKING:
    from .profile import Backend, Profile

logger = logging.getLogger(__name__)

LAYER = "decoy"
"""What a trip's detection row and event are credited to, where a layer's name goes."""


@dataclass(frozen=True)
class Trip:
    """One call that should not have happened.

    ``what`` goes in the audit row: the kind of trip and the ids of any
    planted credentials, never a value. ``result`` is what the caller is
    answered with; None refuses the call.
    """

    what: str
    result: dict[str, Any] | None


def served_tools(backend: Backend) -> list[dict[str, Any]]:
    """A decoy backend's tool list, in the shape a real backend's arrives in."""
    return [
        {"name": name, "description": decoy.description, "inputSchema": decoy.input_schema}
        for name, decoy in backend.decoys.items()
    ]


def trip_of(
    profile: Profile, backend: Backend, tool_name: str, arguments: dict[str, Any]
) -> Trip | None:
    """Whether this call is one, and what to answer it with.

    A call to a decoy tool is answered with the tool's canned result, so the
    caller carries on and what it does next is recorded too. A planted
    credential on its way to a real backend is refused: the backend is real,
    and so is wherever the arguments were pointed.
    """
    sent = json.dumps(arguments, ensure_ascii=False, default=str)
    leaked = sorted(
        token
        for token, planted in profile.honeytokens.items()
        if planted.value is not None and planted.value.get_secret_value() in sent
    )
    carried = f"honeytoken {', '.join(leaked)}" if leaked else ""
    decoy = backend.decoys.get(tool_name)
    if decoy is None:
        return Trip(carried, None) if leaked else None

    def planted_value(match: Any) -> str:
        secret = profile.honeytokens[match.group(1)].value
        return secret.get_secret_value() if secret is not None else str(match.group(0))

    text = HONEYTOKEN_REF_RE.sub(planted_value, decoy.result)
    result = {"content": [{"type": "text", "text": text}], "isError": False}
    return Trip(f"decoy tool, {carried}" if leaked else "decoy tool", result)


def record_trip(profile: str, backend: str, tool: str, trip: Trip) -> None:
    """A detection row and a live event for ``trip``.

    Never blocklisted: ``blocked`` keys the blocklist, which refuses a source
    on its next fetch, and a tool is not a source. A failed write is logged
    and the trip stands: the audit row is written separately.
    """
    source = f"{profile}:{backend}:{tool}"
    try:
        record_detection(
            source_type="decoy",
            source=source,
            domain=None,
            layer1_stats={},
            risk_level="high",
            profile=profile,
            backend=backend,
            tool=tool,
            direction="request",
            blocked=False,
            verdicts={"flagged_by": LAYER},
            call_ref=current_call.get() or None,
        )
        emit_detection_event(LAYER, source, "high", {"trip": trip.what})
    except Exception as exc:
        logger.error("decoy: failed to record a trip profile=%s: %s", profile, exc_kind(exc))
