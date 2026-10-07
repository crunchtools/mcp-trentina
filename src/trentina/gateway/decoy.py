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
from typing import TYPE_CHECKING, Any

from ..database import record_detection
from ..dbus_interface import emit_detection_event
from ..logsafe import exc_kind
from .context import current_call
from .profile import HONEYTOKEN_REF_RE

if TYPE_CHECKING:
    from .profile import Backend, DecoyTool, Profile

logger = logging.getLogger(__name__)

LAYER = "decoy"
"""What a trip's detection row and event are credited to, where a layer's name goes."""


def served_tools(backend: Backend) -> list[dict[str, Any]]:
    """A decoy backend's tool list, in the shape a real backend's arrives in."""
    return [
        {"name": name, "description": decoy.description, "inputSchema": decoy.input_schema}
        for name, decoy in backend.decoys.items()
    ]


def leaked_tokens(profile: Profile, sent: Any) -> list[str]:
    """The ids of the profile's honeytokens found anywhere in ``sent``.

    ``sent`` is a request's whole ``params``, whatever its shape: the check
    runs before the tool name is resolved or the arguments are known to be a
    mapping, because a hijacked agent reaching for a tool it was never given
    is the call most worth an alarm.
    """
    text = json.dumps(sent, ensure_ascii=False, default=str)
    return sorted(
        token
        for token, planted in profile.honeytokens.items()
        if planted.value is not None and planted.value.get_secret_value() in text
    )


def canned_result(profile: Profile, decoy: DecoyTool) -> dict[str, Any]:
    """What a call to ``decoy`` is answered with: its result text, with each
    ``{honeytoken:<id>}`` replaced by that planted value."""

    def planted_value(match: Any) -> str:
        secret = profile.honeytokens[match.group(1)].value
        return secret.get_secret_value() if secret is not None else str(match.group(0))

    text = HONEYTOKEN_REF_RE.sub(planted_value, decoy.result)
    return {"content": [{"type": "text", "text": text}], "isError": False}


def record_trip(profile: str, backend: str, tool: str, what: str) -> None:
    """A detection row and a live event for a trip. ``what`` is the kind of
    trip and the ids of any planted credentials, never a value.

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
        emit_detection_event(LAYER, source, "high", {"trip": what})
    except Exception as exc:
        logger.error("decoy: failed to record a trip profile=%s: %s", profile, exc_kind(exc))
