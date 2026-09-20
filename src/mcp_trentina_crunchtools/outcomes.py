"""Outcome taxonomy for gateway audit rows.

A single ``success`` boolean cannot describe what happened to a tool call, and
reading one as a health signal actively misleads. ``safe_fetch`` and
``safe_read`` fail closed by design: when the defense pipeline blocks content
the tool *raises*, which under a boolean schema is indistinguishable from the
backend being down. An operator reading "2 ok / 34 errors" concludes the tool
is broken when the truth may be that it blocked 34 hostile pages.

The taxonomy splits three questions that the boolean collapsed into one:

- Did the call return content?           -> ``OK``
- Did *policy* stop it?                  -> the ``blocked`` group
- Did something *break*?                 -> the ``failed`` group

Only the ``failed`` group belongs in a health signal. The ``blocked`` group is
the gateway working as designed, and its rate is a security metric, not an
error rate.
"""

from __future__ import annotations

from enum import Enum

from .errors import (
    TrentinaError,
    BlockedSourceError,
    ConfigError,
    ContentSizeError,
    FetchError,
    FileReadError,
    QuarantineAgentError,
    SanitizationError,
    UnscannableContentError,
    UnsupportedContentTypeError,
)


class Outcome(str, Enum):
    """What actually happened to a ``tools/call`` invocation."""

    OK = "ok"
    """Backend returned content and did not flag it as an error."""

    TOOL_ERROR = "tool_error"
    """Backend completed but reported ``isError`` — a tool-level failure.

    Previously recorded as a *success*, because the router only inspected
    whether an exception was raised.
    """

    BLOCKED_DEFENSE = "blocked_defense"
    """L1/L2/L3 refused the content. The defense working, not a failure."""

    DENIED_ALLOWLIST = "denied_allowlist"
    """Tool is not permitted for this profile.

    Previously not recorded at all — the router returned before auditing.
    """

    DENIED_GUARD = "denied_guard"
    """A parameter guard rejected the arguments.

    Previously not recorded at all — the router returned before auditing.
    """

    BACKEND_ERROR = "backend_error"
    """Upstream failed: network, timeout, auth, malformed response."""

    GATEWAY_ERROR = "gateway_error"
    """Our own bug. The only outcome that should ever page anyone."""


BLOCKED_OUTCOMES: frozenset[Outcome] = frozenset(
    {Outcome.BLOCKED_DEFENSE, Outcome.DENIED_ALLOWLIST, Outcome.DENIED_GUARD}
)
"""Policy outcomes. The gateway did its job; nothing is broken."""

FAILED_OUTCOMES: frozenset[Outcome] = frozenset(
    {Outcome.TOOL_ERROR, Outcome.BACKEND_ERROR, Outcome.GATEWAY_ERROR}
)
"""Genuine failures. This is the health signal."""

_CLASSIFICATION: tuple[tuple[type[BaseException], Outcome], ...] = (
    (BlockedSourceError, Outcome.BLOCKED_DEFENSE),
    (UnscannableContentError, Outcome.BLOCKED_DEFENSE),
    (UnsupportedContentTypeError, Outcome.BLOCKED_DEFENSE),
    (ContentSizeError, Outcome.BLOCKED_DEFENSE),
    (FetchError, Outcome.BACKEND_ERROR),
    (FileReadError, Outcome.BACKEND_ERROR),
    (QuarantineAgentError, Outcome.BACKEND_ERROR),
    (ConfigError, Outcome.GATEWAY_ERROR),
    (SanitizationError, Outcome.GATEWAY_ERROR),
)
"""Exception type to outcome, ordered most-specific first.

The first isinstance match along the cause chain wins, so a subclass must
precede any broader entry. The three bands are, in order: defense refused the
content (fail-closed, working as designed), upstream broke, we broke.
"""


_MAX_CAUSE_DEPTH = 10


def classify_exception(exc: BaseException) -> Outcome:
    """Map a raised exception to an :class:`Outcome`.

    ``call_internal_tool`` wraps every tool exception in ``BackendCallError``
    but chains the original with ``raise ... from exc``, so the meaningful
    error is reachable through ``__cause__``. Without walking that chain every
    fail-closed block would look like a backend error.

    The ``__cause__`` walk is depth- and cycle-guarded: an exception chain that
    loops back on itself must never hang the audit path.

    A bare ``TrentinaError`` with no more specific subclass is still ours, so it
    falls through to ``GATEWAY_ERROR``. Anything else classifies as
    ``BACKEND_ERROR``: the overwhelming majority of unknowns originate
    upstream, and over-reporting our own bugs would make the one outcome that
    should page someone meaningless.
    """
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and len(chain) < _MAX_CAUSE_DEPTH:
        if id(current) in seen:
            break
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__

    for err in chain:
        for exc_type, outcome in _CLASSIFICATION:
            if isinstance(err, exc_type):
                return outcome
    if any(isinstance(err, TrentinaError) for err in chain):
        return Outcome.GATEWAY_ERROR
    return Outcome.BACKEND_ERROR


def group_of(outcome: str) -> str:
    """Bucket an outcome into ``ok`` / ``blocked`` / ``failed`` / ``unknown``.

    Accepts the raw string form so it can classify rows read back from SQLite,
    including legacy rows whose ``outcome`` is NULL.
    """
    try:
        parsed = Outcome(outcome)
    except ValueError:
        return "unknown"
    if parsed is Outcome.OK:
        return "ok"
    if parsed in BLOCKED_OUTCOMES:
        return "blocked"
    return "failed"
