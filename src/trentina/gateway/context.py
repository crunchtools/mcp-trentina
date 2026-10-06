"""Request context for threading profile information to internal tools.

Uses contextvars to propagate the authenticated profile from the gateway's
tool dispatch layer down to the quarantine system's provider selection. This
allows per-profile API keys and model overrides to work for internal://
tool calls without changing the MCP protocol or tool signatures.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..modes import ModePolicy
    from ..preprocess.policy import PreProcessPolicy
    from .profile import Profile

_current_profile: ContextVar[Profile | None] = ContextVar("current_profile", default=None)
_current_policy: ContextVar[ModePolicy | None] = ContextVar("current_mode_policy", default=None)
_current_preprocess: ContextVar[PreProcessPolicy | None] = ContextVar(
    "current_preprocess_policy", default=None
)


@contextmanager
def profile_context(
    profile: Profile,
    policy: ModePolicy | None = None,
    preprocess: PreProcessPolicy | None = None,
) -> Iterator[None]:
    """Bind ``profile`` to the current async context for the duration of the block.

    Used by the gateway around internal:// tool dispatch. Restoring the
    previous value on exit is what keeps a profile from leaking into a
    reused async task, including when the tool call raises. ``policy`` is
    the call's mode policy (#193): what a web tool's refusal offers.
    ``preprocess`` is the tool's pre-processor policy (#183), which the tool
    resolves against its own default.
    """
    token = _current_profile.set(profile)
    policy_token = _current_policy.set(policy)
    preprocess_token = _current_preprocess.set(preprocess)
    try:
        yield
    finally:
        _current_preprocess.reset(preprocess_token)
        _current_policy.reset(policy_token)
        _current_profile.reset(token)


def get_current_policy() -> ModePolicy | None:
    """The mode policy the gateway bound for this call, or None standalone."""
    return _current_policy.get()


def get_current_preprocess_policy() -> PreProcessPolicy | None:
    """The pre-processor policy the gateway bound for this call, or None standalone."""
    return _current_preprocess.get()


def get_current_profile() -> Profile | None:
    """Get the profile for the current async context.

    Returns None when called outside gateway context (e.g., standalone
    MCP server mode, tests).
    """
    return _current_profile.get()
