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

    from .profile import Profile

_current_profile: ContextVar[Profile | None] = ContextVar(
    "current_profile", default=None
)


@contextmanager
def profile_context(profile: Profile) -> Iterator[None]:
    """Bind ``profile`` to the current async context for the duration of the block.

    Used by the gateway around internal:// tool dispatch. Restoring the
    previous value on exit is what keeps a profile from leaking into a
    reused async task, including when the tool call raises.
    """
    token = _current_profile.set(profile)
    try:
        yield
    finally:
        _current_profile.reset(token)


def get_current_profile() -> Profile | None:
    """Get the profile for the current async context.

    Returns None when called outside gateway context (e.g., standalone
    MCP server mode, tests).
    """
    return _current_profile.get()
