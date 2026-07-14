"""Request context for threading profile information to internal tools.

Uses contextvars to propagate the authenticated profile from the gateway's
tool dispatch layer down to the quarantine system's provider selection. This
allows per-profile API keys and model overrides to work for internal://
tool calls without changing the MCP protocol or tool signatures.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .profile import Profile

_current_profile: ContextVar[Profile | None] = ContextVar(
    "current_profile", default=None
)


def set_current_profile(profile: Profile) -> None:
    """Set the profile for the current async context.

    Called by the gateway before dispatching to internal:// tools.
    """
    _current_profile.set(profile)


def get_current_profile() -> Profile | None:
    """Get the profile for the current async context.

    Returns None when called outside gateway context (e.g., standalone
    MCP server mode, tests).
    """
    return _current_profile.get()
