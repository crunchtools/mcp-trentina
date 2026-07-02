"""Per-profile session registry for Streamable HTTP gateway.

Tracks active MCP sessions per consumer profile, enforces TTL and
max-sessions limits, and broadcasts notifications to all sessions
belonging to a specific profile.

Sessions are lightweight tracking objects — transport-level session
management is handled by the MCP framework.  This registry maps
profile names to their active session IDs so the gateway can broadcast
``notifications/tools/listChanged`` when a circuit breaker state change
affects a profile's tool list.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_SESSION_TTL = 300.0
DEFAULT_MAX_SESSIONS_PER_PROFILE = 10


@dataclass
class Session:
    """One active MCP session."""

    session_id: str
    profile_name: str
    created_at: float
    last_access: float


@dataclass
class SessionRegistry:
    """Track active sessions per profile, enforce limits, broadcast notifications."""

    session_ttl: float = DEFAULT_SESSION_TTL
    max_sessions_per_profile: int = DEFAULT_MAX_SESSIONS_PER_PROFILE
    _sessions: dict[str, Session] = field(default_factory=dict)
    _profile_index: dict[str, set[str]] = field(default_factory=dict)
    _notification_callback: Any = field(default=None)

    def set_notification_callback(self, callback: Any) -> None:
        """Register a callback for pushing notifications to transport sessions.

        The callback signature is:
            async def callback(session_id: str, notification: dict) -> None
        """
        self._notification_callback = callback

    def create_session(self, profile_name: str) -> str:
        """Create a new session for a profile.  Returns the session ID.

        Enforces max sessions per profile — evicts the oldest session
        if the limit would be exceeded.
        """
        self._expire_stale()

        profile_sessions = self._profile_index.get(profile_name, set())
        while len(profile_sessions) >= self.max_sessions_per_profile:
            oldest = self._oldest_session_for_profile(profile_name)
            if oldest is None:
                break
            self._remove(oldest)
            profile_sessions = self._profile_index.get(profile_name, set())
            logger.info(
                "sessions: evicted oldest session for profile=%s (limit=%d)",
                profile_name,
                self.max_sessions_per_profile,
            )

        now = time.monotonic()
        session_id = uuid.uuid4().hex
        session = Session(
            session_id=session_id,
            profile_name=profile_name,
            created_at=now,
            last_access=now,
        )
        self._sessions[session_id] = session
        self._profile_index.setdefault(profile_name, set()).add(session_id)

        logger.info(
            "sessions: created session=%s profile=%s (active=%d)",
            session_id[:8],
            profile_name,
            len(self._profile_index.get(profile_name, set())),
        )
        return session_id

    def get_session(self, session_id: str) -> Session | None:
        """Look up a session by ID, returning None if expired or unknown."""
        self._expire_stale()
        session = self._sessions.get(session_id)
        if session is not None:
            session.last_access = time.monotonic()
        return session

    def delete_session(self, session_id: str) -> bool:
        """Explicitly tear down a session.  Returns True if it existed."""
        return self._remove(session_id)

    def get_sessions_for_profile(self, profile_name: str) -> list[Session]:
        """Return all active sessions for a profile."""
        self._expire_stale()
        ids = self._profile_index.get(profile_name, set())
        return [self._sessions[sid] for sid in ids if sid in self._sessions]

    def profiles_for_backend_url(
        self, url: str, all_profiles: dict[str, Any]
    ) -> list[str]:
        """Return profile names whose backends include the given URL."""
        affected: list[str] = []
        for pname, profile in all_profiles.items():
            for backend in profile.backends.values():
                if not backend.is_internal and backend.url == url:
                    affected.append(pname)
                    break
        return affected

    async def broadcast_tools_changed(self, profile_name: str) -> int:
        """Push ``notifications/tools/listChanged`` to all sessions for a profile.

        Returns the number of sessions notified.
        """
        sessions = self.get_sessions_for_profile(profile_name)
        if not sessions:
            return 0

        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/listChanged",
        }

        notified = 0
        for session in sessions:
            if self._notification_callback is not None:
                try:
                    await self._notification_callback(
                        session.session_id, notification
                    )
                    notified += 1
                except Exception:
                    logger.warning(
                        "sessions: failed to notify session=%s",
                        session.session_id[:8],
                        exc_info=True,
                    )
        if notified:
            logger.info(
                "sessions: broadcast tools/listChanged to %d session(s) "
                "for profile=%s",
                notified,
                profile_name,
            )
        return notified

    @property
    def active_count(self) -> int:
        """Total number of active sessions across all profiles."""
        self._expire_stale()
        return len(self._sessions)

    def reset(self) -> None:
        """Clear all sessions (for testing)."""
        self._sessions.clear()
        self._profile_index.clear()

    def _remove(self, session_id: str) -> bool:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        profile_set = self._profile_index.get(session.profile_name)
        if profile_set is not None:
            profile_set.discard(session_id)
            if not profile_set:
                del self._profile_index[session.profile_name]
        return True

    def _expire_stale(self) -> None:
        now = time.monotonic()
        expired = [
            sid
            for sid, s in self._sessions.items()
            if (now - s.last_access) > self.session_ttl
        ]
        for sid in expired:
            self._remove(sid)
            logger.debug("sessions: expired session=%s", sid[:8])

    def _oldest_session_for_profile(self, profile_name: str) -> str | None:
        ids = self._profile_index.get(profile_name, set())
        oldest_id = None
        oldest_time = float("inf")
        for sid in ids:
            session = self._sessions.get(sid)
            if session is not None and session.last_access < oldest_time:
                oldest_time = session.last_access
                oldest_id = sid
        return oldest_id


session_registry = SessionRegistry()
