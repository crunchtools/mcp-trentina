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

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_SESSION_TTL = 300.0
DEFAULT_MAX_SESSIONS_PER_PROFILE = 10

SUBSCRIBER_QUEUE_MAXSIZE = 32
"""Bound per subscriber queue so a stalled SSE reader can't grow memory
without limit. listChanged is idempotent, so dropping a frame on a full
queue is harmless — the client re-requests tools/list on the next one."""


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
    _subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = field(
        default_factory=dict
    )

    def set_notification_callback(self, callback: Any) -> None:
        """Register a callback for pushing notifications to transport sessions.

        Optional escape hatch for transports other than the built-in SSE GET
        stream (which delivers via :meth:`subscribe` queues).  When set, the
        callback is invoked in addition to any subscriber queues.  Signature:
            async def callback(session_id: str, notification: dict) -> None
        """
        self._notification_callback = callback

    def subscribe(self, session_id: str) -> asyncio.Queue[dict[str, Any]]:
        """Register an SSE stream's notification queue for a session.

        Returns a fresh bounded queue that :meth:`broadcast_tools_changed`
        pushes onto.  The GET SSE handler drains it and must call
        :meth:`unsubscribe` when the stream closes.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=SUBSCRIBER_QUEUE_MAXSIZE
        )
        self._subscribers.setdefault(session_id, set()).add(queue)
        return queue

    def unsubscribe(
        self, session_id: str, queue: asyncio.Queue[dict[str, Any]]
    ) -> None:
        """Deregister an SSE stream's queue (call on stream close/disconnect)."""
        subs = self._subscribers.get(session_id)
        if subs is None:
            return
        subs.discard(queue)
        if not subs:
            del self._subscribers[session_id]

    def subscriber_count(self, session_id: str) -> int:
        """Number of live SSE streams subscribed to a session (diagnostics/tests)."""
        return len(self._subscribers.get(session_id, ()))

    def create_session(self, profile_name: str) -> str:
        """Create a new session for a profile.  Returns the session ID.

        Enforces max sessions per profile — evicts the oldest session
        if the limit would be exceeded.
        """
        self._expire_stale()

        profile_sessions = self._profile_index.get(profile_name, set())
        while len(profile_sessions) >= self.max_sessions_per_profile:
            oldest_id: str | None = None
            oldest_time = float("inf")
            for sid in profile_sessions:
                s = self._sessions.get(sid)
                if s is not None and s.last_access < oldest_time:
                    oldest_time = s.last_access
                    oldest_id = sid
            if oldest_id is None:
                break
            self._remove(oldest_id)
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

        Delivers to each session's live SSE subscriber queues (the built-in
        transport) and, when set, to :attr:`_notification_callback`.  Returns
        the number of sessions that received at least one delivery.
        """
        sessions = self.get_sessions_for_profile(profile_name)
        if not sessions:
            return 0

        notification: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/listChanged",
        }

        notified = 0
        for session in sessions:
            delivered = False

            if self._notification_callback is not None:
                try:
                    await self._notification_callback(
                        session.session_id, notification
                    )
                    delivered = True
                except Exception:
                    logger.warning(
                        "sessions: failed to notify session=%s",
                        session.session_id[:8],
                        exc_info=True,
                    )

            for queue in list(self._subscribers.get(session.session_id, ())):
                try:
                    queue.put_nowait(dict(notification))
                    delivered = True
                except asyncio.QueueFull:
                    logger.warning(
                        "sessions: subscriber queue full, dropped "
                        "listChanged for session=%s",
                        session.session_id[:8],
                    )

            if delivered:
                notified += 1
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
        self._subscribers.clear()

    def _remove(self, session_id: str) -> bool:
        session = self._sessions.pop(session_id, None)
        self._subscribers.pop(session_id, None)
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


session_registry = SessionRegistry()
