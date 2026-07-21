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

REASON_TTL_EXPIRED = "ttl_expired"
REASON_EVICTED = "evicted_max_sessions"
REASON_CLIENT_DELETE = "client_delete"
REASON_REGISTRY_RESET = "registry_reset"

TOMBSTONE_MAXSIZE = 512
"""How many ended sessions to remember so a later 404 can name its cause.
Without this a stale-session 404 is indistinguishable from a bad token or a
gateway restart, which is exactly the ambiguity that makes disconnects hard
to diagnose."""


@dataclass
class Session:
    """One active MCP session."""

    session_id: str
    profile_name: str
    created_at: float
    last_access: float


@dataclass
class Tombstone:
    """Why a session stopped existing, kept for post-mortem on the next 404."""

    session_id: str
    profile_name: str
    reason: str
    ended_at: float
    lifetime_seconds: float
    idle_seconds: float


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
    _tombstones: dict[str, Tombstone] = field(default_factory=dict)

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
            evicted_idle = time.monotonic() - oldest_time
            self._remove(oldest_id, REASON_EVICTED)
            profile_sessions = self._profile_index.get(profile_name, set())
            logger.warning(
                "sessions: EVICTED session=%s profile=%s — at max_sessions_per_profile"
                "=%d; victim was idle %.1fs. Raise gateway.max_sessions_per_profile "
                "in profiles.yaml if this is disconnecting live clients.",
                oldest_id[:8],
                profile_name,
                self.max_sessions_per_profile,
                evicted_idle,
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
            "sessions: created session=%s profile=%s (active=%d/%d, ttl=%.0fs) "
            "census=%s",
            session_id[:8],
            profile_name,
            len(self._profile_index.get(profile_name, set())),
            self.max_sessions_per_profile,
            self.session_ttl,
            self.census(),
        )
        return session_id

    def census(self) -> dict[str, int]:
        """Live session count per profile, for tracking accumulation over time."""
        return {
            pname: len(ids) for pname, ids in self._profile_index.items() if ids
        }

    def explain_missing(self, session_id: str) -> str:
        """Describe why ``session_id`` is not in the registry.

        Turns an otherwise opaque 404 into a cause: TTL expiry, eviction under
        the per-profile cap, an explicit client teardown, or a session this
        process never issued at all (typically a client that outlived a
        gateway restart).
        """
        tomb = self._tombstones.get(session_id)
        if tomb is None:
            return (
                "never issued by this gateway process — client predates a "
                "gateway restart, or is using a session from another process"
            )
        return (
            f"{tomb.reason} {time.monotonic() - tomb.ended_at:.1f}s ago "
            f"(profile={tomb.profile_name}, lived {tomb.lifetime_seconds:.1f}s, "
            f"idle {tomb.idle_seconds:.1f}s when it ended)"
        )

    def get_session(self, session_id: str) -> Session | None:
        """Look up a session by ID, returning None if expired or unknown."""
        self._expire_stale()
        session = self._sessions.get(session_id)
        if session is not None:
            session.last_access = time.monotonic()
        return session

    def delete_session(self, session_id: str) -> bool:
        """Explicitly tear down a session.  Returns True if it existed."""
        return self._remove(session_id, REASON_CLIENT_DELETE)

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
        for sid in list(self._sessions):
            self._remove(sid, REASON_REGISTRY_RESET)
        self._sessions.clear()
        self._profile_index.clear()
        self._subscribers.clear()
        self._tombstones.clear()

    def _remove(self, session_id: str, reason: str) -> bool:
        session = self._sessions.pop(session_id, None)
        self._subscribers.pop(session_id, None)
        if session is None:
            return False
        profile_set = self._profile_index.get(session.profile_name)
        if profile_set is not None:
            profile_set.discard(session_id)
            if not profile_set:
                del self._profile_index[session.profile_name]

        now = time.monotonic()
        self._tombstones[session_id] = Tombstone(
            session_id=session_id,
            profile_name=session.profile_name,
            reason=reason,
            ended_at=now,
            lifetime_seconds=now - session.created_at,
            idle_seconds=now - session.last_access,
        )
        while len(self._tombstones) > TOMBSTONE_MAXSIZE:
            self._tombstones.pop(next(iter(self._tombstones)))
        return True

    def _expire_stale(self) -> None:
        now = time.monotonic()
        expired = [
            (sid, now - s.last_access)
            for sid, s in self._sessions.items()
            if (now - s.last_access) > self.session_ttl
        ]
        for sid, idle in expired:
            profile_name = self._sessions[sid].profile_name
            self._remove(sid, REASON_TTL_EXPIRED)
            logger.info(
                "sessions: EXPIRED session=%s profile=%s — idle %.1fs > ttl %.0fs. "
                "Raise gateway.session_ttl_seconds in profiles.yaml if this is "
                "disconnecting idle clients. census=%s",
                sid[:8],
                profile_name,
                idle,
                self.session_ttl,
                self.census(),
            )


session_registry = SessionRegistry()
