"""Tests for Streamable HTTP gateway features — circuit callbacks, app endpoints."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from mcp_trentina_crunchtools import _wire_circuit_notifications
from mcp_trentina_crunchtools.gateway.app import (
    MCP_SESSION_ID_HEADER,
    SSE_RETRY_MS,
    _sse_event_stream,
    gateway_app,
)
from mcp_trentina_crunchtools.gateway.circuit import CircuitBreaker, State
from mcp_trentina_crunchtools.gateway.profile import AuthConfig, Backend, Profile
from mcp_trentina_crunchtools.gateway.router import NAMESPACE_SEP
from mcp_trentina_crunchtools.gateway.sessions import SessionRegistry

TEST_TOKEN = "alice-token"


def _make_profile(name: str = "alice", token: str = TEST_TOKEN) -> Profile:
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="A"),
        backends={"mcp-slack": Backend(url="http://mcp-slack:8005/mcp")},
    )
    profile.auth.bearer_token = SecretStr(token)
    return profile


def _make_registry_and_client(
    session_ttl: float = 300.0,
) -> tuple[SessionRegistry, TestClient]:
    profile = _make_profile()
    sessions = SessionRegistry(session_ttl=session_ttl, max_sessions_per_profile=10)
    app = gateway_app({"alice": profile}, sessions=sessions)
    return sessions, TestClient(app)


AUTH = {"Authorization": "Bearer alice-token"}


class TestCircuitBreakerCallbacks:
    def test_callback_on_open(self) -> None:
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)
        changes: list[tuple[str, State, State]] = []
        cb.on_state_change(lambda url, old, new: changes.append((url, old, new)))

        cb.record_failure("http://test/mcp")
        assert changes == []

        cb.record_failure("http://test/mcp")
        assert len(changes) == 1
        assert changes[0] == ("http://test/mcp", State.CLOSED, State.OPEN)

    def test_callback_on_close_after_probe(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        changes: list[tuple[str, State, State]] = []
        cb.on_state_change(lambda url, old, new: changes.append((url, old, new)))

        cb.record_failure("http://test/mcp")
        changes.clear()

        cb.allow("http://test/mcp")
        assert any(s == State.HALF_OPEN for _, _, s in changes)

        changes.clear()
        cb.record_success("http://test/mcp")
        assert len(changes) == 1
        assert changes[0] == ("http://test/mcp", State.HALF_OPEN, State.CLOSED)

    def test_callback_on_reopen_after_failed_probe(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        changes: list[tuple[str, State, State]] = []
        cb.on_state_change(lambda url, old, new: changes.append((url, old, new)))

        cb.record_failure("http://test/mcp")
        cb.allow("http://test/mcp")
        changes.clear()

        cb.record_failure("http://test/mcp")
        assert len(changes) == 1
        assert changes[0] == ("http://test/mcp", State.HALF_OPEN, State.OPEN)

    def test_callback_exception_does_not_propagate(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.01)
        cb.on_state_change(lambda url, old, new: (_ for _ in ()).throw(RuntimeError("boom")))
        cb.record_failure("http://test/mcp")


class TestStreamableHTTPPost:
    def test_initialize_returns_session_id(self) -> None:
        sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        assert resp.status_code == 200
        session_id = resp.headers.get(MCP_SESSION_ID_HEADER)
        assert session_id is not None
        assert len(session_id) == 32
        assert sessions.active_count == 1

    def test_post_with_session_id_succeeds(self) -> None:
        _sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        session_id = resp.headers[MCP_SESSION_ID_HEADER]

        resp2 = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: session_id},
        )
        assert resp2.status_code == 200
        assert resp2.headers.get(MCP_SESSION_ID_HEADER) == session_id

    def test_post_with_expired_session_returns_404(self) -> None:
        _sessions, client = _make_registry_and_client(session_ttl=0.001)
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        session_id = resp.headers[MCP_SESSION_ID_HEADER]

        import time

        time.sleep(0.01)
        resp2 = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={**AUTH, MCP_SESSION_ID_HEADER: session_id},
        )
        assert resp2.status_code == 404

    def test_post_without_session_id_still_works(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers=AUTH,
        )
        assert resp.status_code == 200

    def test_post_with_wrong_profile_session_returns_403(self) -> None:
        bob = _make_profile(name="bob", token="bob-token")
        alice = _make_profile()
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        app = gateway_app({"alice": alice, "bob": bob}, sessions=sessions)
        client = TestClient(app)

        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={"Authorization": "Bearer alice-token"},
        )
        alice_session = resp.headers[MCP_SESSION_ID_HEADER]

        resp2 = client.post(
            "/bob/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={
                "Authorization": "Bearer bob-token",
                MCP_SESSION_ID_HEADER: alice_session,
            },
        )
        assert resp2.status_code == 403

    def test_initialize_advertises_list_changed(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        result = resp.json()["result"]
        assert result["capabilities"]["tools"]["listChanged"] is True

    def test_initialize_uses_2025_protocol(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        result = resp.json()["result"]
        assert result["protocolVersion"] == "2025-03-26"


class TestStreamableHTTPDelete:
    def test_delete_tears_down_session(self) -> None:
        sessions, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers=AUTH,
        )
        session_id = resp.headers[MCP_SESSION_ID_HEADER]

        resp2 = client.delete(
            "/alice/mcp",
            headers={**AUTH, MCP_SESSION_ID_HEADER: session_id},
        )
        assert resp2.status_code == 204
        assert sessions.active_count == 0

    def test_delete_without_session_returns_400(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.delete("/alice/mcp", headers=AUTH)
        assert resp.status_code == 400

    def test_delete_unknown_session_returns_404(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.delete(
            "/alice/mcp",
            headers={**AUTH, MCP_SESSION_ID_HEADER: "nonexistent"},
        )
        assert resp.status_code == 404

    def test_delete_without_auth_returns_401(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.delete(
            "/alice/mcp",
            headers={MCP_SESSION_ID_HEADER: "some-id"},
        )
        assert resp.status_code == 401


class TestStreamableHTTPGet:
    def test_get_without_session_returns_400(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.get("/alice/mcp", headers=AUTH)
        assert resp.status_code == 400

    def test_get_with_unknown_session_returns_404(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.get(
            "/alice/mcp",
            headers={**AUTH, MCP_SESSION_ID_HEADER: "nonexistent"},
        )
        assert resp.status_code == 404

    def test_get_without_auth_returns_401(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.get(
            "/alice/mcp",
            headers={MCP_SESSION_ID_HEADER: "some-id"},
        )
        assert resp.status_code == 401

    def test_get_with_valid_session_accepted(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")

        session = sessions.get_session(sid)
        assert session is not None
        assert session.profile_name == "alice"


class TestSSEEventStream:
    """The long-lived SSE stream that carries server-push notifications."""

    @pytest.mark.asyncio
    async def test_first_frame_is_retry_hint(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        try:
            first = await stream.__anext__()
            assert first == f"retry: {SSE_RETRY_MS}\n\n"
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_stream_subscribes_on_open(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        try:
            await stream.__anext__()  # retry frame; subscription is now live
            assert sessions.subscriber_count(sid) == 1
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_broadcast_delivers_message_frame(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        try:
            await stream.__anext__()  # drain retry frame, register subscription

            count = await sessions.broadcast_tools_changed("alice")
            assert count == 1

            frame = await stream.__anext__()
            assert frame.startswith("event: message\ndata: ")
            payload = json.loads(frame.split("data: ", 1)[1].strip())
            assert payload["method"] == "notifications/tools/listChanged"
            assert "event: endpoint" not in frame
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_keepalive_on_idle(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.01)
        try:
            await stream.__anext__()  # retry frame
            frame = await stream.__anext__()  # nothing queued → keepalive
            assert frame == ": keepalive\n\n"
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_stream_closes_when_session_removed(self) -> None:
        """An orphaned stream must terminate, not keepalive into the void."""
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.01)
        try:
            await stream.__anext__()  # retry frame
            assert await stream.__anext__() == ": keepalive\n\n"

            sessions.delete_session(sid)

            with pytest.raises(StopAsyncIteration):
                await stream.__anext__()
            assert sessions.subscriber_count(sid) == 0
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_stream_closes_when_session_expires(self) -> None:
        """TTL expiry reaches the stream too, not just explicit teardown."""
        sessions = SessionRegistry(session_ttl=0.02, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.05)
        try:
            await stream.__anext__()  # retry frame
            with pytest.raises(StopAsyncIteration):
                await stream.__anext__()
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_keepalive_does_not_extend_session_lifetime(self) -> None:
        """The liveness poll must not refresh last_access.

        If it did, any client holding an SSE stream would become immortal and
        TTL expiry could never fire for it.
        """
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        session = sessions.get_session(sid)
        assert session is not None
        before = session.last_access

        stream = _sse_event_stream(sessions, sid, keepalive_seconds=0.01)
        try:
            await stream.__anext__()  # retry frame
            await stream.__anext__()  # keepalive → liveness poll runs
            await stream.__anext__()  # and again
            assert session.last_access == before
        finally:
            await stream.aclose()

    @pytest.mark.asyncio
    async def test_close_unsubscribes(self) -> None:
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")
        stream = _sse_event_stream(sessions, sid, keepalive_seconds=5.0)
        await stream.__anext__()
        assert sessions.subscriber_count(sid) == 1
        await stream.aclose()
        assert sessions.subscriber_count(sid) == 0


class TestCircuitToSSEDelivery:
    """End-to-end: a circuit trip reaches a subscribed session's queue."""

    @pytest.mark.asyncio
    async def test_circuit_open_delivers_listchanged(self) -> None:
        backend_url = "http://mcp-slack:8005/mcp"
        profile = _make_profile()
        profiles = {"alice": profile}
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)

        _wire_circuit_notifications(cb, sessions, profiles)

        sid = sessions.create_session("alice")
        queue = sessions.subscribe(sid)

        cb.record_failure(backend_url)
        cb.record_failure(backend_url)

        for _ in range(50):
            if not queue.empty():
                break
            await asyncio.sleep(0.01)

        assert not queue.empty()
        notification = queue.get_nowait()
        assert notification["method"] == "notifications/tools/listChanged"

    @pytest.mark.asyncio
    async def test_unaffected_profile_not_notified(self) -> None:
        profile = _make_profile()  # backend http://mcp-slack:8005/mcp
        profiles = {"alice": profile}
        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.01)

        _wire_circuit_notifications(cb, sessions, profiles)

        sid = sessions.create_session("alice")
        queue = sessions.subscribe(sid)

        cb.record_failure("http://other:9000/mcp")
        cb.record_failure("http://other:9000/mcp")

        for _ in range(10):
            await asyncio.sleep(0.01)

        assert queue.empty()


class TestBackwardsCompatibility:
    """Phase 1 behaviour must still work for stateless POST clients."""

    def test_post_unknown_profile_404(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post("/missing/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 404

    def test_post_missing_auth_401(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post("/alice/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401

    def test_post_empty_body_400(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            content=b"",
            headers={**AUTH, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_post_invalid_json_400(self) -> None:
        _, client = _make_registry_and_client()
        resp = client.post(
            "/alice/mcp",
            content=b"{not json",
            headers={**AUTH, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_tools_call_dispatch(self) -> None:
        from unittest.mock import AsyncMock

        mock_route = AsyncMock(return_value={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
        })
        with patch(
            "mcp_trentina_crunchtools.gateway.app.route_jsonrpc",
            mock_route,
        ):
            _, client = _make_registry_and_client()
            resp = client.post(
                "/alice/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {},
                    },
                },
                headers=AUTH,
            )
            assert resp.status_code == 200
