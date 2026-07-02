"""Tests for Streamable HTTP gateway features — circuit callbacks, app endpoints."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from mcp_trentina_crunchtools.gateway.app import MCP_SESSION_ID_HEADER, gateway_app
from mcp_trentina_crunchtools.gateway.circuit import CircuitBreaker, State
from mcp_trentina_crunchtools.gateway.profile import AuthConfig, Backend, Profile
from mcp_trentina_crunchtools.gateway.router import NAMESPACE_SEP
from mcp_trentina_crunchtools.gateway.sessions import SessionRegistry


def _make_profile(name: str = "alice", token: str = "alice-token") -> Profile:  # noqa: S107
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

    @pytest.mark.asyncio
    async def test_get_with_valid_session_calls_handler(self) -> None:
        from mcp_trentina_crunchtools.gateway.app import _handle_get

        sessions = SessionRegistry(session_ttl=300.0, max_sessions_per_profile=10)
        sid = sessions.create_session("alice")

        profile = _make_profile()

        fake_request = type(
            "FakeRequest",
            (),
            {
                "path_params": {"profile": "alice"},
                "headers": {
                    "authorization": "Bearer alice-token",
                    "mcp-session-id": sid,
                },
            },
        )()

        resp = await _handle_get(
            fake_request,  # type: ignore[arg-type]
            {"alice": profile},
            sessions,
        )
        assert resp.status_code == 200
        assert resp.media_type == "text/event-stream"


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

    @patch("mcp_trentina_crunchtools.gateway.router.route_jsonrpc")
    def test_tools_call_dispatch(self, mock_route: object) -> None:
        from unittest.mock import AsyncMock

        mock_route_async = AsyncMock(return_value={  # type: ignore[assignment]
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}], "isError": False},
        })
        with patch(
            "mcp_trentina_crunchtools.gateway.app.route_jsonrpc",
            mock_route_async,
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
