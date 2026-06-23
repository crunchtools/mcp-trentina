"""Tests for gateway/app.py — Starlette routes end-to-end."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from mcp_trentina_crunchtools.gateway.app import gateway_app
from mcp_trentina_crunchtools.gateway.backend import BackendCall
from mcp_trentina_crunchtools.gateway.profile import AuthConfig, Backend, Profile
from mcp_trentina_crunchtools.gateway.router import NAMESPACE_SEP


@pytest.fixture
def client() -> TestClient:
    """Build a TestClient over a one-profile registry for endpoint-level tests."""
    profile = Profile(
        name="alice",
        auth=AuthConfig(bearer_token_env="A"),
        backends={"mcp-slack": Backend(url="http://mcp-slack:8005/mcp")},
    )
    profile.auth.bearer_token = SecretStr("alice-token")
    return TestClient(gateway_app({"alice": profile}))


class TestGatewayApp:
    """Endpoint behaviour across auth, body parsing, methods, and dispatch."""

    def test_post_unknown_profile_404(self, client: TestClient) -> None:
        resp = client.post("/missing/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 404

    def test_post_missing_auth_401(self, client: TestClient) -> None:
        resp = client.post("/alice/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401

    def test_post_wrong_token_401(self, client: TestClient) -> None:
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer wrong"},
        )
        assert resp.status_code == 401

    def test_get_returns_405(self, client: TestClient) -> None:
        resp = client.get("/alice/mcp")
        assert resp.status_code == 405

    def test_delete_returns_405(self, client: TestClient) -> None:
        resp = client.delete("/alice/mcp")
        assert resp.status_code == 405

    def test_empty_body_400(self, client: TestClient) -> None:
        resp = client.post(
            "/alice/mcp",
            content=b"",
            headers={
                "Authorization": "Bearer alice-token",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 400

    def test_invalid_json_400(self, client: TestClient) -> None:
        resp = client.post(
            "/alice/mcp",
            content=b"{not json",
            headers={
                "Authorization": "Bearer alice-token",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 400

    def test_non_object_body_400(self, client: TestClient) -> None:
        resp = client.post(
            "/alice/mcp",
            json=[1, 2, 3],
            headers={"Authorization": "Bearer alice-token"},
        )
        assert resp.status_code == 400

    def test_ping_authorized_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 5, "method": "ping"},
            headers={"Authorization": "Bearer alice-token"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"jsonrpc": "2.0", "id": 5, "result": {}}

    def test_initialize_authorized_returns_server_info(self, client: TestClient) -> None:
        resp = client.post(
            "/alice/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
            headers={"Authorization": "Bearer alice-token"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"]["serverInfo"]["name"] == "mcp-trentina-gateway:alice"

    def test_tools_call_invalid_backend_returns_jsonrpc_error(
        self, client: TestClient
    ) -> None:
        resp = client.post(
            "/alice/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": f"mcp-not-in-profile{NAMESPACE_SEP}whatever",
                    "arguments": {},
                },
            },
            headers={"Authorization": "Bearer alice-token"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["error"]["code"] == -32602

    def test_tools_call_happy_path_with_mocked_backend(self, client: TestClient) -> None:
        async def fake_call(*_args: object, **_kw: object) -> BackendCall:
            return BackendCall(
                content=[{"type": "text", "text": "channels: [#general]"}],
                is_error=False,
                structured_content=None,
            )

        with patch(
            "mcp_trentina_crunchtools.gateway.router.call_backend_tool",
            side_effect=fake_call,
        ):
            resp = client.post(
                "/alice/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {"limit": 5},
                    },
                },
                headers={"Authorization": "Bearer alice-token"},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["result"]["isError"] is False
        assert body["result"]["content"][0]["text"] == "channels: [#general]"
