"""Tests for gateway/app.py — Starlette routes end-to-end."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from mcp_trentina_crunchtools.gateway.app import OAuthContext, gateway_app
from mcp_trentina_crunchtools.gateway.backend import BackendCall
from mcp_trentina_crunchtools.gateway.profile import (
    AuthConfig,
    Backend,
    OAuthConfig,
    Profile,
)
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

    def test_get_without_auth_returns_401(self, client: TestClient) -> None:
        resp = client.get("/alice/mcp")
        assert resp.status_code == 401

    def test_delete_without_auth_returns_401(self, client: TestClient) -> None:
        resp = client.delete("/alice/mcp")
        assert resp.status_code == 401

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


class TestHealthEndpoint:
    """Liveness probe.

    During the 2026-08-22 incident the gateway spent ~90 minutes with a
    blocked event loop and there was no endpoint to detect it from. This
    route's value is that it is served at all: the handler runs on the loop,
    so a hang here means the loop is wedged.
    """

    def test_health_returns_ok(self, client: TestClient) -> None:
        resp = client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["profiles"] == 1
        assert body["classifier"] in {"loaded", "not-loaded", "failed"}

    def test_health_needs_no_auth(self, client: TestClient) -> None:
        """A probe that requires a per-profile token is useless to a monitor."""
        assert client.get("/health").status_code == 200

    def test_health_does_not_load_the_model(self, client: TestClient) -> None:
        with patch(
            "mcp_trentina_crunchtools.quarantine.classifier.is_classifier_available"
        ) as loader:
            assert client.get("/health").status_code == 200

        loader.assert_not_called()

    def test_health_does_not_shadow_a_profile_named_health(self) -> None:
        """/health is a fixed route; /{profile}/mcp still resolves separately."""
        resp = client_with_profile("health").post(
            "/health/mcp", json={"jsonrpc": "2.0", "id": 1}
        )
        assert resp.status_code == 401  # reached auth, not the health handler


def client_with_profile(name: str) -> TestClient:
    """Build a TestClient whose single profile has the given name."""
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="A"),
        backends={"mcp-slack": Backend(url="http://mcp-slack:8005/mcp")},
    )
    profile.auth.bearer_token = SecretStr("token")
    return TestClient(gateway_app({name: profile}))


class _StubAccessToken:
    def __init__(self, claims: dict[str, object]) -> None:
        self.claims = claims


class _StubProvider:
    """Fake OAuth provider: maps a presented token to a validated AccessToken."""

    def __init__(self, token_map: dict[str, _StubAccessToken | None]) -> None:
        self._token_map = token_map

    async def load_access_token(self, token: str) -> _StubAccessToken | None:
        return self._token_map.get(token)


OAUTH_BASE_URL = "https://mcp.example.com"


@pytest.fixture
def oauth_client() -> TestClient:
    """TestClient over a profile that accepts static bearer OR Google OAuth."""
    profile = Profile(
        name="gemini-app",
        auth=AuthConfig(bearer_token_env="A"),
        oauth=OAuthConfig(enabled=True, allowed_emails=["scott@example.com"]),
    )
    profile.auth.bearer_token = SecretStr("static-token")
    provider = _StubProvider({
        "good": _StubAccessToken({"email": "scott@example.com", "email_verified": True}),
        "wrong-user": _StubAccessToken({"email": "eve@evil.com", "email_verified": True}),
    })
    oauth = OAuthContext(provider=provider, base_url=OAUTH_BASE_URL)
    return TestClient(gateway_app({"gemini-app": profile}, oauth=oauth))


class TestGatewayOAuth:
    """OAuth-enabled profile: challenge, token accept/reject, discovery route."""

    def test_no_credential_challenges_401(self, oauth_client: TestClient) -> None:
        resp = oauth_client.post("/gemini-app/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401
        challenge = resp.headers.get("WWW-Authenticate", "")
        assert "resource_metadata=" in challenge
        assert (
            f"{OAUTH_BASE_URL}/.well-known/oauth-protected-resource"
            "/gateway/gemini-app/mcp" in challenge
        )

    def test_valid_oauth_token_accepted(self, oauth_client: TestClient) -> None:
        resp = oauth_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 5, "method": "ping"},
            headers={"Authorization": "Bearer good"},
        )
        assert resp.status_code == 200

    def test_wrong_user_forbidden_403(self, oauth_client: TestClient) -> None:
        resp = oauth_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer wrong-user"},
        )
        assert resp.status_code == 403

    def test_unknown_token_challenges_401(self, oauth_client: TestClient) -> None:
        resp = oauth_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer nonexistent"},
        )
        assert resp.status_code == 401
        assert "resource_metadata=" in resp.headers.get("WWW-Authenticate", "")

    def test_static_bearer_still_works_on_oauth_profile(
        self, oauth_client: TestClient
    ) -> None:
        resp = oauth_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 5, "method": "ping"},
            headers={"Authorization": "Bearer static-token"},
        )
        assert resp.status_code == 200

    def test_resource_metadata_document(self, oauth_client: TestClient) -> None:
        resp = oauth_client.get(
            "/.well-known/oauth-protected-resource/gateway/gemini-app/mcp"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["resource"] == f"{OAUTH_BASE_URL}/gateway/gemini-app/mcp"
        assert body["authorization_servers"] == [OAUTH_BASE_URL]
        assert body["bearer_methods_supported"] == ["header"]
        assert "openid" in body["scopes_supported"]

    def test_resource_metadata_unknown_profile_404(
        self, oauth_client: TestClient
    ) -> None:
        resp = oauth_client.get(
            "/.well-known/oauth-protected-resource/gateway/nope/mcp"
        )
        assert resp.status_code == 404


class TestGatewayOAuthDisabled:
    """Without an OAuth context, an OAuth-less profile is unchanged."""

    def test_static_profile_401_has_no_challenge(self) -> None:
        profile = Profile(name="alice", auth=AuthConfig(bearer_token_env="A"))
        profile.auth.bearer_token = SecretStr("alice-token")
        client = TestClient(gateway_app({"alice": profile}))
        resp = client.post("/alice/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401
        assert "WWW-Authenticate" not in resp.headers

    def test_resource_metadata_route_absent_without_oauth(self) -> None:
        # gateway_app always registers the route, but it 404s when no OAuth
        # context backs it — discovery is never served for a static gateway.
        profile = Profile(name="alice", auth=AuthConfig(bearer_token_env="A"))
        profile.auth.bearer_token = SecretStr("alice-token")
        client = TestClient(gateway_app({"alice": profile}))
        resp = client.get(
            "/.well-known/oauth-protected-resource/gateway/alice/mcp"
        )
        assert resp.status_code == 404
