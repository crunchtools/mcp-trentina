"""Tests for gateway/app.py — Starlette routes end-to-end."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr, ValidationError
from starlette.testclient import TestClient

from mcp_trentina_crunchtools.gateway.app import OAuthContext, gateway_app
from mcp_trentina_crunchtools.gateway.backend import BackendCall
from mcp_trentina_crunchtools.gateway.loader import GatewayConfig
from mcp_trentina_crunchtools.gateway.profile import (
    AuthConfig,
    Backend,
    OAuthConfig,
    Profile,
)
from mcp_trentina_crunchtools.gateway.router import NAMESPACE_SEP

if TYPE_CHECKING:
    from collections.abc import Iterator


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

    async def verify_token(self, token: str) -> _StubAccessToken | None:
        # Mirrors fastmcp's OAuthProvider.verify_token, which forwards to
        # load_access_token — the gateway calls only verify_token now.
        return await self.load_access_token(token)


OAUTH_BASE_URL = "https://mcp.example.com"
# The AS identifier FastMCP advertises as `issuer` — a bare origin rendered
# through pydantic AnyHttpUrl gains a trailing slash. The protected-resource
# metadata must name the AS with this exact string, not the slash-less base URL,
# or RFC 8414 §3.3 makes a strict client (gemini.google.com) reject the AS.
OAUTH_ISSUER = OAUTH_BASE_URL + "/"
# The provider's normalized scopes_supported — GoogleProvider expands the
# email/profile shorthands to their full googleapis URIs, and our
# protected-resource document must advertise this identical list so the two
# discovery docs never name different scope strings.
OAUTH_SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
)


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
    oauth = OAuthContext(
        provider=provider,
        base_url=OAUTH_BASE_URL,
        issuer=OAUTH_ISSUER,
        scopes=OAUTH_SCOPES,
    )
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
        # Regression: the AS identifier is the provider's exact `issuer` string
        # (trailing slash and all), not the slash-less base URL. A mismatch here
        # is what made gemini.google.com reject the metadata and report
        # "automatic registration failed".
        assert body["authorization_servers"] == [OAUTH_ISSUER]
        assert body["authorization_servers"] != [OAUTH_BASE_URL]
        assert body["bearer_methods_supported"] == ["header"]
        # Regression: advertise the provider's exact (normalized) scope list, not
        # the email/profile shorthand — the two discovery docs must agree or a
        # strict client requests a scope the AS rejects at authorization time.
        assert body["scopes_supported"] == list(OAUTH_SCOPES)
        assert "email" not in body["scopes_supported"]

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


class TestOAuthResourcePin:
    """_build_oauth_context pins the RFC 8707 resource to the gateway endpoint.

    FastMCP would otherwise derive it from the path it mounts its own MCP app
    at, which Trentina tombstones at a per-boot random /mcp-internal-<hex> —
    a URL no discovery document advertises, so a client's resource indicator
    never matched and /authorize failed with invalid_target. See CHANGELOG 0.8.3.
    """

    @staticmethod
    def _build(profiles: dict[str, Profile]) -> OAuthContext:
        from mcp_trentina_crunchtools import _build_oauth_context

        env = {
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID": "cid",
            "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET": "secret",
            "TRENTINA_OAUTH_BASE_URL": OAUTH_BASE_URL,
        }
        with patch.dict("os.environ", env, clear=False):
            ctx = _build_oauth_context(GatewayConfig(profiles=profiles))
        assert ctx is not None
        return ctx

    @staticmethod
    def _oauth_profile(name: str) -> Profile:
        return Profile(
            name=name,
            auth=AuthConfig(bearer_token_env="A"),
            oauth=OAuthConfig(enabled=True, allowed_emails=["scott@example.com"]),
        )

    def test_resource_url_is_the_gateway_endpoint(self) -> None:
        ctx = self._build({"gemini-app": self._oauth_profile("gemini-app")})
        ctx.provider.set_mcp_path("/mcp-internal-deadbeef")
        assert str(ctx.provider._resource_url) == (
            f"{OAUTH_BASE_URL}/gateway/gemini-app/mcp"
        )

    def test_internal_mount_path_is_not_appended(self) -> None:
        ctx = self._build({"gemini-app": self._oauth_profile("gemini-app")})
        ctx.provider.set_mcp_path("/mcp-internal-deadbeef")
        assert "mcp-internal" not in str(ctx.provider._resource_url)

    def test_jwt_audience_is_bound_to_the_pinned_resource(self) -> None:
        ctx = self._build({"gemini-app": self._oauth_profile("gemini-app")})
        ctx.provider.set_mcp_path("/mcp-internal-deadbeef")
        assert ctx.provider.jwt_issuer.audience == (
            f"{OAUTH_BASE_URL}/gateway/gemini-app/mcp"
        )

    def test_multiple_oauth_profiles_pin_the_first_sorted(self) -> None:
        ctx = self._build({
            "zulu-app": self._oauth_profile("zulu-app"),
            "gemini-app": self._oauth_profile("gemini-app"),
        })
        ctx.provider.set_mcp_path("/mcp-internal-deadbeef")
        assert str(ctx.provider._resource_url) == (
            f"{OAUTH_BASE_URL}/gateway/gemini-app/mcp"
        )

    def test_no_oauth_profile_builds_no_context(self) -> None:
        from mcp_trentina_crunchtools import _build_oauth_context

        profile = Profile(name="alice", auth=AuthConfig(bearer_token_env="A"))
        assert _build_oauth_context(GatewayConfig(profiles={"alice": profile})) is None


class TestProvisionedConfidentialClient:
    """Statically provisioned confidential clients (RT #1502).

    gemini.google.com Custom Apps offers only an MCP URL, a Client ID and a
    Client Secret: it discovers our AS from the URL and then authenticates to
    it with those credentials. A proxy advertising only `none` tells it the
    credentials are unusable, and it abandons the flow before calling /token.
    """

    CLIENT_ID = "375f3fdb-c322-41bc-8dc6-c2010a095f04"
    REDIRECT = "https://oauth-redirect.googleusercontent.com/r/user_bound_x"

    @staticmethod
    def _profile(**oauth_kwargs: Any) -> Profile:
        return Profile(
            name="gemini-app",
            auth=AuthConfig(bearer_token_env="A"),
            oauth=OAuthConfig(
                enabled=True,
                allowed_emails=["scott@example.com"],
                **oauth_kwargs,
            ),
        )

    def _provisioned_profile(self) -> Profile:
        return self._profile(
            client_id=self.CLIENT_ID,
            client_secret_env="GEMINI_APP_SECRET",
            client_redirect_uris=[self.REDIRECT],
        )

    def _build(self, profiles: dict[str, Profile]) -> OAuthContext:
        from mcp_trentina_crunchtools import _build_oauth_context
        from mcp_trentina_crunchtools.gateway.loader import _resolve_oauth_client_secret

        for name, profile in profiles.items():
            _resolve_oauth_client_secret(name, profile)

        env = {
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID": "cid",
            "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET": "upstream-secret",
            "TRENTINA_OAUTH_BASE_URL": OAUTH_BASE_URL,
        }
        with patch.dict("os.environ", env, clear=False):
            ctx = _build_oauth_context(GatewayConfig(profiles=profiles))
        assert ctx is not None
        return ctx

    @pytest.fixture(autouse=True)
    def _secret_env(self) -> Iterator[None]:
        with patch.dict("os.environ", {"GEMINI_APP_SECRET": "s3cr3t"}, clear=False):
            yield

    @pytest.fixture(autouse=True)
    def _clean_provisioned(self) -> Iterator[None]:
        """The provisioned map is a class attribute, so it outlives one test.

        _build_oauth_context defines the provider class on each call, but the
        map is reachable through any context built earlier in the session --
        clear it so a provisioned client from one test cannot satisfy another.
        """
        yield
        from mcp_trentina_crunchtools import _build_oauth_context

        env = {
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID": "cid",
            "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET": "upstream-secret",
            "TRENTINA_OAUTH_BASE_URL": OAUTH_BASE_URL,
        }
        bare = Profile(name="bare", auth=AuthConfig(bearer_token_env="A"))
        with patch.dict("os.environ", env, clear=False):
            _build_oauth_context(GatewayConfig(profiles={"bare": bare}))

    def test_provisioned_client_is_confidential(self) -> None:
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        client = ctx.provider.provisioned[self.CLIENT_ID]
        assert client.token_endpoint_auth_method == "client_secret_post"
        assert client.client_secret == "s3cr3t"

    @pytest.mark.asyncio
    async def test_get_client_resolves_provisioned_ahead_of_store(self) -> None:
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        client = await ctx.provider.get_client(self.CLIENT_ID)
        assert client is not None
        assert client.client_secret == "s3cr3t"

    def test_redirect_uris_are_registered_verbatim(self) -> None:
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        client = ctx.provider.provisioned[self.CLIENT_ID]
        assert [str(u) for u in client.redirect_uris] == [self.REDIRECT]
        assert client.allowed_redirect_uri_patterns == [self.REDIRECT]

    def test_no_provisioned_client_leaves_the_map_empty(self) -> None:
        ctx = self._build({"gemini-app": self._profile()})
        assert ctx.provider.provisioned == {}

    def test_half_declared_client_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="client_secret_env"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["scott@example.com"],
                client_id=self.CLIENT_ID,
                client_redirect_uris=[self.REDIRECT],
            )

    def test_provisioned_client_requires_oauth_enabled(self) -> None:
        with pytest.raises(ValidationError, match=r"requires oauth\.enabled"):
            OAuthConfig(
                enabled=False,
                client_id=self.CLIENT_ID,
                client_secret_env="GEMINI_APP_SECRET",
                client_redirect_uris=[self.REDIRECT],
            )

    def test_lowercase_secret_env_name_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="UPPERCASE"):
            OAuthConfig(
                enabled=True,
                allowed_emails=["scott@example.com"],
                client_id=self.CLIENT_ID,
                client_secret_env="gemini_app_secret",
                client_redirect_uris=[self.REDIRECT],
            )

    def test_unset_secret_env_fails_closed(self) -> None:
        from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
        from mcp_trentina_crunchtools.gateway.loader import _resolve_oauth_client_secret

        profile = self._provisioned_profile()
        with (
            patch.dict("os.environ", {"GEMINI_APP_SECRET": ""}, clear=False),
            pytest.raises(ProfileConfigError),
        ):
            _resolve_oauth_client_secret("gemini-app", profile)

    @staticmethod
    def _metadata_document(ctx: OAuthContext) -> dict[str, Any]:
        """Render the AS metadata document the provider's routes actually serve."""
        from starlette.applications import Starlette
        from starlette.testclient import TestClient as _TestClient

        routes = ctx.provider.get_routes("/mcp-internal-deadbeef")
        app = Starlette(routes=list(routes))
        resp = _TestClient(app).get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        return dict(resp.json())

    def test_metadata_advertises_client_secret_post_when_provisioned(self) -> None:
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        document = self._metadata_document(ctx)
        methods: list[str] = document["token_endpoint_auth_methods_supported"]
        assert "client_secret_post" in methods

    def test_metadata_keeps_none_for_dcr_clients(self) -> None:
        """DCR-registered public clients must keep working alongside."""
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        document = self._metadata_document(ctx)
        methods: list[str] = document["token_endpoint_auth_methods_supported"]
        assert "none" in methods

    def test_metadata_advertises_secret_post_without_a_provisioned_client(self) -> None:
        """Advertised unconditionally since RT #1502's confidential DCR.

        A client reads this document BEFORE it registers and uses it to decide
        whether this server can issue the confidential registration it needs.
        Advertising only once a provisioned client exists would leave that
        client with nothing to go on, which is the state gemini.google.com was
        in when it gave up without sending a request.
        """
        ctx = self._build({"gemini-app": self._profile()})
        methods = self._metadata_document(ctx)[
            "token_endpoint_auth_methods_supported"
        ]
        assert methods == ["none", "client_secret_post"]

    def test_other_routes_are_untouched(self) -> None:
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        paths = {r.path for r in ctx.provider.get_routes("/mcp-internal-deadbeef")}
        assert "/token" in paths
        assert "/authorize" in paths

    def test_provisioned_client_carries_the_provider_scope(self) -> None:
        """Registering with no scope refuses every /authorize as invalid_scope.

        The SDK validates each requested scope against the client's registered
        scope. 0.9.0 registered provisioned clients with scope=None, so live
        /authorize returned
        `error=invalid_scope&error_description=Client was not registered with
        scope openid` and the flow died before consent. See CHANGELOG 0.9.1.
        """
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        client = ctx.provider.provisioned[self.CLIENT_ID]
        assert client.scope
        assert set(str(client.scope).split()) == set(ctx.scopes)

    def test_every_advertised_scope_is_registered_on_the_client(self) -> None:
        """A scope we advertise but did not register is refused at /authorize."""
        ctx = self._build({"gemini-app": self._provisioned_profile()})
        client = ctx.provider.provisioned[self.CLIENT_ID]
        registered = set(str(client.scope).split())
        assert "openid" in registered
        for advertised in ctx.scopes:
            assert advertised in registered


DELEGATED_ISSUER = "https://accounts.google.com"


class _StubVerifier:
    """Delegated verifier: verify_token only, no load_access_token.

    Deliberately missing the proxy method, so a code path that reaches for it
    fails loudly instead of quietly working in proxy mode alone.
    """

    def __init__(self, token_map: dict[str, _StubAccessToken | None]) -> None:
        self._token_map = token_map

    async def verify_token(self, token: str) -> _StubAccessToken | None:
        return self._token_map.get(token)


@pytest.fixture
def delegated_client() -> TestClient:
    """A gateway whose only OAuth profile delegates to Google."""
    from mcp_trentina_crunchtools.gateway.app import DelegatedAuth

    profile = Profile(
        name="gemini-app",
        auth=AuthConfig(bearer_token_env="A"),
        oauth=OAuthConfig(
            enabled=True,
            allowed_emails=["scott@example.com"],
            issuer=DELEGATED_ISSUER,
            audience_env="AUD_ENV",
        ),
    )
    profile.auth.bearer_token = SecretStr("static-token")
    verifier = _StubVerifier({
        "good": _StubAccessToken({"email": "scott@example.com", "email_verified": True}),
        "wrong-user": _StubAccessToken({"email": "eve@evil.com", "email_verified": True}),
    })
    oauth = OAuthContext(
        provider=None,
        base_url=OAUTH_BASE_URL,
        issuer=None,
        scopes=(),
        delegated={
            "gemini-app": DelegatedAuth(
                issuer=DELEGATED_ISSUER,
                scopes=("openid", "email", "profile"),
                verifier=verifier,
            )
        },
    )
    return TestClient(gateway_app({"gemini-app": profile}, oauth=oauth))


class TestDelegatedProfile:
    """A profile that names an external authorization server."""

    def test_metadata_advertises_the_external_issuer(
        self, delegated_client: TestClient
    ) -> None:
        resp = delegated_client.get(
            "/.well-known/oauth-protected-resource/gateway/gemini-app/mcp"
        )
        assert resp.status_code == 200
        assert resp.json()["authorization_servers"] == [DELEGATED_ISSUER]

    def test_advertised_issuer_has_no_trailing_slash(
        self, delegated_client: TestClient
    ) -> None:
        """Google publishes the bare origin; a client compares byte-for-byte."""
        resp = delegated_client.get(
            "/.well-known/oauth-protected-resource/gateway/gemini-app/mcp"
        )
        assert not resp.json()["authorization_servers"][0].endswith("/")

    def test_resource_is_still_ours(self, delegated_client: TestClient) -> None:
        resp = delegated_client.get(
            "/.well-known/oauth-protected-resource/gateway/gemini-app/mcp"
        )
        assert resp.json()["resource"] == f"{OAUTH_BASE_URL}/gateway/gemini-app/mcp"

    def test_valid_delegated_token_accepted(
        self, delegated_client: TestClient
    ) -> None:
        resp = delegated_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 1},
            headers={"authorization": "Bearer good"},
        )
        assert resp.status_code != 401

    def test_wrong_user_forbidden_403(self, delegated_client: TestClient) -> None:
        resp = delegated_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 1},
            headers={"authorization": "Bearer wrong-user"},
        )
        assert resp.status_code == 403

    def test_static_bearer_still_short_circuits(
        self, delegated_client: TestClient
    ) -> None:
        """It is checked before any outbound verification, so a delegated
        profile carries two independent credentials. Intended; documented."""
        resp = delegated_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 1},
            headers={"authorization": "Bearer static-token"},
        )
        assert resp.status_code != 401

    def test_challenge_still_points_at_our_metadata(
        self, delegated_client: TestClient
    ) -> None:
        """We are still the resource, even though Google is the AS."""
        resp = delegated_client.post("/gemini-app/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401
        assert OAUTH_BASE_URL in resp.headers["WWW-Authenticate"]


class TestChallengeErrorCode:
    """RFC 6750 §3.1 — an error code only when a credential was refused."""

    def test_no_error_code_when_no_credential_is_sent(
        self, oauth_client: TestClient
    ) -> None:
        """'SHOULD NOT include an error code' when the request lacks any
        authentication information — there is nothing yet to call invalid."""
        resp = oauth_client.post("/gemini-app/mcp", json={"jsonrpc": "2.0", "id": 1})
        assert resp.status_code == 401
        assert "error=" not in resp.headers["WWW-Authenticate"]

    def test_invalid_token_when_a_bearer_is_refused(
        self, oauth_client: TestClient
    ) -> None:
        resp = oauth_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 1},
            headers={"authorization": "Bearer nonsense"},
        )
        assert resp.status_code == 401
        assert 'error="invalid_token"' in resp.headers["WWW-Authenticate"]

    def test_resource_metadata_present_in_both_cases(
        self, oauth_client: TestClient
    ) -> None:
        bare = oauth_client.post("/gemini-app/mcp", json={"jsonrpc": "2.0", "id": 1})
        refused = oauth_client.post(
            "/gemini-app/mcp",
            json={"jsonrpc": "2.0", "id": 1},
            headers={"authorization": "Bearer nonsense"},
        )
        for resp in (bare, refused):
            assert "resource_metadata=" in resp.headers["WWW-Authenticate"]


class TestConfidentialDynamicRegistration:
    """DCR that issues a real client secret (RT #1502).

    FastMCP's OAuthProxy discards the secret the MCP SDK mints and rewrites
    every registration to ``token_endpoint_auth_method="none"``, reasoning that
    the proxy holds the upstream credentials and never checks a downstream one.

    gemini.google.com Custom Apps breaks that assumption: Google Account Linking
    authenticates at the token endpoint with a client id AND secret, so a
    registration answered with "you are public, here is no secret" does not
    satisfy what it asked for. It reported "automatic registration failed" and
    stopped — leaving nothing in our logs, because the flow ended before a
    single POST was sent.
    """

    REDIRECT = "https://oauth-redirect.googleusercontent.com/r/user_bound_x"
    SECRET = "0123456789abcdef" * 4

    def _provider(self) -> Any:
        from mcp_trentina_crunchtools import _build_oauth_context

        env = {
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID": "cid",
            "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET": "upstream-secret",
            "TRENTINA_OAUTH_BASE_URL": OAUTH_BASE_URL,
        }
        profile = Profile(
            name="gemini-app",
            auth=AuthConfig(bearer_token_env="A"),
            oauth=OAuthConfig(enabled=True, allowed_emails=["scott@example.com"]),
        )
        with patch.dict("os.environ", env, clear=False):
            ctx = _build_oauth_context(GatewayConfig(profiles={"gemini-app": profile}))
        assert ctx is not None
        return ctx.provider

    def _registration(self, *, method: str, secret: str | None) -> Any:
        """Build the object the SDK's RegistrationHandler hands register_client.

        The SDK defaults an omitted ``token_endpoint_auth_method`` to
        ``client_secret_post`` and mints ``secrets.token_hex(32)`` for anything
        that is not ``"none"``, so this is the shape that actually arrives.
        """
        from mcp.shared.auth import OAuthClientInformationFull

        return OAuthClientInformationFull.model_validate({
            "client_id": f"probe-{method}",
            "client_id_issued_at": 1790000000,
            "client_secret": secret,
            "client_secret_expires_at": 0 if secret else None,
            "redirect_uris": [self.REDIRECT],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
            "application_type": "web",
            "client_name": "probe",
        })

    @pytest.mark.asyncio
    async def test_the_secret_survives_registration(self) -> None:
        """The whole bug: this used to come back None."""
        provider = self._provider()
        info = self._registration(method="client_secret_post", secret=self.SECRET)
        await provider.register_client(info)
        assert info.client_secret == self.SECRET
        assert info.token_endpoint_auth_method == "client_secret_post"

    @pytest.mark.asyncio
    async def test_the_stored_client_is_the_confidential_one(self) -> None:
        """Advertising a secret we do not store would leave /token accepting
        anything — the record get_client returns is what the SDK's
        ClientAuthenticator actually compares against."""
        provider = self._provider()
        info = self._registration(method="client_secret_post", secret=self.SECRET)
        await provider.register_client(info)
        stored = await provider.get_client(info.client_id)
        assert stored is not None
        assert stored.client_secret == self.SECRET
        assert stored.token_endpoint_auth_method == "client_secret_post"

    @pytest.mark.asyncio
    async def test_a_public_registration_stays_public(self) -> None:
        """Claude Code and every other DCR client register with "none" and must
        keep the public client they already have."""
        provider = self._provider()
        info = self._registration(method="none", secret=None)
        await provider.register_client(info)
        assert info.client_secret is None
        assert info.token_endpoint_auth_method == "none"
        stored = await provider.get_client(info.client_id)
        assert stored.client_secret is None
        assert stored.token_endpoint_auth_method == "none"

    @pytest.mark.asyncio
    async def test_a_confidential_request_with_no_secret_is_not_upgraded(self) -> None:
        """Defensive: registering client_secret_post with nothing to compare
        against would enforce a secret of None, which is no enforcement."""
        provider = self._provider()
        info = self._registration(method="client_secret_post", secret=None)
        await provider.register_client(info)
        stored = await provider.get_client(info.client_id)
        assert stored.token_endpoint_auth_method == "none"
        assert stored.client_secret is None

    @pytest.mark.asyncio
    async def test_the_redirect_uri_survives(self) -> None:
        provider = self._provider()
        info = self._registration(method="client_secret_post", secret=self.SECRET)
        await provider.register_client(info)
        stored = await provider.get_client(info.client_id)
        assert [str(u) for u in stored.redirect_uris] == [self.REDIRECT]

    @pytest.mark.asyncio
    async def test_the_client_carries_a_scope(self) -> None:
        """A client registered without one has every /authorize refused as
        invalid_scope before consent — the 0.9.0 regression, in the DCR path."""
        provider = self._provider()
        info = self._registration(method="client_secret_post", secret=self.SECRET)
        info.scope = None
        await provider.register_client(info)
        stored = await provider.get_client(info.client_id)
        assert stored.scope
