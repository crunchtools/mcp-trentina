"""How the gateway decides which OAuth machinery to build (RT #1502).

Covers the split between proxy mode and delegated mode: which profiles get a
verifier, when a proxy is built at all, and the cross-profile audience rules
that a per-profile pydantic validator cannot see.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from mcp_trentina_crunchtools import _build_oauth_context
from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
from mcp_trentina_crunchtools.gateway.loader import GatewayConfig
from mcp_trentina_crunchtools.gateway.profile import (
    AuthConfig,
    OAuthConfig,
    Profile,
)

BASE_URL = "https://mcp.example.com"
GOOGLE = "https://accounts.google.com"
PROXY_CLIENT_ID = "proxy-client.apps.googleusercontent.com"
GEMINI_AUD = "gemini-client.apps.googleusercontent.com"
OTHER_AUD = "other-client.apps.googleusercontent.com"

PROXY_ENV = {
    "TRENTINA_OAUTH_GOOGLE_CLIENT_ID": PROXY_CLIENT_ID,
    "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET": "upstream-secret",
    "TRENTINA_OAUTH_BASE_URL": BASE_URL,
}
BARE_ENV = {"TRENTINA_OAUTH_BASE_URL": BASE_URL}


def _proxy_profile(name: str = "agent2") -> Profile:
    return Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="A"),
        oauth=OAuthConfig(enabled=True, allowed_emails=["alice@example.com"]),
    )


def _delegated_profile(name: str = "gemini-app", audience: str = GEMINI_AUD) -> Profile:
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="A"),
        oauth=OAuthConfig(
            enabled=True,
            allowed_emails=["alice@example.com"],
            issuer=GOOGLE,
            audience_env="AUD_ENV",
        ),
    )
    assert profile.oauth is not None
    profile.oauth.audience = audience  # the loader does this from the env
    return profile


def _build(profiles: dict[str, Profile], env: dict[str, str]):
    with patch.dict("os.environ", env, clear=False):
        return _build_oauth_context(GatewayConfig(profiles=profiles))


class TestDelegatedOnly:
    """A gateway where every OAuth profile delegates runs no AS of its own."""

    def test_no_proxy_is_built(self) -> None:
        ctx = _build({"gemini-app": _delegated_profile()}, BARE_ENV)
        assert ctx is not None
        assert ctx.provider is None
        assert ctx.issuer is None

    def test_upstream_google_credentials_are_not_required(self) -> None:
        """Nothing calls Google on our behalf, so demanding a client secret we
        would never use would block a perfectly valid deployment."""
        ctx = _build({"gemini-app": _delegated_profile()}, BARE_ENV)
        assert ctx is not None

    def test_the_profile_gets_a_verifier(self) -> None:
        ctx = _build({"gemini-app": _delegated_profile()}, BARE_ENV)
        assert ctx is not None
        assert ctx.verifier_for("gemini-app") is not None
        assert ctx.verifier_for("gemini-app").audience == GEMINI_AUD

    def test_metadata_advertises_the_external_issuer(self) -> None:
        ctx = _build({"gemini-app": _delegated_profile()}, BARE_ENV)
        assert ctx is not None
        advertised = ctx.metadata_for("gemini-app")
        assert advertised is not None
        assert advertised[0] == GOOGLE

    def test_a_proxy_profile_here_has_nothing_to_advertise(self) -> None:
        """metadata_for must return None rather than a null issuer."""
        ctx = _build({"gemini-app": _delegated_profile()}, BARE_ENV)
        assert ctx is not None
        assert ctx.metadata_for("some-proxy-profile") is None


class TestProxyStillRequiresCredentials:
    def test_proxy_profile_without_credentials_still_raises(self) -> None:
        with pytest.raises(ProfileConfigError, match="CLIENT_ID"):
            _build({"agent2": _proxy_profile()}, BARE_ENV)

    def test_mixed_mode_without_credentials_still_raises(self) -> None:
        """One proxied profile is enough to need the upstream credentials."""
        with pytest.raises(ProfileConfigError, match="CLIENT_ID"):
            _build(
                {"agent2": _proxy_profile(), "gemini-app": _delegated_profile()},
                BARE_ENV,
            )


class TestResourcePin:
    """The RFC 8707 pin is computed over PROXIED profiles only."""

    def test_delegated_profile_never_wins_the_pin(self) -> None:
        """'gemini-app' sorts before 'agent2'. Pinning the proxy's resource to a
        delegated profile would fail every proxy /authorize with
        invalid_target — the 0.8.3 outage, re-created for the profiles this
        change does not touch."""
        ctx = _build(
            {"agent2": _proxy_profile(), "gemini-app": _delegated_profile()},
            PROXY_ENV,
        )
        assert ctx is not None
        ctx.provider.set_mcp_path("/mcp-internal-deadbeef")
        assert str(ctx.provider._resource_url) == f"{BASE_URL}/gateway/agent2/mcp"


class TestAudienceUniqueness:
    """Cross-profile rules a per-profile validator cannot see."""

    def test_two_delegated_profiles_may_not_share_an_audience(self) -> None:
        """Sharing collapses both profiles' defence to their allowlists."""
        with pytest.raises(ProfileConfigError, match="already used by profile"):
            _build(
                {
                    "gemini-app": _delegated_profile("gemini-app", GEMINI_AUD),
                    "other-app": _delegated_profile("other-app", GEMINI_AUD),
                },
                BARE_ENV,
            )

    def test_distinct_audiences_are_fine(self) -> None:
        ctx = _build(
            {
                "gemini-app": _delegated_profile("gemini-app", GEMINI_AUD),
                "other-app": _delegated_profile("other-app", OTHER_AUD),
            },
            BARE_ENV,
        )
        assert ctx is not None
        assert len(ctx.delegated) == 2

    def test_audience_may_not_equal_the_proxy_client_id(self) -> None:
        """The proxy holds live upstream Google tokens carrying exactly that
        aud, so a profile pinned to it would accept every one of them."""
        with pytest.raises(ProfileConfigError, match="TRENTINA_OAUTH_GOOGLE_CLIENT_ID"):
            _build(
                {
                    "agent2": _proxy_profile(),
                    "gemini-app": _delegated_profile("gemini-app", PROXY_CLIENT_ID),
                },
                PROXY_ENV,
            )

    def test_unresolved_audience_is_refused(self) -> None:
        """The loader failing closed is the first line; this is the second."""
        profile = _delegated_profile()
        assert profile.oauth is not None
        profile.oauth.audience = None
        with pytest.raises(ProfileConfigError, match="did not resolve"):
            _build({"gemini-app": profile}, BARE_ENV)


class TestMixedMode:
    def test_each_profile_advertises_its_own_authorization_server(self) -> None:
        """The whole point of the per-profile map."""
        ctx = _build(
            {"agent2": _proxy_profile(), "gemini-app": _delegated_profile()},
            PROXY_ENV,
        )
        assert ctx is not None
        delegated = ctx.metadata_for("gemini-app")
        proxied = ctx.metadata_for("agent2")
        assert delegated is not None and proxied is not None
        assert delegated[0] == GOOGLE
        assert proxied[0].startswith(BASE_URL)
        assert delegated[0] != proxied[0]

    def test_each_profile_gets_its_own_verifier(self) -> None:
        ctx = _build(
            {"agent2": _proxy_profile(), "gemini-app": _delegated_profile()},
            PROXY_ENV,
        )
        assert ctx is not None
        assert ctx.verifier_for("gemini-app") is not ctx.provider
        assert ctx.verifier_for("agent2") is ctx.provider

    def test_provisioned_clients_skip_delegated_profiles(self) -> None:
        ctx = _build(
            {"agent2": _proxy_profile(), "gemini-app": _delegated_profile()},
            PROXY_ENV,
        )
        assert ctx is not None
        assert ctx.provider.provisioned == {}


class TestStartupLogsCarryNoSecrets:
    """CodeQL flags the startup log calls as clear-text logging of sensitive
    data, with no dataflow path — a name-based heuristic firing because these
    functions also hold `client_secret` locals.

    Reading the code is not a guarantee, so the property is pinned here: build
    a context both ways with recognisable secrets in the environment and assert
    none of them reaches a log record. If someone later adds a secret to one of
    those lines, this fails.
    """

    UPSTREAM_SECRET = "upstream-secret-must-not-be-logged"
    SIGNING_KEY = "signing-key-must-not-be-logged"
    BEARER = "bearer-must-not-be-logged"

    def _env(self, **extra: str) -> dict[str, str]:
        return {
            "TRENTINA_OAUTH_GOOGLE_CLIENT_ID": PROXY_CLIENT_ID,
            "TRENTINA_OAUTH_GOOGLE_CLIENT_SECRET": self.UPSTREAM_SECRET,
            "TRENTINA_OAUTH_JWT_SIGNING_KEY": self.SIGNING_KEY,
            "TRENTINA_OAUTH_BASE_URL": BASE_URL,
            **extra,
        }

    def _secrets(self) -> list[str]:
        return [self.UPSTREAM_SECRET, self.SIGNING_KEY, self.BEARER]

    def test_proxy_startup_logs_no_secret(self, caplog: pytest.LogCaptureFixture) -> None:
        profile = _proxy_profile()
        profile.auth.bearer_token = SecretStr(self.BEARER)
        with caplog.at_level("DEBUG"):
            ctx = _build({"agent2": profile}, self._env())
            assert ctx is not None
            ctx.provider.set_mcp_path("/mcp-internal-deadbeef")
        for secret in self._secrets():
            assert secret not in caplog.text

    def test_delegated_startup_logs_no_secret(self, caplog: pytest.LogCaptureFixture) -> None:
        profile = _delegated_profile()
        profile.auth.bearer_token = SecretStr(self.BEARER)
        with caplog.at_level("DEBUG"):
            assert _build({"gemini-app": profile}, self._env()) is not None
        for secret in self._secrets():
            assert secret not in caplog.text

    def test_mixed_startup_logs_no_secret(self, caplog: pytest.LogCaptureFixture) -> None:
        """Exercises the multi-proxy warning and the operator-role warning too."""
        proxy_a = _proxy_profile("agent2")
        proxy_b = _proxy_profile("agent1")
        delegated = _delegated_profile()
        for p in (proxy_a, proxy_b, delegated):
            p.auth.bearer_token = SecretStr(self.BEARER)
        with caplog.at_level("DEBUG"):
            ctx = _build(
                {"agent2": proxy_a, "agent1": proxy_b, "gemini-app": delegated},
                self._env(),
            )
            assert ctx is not None
            ctx.provider.set_mcp_path("/mcp-internal-deadbeef")
        for secret in self._secrets():
            assert secret not in caplog.text

    def test_divergent_allowlist_warning_logs_no_secret(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The 0.14.0 warning path. CodeQL flags its logger call as clear-text
        logging of a password because the `profiles` mapping — which holds
        every bearer token and client secret — is a parameter of the function
        that logs. Only `sorted(proxied)`, a list of profile names, is passed
        to the logger. Pinned here so that stays true."""
        a = _proxy_profile("claude-web")
        b = _proxy_profile("gemini-web")
        a.auth.bearer_token = SecretStr(self.BEARER)
        b.auth.bearer_token = SecretStr(self.BEARER)
        assert b.oauth is not None
        b.oauth.allowed_emails = ["someone-else@example.com"]

        with caplog.at_level("DEBUG"):
            ctx = _build({"claude-web": a, "gemini-web": b}, self._env())
            assert ctx is not None
            ctx.provider.set_mcp_path("/mcp-internal-deadbeef")

        # The warning must actually have fired, or this proves nothing.
        assert "different allowed_emails" in caplog.text
        for secret in self._secrets():
            assert secret not in caplog.text

    def test_the_guard_would_catch_a_real_leak(self, caplog: pytest.LogCaptureFixture) -> None:
        """A canary: the assertion above only means something if caplog is
        actually capturing this logger."""
        with caplog.at_level("DEBUG"):
            logging.getLogger("mcp_trentina_crunchtools").info("canary %s", self.UPSTREAM_SECRET)
        assert self.UPSTREAM_SECRET in caplog.text
