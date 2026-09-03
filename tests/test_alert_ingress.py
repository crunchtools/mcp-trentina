"""Tests for the alert webhook ingress."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from mcp_trentina_crunchtools.gateway.alert_ingress import (
    _resolve_profile_by_alert_token,
)
from mcp_trentina_crunchtools.gateway.profile import (
    AlertIngressConfig,
    AuthConfig,
    Profile,
)


def _make_profile(
    name: str, *, alert_token: str | None = None, forward_url: str = "http://localhost:9999/hook",
) -> Profile:
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="DUMMY_TOKEN"),
    )
    profile.auth.bearer_token = SecretStr("dummy")
    if alert_token is not None:
        profile.alert_ingress = AlertIngressConfig(
            token_env="DUMMY_ALERT_TOKEN",
            forward_url=forward_url,
        )
        profile.alert_ingress.token = SecretStr(alert_token)
    return profile


class TestResolveProfileByAlertToken:
    def test_matches_correct_profile(self) -> None:
        profiles = {
            "alpha": _make_profile("alpha", alert_token="tok-alpha"),
            "beta": _make_profile("beta", alert_token="tok-beta"),
        }
        result = _resolve_profile_by_alert_token("tok-beta", profiles)
        assert result is not None
        assert result.name == "beta"

    def test_returns_none_for_unknown_token(self) -> None:
        profiles = {
            "alpha": _make_profile("alpha", alert_token="tok-alpha"),
        }
        assert _resolve_profile_by_alert_token("wrong", profiles) is None

    def test_skips_profiles_without_alert_ingress(self) -> None:
        profiles = {
            "no-alert": _make_profile("no-alert"),
            "has-alert": _make_profile("has-alert", alert_token="tok-yes"),
        }
        assert _resolve_profile_by_alert_token("tok-yes", profiles) is not None
        assert _resolve_profile_by_alert_token("tok-yes", profiles).name == "has-alert"

    def test_empty_profiles(self) -> None:
        assert _resolve_profile_by_alert_token("anything", {}) is None


class TestAlertIngressConfig:
    def test_valid_config(self) -> None:
        cfg = AlertIngressConfig(
            token_env="MY_TOKEN",
            forward_url="http://kagetora:8644/webhooks/nagios",
        )
        assert cfg.token_env == "MY_TOKEN"
        assert cfg.forward_url == "http://kagetora:8644/webhooks/nagios"

    def test_rejects_lowercase_env(self) -> None:
        with pytest.raises(ValueError, match="UPPERCASE"):
            AlertIngressConfig(token_env="my_token", forward_url="http://x:80/hook")

    def test_rejects_non_http_url(self) -> None:
        with pytest.raises(ValueError, match="http://"):
            AlertIngressConfig(token_env="MY_TOKEN", forward_url="ftp://bad/hook")
