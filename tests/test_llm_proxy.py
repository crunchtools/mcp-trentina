"""Tests for gateway/llm_proxy.py — provider loading and proxy behavior."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr, ValidationError
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_trentina_crunchtools.gateway import llm_proxy
from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
from mcp_trentina_crunchtools.gateway.llm_proxy import (
    LlmProvider,
    _proxy_llm,
    load_llm_providers,
    validate_profile_llm_keys,
)
from mcp_trentina_crunchtools.gateway.profile import (
    AuthConfig,
    LlmKeyOverride,
    Profile,
)
from mcp_trentina_crunchtools.gateway.proxy_utils import sanitize_proxy_path

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response


class TestSanitizeProxyPath:
    """Path traversal prevention for proxy endpoints."""

    def test_clean_path_passes(self) -> None:
        assert sanitize_proxy_path("v1/chat/completions") == "v1/chat/completions"

    def test_empty_path_passes(self) -> None:
        assert sanitize_proxy_path("") == ""

    def test_dotdot_rejected(self) -> None:
        assert sanitize_proxy_path("../admin") is None

    def test_dotdot_middle_rejected(self) -> None:
        assert sanitize_proxy_path("v1/../admin/secret") is None

    def test_encoded_dotdot_rejected(self) -> None:
        assert sanitize_proxy_path("v1/%2e%2e/admin") is None

    def test_backslash_dotdot_rejected(self) -> None:
        assert sanitize_proxy_path("v1\\..\\admin") is None

    def test_single_dot_rejected(self) -> None:
        assert sanitize_proxy_path("v1/./completions") is None

    def test_deep_path_passes(self) -> None:
        assert sanitize_proxy_path("v1beta/models/gemini-pro:generateContent") == (
            "v1beta/models/gemini-pro:generateContent"
        )


class TestLlmProviderModel:
    """Pydantic validation for LlmProvider."""

    def test_valid_provider(self) -> None:
        provider = LlmProvider(
            enabled=True,
            upstream="https://api.anthropic.com",
            auth_header="x-api-key",
            api_key_env="ANTHROPIC_API_KEY",
        )
        assert provider.upstream == "https://api.anthropic.com"

    def test_http_upstream_rejected(self) -> None:
        with pytest.raises(ValidationError, match="https://"):
            LlmProvider(
                upstream="http://api.anthropic.com",
                auth_header="x-api-key",
                api_key_env="KEY",
            )

    def test_trailing_slash_stripped(self) -> None:
        provider = LlmProvider(
            upstream="https://api.openai.com/",
            auth_header="Authorization",
            api_key_env="KEY",
        )
        assert provider.upstream == "https://api.openai.com"

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LlmProvider(
                upstream="https://api.openai.com",
                auth_header="Authorization",
                api_key_env="KEY",
                unknown_field="bad",
            )


class TestLoadLlmProviders:
    """Provider loading from the llm_providers config section."""

    def test_empty_section_returns_empty(self) -> None:
        assert load_llm_providers({}) == {}

    def test_disabled_provider_skipped(self) -> None:
        section: dict[str, Any] = {
            "anthropic": {
                "enabled": False,
                "upstream": "https://api.anthropic.com",
                "auth_header": "x-api-key",
                "api_key_env": "ANTHROPIC_API_KEY",
            }
        }
        assert load_llm_providers(section) == {}

    def test_missing_api_key_env_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("MISSING_KEY_FOR_TEST", raising=False)
        section: dict[str, Any] = {
            "test": {
                "enabled": True,
                "upstream": "https://example.com",
                "auth_header": "Authorization",
                "api_key_env": "MISSING_KEY_FOR_TEST",
            }
        }
        with pytest.raises(ProfileConfigError, match="not set or empty"):
            load_llm_providers(section)

    def test_valid_provider_loaded(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("TEST_LLM_KEY", "sk-test")
        section: dict[str, Any] = {
            "openai": {
                "enabled": True,
                "upstream": "https://api.openai.com",
                "auth_header": "Authorization",
                "auth_prefix": "Bearer ",
                "api_key_env": "TEST_LLM_KEY",
            }
        }
        providers = load_llm_providers(section)
        assert "openai" in providers
        assert providers["openai"].api_key.get_secret_value() == "sk-test"

    def test_non_dict_entry_raises(self) -> None:
        section: dict[str, Any] = {"bad": "not-a-dict"}
        with pytest.raises(ProfileConfigError, match="must be a mapping"):
            load_llm_providers(section)


def _gemini_provider() -> LlmProvider:
    provider = LlmProvider(
        enabled=True,
        upstream="https://generativelanguage.googleapis.com",
        auth_header="x-goog-api-key",
        api_key_env="GLOBAL_GEMINI_KEY",
    )
    provider.api_key = SecretStr("global-key")
    return provider


def _profile(name: str, token: str, keys: dict[str, str]) -> Profile:
    """Build a Profile with a resolved bearer token and resolved llm_keys."""
    p = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TOK"),
        llm_keys={
            provider: LlmKeyOverride(api_key_env=f"{name.upper()}_{provider.upper()}_KEY")
            for provider in keys
        },
    )
    p.auth.bearer_token = SecretStr(token)
    for provider, value in keys.items():
        p.llm_keys[provider].api_key = SecretStr(value)
    return p


class TestValidateProfileLlmKeys:
    """Startup cross-validation of profile llm_keys against configured providers."""

    def test_valid_reference_passes(self) -> None:
        providers = {"gemini": _gemini_provider()}
        profiles = {"kagetora": _profile("kagetora", "tok", {"gemini": "k-key"})}
        validate_profile_llm_keys(providers, profiles)  # no raise

    def test_dangling_reference_fails_closed(self) -> None:
        providers = {"gemini": _gemini_provider()}
        profiles = {"kagetora": _profile("kagetora", "tok", {"openai": "k-key"})}
        with pytest.raises(ProfileConfigError, match="not a configured"):
            validate_profile_llm_keys(providers, profiles)

    def test_profile_without_llm_keys_passes(self) -> None:
        providers = {"gemini": _gemini_provider()}
        profiles = {"josui": _profile("josui", "tok", {})}
        validate_profile_llm_keys(providers, profiles)  # no raise


class _FakeUpstreamResp:
    """Minimal stand-in for httpx.Response used by _streaming_response."""

    def __init__(self) -> None:
        self.status_code = 200
        self.headers = {"content-type": "application/json"}

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        yield b'{"ok": true}'

    async def aclose(self) -> None:
        return None


class _FakeClient:
    """Captures the request built by the proxy so tests can assert headers."""

    def __init__(self) -> None:
        self.captured_headers: dict[str, str] = {}
        self.captured_url: str = ""

    def build_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        content: Any = None,
    ) -> Any:
        self.captured_url = url
        self.captured_headers = headers or {}
        return object()

    async def send(self, request: Any, stream: bool = False) -> _FakeUpstreamResp:
        return _FakeUpstreamResp()


class TestProxyLlm:
    """End-to-end behavior of the authenticated LLM proxy endpoint."""

    def _client(
        self, providers: dict[str, LlmProvider], profiles: dict[str, Profile]
    ) -> TestClient:
        async def endpoint(request: Request) -> Response:
            return await _proxy_llm(request, providers, profiles)

        app = Starlette(
            routes=[
                Route(
                    "/llm/{provider}/{path:path}",
                    endpoint,
                    methods=["GET", "POST"],
                )
            ]
        )
        return TestClient(app)

    def _fixtures(self) -> tuple[dict[str, LlmProvider], dict[str, Profile]]:
        providers = {"gemini": _gemini_provider()}
        profiles = {
            "kagetora": _profile("kagetora", "kagetora-tok", {"gemini": "kagetora-key"}),
            "takeda": _profile("takeda", "takeda-tok", {"gemini": "takeda-key"}),
            "josui": _profile("josui", "josui-tok", {}),
        }
        return providers, profiles

    def test_unknown_provider_404(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/nonesuch/v1/x", headers={"authorization": "Bearer kagetora-tok"})
        assert resp.status_code == 404

    def test_missing_token_401(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/gemini/v1/x")
        assert resp.status_code == 401

    def test_unknown_token_401(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/gemini/v1/x", headers={"authorization": "Bearer nope"})
        assert resp.status_code == 401

    def test_profile_without_key_502(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post("/llm/gemini/v1/x", headers={"authorization": "Bearer josui-tok"})
        assert resp.status_code == 502

    def test_success_injects_profile_key_and_strips_auth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        providers, profiles = self._fixtures()
        fake = _FakeClient()
        monkeypatch.setattr(llm_proxy, "_get_llm_client", lambda: fake)
        client = self._client(providers, profiles)

        resp = client.post(
            "/llm/gemini/v1beta/models/gemini-2.5-flash:generateContent",
            headers={"authorization": "Bearer kagetora-tok"},
            content=b'{"contents": []}',
        )
        assert resp.status_code == 200
        assert fake.captured_headers.get("x-goog-api-key") == "kagetora-key"
        assert not any(k.lower() == "authorization" for k in fake.captured_headers)

    def test_success_selects_correct_profile_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        providers, profiles = self._fixtures()
        fake = _FakeClient()
        monkeypatch.setattr(llm_proxy, "_get_llm_client", lambda: fake)
        client = self._client(providers, profiles)

        client.post(
            "/llm/gemini/v1/x",
            headers={"authorization": "Bearer takeda-tok"},
            content=b"{}",
        )
        assert fake.captured_headers.get("x-goog-api-key") == "takeda-key"

    def test_path_traversal_rejected(self) -> None:
        providers, profiles = self._fixtures()
        client = self._client(providers, profiles)
        resp = client.post(
            "/llm/gemini/v1/..%2fadmin",
            headers={"authorization": "Bearer kagetora-tok"},
        )
        assert resp.status_code == 400
