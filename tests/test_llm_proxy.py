"""Tests for gateway/llm_proxy.py — provider loading and proxy behavior."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
from mcp_trentina_crunchtools.gateway.llm_proxy import (
    LlmProvider,
    load_llm_providers,
)
from mcp_trentina_crunchtools.gateway.proxy_utils import sanitize_proxy_path


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
