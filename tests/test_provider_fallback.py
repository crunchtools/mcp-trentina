"""Tests for the automatic provider fallback chain (issue #42)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from mcp_trentina_crunchtools.config import get_config
from mcp_trentina_crunchtools.errors import ConfigError, QuarantineAgentError
from mcp_trentina_crunchtools.quarantine.agent import (
    _call_with_fallback,
    _is_retryable,
)
from mcp_trentina_crunchtools.quarantine.providers import (
    get_fallback_providers,
    reset_provider,
)


@pytest.fixture(autouse=True)
def reset_config_and_providers(monkeypatch):
    """Clear singletons between tests."""
    import mcp_trentina_crunchtools.config as cfg_mod

    monkeypatch.setattr(cfg_mod, "_config", None)
    reset_provider()
    yield
    reset_provider()


# ---------------------------------------------------------------------------
# _is_retryable
# ---------------------------------------------------------------------------


class TestIsRetryable:
    def test_429_is_retryable(self):
        exc = QuarantineAgentError("rate limited", status_code=429)
        assert _is_retryable(exc)

    def test_503_is_retryable(self):
        exc = QuarantineAgentError("service unavailable", status_code=503)
        assert _is_retryable(exc)

    def test_400_not_retryable(self):
        exc = QuarantineAgentError("bad request", status_code=400)
        assert not _is_retryable(exc)

    def test_401_not_retryable(self):
        exc = QuarantineAgentError("unauthorized", status_code=401)
        assert not _is_retryable(exc)

    def test_403_not_retryable(self):
        exc = QuarantineAgentError("forbidden", status_code=403)
        assert not _is_retryable(exc)

    def test_timeout_message_retryable(self):
        exc = QuarantineAgentError("Request timed out")
        assert _is_retryable(exc)

    def test_unreachable_message_retryable(self):
        exc = QuarantineAgentError("Ollama unreachable at http://localhost:11434: ...")
        assert _is_retryable(exc)

    def test_json_error_not_retryable(self):
        exc = QuarantineAgentError("Invalid JSON in provider response")
        assert not _is_retryable(exc)

    def test_canary_error_not_retryable(self):
        exc = QuarantineAgentError("SECURITY: canary token leaked")
        assert not _is_retryable(exc)

    def test_no_status_code_generic_error_not_retryable(self):
        exc = QuarantineAgentError("GEMINI_API_KEY not configured")
        assert not _is_retryable(exc)


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------


class TestConfigFallbackParsing:
    def test_empty_fallback_defaults_to_empty_list(self, monkeypatch):
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == []

    def test_single_fallback(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["openai"]

    def test_multiple_fallbacks(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai,anthropic")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["openai", "anthropic"]

    def test_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", " openai , anthropic ")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["openai", "anthropic"]

    def test_invalid_provider_raises_config_error(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "invalid-llm")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        with pytest.raises(ConfigError, match="Unknown fallback provider"):
            get_config()

    def test_ollama_valid_in_chain(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "ollama")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        config = get_config()
        assert config.provider_fallback == ["ollama"]


# ---------------------------------------------------------------------------
# get_fallback_providers (standalone mode)
# ---------------------------------------------------------------------------


class TestGetFallbackProvidersStandalone:
    def test_empty_chain_returns_empty(self, monkeypatch):
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        get_config()
        assert get_fallback_providers() == []

    def test_openai_with_key(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        get_config()
        chain = get_fallback_providers()
        assert len(chain) == 1
        name, key = chain[0]
        assert name == "openai"
        assert key is not None
        assert key.get_secret_value() == "sk-test"

    def test_provider_without_key_skipped(self, monkeypatch, caplog):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        get_config()
        chain = get_fallback_providers()
        assert chain == []
        assert "skipping" in caplog.text

    def test_ollama_has_none_key(self, monkeypatch):
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "ollama")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        get_config()
        chain = get_fallback_providers()
        assert len(chain) == 1
        name, key = chain[0]
        assert name == "ollama"
        assert key is None


# ---------------------------------------------------------------------------
# _call_with_fallback integration tests (mocked provider.generate)
# ---------------------------------------------------------------------------

FAKE_EXTRACTED = {
    "extracted_text": "hello world",
    "confidence": "high",
    "injection_detected": False,
}
FAKE_SCHEMA = {
    "type": "object",
    "properties": {"extracted_text": {"type": "string"}},
}


def make_provider_result(text: str) -> object:
    from mcp_trentina_crunchtools.quarantine.providers.base import ProviderResult

    return ProviderResult(text=text, input_tokens=10, output_tokens=5)


def make_good_response() -> str:
    return json.dumps(FAKE_EXTRACTED)


def make_429_error() -> QuarantineAgentError:
    return QuarantineAgentError("HTTP 429", status_code=429)


def make_503_error() -> QuarantineAgentError:
    return QuarantineAgentError("HTTP 503", status_code=503)


def make_400_error() -> QuarantineAgentError:
    return QuarantineAgentError("HTTP 400", status_code=400)


@pytest.mark.asyncio
class TestCallWithFallback:
    async def test_primary_succeeds_no_fallback_called(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        get_config()

        call_count = {"n": 0}
        good_result = make_provider_result(make_good_response())

        async def fake_generate(*_args, **_kwargs):
            call_count["n"] += 1
            return good_result

        with patch(
            "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
            new=fake_generate,
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        assert call_count["n"] == 1
        assert result["extracted_text"] == "hello world"

    async def test_429_triggers_fallback(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())
        openai_result = make_provider_result(make_good_response())
        openai_mock = AsyncMock(return_value=openai_result)

        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()
        assert result["extracted_text"] == "hello world"

    async def test_503_triggers_fallback(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_503_error())
        openai_result = make_provider_result(make_good_response())
        openai_mock = AsyncMock(return_value=openai_result)

        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()
        assert result["extracted_text"] == "hello world"

    async def test_400_does_not_trigger_fallback(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_400_error())
        openai_mock = AsyncMock()

        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),pytest.raises(QuarantineAgentError, match="HTTP 400")
        ):
            await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_not_called()

    async def test_all_providers_exhausted_raises(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())
        openai_mock = AsyncMock(side_effect=make_503_error())

        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),pytest.raises(QuarantineAgentError, match="all providers exhausted")
        ):
            await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()

    async def test_empty_chain_single_provider_fails_raises(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_PROVIDER_FALLBACK", raising=False)
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())

        with patch(
            "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
            new=gemini_mock,
        ), pytest.raises(QuarantineAgentError, match="all providers exhausted"):
            await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

    async def test_timeout_triggers_fallback(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        get_config()

        gemini_mock = AsyncMock(
            side_effect=QuarantineAgentError("Request timed out")
        )
        openai_result = make_provider_result(make_good_response())
        openai_mock = AsyncMock(return_value=openai_result)

        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        assert result["extracted_text"] == "hello world"

    async def test_three_provider_chain(self, monkeypatch):
        """Gemini fails, OpenAI fails, Anthropic succeeds."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("TRENTINA_PROVIDER_FALLBACK", "openai,anthropic")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-test")
        get_config()

        gemini_mock = AsyncMock(side_effect=make_429_error())
        openai_mock = AsyncMock(side_effect=make_503_error())
        anthropic_result = make_provider_result(make_good_response())
        anthropic_mock = AsyncMock(return_value=anthropic_result)

        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.gemini.GeminiProvider.generate",
                new=gemini_mock,
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.openai.OpenAIProvider.generate",
                new=openai_mock,
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.providers.anthropic.AnthropicProvider.generate",
                new=anthropic_mock,
            ),
        ):
            result, _ = await _call_with_fallback(
                content="test content",
                system_prompt="test prompt",
                response_schema=FAKE_SCHEMA,
            )

        gemini_mock.assert_called_once()
        openai_mock.assert_called_once()
        anthropic_mock.assert_called_once()
        assert result["extracted_text"] == "hello world"
