"""Tests for quarantine/providers — mocked unit tests for each driver."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_trentina_crunchtools.errors import QuarantineAgentError
from mcp_trentina_crunchtools.quarantine.providers import get_provider, reset_provider
from mcp_trentina_crunchtools.quarantine.providers.anthropic import AnthropicProvider
from mcp_trentina_crunchtools.quarantine.providers.gemini import GeminiProvider
from mcp_trentina_crunchtools.quarantine.providers.ollama import OllamaProvider
from mcp_trentina_crunchtools.quarantine.providers.openai import OpenAIProvider


def _gemini_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "candidates": [{"content": {"parts": [{"text": text}]}}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5},
        },
        request=httpx.Request("POST", "https://example.com"),
    )


def _openai_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": text}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
        request=httpx.Request("POST", "https://example.com"),
    )


def _anthropic_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        },
        request=httpx.Request("POST", "https://example.com"),
    )


def _ollama_response(text: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "message": {"role": "assistant", "content": text},
            "prompt_eval_count": 10,
            "eval_count": 5,
        },
        request=httpx.Request("POST", "http://localhost:11434/api/chat"),
    )


SAMPLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
}


@pytest.mark.asyncio
class TestGeminiProvider:

    async def test_generate_returns_text(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="gemini-2.5-flash-lite")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _gemini_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10
        assert result.output_tokens == 5

    async def test_generate_with_schema(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _gemini_response('{"answer":"hi"}')
            await provider.generate("sys", "user", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs["json"]
            assert request_body["generationConfig"]["responseSchema"] == SAMPLE_SCHEMA

    async def test_timeout_raises(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("timeout")
            with pytest.raises(QuarantineAgentError, match="timed out"):
                await provider.generate("sys", "user")

    async def test_no_candidates_raises(self) -> None:
        provider = GeminiProvider(api_key="test-key", model="test")
        empty_resp = httpx.Response(
            200,
            json={"candidates": []},
            request=httpx.Request("POST", "https://example.com"),
        )
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = empty_resp
            with pytest.raises(QuarantineAgentError, match="No candidates"):
                await provider.generate("sys", "user")


@pytest.mark.asyncio
class TestOpenAIProvider:

    async def test_generate_returns_text(self) -> None:
        provider = OpenAIProvider(api_key="sk-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10

    async def test_generate_with_schema_sends_json_schema(self) -> None:
        provider = OpenAIProvider(api_key="sk-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response('{"answer":"hi"}')
            await provider.generate("sys", "user", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs["json"]
            assert request_body["response_format"]["type"] == "json_schema"

    async def test_auth_header_sent(self) -> None:
        provider = OpenAIProvider(api_key="sk-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _openai_response("{}")
            await provider.generate("sys", "user")
            headers = mock_post.call_args.kwargs["headers"]
            assert headers["Authorization"] == "Bearer sk-test"


@pytest.mark.asyncio
class TestAnthropicProvider:

    async def test_generate_returns_text(self) -> None:
        provider = AnthropicProvider(api_key="sk-ant-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _anthropic_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10

    async def test_auth_headers_sent(self) -> None:
        provider = AnthropicProvider(api_key="sk-ant-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _anthropic_response("{}")
            await provider.generate("sys", "user")
            headers = mock_post.call_args.kwargs["headers"]
            assert headers["x-api-key"] == "sk-ant-test"
            assert headers["anthropic-version"] == "2023-06-01"

    async def test_schema_hint_appended_to_user_content(self) -> None:
        provider = AnthropicProvider(api_key="sk-ant-test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _anthropic_response('{"answer":"hi"}')
            await provider.generate("sys", "user text", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs["json"]
            user_msg = request_body["messages"][0]["content"]
            assert "user text" in user_msg
            assert "answer" in user_msg


@pytest.mark.asyncio
class TestOllamaProvider:

    async def test_generate_returns_text(self) -> None:
        provider = OllamaProvider(model="qwen2.5:0.5b")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _ollama_response('{"answer":"hello"}')
            result = await provider.generate("system", "user")
        assert result.text == '{"answer":"hello"}'
        assert result.input_tokens == 10

    async def test_json_format_with_schema(self) -> None:
        provider = OllamaProvider(model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _ollama_response('{"answer":"hi"}')
            await provider.generate("sys", "user", response_schema=SAMPLE_SCHEMA)
            request_body = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1]["json"]
            assert request_body["format"] == "json"

    async def test_connect_error_raises(self) -> None:
        provider = OllamaProvider(model="test")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.ConnectError("refused")
            with pytest.raises(QuarantineAgentError, match="Ollama unreachable"):
                await provider.generate("sys", "user")


class TestGetProviderFactory:

    def setup_method(self) -> None:
        reset_provider()

    def teardown_method(self) -> None:
        reset_provider()

    def test_gemini_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("TRENTINA_MODEL_PROVIDER", raising=False)
        from mcp_trentina_crunchtools import config as config_mod
        config_mod._config = None
        provider = get_provider()
        assert isinstance(provider, GeminiProvider)
        config_mod._config = None

    def test_openai_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        from mcp_trentina_crunchtools import config as config_mod
        config_mod._config = None
        provider = get_provider()
        assert isinstance(provider, OpenAIProvider)
        config_mod._config = None

    def test_unknown_provider_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "unknown")
        from mcp_trentina_crunchtools import config as config_mod
        config_mod._config = None
        with pytest.raises(QuarantineAgentError, match="Unknown provider"):
            get_provider()
        config_mod._config = None

    def test_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_MODEL_PROVIDER", "openai")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        from mcp_trentina_crunchtools import config as config_mod
        config_mod._config = None
        with pytest.raises(QuarantineAgentError, match="OPENAI_API_KEY"):
            get_provider()
        config_mod._config = None
