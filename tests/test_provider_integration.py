"""Integration tests for provider drivers — real API calls, gated on env vars.

Run with:
    OPENAI_API_KEY=sk-... uv run pytest tests/test_provider_integration.py -v
    ANTHROPIC_API_KEY=sk-... uv run pytest tests/test_provider_integration.py -v
"""

from __future__ import annotations

import json
import os

import pytest

from mcp_trentina_crunchtools.quarantine.providers.base import ProviderResult

SIMPLE_SCHEMA = {
    "type": "object",
    "properties": {
        "capital": {"type": "string"},
        "country": {"type": "string"},
    },
    "required": ["capital", "country"],
}


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set",
)
@pytest.mark.asyncio
class TestOpenAIIntegration:

    async def test_simple_generation(self) -> None:
        from mcp_trentina_crunchtools.quarantine.providers.openai import OpenAIProvider

        provider = OpenAIProvider(
            api_key=os.environ["OPENAI_API_KEY"],
            model="gpt-4o-mini",
        )
        result = await provider.generate(
            system_prompt="You are a geography expert. Respond with JSON.",
            user_content=(
                "What is the capital of France? "
                "Respond as JSON with keys: capital, country"
            ),
            response_schema=SIMPLE_SCHEMA,
        )
        assert isinstance(result, ProviderResult)
        assert result.input_tokens > 0
        parsed = json.loads(result.text)
        assert parsed["capital"].lower() == "paris"


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set",
)
@pytest.mark.asyncio
class TestAnthropicIntegration:

    async def test_simple_generation(self) -> None:
        from mcp_trentina_crunchtools.quarantine.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider(
            api_key=os.environ["ANTHROPIC_API_KEY"],
            model="claude-haiku-4-5-20251001",
        )
        result = await provider.generate(
            system_prompt="You are a geography expert. Respond with valid JSON only.",
            user_content=(
                "What is the capital of France? "
                "Respond as JSON with keys: capital, country"
            ),
            response_schema=SIMPLE_SCHEMA,
        )
        assert isinstance(result, ProviderResult)
        assert result.input_tokens > 0
        parsed = json.loads(result.text)
        assert parsed["capital"].lower() == "paris"


@pytest.mark.skipif(
    not os.environ.get("GEMINI_API_KEY"),
    reason="GEMINI_API_KEY not set",
)
@pytest.mark.asyncio
class TestGeminiIntegration:

    async def test_simple_generation(self) -> None:
        from mcp_trentina_crunchtools.quarantine.providers.gemini import GeminiProvider

        provider = GeminiProvider(
            api_key=os.environ["GEMINI_API_KEY"],
            model="gemini-2.5-flash-lite",
        )
        result = await provider.generate(
            system_prompt="You are a geography expert.",
            user_content="What is the capital of France?",
            response_schema=SIMPLE_SCHEMA,
        )
        assert isinstance(result, ProviderResult)
        assert result.input_tokens > 0
        parsed = json.loads(result.text)
        assert parsed["capital"].lower() == "paris"
