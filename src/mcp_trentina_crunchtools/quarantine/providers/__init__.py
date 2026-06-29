"""Pluggable LLM provider drivers for the Q-Agent and compression."""

from __future__ import annotations

import logging

from ...config import get_config
from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

logger = logging.getLogger(__name__)

_provider_cache: dict[str, Provider] = {}

__all__ = ["Provider", "ProviderResult", "get_provider"]

_DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-lite"


def get_provider(provider_name: str | None = None) -> Provider:
    """Return a provider instance, cached per provider name.

    Args:
        provider_name: Explicit provider to use. When None, falls back
            to TRENTINA_MODEL_PROVIDER from config (the global default).
    """
    config = get_config()
    resolved = provider_name or config.provider

    if resolved in _provider_cache:
        return _provider_cache[resolved]

    match resolved:
        case "gemini":
            from .gemini import GeminiProvider

            if not config.has_api_key:
                raise QuarantineAgentError("GEMINI_API_KEY not configured")
            provider: Provider = GeminiProvider(
                api_key=config.api_key.get_secret_value(),
                model=config.model,
            )

        case "openai":
            from .openai import OpenAIProvider

            key = config.openai_api_key
            if not key:
                raise QuarantineAgentError("OPENAI_API_KEY not configured")
            model = config.model if config.model != _DEFAULT_GEMINI_MODEL else "gpt-4o-mini"
            provider = OpenAIProvider(api_key=key, model=model)

        case "anthropic":
            from .anthropic import AnthropicProvider

            key = config.anthropic_api_key
            if not key:
                raise QuarantineAgentError("ANTHROPIC_API_KEY not configured")
            model = (
                config.model
                if config.model != _DEFAULT_GEMINI_MODEL
                else "claude-haiku-4-5-20251001"
            )
            provider = AnthropicProvider(api_key=key, model=model)

        case "ollama":
            from .ollama import OllamaProvider

            provider = OllamaProvider(
                model=config.ollama_model,
                base_url=config.ollama_base_url,
            )

        case _:
            raise QuarantineAgentError(
                f"Unknown provider {resolved!r}. "
                "Supported: gemini, openai, anthropic, ollama"
            )

    _provider_cache[resolved] = provider
    logger.info("provider: initialized %s", resolved)
    return provider


def reset_provider() -> None:
    """Clear the cached providers (for testing)."""
    _provider_cache.clear()
