"""Pluggable LLM provider drivers for the Q-Agent and compression."""

from __future__ import annotations

import logging

from ...config import get_config
from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

logger = logging.getLogger(__name__)

_cached_provider: Provider | None = None

__all__ = ["Provider", "ProviderResult", "get_provider"]

_DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-lite"


def get_provider() -> Provider:
    """Return the configured provider singleton.

    Reads TRENTINA_MODEL_PROVIDER from config and instantiates the
    matching driver. Caches the result for the process lifetime.
    """
    global _cached_provider
    if _cached_provider is not None:
        return _cached_provider

    config = get_config()

    match config.provider:
        case "gemini":
            from .gemini import GeminiProvider

            if not config.has_api_key:
                raise QuarantineAgentError("GEMINI_API_KEY not configured")
            _cached_provider = GeminiProvider(
                api_key=config.api_key.get_secret_value(),
                model=config.model,
            )

        case "openai":
            from .openai import OpenAIProvider

            key = config.openai_api_key
            if not key:
                raise QuarantineAgentError("OPENAI_API_KEY not configured")
            model = config.model if config.model != _DEFAULT_GEMINI_MODEL else "gpt-4o-mini"
            _cached_provider = OpenAIProvider(api_key=key, model=model)

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
            _cached_provider = AnthropicProvider(api_key=key, model=model)

        case "ollama":
            from .ollama import OllamaProvider

            _cached_provider = OllamaProvider(
                model=config.ollama_model,
                base_url=config.ollama_base_url,
            )

        case _:
            raise QuarantineAgentError(
                f"Unknown provider {config.provider!r}. "
                "Supported: gemini, openai, anthropic, ollama"
            )

    logger.info("provider: initialized %s", config.provider)
    return _cached_provider


def reset_provider() -> None:
    """Clear the cached provider (for testing)."""
    global _cached_provider
    _cached_provider = None
