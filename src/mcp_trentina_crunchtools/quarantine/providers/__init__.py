"""Pluggable LLM provider drivers for the Q-Agent and compression."""

from __future__ import annotations

import logging

from pydantic import SecretStr

from ...config import get_config
from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

logger = logging.getLogger(__name__)

_provider_cache: dict[tuple[str, str, str], Provider] = {}

__all__ = ["Provider", "ProviderResult", "get_provider"]

_DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-lite"


def get_provider(
    provider_name: str | None = None,
    api_key: SecretStr | None = None,
    model: str | None = None,
) -> Provider:
    """Return a provider instance, cached per (provider, api_key, model) tuple.

    Args:
        provider_name: Explicit provider to use. When None, falls back
            to TRENTINA_MODEL_PROVIDER from config (the global default).
        api_key: API key override for this provider. When None, falls back
            to the global config key for the provider.
        model: Model override for this provider. When None, falls back
            to QUARANTINE_MODEL from config.
    """
    config = get_config()
    resolved_provider = provider_name or config.provider
    resolved_model = model or config.model

    # Build cache key from resolved values (use full key value for uniqueness)
    key_value = api_key.get_secret_value() if api_key else "global"
    cache_key = (resolved_provider, key_value, resolved_model)

    if cache_key in _provider_cache:
        return _provider_cache[cache_key]

    match resolved_provider:
        case "gemini":
            from .gemini import GeminiProvider

            key_value = (
                api_key.get_secret_value()
                if api_key
                else config.api_key.get_secret_value()
            )
            if not key_value:
                raise QuarantineAgentError("GEMINI_API_KEY not configured")
            provider: Provider = GeminiProvider(
                api_key=key_value,
                model=resolved_model,
            )

        case "openai":
            from .openai import OpenAIProvider

            key_value = (
                api_key.get_secret_value() if api_key else config.openai_api_key
            )
            if not key_value:
                raise QuarantineAgentError("OPENAI_API_KEY not configured")
            default_model = (
                resolved_model
                if resolved_model != _DEFAULT_GEMINI_MODEL
                else "gpt-4o-mini"
            )
            provider = OpenAIProvider(api_key=key_value, model=default_model)

        case "anthropic":
            from .anthropic import AnthropicProvider

            key_value = (
                api_key.get_secret_value() if api_key else config.anthropic_api_key
            )
            if not key_value:
                raise QuarantineAgentError("ANTHROPIC_API_KEY not configured")
            default_model = (
                resolved_model
                if resolved_model != _DEFAULT_GEMINI_MODEL
                else "claude-haiku-4-5-20251001"
            )
            provider = AnthropicProvider(api_key=key_value, model=default_model)

        case "ollama":
            from .ollama import OllamaProvider

            # Ollama doesn't use API keys
            provider = OllamaProvider(
                model=resolved_model if resolved_model != _DEFAULT_GEMINI_MODEL else config.ollama_model,
                base_url=config.ollama_base_url,
            )

        case _:
            raise QuarantineAgentError(
                f"Unknown provider {resolved_provider!r}. "
                "Supported: gemini, openai, anthropic, ollama"
            )

    _provider_cache[cache_key] = provider
    logger.info(
        "provider: initialized %s (model=%s, key=%s)",
        resolved_provider,
        resolved_model,
        "override" if api_key else "global",
    )
    return provider


def reset_provider() -> None:
    """Clear the cached providers (for testing)."""
    _provider_cache.clear()
