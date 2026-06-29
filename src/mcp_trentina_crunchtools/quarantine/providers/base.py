"""Provider ABC and result type for pluggable LLM backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderResult:
    """Result from a provider generate() call."""

    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class Provider(ABC):
    """Abstract base for LLM provider drivers.

    Each driver maps the common interface to a provider's REST API
    using raw httpx (no SDKs, per constitution §I.2).
    """

    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_content: str,
        response_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_output_tokens: int = 4096,
    ) -> ProviderResult:
        """Generate a completion and return the response text.

        Args:
            system_prompt: System-level instructions.
            user_content: User message content.
            response_schema: JSON Schema for structured output (optional).
            temperature: Sampling temperature.
            max_output_tokens: Maximum tokens in the response.

        Returns:
            ProviderResult with the model's text output and token counts.
        """
