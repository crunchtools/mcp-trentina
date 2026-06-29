"""Anthropic provider — Messages API with raw httpx."""

from __future__ import annotations

import json
from typing import Any

import httpx

from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
ANTHROPIC_TIMEOUT = 60.0
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-haiku-4-5-20251001"


class AnthropicProvider(Provider):
    """Anthropic Messages API provider using raw httpx."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._api_key = api_key
        self._model = model

    async def generate(
        self,
        system_prompt: str,
        user_content: str,
        response_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_output_tokens: int = 4096,
    ) -> ProviderResult:
        url = f"{ANTHROPIC_API_BASE}/messages"

        user_msg = user_content
        if response_schema is not None:
            schema_hint = json.dumps(response_schema, indent=2)
            user_msg = (
                f"{user_content}\n\n"
                f"Respond with ONLY valid JSON matching this schema:\n{schema_hint}"
            )

        request_body: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_output_tokens,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_msg},
            ],
            "temperature": temperature,
        }

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(ANTHROPIC_TIMEOUT),
            ) as client:
                resp = await client.post(
                    url,
                    json=request_body,
                    headers={
                        "x-api-key": self._api_key,
                        "anthropic-version": ANTHROPIC_VERSION,
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                resp_json = resp.json()

            content_blocks = resp_json.get("content", [])
            if not content_blocks:
                raise QuarantineAgentError("No content in Anthropic response")

            text = content_blocks[0].get("text", "").strip()
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:-1]).strip()
            usage = resp_json.get("usage", {})

            return ProviderResult(
                text=text,
                input_tokens=usage.get("input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
            )

        except httpx.HTTPStatusError as exc:
            raise QuarantineAgentError(f"HTTP {exc.response.status_code}") from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
