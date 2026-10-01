"""Ollama provider — OpenAI-compatible /api/chat endpoint."""

from __future__ import annotations

from typing import Any

import httpx

from ...errors import MalformedResponseError, QuarantineAgentError
from .base import Provider, ProviderResult, count, dig, envelope, status_error

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:0.5b"
OLLAMA_TIMEOUT = 120.0


class OllamaProvider(Provider):
    """Ollama local LLM provider using raw httpx."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")

    async def generate(
        self,
        system_prompt: str,
        user_content: str,
        response_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_output_tokens: int = 4096,
    ) -> ProviderResult:
        url = f"{self._base_url}/api/chat"

        request_body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_output_tokens,
            },
        }

        if response_schema is not None:
            request_body["format"] = "json"

        try:
            # nosemgrep: trentina-httpx-client-outside-egress -- operator URL
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(OLLAMA_TIMEOUT),
            ) as client:
                resp = await client.post(url, json=request_body)
                resp.raise_for_status()
                resp_json = envelope(resp)

            text = dig(resp_json, "message", "content")
            if not isinstance(text, str):
                raise MalformedResponseError("no text")

            return ProviderResult(
                text=text,
                input_tokens=count(dig(resp_json, "prompt_eval_count")),
                output_tokens=count(dig(resp_json, "eval_count")),
            )

        except httpx.HTTPStatusError as exc:
            raise status_error(exc) from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.ConnectError as exc:
            raise QuarantineAgentError(f"Ollama unreachable at {self._base_url}: {exc}") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
