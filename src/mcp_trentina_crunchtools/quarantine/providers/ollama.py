"""Ollama provider — OpenAI-compatible /api/chat endpoint."""

from __future__ import annotations

from typing import Any

import httpx

from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

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
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(OLLAMA_TIMEOUT),
            ) as client:
                resp = await client.post(url, json=request_body)
                resp.raise_for_status()
                resp_json = resp.json()

            message = resp_json.get("message", {})
            text = message.get("content", "")

            prompt_eval_count = resp_json.get("prompt_eval_count", 0)
            eval_count = resp_json.get("eval_count", 0)

            return ProviderResult(
                text=text,
                input_tokens=prompt_eval_count,
                output_tokens=eval_count,
            )

        except httpx.HTTPStatusError as exc:
            raise QuarantineAgentError(f"HTTP {exc.response.status_code}") from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.ConnectError as exc:
            raise QuarantineAgentError(
                f"Ollama unreachable at {self._base_url}: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
