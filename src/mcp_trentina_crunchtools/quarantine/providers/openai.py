"""OpenAI provider — also covers Azure OpenAI via base_url override."""

from __future__ import annotations

from typing import Any

import httpx

from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

OPENAI_API_BASE = "https://api.openai.com/v1"
OPENAI_TIMEOUT = 60.0
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider(Provider):
    """OpenAI Chat Completions API provider using raw httpx."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = OPENAI_API_BASE,
    ) -> None:
        self._api_key = api_key
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
        url = f"{self._base_url}/chat/completions"

        request_body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": temperature,
            "max_tokens": max_output_tokens,
        }

        if response_schema is not None:
            schema_copy = dict(response_schema)
            schema_copy["additionalProperties"] = False
            request_body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "response",
                    "strict": True,
                    "schema": schema_copy,
                },
            }

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(OPENAI_TIMEOUT),
            ) as client:
                resp = await client.post(
                    url,
                    json=request_body,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                resp_json = resp.json()

            choices = resp_json.get("choices", [])
            if not choices:
                raise QuarantineAgentError("No choices in OpenAI response")

            text = choices[0].get("message", {}).get("content", "")
            usage = resp_json.get("usage", {})

            return ProviderResult(
                text=text,
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
            )

        except httpx.HTTPStatusError as exc:
            raise QuarantineAgentError(f"HTTP {exc.response.status_code}") from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
