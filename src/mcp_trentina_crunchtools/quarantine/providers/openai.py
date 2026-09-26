"""OpenAI provider — also covers Azure OpenAI and OpenRouter via base_url override."""

from __future__ import annotations

import copy
from typing import Any

import httpx

from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult, status_error

OPENAI_API_BASE = "https://api.openai.com/v1"
OPENAI_TIMEOUT = 60.0
DEFAULT_MODEL = "gpt-4o-mini"
OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"

#: OpenRouter's per-request host selection. ``require_parameters`` keeps a
#: request off any host that would ignore ``response_format`` and answer in
#: free text; ``data_collection: deny`` keeps judged payloads — which include
#: a tenant's own mail and documents — off hosts that retain or train on them.
OPENROUTER_ROUTING: dict[str, Any] = {"require_parameters": True, "data_collection": "deny"}


_UNSUPPORTED_KEYS = {"maxLength", "minLength", "minimum", "maximum", "multipleOf"}


def _add_additional_properties(schema: dict[str, Any]) -> dict[str, Any]:
    """Prepare a JSON Schema for OpenAI's strict mode.

    Recursively adds additionalProperties: false to all object types and
    strips constraints OpenAI doesn't support (maxLength, minimum, etc.).
    """
    schema = copy.deepcopy(schema)
    for key in _UNSUPPORTED_KEYS:
        schema.pop(key, None)
    if schema.get("type") == "object":
        schema["additionalProperties"] = False
        props = schema.get("properties", {})
        schema["required"] = list(props.keys())
        for prop in props.values():
            if isinstance(prop, dict):
                prop.update(_add_additional_properties(prop))
    if "items" in schema and isinstance(schema["items"], dict):
        schema["items"] = _add_additional_properties(schema["items"])
    return schema


class OpenAIProvider(Provider):
    """OpenAI Chat Completions API provider using raw httpx."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = OPENAI_API_BASE,
        routing: dict[str, Any] | None = None,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._routing = routing

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
        if self._routing is not None:
            request_body["provider"] = self._routing

        if response_schema is not None:
            schema_copy = _add_additional_properties(response_schema)
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
            raise status_error(exc) from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
