"""OpenAI provider — also covers Azure OpenAI and OpenRouter via base_url override."""

from __future__ import annotations

import copy
from typing import Any

import httpx

from ...errors import MalformedResponseError, QuarantineAgentError
from .base import (
    Provider,
    ProviderResult,
    count,
    dig,
    enforce_no_tools,
    envelope,
    status_error,
)

OPENAI_API_BASE = "https://api.openai.com/v1"
OPENAI_TIMEOUT = 60.0
DEFAULT_MODEL = "gpt-4o-mini"
OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"

#: OpenRouter's per-request host selection. ``require_parameters`` keeps a
#: request off any host that would ignore ``response_format`` and answer in
#: free text; ``data_collection: deny`` keeps judged payloads — which include
#: a tenant's own mail and documents — off hosts that retain or train on them.
OPENROUTER_ROUTING: dict[str, Any] = {"require_parameters": True, "data_collection": "deny"}

NOT_FOUND = 404
"""What OpenRouter answers when no host of a model takes every parameter of
the request, as well as when the model does not exist."""


class ParametersRefusedError(QuarantineAgentError):
    """OpenRouter has no host for this model that takes the request's parameters."""


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

    _reasoning_effort: str | None = None
    _fixed_temperature = False

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = OPENAI_API_BASE,
        routing: dict[str, Any] | None = None,
        reasoning_effort: str | None = None,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._routing = routing
        self._reasoning_effort = reasoning_effort

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
            "max_tokens": max_output_tokens,
        }
        if not self._fixed_temperature:
            request_body["temperature"] = temperature
        if self._routing is not None:
            request_body["provider"] = self._routing
        if self._reasoning_effort is not None:
            request_body["reasoning"] = {"effort": self._reasoning_effort}

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

        enforce_no_tools(request_body)
        try:
            return await self._ask(url, request_body)
        except ParametersRefusedError:
            if "temperature" not in request_body:
                raise
        # Reasoning models fix their own sampling, and under
        # ``require_parameters`` OpenRouter has no host for a request that
        # sets it (Gemini 3.8 Flash, GPT-6 Luna). Asked once without it, and
        # this judge is not sent it again.
        self._fixed_temperature = True
        unset = {key: value for key, value in request_body.items() if key != "temperature"}
        return await self._ask(url, unset)

    async def _ask(self, url: str, request_body: dict[str, Any]) -> ProviderResult:
        try:
            # nosemgrep: trentina-httpx-client-outside-egress -- fixed or operator URL
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
                resp_json = envelope(resp)

            if not dig(resp_json, "choices", 0):
                raise QuarantineAgentError("No choices in OpenAI response")

            # null when the model refused structured output.
            text = dig(resp_json, "choices", 0, "message", "content")
            if not isinstance(text, str):
                raise MalformedResponseError("no text")

            return ProviderResult(
                text=text,
                input_tokens=count(dig(resp_json, "usage", "prompt_tokens")),
                output_tokens=count(dig(resp_json, "usage", "completion_tokens")),
                truncated=dig(resp_json, "choices", 0, "finish_reason") == "length",
            )

        except httpx.HTTPStatusError as exc:
            # The body is OpenRouter's own sentence; it picks the error's
            # class and goes nowhere else.
            refused = exc.response.status_code == NOT_FOUND
            if refused and "requested parameters" in exc.response.text:
                raise ParametersRefusedError("HTTP 404", status_code=NOT_FOUND) from exc
            raise status_error(exc) from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
