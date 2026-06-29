"""Gemini provider — extracted from agent.py's _call_gemini."""

from __future__ import annotations

from typing import Any

import httpx

from ...errors import QuarantineAgentError
from .base import Provider, ProviderResult

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_TIMEOUT = 60.0


class GeminiProvider(Provider):
    """Gemini REST API provider using raw httpx."""

    def __init__(self, api_key: str, model: str) -> None:
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
        url = f"{GEMINI_API_BASE}/{self._model}:generateContent?key={self._api_key}"

        gen_config: dict[str, Any] = {
            "temperature": temperature,
            "maxOutputTokens": max_output_tokens,
        }
        if response_schema is not None:
            gen_config["responseMimeType"] = "application/json"
            gen_config["responseSchema"] = response_schema

        request_body: dict[str, Any] = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_content}]}],
            "generationConfig": gen_config,
        }

        if "tools" in request_body or "functionDeclarations" in request_body:
            raise QuarantineAgentError("SECURITY: tools in provider request")

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(GEMINI_TIMEOUT),
            ) as client:
                resp = await client.post(
                    url,
                    json=request_body,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                resp_json = resp.json()

            candidates = resp_json.get("candidates", [])
            if not candidates:
                raise QuarantineAgentError("No candidates in Gemini response")

            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                raise QuarantineAgentError("No parts in Gemini response")

            text = parts[0].get("text", "")
            usage = resp_json.get("usageMetadata", {})

            return ProviderResult(
                text=text,
                input_tokens=usage.get("promptTokenCount", 0),
                output_tokens=usage.get("candidatesTokenCount", 0),
            )

        except httpx.HTTPStatusError as exc:
            raise QuarantineAgentError(f"HTTP {exc.response.status_code}") from exc
        except httpx.TimeoutException as exc:
            raise QuarantineAgentError("Request timed out") from exc
        except httpx.RequestError as exc:
            raise QuarantineAgentError(str(exc)) from exc
