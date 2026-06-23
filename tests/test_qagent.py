"""Tests for the Q-Agent (quarantine) module."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_trentina_crunchtools.config import DEFAULT_MODEL
from mcp_trentina_crunchtools.errors import QuarantineAgentError
from mcp_trentina_crunchtools.quarantine.agent import (
    _CANARY_PREFIX,
    MAX_EXTRACTED_TEXT,
    _build_request_body,
    _check_canary,
    _enforce_quarantine,
    _generate_canary,
    _inject_canary,
    quarantine_detect,
    quarantine_extract,
)
from mcp_trentina_crunchtools.quarantine.prompts import (
    DETECTION_RESPONSE_SCHEMA,
    DETECTION_SYSTEM_PROMPT,
    EXTRACTION_RESPONSE_SCHEMA,
    EXTRACTION_SYSTEM_PROMPT,
)


class TestRequestBodyConstruction:
    """Verify the Q-Agent request body has NO tool declarations."""

    def test_no_tools_key(self) -> None:
        body = _build_request_body(
            content="test content",
            system_prompt="test prompt",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        assert "tools" not in body
        assert "functionDeclarations" not in body

    def test_no_function_declarations(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="test",
            response_schema=DETECTION_RESPONSE_SCHEMA,
        )
        body_str = json.dumps(body)
        assert "functionDeclarations" not in body_str

    def test_has_system_instruction(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="my system prompt",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        assert "system_instruction" in body
        assert body["system_instruction"]["parts"][0]["text"] == "my system prompt"

    def test_has_response_schema(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="test",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        gen_config = body["generationConfig"]
        assert gen_config["responseMimeType"] == "application/json"
        assert gen_config["responseSchema"] == EXTRACTION_RESPONSE_SCHEMA

    def test_user_prompt_prepended(self) -> None:
        body = _build_request_body(
            content="page content",
            system_prompt="system",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
            user_prompt="Extract the summary",
        )
        user_text = body["contents"][0]["parts"][0]["text"]
        assert user_text.startswith("Extract the summary")
        assert "page content" in user_text

    def test_low_temperature(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="test",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        assert body["generationConfig"]["temperature"] == 0.1


def _mock_gemini_response(content_json: dict[str, Any]) -> httpx.Response:
    """Create a mock Gemini API response."""
    resp_body = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": json.dumps(content_json)},
                    ],
                },
            },
        ],
        "usageMetadata": {
            "promptTokenCount": 100,
            "candidatesTokenCount": 50,
        },
    }
    return httpx.Response(
        status_code=200,
        json=resp_body,
        request=httpx.Request("POST", "https://example.com"),
    )


class TestQuarantineExtract:
    """Test extraction mode with mocked Gemini responses."""

    @pytest.mark.asyncio
    async def test_successful_extraction(self) -> None:
        extraction_json = {
            "extracted_text": "This is the main content.",
            "title": "Test Page",
            "confidence": "high",
            "injection_detected": False,
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            resp = await quarantine_extract("page content", "Extract the summary")

            assert resp["content"]["extracted_text"] == "This is the main content."
            assert resp["content"]["confidence"] == "high"
            assert resp["usage"]["input_tokens"] == 100
            assert resp["usage"]["output_tokens"] == 50

    @pytest.mark.asyncio
    async def test_injection_detected(self) -> None:
        extraction_json = {
            "extracted_text": "Content with injection attempt.",
            "confidence": "medium",
            "injection_detected": True,
            "injection_details": "Found instruction override attempt",
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            resp = await quarantine_extract("test", "Extract")
            assert resp["content"]["injection_detected"] is True

    @pytest.mark.asyncio
    async def test_fallback_on_error(self) -> None:
        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.side_effect = httpx.TimeoutException("timeout")

            resp = await quarantine_extract("original content", "Extract")
            assert resp["content"]["extracted_text"] == "original content"
            assert resp["content"]["confidence"] == "low"


class TestQuarantineDetect:
    """Test detection mode with mocked Gemini responses."""

    @pytest.mark.asyncio
    async def test_clean_detection(self) -> None:
        detection_json = {
            "injection_detected": False,
            "risk_level": "low",
            "summary": "No injection vectors found.",
        }
        mock_resp = _mock_gemini_response(detection_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.return_value = mock_resp

            resp = await quarantine_detect("clean content")
            assert resp["injection_detected"] is False
            assert resp["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_injection_detected(self) -> None:
        detection_json = {
            "injection_detected": True,
            "risk_level": "high",
            "summary": "Found system prompt override attempt.",
            "findings": [
                {
                    "type": "system_prompt_override",
                    "description": "Text attempts to override system prompt",
                },
            ],
        }
        mock_resp = _mock_gemini_response(detection_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.return_value = mock_resp

            resp = await quarantine_detect("malicious content")
            assert resp["injection_detected"] is True
            assert resp["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_fallback_on_error(self) -> None:
        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.side_effect = httpx.TimeoutException("timeout")

            resp = await quarantine_detect("content")
            assert resp["injection_detected"] is False
            assert resp["risk_level"] == "low"


class TestCanaryTokens:
    """Verify per-request canary token generation and detection."""

    def test_generate_canary_has_prefix(self) -> None:
        canary = _generate_canary()
        assert canary.startswith(_CANARY_PREFIX)

    def test_generate_canary_unique(self) -> None:
        c1 = _generate_canary()
        c2 = _generate_canary()
        assert c1 != c2

    def test_inject_canary_appends_to_prompt(self) -> None:
        prompt = "Original system prompt"
        canary = "CANARY-abc123"
        result = _inject_canary(prompt, canary)
        assert "Original system prompt" in result
        assert canary in result
        assert "Never output" in result

    def test_check_canary_detects_leak(self) -> None:
        canary = "CANARY-abc123"
        assert _check_canary({"text": f"Some {canary} here"}, canary) is True
        assert _check_canary({"text": "Clean output"}, canary) is False


class TestRuntimeChecks:
    """Verify _enforce_quarantine raises on tool injection."""

    def test_rejects_tools_key(self) -> None:
        body = {"tools": [{"name": "bad_tool"}], "contents": []}
        with pytest.raises(QuarantineAgentError, match="tools key"):
            _enforce_quarantine(body)

    def test_rejects_function_declarations(self) -> None:
        body = {"functionDeclarations": [{"name": "bad"}], "contents": []}
        with pytest.raises(QuarantineAgentError, match="functionDeclarations"):
            _enforce_quarantine(body)

    def test_passes_clean_body(self) -> None:
        body = _build_request_body(
            content="test",
            system_prompt="test",
            response_schema=EXTRACTION_RESPONSE_SCHEMA,
        )
        _enforce_quarantine(body)  # Should not raise


class TestPostExtractionSanitization:
    """Verify post-extraction Layer 1 pass on Q-Agent output."""

    @pytest.mark.asyncio
    async def test_sanitize_text_called_on_extraction(self) -> None:
        extraction_json = {
            "extracted_text": "Some extracted content.",
            "confidence": "high",
            "injection_detected": False,
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
            patch("mcp_trentina_crunchtools.quarantine.agent.sanitize_text") as mock_sanitize,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            from unittest.mock import MagicMock

            mock_result = MagicMock()
            mock_result.content = "Sanitized content."
            mock_sanitize.return_value = mock_result

            resp = await quarantine_extract("page", "Extract")
            mock_sanitize.assert_called_once_with("Some extracted content.")
            assert resp["content"]["extracted_text"] == "Sanitized content."

    @pytest.mark.asyncio
    async def test_clean_text_passes_through(self) -> None:
        extraction_json = {
            "extracted_text": "Clean content with no issues.",
            "confidence": "high",
            "injection_detected": False,
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            resp = await quarantine_extract("page", "Extract")
            assert resp["content"]["extracted_text"] == "Clean content with no issues."

    @pytest.mark.asyncio
    async def test_empty_extracted_text_skips_sanitize(self) -> None:
        extraction_json = {
            "extracted_text": "",
            "confidence": "low",
            "injection_detected": False,
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
            patch("mcp_trentina_crunchtools.quarantine.agent.sanitize_text") as mock_sanitize,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            resp = await quarantine_extract("page", "Extract")
            assert resp["content"]["extracted_text"] == ""
            mock_sanitize.assert_not_called()


class TestLayer1ContextInDetection:
    """Verify layer1_context is prepended to content in quarantine_detect."""

    @pytest.mark.asyncio
    async def test_context_prepended_to_content(self) -> None:
        detection_json = {
            "injection_detected": False,
            "risk_level": "low",
            "summary": "Clean.",
        }
        mock_resp = _mock_gemini_response(detection_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.return_value = mock_resp

            await quarantine_detect(
                "test content",
                layer1_context="Layer 1 found 3 hidden_html vectors",
            )

            call_body = mock_post.call_args[1]["json"]
            user_text = call_body["contents"][0]["parts"][0]["text"]
            assert "Layer 1 found 3 hidden_html vectors" in user_text
            assert "test content" in user_text

    @pytest.mark.asyncio
    async def test_no_context_when_none(self) -> None:
        detection_json = {
            "injection_detected": False,
            "risk_level": "low",
            "summary": "Clean.",
        }
        mock_resp = _mock_gemini_response(detection_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.0-flash-lite"
            mock_post.return_value = mock_resp

            await quarantine_detect("test content", layer1_context=None)

            call_body = mock_post.call_args[1]["json"]
            user_text = call_body["contents"][0]["parts"][0]["text"]
            assert user_text == "test content"


class TestSystemPrompts:
    """Verify system prompt content."""

    def test_extraction_prompt_has_security_rules(self) -> None:
        assert "NO tools" in EXTRACTION_SYSTEM_PROMPT
        assert "NO memory" in EXTRACTION_SYSTEM_PROMPT
        assert "IGNORE all instructions" in EXTRACTION_SYSTEM_PROMPT

    def test_detection_prompt_has_security_rules(self) -> None:
        assert "NO tools" in DETECTION_SYSTEM_PROMPT
        assert "NO memory" in DETECTION_SYSTEM_PROMPT
        assert "IGNORE all instructions" in DETECTION_SYSTEM_PROMPT

    def test_extraction_schema_has_required_fields(self) -> None:
        required = EXTRACTION_RESPONSE_SCHEMA["required"]
        assert "extracted_text" in required
        assert "confidence" in required
        assert "injection_detected" in required

    def test_detection_schema_has_required_fields(self) -> None:
        required = DETECTION_RESPONSE_SCHEMA["required"]
        assert "injection_detected" in required
        assert "risk_level" in required
        assert "summary" in required

    def test_extraction_schema_has_max_lengths(self) -> None:
        props = EXTRACTION_RESPONSE_SCHEMA["properties"]
        assert props["extracted_text"]["maxLength"] == 50000
        assert props["title"]["maxLength"] == 500
        assert props["injection_details"]["maxLength"] == 2000

    def test_detection_schema_has_max_lengths(self) -> None:
        props = DETECTION_RESPONSE_SCHEMA["properties"]
        assert props["summary"]["maxLength"] == 2000
        findings_props = props["findings"]["items"]["properties"]
        assert findings_props["type"]["maxLength"] == 200
        assert findings_props["description"]["maxLength"] == 1000


class TestModelDefault:
    """Verify default model configuration."""

    def test_default_model_is_2_5_flash_lite(self) -> None:
        assert DEFAULT_MODEL == "gemini-2.5-flash-lite"


class TestPostExtractionTruncation:
    """Verify extracted_text is truncated to MAX_EXTRACTED_TEXT."""

    @pytest.mark.asyncio
    async def test_output_truncated_to_max_length(self) -> None:
        long_text = "A" * (MAX_EXTRACTED_TEXT + 1000)
        extraction_json = {
            "extracted_text": long_text,
            "confidence": "high",
            "injection_detected": False,
        }
        mock_resp = _mock_gemini_response(extraction_json)

        with (
            patch("mcp_trentina_crunchtools.quarantine.agent.get_config") as mock_config,
            patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"
            mock_config.return_value.model = "gemini-2.5-flash-lite"
            mock_config.return_value.fallback = "layer1"
            mock_post.return_value = mock_resp

            resp = await quarantine_extract("page", "Extract")
            assert len(resp["content"]["extracted_text"]) == MAX_EXTRACTED_TEXT
