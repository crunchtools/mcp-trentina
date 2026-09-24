"""Tests for search tools (spec 005)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_trentina_crunchtools.errors import BlockedSourceError, QuarantineAgentError
from mcp_trentina_crunchtools.quarantine.agent import (
    _build_search_request_body,
    _enforce_search_quarantine,
    _extract_grounding_sources,
    _extract_grounding_supports,
    resolve_grounding_urls,
    search_grounded,
)
from mcp_trentina_crunchtools.quarantine.classifier import ClassifierResult
from mcp_trentina_crunchtools.tools.search import (
    block_search,
    clean_search,
    warn_search,
)

from .mode_harness import layers


def _mock_gemini_grounding_response(
    text: str = "RHEL 10 introduced bootc for image-based deployments.",
    sources: list[dict[str, str]] | None = None,
    supports: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a mock Gemini REST API response with grounding metadata."""
    if sources is None:
        sources = [
            {
                "web": {
                    "uri": "https://docs.redhat.com/bootc",
                    "title": "Getting Started with bootc",
                }
            },
            {
                "web": {
                    "uri": "https://crunchtools.com/bootc/",
                    "title": "Image mode for RHEL",
                }
            },
        ]
    if supports is None:
        supports = [
            {
                "segment": {"startIndex": 0, "endIndex": 50, "text": text[:50]},
                "groundingChunkIndices": [0],
                "confidenceScores": [0.92],
            }
        ]

    return {
        "candidates": [
            {
                "content": {"parts": [{"text": text}]},
                "groundingMetadata": {
                    "groundingChunks": sources,
                    "groundingSupports": supports,
                },
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 320,
            "candidatesTokenCount": 580,
        },
    }


class TestL0SearchGrounded:
    """Tests for L0 Gemini grounding call."""

    @pytest.mark.asyncio
    async def test_l0_returns_text_and_metadata(self) -> None:
        """Mocked grounding response parsed correctly."""
        mock_resp = _mock_gemini_grounding_response()

        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.agent.get_config",
            ) as mock_config,
            patch(
                "mcp_trentina_crunchtools.quarantine.agent.httpx.AsyncClient",
            ) as mock_client_cls,
        ):
            cfg = MagicMock()
            cfg.has_api_key = True
            cfg.api_key.get_secret_value.return_value = "fake-key"
            cfg.model = "gemini-2.5-flash-lite"
            mock_config.return_value = cfg

            mock_resp_obj = MagicMock()
            mock_resp_obj.json.return_value = mock_resp
            mock_resp_obj.raise_for_status = MagicMock()

            mock_http = AsyncMock()
            mock_http.post.return_value = mock_resp_obj
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_http

            result = await search_grounded("RHEL 10 bootc")

            assert "bootc" in result["text"]
            assert len(result["sources"]) == 2
            assert result["sources"][0]["uri"] == "https://docs.redhat.com/bootc"
            assert len(result["supports"]) == 1
            assert result["usage"]["input_tokens"] == 320

    @pytest.mark.asyncio
    async def test_l0_missing_api_key(self) -> None:
        """Raises QuarantineAgentError when API key is missing."""
        with patch(
            "mcp_trentina_crunchtools.quarantine.agent.get_config",
        ) as mock_config:
            cfg = MagicMock()
            cfg.has_api_key = False
            mock_config.return_value = cfg

            with pytest.raises(QuarantineAgentError, match="GEMINI_API_KEY"):
                await search_grounded("test query")

    @pytest.mark.asyncio
    async def test_l0_canary_in_text(self) -> None:
        """Canary in plain text raises QuarantineAgentError."""
        with (
            patch(
                "mcp_trentina_crunchtools.quarantine.agent.get_config",
            ) as mock_config,
            patch(
                "mcp_trentina_crunchtools.quarantine.agent._generate_canary",
                return_value="CANARY-abc123",
            ),
            patch(
                "mcp_trentina_crunchtools.quarantine.agent.httpx.AsyncClient",
            ) as mock_client_cls,
        ):
            cfg = MagicMock()
            cfg.has_api_key = True
            cfg.api_key.get_secret_value.return_value = "fake-key"
            cfg.model = "gemini-2.5-flash-lite"
            mock_config.return_value = cfg

            mock_resp = _mock_gemini_grounding_response(
                text="Here is CANARY-abc123 leaked in output"
            )
            mock_resp_obj = MagicMock()
            mock_resp_obj.json.return_value = mock_resp
            mock_resp_obj.raise_for_status = MagicMock()

            mock_http = AsyncMock()
            mock_http.post.return_value = mock_resp_obj
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_http

            with pytest.raises(QuarantineAgentError, match="canary"):
                await search_grounded("test query")


class TestL0QuarantineEnforcement:
    """Tests for _enforce_search_quarantine()."""

    def test_valid_request(self) -> None:
        """Valid L0 request body passes."""
        body = _build_search_request_body("test", "system prompt")
        assert "functionDeclarations" not in body
        assert len(body.get("tools", [])) == 1
        assert "google_search" in body["tools"][0]
        # The three checks above establish the body genuinely satisfies every
        # invariant _enforce_search_quarantine checks, so this call exercises
        # the real pass-through path rather than a body rigged to pass.
        assert _enforce_search_quarantine(body) is None

    def test_rejects_function_declarations(self) -> None:
        """functionDeclarations rejected."""
        body = _build_search_request_body("test", "system prompt")
        body["functionDeclarations"] = [{"name": "evil"}]
        with pytest.raises(QuarantineAgentError, match="functionDeclarations"):
            _enforce_search_quarantine(body)

    def test_rejects_extra_tools(self) -> None:
        """More than 1 tool rejected."""
        body = _build_search_request_body("test", "system prompt")
        body["tools"].append({"code_execution": {}})
        with pytest.raises(QuarantineAgentError, match="exactly 1 tool"):
            _enforce_search_quarantine(body)

    def test_rejects_wrong_tool(self) -> None:
        """Non-google_search tool rejected."""
        body = {"tools": [{"code_execution": {}}]}
        with pytest.raises(QuarantineAgentError, match="google_search"):
            _enforce_search_quarantine(body)

    def test_no_structured_output(self) -> None:
        """Request body has no responseMimeType/responseSchema."""
        body = _build_search_request_body("test", "system prompt")
        gen_config = body.get("generationConfig", {})
        assert "responseMimeType" not in gen_config
        assert "responseSchema" not in gen_config


class TestGroundingExtraction:
    """Tests for _extract_grounding_sources and _extract_grounding_supports."""

    def test_extract_sources(self) -> None:
        """Sources extracted from groundingChunks."""
        metadata = {
            "groundingChunks": [
                {"web": {"uri": "https://example.com", "title": "Example"}},
                {"web": {"uri": "https://test.com", "title": "Test"}},
            ]
        }
        sources = _extract_grounding_sources(metadata)
        assert len(sources) == 2
        assert sources[0]["uri"] == "https://example.com"
        assert sources[1]["title"] == "Test"

    def test_extract_sources_empty(self) -> None:
        """Empty metadata returns empty list."""
        assert _extract_grounding_sources({}) == []

    def test_extract_supports(self) -> None:
        """Supports extracted from groundingSupports."""
        metadata = {
            "groundingSupports": [
                {
                    "segment": {"text": "Some text"},
                    "groundingChunkIndices": [0],
                    "confidenceScores": [0.95],
                }
            ]
        }
        supports = _extract_grounding_supports(metadata)
        assert len(supports) == 1
        assert supports[0]["text"] == "Some text"
        assert supports[0]["chunk_indices"] == [0]
        assert supports[0]["confidence"] == [0.95]


class TestRedirectResolution:
    """Tests for resolve_grounding_urls()."""

    @pytest.mark.asyncio
    async def test_resolve_redirect_url(self) -> None:
        """Mocked redirect resolves to final URL."""
        sources = [
            {
                "uri": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/abc",
                "title": "Test Page",
            }
        ]

        with patch(
            "mcp_trentina_crunchtools.quarantine.agent.httpx.AsyncClient",
        ) as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.url = httpx.URL("https://example.com/final")

            mock_http = AsyncMock()
            mock_http.head.return_value = mock_resp
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_http

            resolved = await resolve_grounding_urls(sources)

            assert len(resolved) == 1
            assert resolved[0]["uri"] == "https://example.com/final"
            assert resolved[0]["title"] == "Test Page"
            assert "original_redirect" in resolved[0]

    @pytest.mark.asyncio
    async def test_resolve_non_redirect(self) -> None:
        """Non-redirect URL returned as-is."""
        sources = [{"uri": "https://example.com/page", "title": "Direct Page"}]

        with patch(
            "mcp_trentina_crunchtools.quarantine.agent.httpx.AsyncClient",
        ) as mock_client_cls:
            mock_http = AsyncMock()
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_http

            resolved = await resolve_grounding_urls(sources)

            assert len(resolved) == 1
            assert resolved[0]["uri"] == "https://example.com/page"
            assert resolved[0]["title"] == "Direct Page"
            mock_http.head.assert_not_called()

    @pytest.mark.asyncio
    async def test_resolve_timeout(self) -> None:
        """Failed resolution flagged but not dropped."""
        sources = [
            {
                "uri": "https://vertexaisearch.cloud.google.com/grounding-api-redirect/xyz",
                "title": "Timeout Page",
            }
        ]

        with patch(
            "mcp_trentina_crunchtools.quarantine.agent.httpx.AsyncClient",
        ) as mock_client_cls:
            mock_http = AsyncMock()
            mock_http.head.side_effect = httpx.TimeoutException("timeout")
            mock_http.__aenter__ = AsyncMock(return_value=mock_http)
            mock_http.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_http

            resolved = await resolve_grounding_urls(sources)

            assert len(resolved) == 1
            assert resolved[0]["redirect_failed"] == "true"
            assert resolved[0]["title"] == "Timeout Page"


class TestSearchThroughTheOneJudgingPath:
    """Search is a producer like any other (#187). The per-family mode matrix
    lives in test_mode_parity / test_mode_gaps; these are search's own edges."""

    @pytest.mark.parametrize("mode", ["block", "warn", "clean"])
    async def test_an_l0_failure_refuses_in_every_mode(self, env: Path, mode: str) -> None:
        """clean_search used to return {"error": ...} instead."""
        with layers(env) as fakes:
            fakes.search_grounded.side_effect = QuarantineAgentError("HTTP 503")
            call = {
                "block": lambda: block_search("q"),
                "warn": lambda: warn_search("q"),
                "clean": lambda: clean_search("q", "Summarize."),
            }[mode]
            with pytest.raises(BlockedSourceError):
                await call()

    async def test_l0_output_is_recorded_as_model_output(self, env: Path) -> None:
        with (
            layers(
                env,
                classification=ClassifierResult(
                    label="MALICIOUS",
                    score=0.9,
                    latency_ms=1.0,
                ),
            ),
            patch("mcp_trentina_crunchtools.defense.record_detection") as record,
        ):
            await warn_search("q")
        assert record.call_args.kwargs["provenance"] == "model_output"

    async def test_block_and_warn_deliver_l0_text_and_sources(self, env: Path) -> None:
        with layers(env) as fakes:
            result = await block_search("q")
        assert result["content"] == fakes.payload
        assert result["sources"] == [
            {"uri": "https://example.com/a", "title": "A", "redirect_failed": False}
        ]
        assert result["query"] == "q"

    async def test_clean_delivers_the_extraction_and_sources_not_the_answer(
        self, env: Path
    ) -> None:
        with layers(env) as fakes:
            result = await clean_search("q", "Summarize.")
        assert result["content"]["extracted_text"] != fakes.payload
        assert result["sources"][0]["uri"] == "https://example.com/a"
        assert "text" not in result
