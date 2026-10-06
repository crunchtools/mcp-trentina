"""Tests for search tools (spec 005)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from trentina.errors import BlockedSourceError, QuarantineAgentError
from trentina.quarantine.agent import (
    _build_search_request_body,
    _enforce_search_quarantine,
    _extract_grounding_sources,
    _extract_grounding_supports,
    resolve_grounding_urls,
    search_grounded,
)
from trentina.quarantine.classifier import ClassifierResult
from trentina.tools.search import (
    block_search,
    flag_search,
    redact_search,
)

from .egress_harness import route
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
    """Tests for L0 Gemini grounding, the standalone fallback route."""

    @pytest.mark.asyncio
    async def test_l0_returns_text_and_metadata(self) -> None:
        """Mocked grounding response parsed correctly."""
        mock_resp = _mock_gemini_grounding_response()

        with (
            patch(
                "trentina.quarantine.agent.get_config",
            ) as mock_config,
            patch(
                "trentina.quarantine.agent.httpx.AsyncClient",
            ) as mock_client_cls,
        ):
            cfg = MagicMock()
            cfg.has_api_key = True
            cfg.api_key.get_secret_value.return_value = "fake-key"
            cfg.openrouter_api_key.get_secret_value.return_value = ""
            cfg.search_model = "google/gemini-2.5-flash"
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
            "trentina.quarantine.agent.get_config",
        ) as mock_config:
            cfg = MagicMock()
            cfg.has_api_key = False
            cfg.openrouter_api_key.get_secret_value.return_value = ""
            mock_config.return_value = cfg

            with pytest.raises(QuarantineAgentError, match="no search provider"):
                await search_grounded("test query")

    @pytest.mark.asyncio
    async def test_l0_canary_in_text(self) -> None:
        """Canary in plain text raises QuarantineAgentError."""
        with (
            patch(
                "trentina.quarantine.agent.get_config",
            ) as mock_config,
            patch(
                "trentina.quarantine.agent._generate_canary",
                return_value="CANARY-abc123",
            ),
            patch(
                "trentina.quarantine.agent.httpx.AsyncClient",
            ) as mock_client_cls,
        ):
            cfg = MagicMock()
            cfg.has_api_key = True
            cfg.api_key.get_secret_value.return_value = "fake-key"
            cfg.openrouter_api_key.get_secret_value.return_value = ""
            cfg.search_model = "google/gemini-2.5-flash"
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
    """Tests for resolve_grounding_urls(). Every hop passes the egress guard (#260)."""

    REDIRECT = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/abc"

    @pytest.mark.asyncio
    async def test_resolve_redirect_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A grounding redirect resolves to its final URL, hop by hop."""

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "HEAD"
            if request.url.host == "vertexaisearch.cloud.google.com":
                return httpx.Response(302, headers={"location": "https://example.com/final"})
            return httpx.Response(200)

        route(monkeypatch, handler)
        resolved = await resolve_grounding_urls([{"uri": self.REDIRECT, "title": "Test Page"}])

        assert resolved == [
            {
                "uri": "https://example.com/final",
                "title": "Test Page",
                "original_redirect": self.REDIRECT,
            }
        ]

    @pytest.mark.asyncio
    async def test_resolve_non_redirect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-redirect URL returned as-is, and never requested."""
        route(monkeypatch, _never_requested)
        sources = [{"uri": "https://example.com/page", "title": "Direct Page"}]
        assert await resolve_grounding_urls(sources) == sources

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "uri",
        [
            "http://10.89.0.1/?vertexaisearch.cloud.google.com",
            "http://10.89.0.1/grounding-api-redirect/x",
            "https://vertexaisearch.cloud.google.com.evil.example/x",
            "https://evil.example/#vertexaisearch.cloud.google.com",
        ],
    )
    async def test_only_the_exact_host_is_resolved(
        self, monkeypatch: pytest.MonkeyPatch, uri: str
    ) -> None:
        """The substring test let any URI naming the host get a HEAD."""
        route(monkeypatch, _never_requested)
        sources = [{"uri": uri, "title": "t"}]
        assert await resolve_grounding_urls(sources) == sources

    @pytest.mark.asyncio
    async def test_a_redirect_inward_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(request.url.host)
            return httpx.Response(302, headers={"location": "https://metadata.internal/"})

        route(monkeypatch, handler, {"metadata.internal": ["169.254.169.254"]})
        resolved = await resolve_grounding_urls([{"uri": self.REDIRECT, "title": "t"}])

        assert resolved[0]["redirect_failed"] == "true"
        assert resolved[0]["uri"] == self.REDIRECT
        assert requested == ["vertexaisearch.cloud.google.com"]

    @pytest.mark.asyncio
    async def test_resolve_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Failed resolution flagged but not dropped."""

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("timeout")

        route(monkeypatch, handler)
        resolved = await resolve_grounding_urls([{"uri": self.REDIRECT, "title": "Timeout Page"}])

        assert len(resolved) == 1
        assert resolved[0]["redirect_failed"] == "true"
        assert resolved[0]["title"] == "Timeout Page"


def _never_requested(_request: httpx.Request) -> httpx.Response:
    raise AssertionError("this URI must not be requested")


class TestSearchThroughTheOneJudgingPath:
    """Search is a producer like any other (#187). The per-family mode matrix
    lives in test_mode_parity / test_mode_gaps; these are search's own edges."""

    @pytest.mark.parametrize("mode", ["block", "flag", "redact"])
    async def test_an_l0_failure_raises_in_every_mode(self, env: Path, mode: str) -> None:
        """redact_search used to return {"error": ...} instead.

        A provider failure is the provider breaking, not the defense working
        (#293): it raises as one, with none of the provider's text (#292).
        """
        with layers(env) as fakes:
            fakes.search_grounded.side_effect = QuarantineAgentError(
                "HTTP 503 from http://ollama.internal:11434", status_code=503
            )
            call = {
                "block": lambda: block_search("q"),
                "flag": lambda: flag_search("q"),
                "redact": lambda: redact_search("q", "Summarize."),
            }[mode]
            with pytest.raises(QuarantineAgentError) as failed:
                await call()
        assert not isinstance(failed.value, BlockedSourceError)
        assert str(failed.value) == "Q-Agent error: search provider unavailable"
        assert failed.value.status_code == 503
        assert failed.value.__cause__ is None

    @pytest.mark.parametrize("mode", ["block", "flag", "redact"])
    async def test_an_l0_canary_leak_refuses_in_every_mode(self, env: Path, mode: str) -> None:
        from trentina.errors import SearchCanaryLeakedError

        with layers(env) as fakes:
            fakes.search_grounded.side_effect = SearchCanaryLeakedError()
            call = {
                "block": lambda: block_search("q"),
                "flag": lambda: flag_search("q"),
                "redact": lambda: redact_search("q", "Summarize."),
            }[mode]
            with pytest.raises(BlockedSourceError) as refused:
                await call()
        assert refused.value.refusal == {
            "reason": "L0 canary leaked",
            "mode": mode,
            "flagged_by": "l0",
            "alternatives": [],
        }

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
            patch("trentina.defense.record_detection") as record,
        ):
            await flag_search("q")
        assert record.call_args.kwargs["provenance"] == "model_output"

    async def test_block_and_flag_deliver_l0_text_and_sources(self, env: Path) -> None:
        with layers(env) as fakes:
            result = await block_search("q")
        assert result["content"] == fakes.payload
        assert result["sources"] == [
            {"uri": "https://example.com/a", "title": "A", "redirect_failed": False}
        ]
        assert result["query"] == "q"

    async def test_redact_delivers_the_extraction_and_sources_not_the_answer(
        self, env: Path
    ) -> None:
        with layers(env) as fakes:
            result = await redact_search("q", "Summarize.")
        assert result["content"]["extracted_text"] != fakes.payload
        assert result["sources"][0]["uri"] == "https://example.com/a"
        assert "text" not in result
