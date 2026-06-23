"""Tests for scan tools — quarantine_scan and deep_quarantine_scan."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_trentina_crunchtools.tools.scan import (
    _build_layer1_context,
    _build_scan_result,
    deep_quarantine_scan,
    quarantine_scan,
)


class TestBuildLayer1Context:
    """Verify Layer 1 context string construction."""

    def test_returns_none_when_no_detections(self) -> None:
        stats = {"hidden_html": 0, "invisible_unicode": 0}
        result = _build_layer1_context(stats, detections=0)
        assert result is None

    def test_returns_context_with_detections(self) -> None:
        stats = {"hidden_html": 3, "invisible_unicode": 0, "encoded_payloads": 2}
        result = _build_layer1_context(stats, detections=5)
        assert result is not None
        assert "hidden_html: 3" in result
        assert "encoded_payloads: 2" in result
        assert "invisible_unicode" not in result  # zero values excluded


class TestBuildScanResult:
    """Verify scan result construction."""

    def test_standard_mode(self) -> None:
        result = _build_scan_result(
            source_type="url",
            source="https://example.com",
            layer1_stats={"hidden_html": 0},
            layer1_risk="low",
            layer1_detections=0,
            qagent_assessment=None,
            has_api_key=False,
            scan_mode="standard",
        )
        assert result["scan_mode"] == "standard"
        assert result["risk_level"] == "low"

    def test_deep_mode(self) -> None:
        result = _build_scan_result(
            source_type="file",
            source="/tmp/test.txt",
            layer1_stats={},
            layer1_risk="low",
            layer1_detections=0,
            qagent_assessment=None,
            has_api_key=False,
            scan_mode="deep",
        )
        assert result["scan_mode"] == "deep"

    def test_overall_risk_takes_max(self) -> None:
        result = _build_scan_result(
            source_type="url",
            source="https://example.com",
            layer1_stats={},
            layer1_risk="medium",
            layer1_detections=2,
            qagent_assessment={"risk_level": "high", "injection_detected": True},
            has_api_key=True,
        )
        assert result["risk_level"] == "high"


class TestDeepScanVsStandardScan:
    """Verify deep_quarantine_scan sends raw content, standard sends sanitized."""

    @pytest.mark.asyncio
    async def test_deep_scan_passes_raw_content(self) -> None:
        with (
            patch("mcp_trentina_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_trentina_crunchtools.tools.scan._fetch_content",
                new_callable=AsyncMock,
            ) as mock_fetch,
            patch("mcp_trentina_crunchtools.tools.scan.looks_like_html") as mock_html,
            patch("mcp_trentina_crunchtools.tools.scan.sanitize_text") as mock_sanitize,
            patch(
                "mcp_trentina_crunchtools.tools.scan.quarantine_detect",
                new_callable=AsyncMock,
            ) as mock_detect,
        ):
            raw = "RAW UNSANITIZED CONTENT"
            mock_fetch.return_value = (raw, "file", "/tmp/test.txt")
            mock_html.return_value = False

            mock_pipeline = MagicMock()
            mock_pipeline.content = "SANITIZED CONTENT"
            mock_pipeline.stats.to_flat_dict.return_value = {}
            mock_pipeline.stats.risk_level.return_value = "low"
            mock_pipeline.stats.total_detections.return_value = 0
            mock_sanitize.return_value = mock_pipeline

            mock_config.return_value.has_api_key = True
            mock_config.return_value.max_content = 100000

            mock_detect.return_value = {
                "injection_detected": False,
                "risk_level": "low",
                "summary": "Clean",
            }

            result = await deep_quarantine_scan(path="/tmp/test.txt")

            detect_content = mock_detect.call_args[0][0]
            assert detect_content == raw
            assert result["scan_mode"] == "deep"

    @pytest.mark.asyncio
    async def test_standard_scan_passes_sanitized_content(self) -> None:
        with (
            patch("mcp_trentina_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_trentina_crunchtools.tools.scan._fetch_content",
                new_callable=AsyncMock,
            ) as mock_fetch,
            patch("mcp_trentina_crunchtools.tools.scan.looks_like_html") as mock_html,
            patch("mcp_trentina_crunchtools.tools.scan.sanitize_text") as mock_sanitize,
            patch(
                "mcp_trentina_crunchtools.tools.scan.quarantine_detect",
                new_callable=AsyncMock,
            ) as mock_detect,
        ):
            raw = "RAW UNSANITIZED CONTENT"
            mock_fetch.return_value = (raw, "file", "/tmp/test.txt")
            mock_html.return_value = False

            mock_pipeline = MagicMock()
            mock_pipeline.content = "SANITIZED CONTENT"
            mock_pipeline.stats.to_flat_dict.return_value = {}
            mock_pipeline.stats.risk_level.return_value = "low"
            mock_pipeline.stats.total_detections.return_value = 0
            mock_sanitize.return_value = mock_pipeline

            mock_config.return_value.has_api_key = True
            mock_config.return_value.max_content = 100000

            mock_detect.return_value = {
                "injection_detected": False,
                "risk_level": "low",
                "summary": "Clean",
            }

            result = await quarantine_scan(path="/tmp/test.txt")

            detect_content = mock_detect.call_args[0][0]
            assert detect_content == "SANITIZED CONTENT"
            assert result["scan_mode"] == "standard"

    @pytest.mark.asyncio
    async def test_deep_scan_no_qagent_without_api_key(self) -> None:
        with (
            patch("mcp_trentina_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_trentina_crunchtools.tools.scan._fetch_content",
                new_callable=AsyncMock,
            ) as mock_fetch,
            patch("mcp_trentina_crunchtools.tools.scan.looks_like_html") as mock_html,
            patch("mcp_trentina_crunchtools.tools.scan.sanitize_text") as mock_sanitize,
            patch(
                "mcp_trentina_crunchtools.tools.scan.quarantine_detect",
                new_callable=AsyncMock,
            ) as mock_detect,
        ):
            mock_fetch.return_value = ("content", "file", "/tmp/test.txt")
            mock_html.return_value = False

            mock_pipeline = MagicMock()
            mock_pipeline.content = "sanitized"
            mock_pipeline.stats.to_flat_dict.return_value = {}
            mock_pipeline.stats.risk_level.return_value = "low"
            mock_pipeline.stats.total_detections.return_value = 0
            mock_sanitize.return_value = mock_pipeline

            mock_config.return_value.has_api_key = False
            mock_config.return_value.max_content = 100000

            result = await deep_quarantine_scan(path="/tmp/test.txt")

            mock_detect.assert_not_called()
            assert result["qagent"]["available"] is False
            assert result["scan_mode"] == "deep"
