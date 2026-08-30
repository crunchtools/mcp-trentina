"""Tests for unified scan tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_airlock_crunchtools.tools.scan import (
    _build_layer1_context,
    scan,
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


class TestUnifiedScan:
    """Verify unified scan tool behavior."""

    @pytest.mark.asyncio
    async def test_scan_url(self) -> None:
        """URL scan returns threat assessment."""
        with (
            patch("mcp_airlock_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_airlock_crunchtools.tools.scan.fetch_url",
                new_callable=AsyncMock,
                return_value=("Clean content", "text/plain"),
            ),
            patch(
                "mcp_airlock_crunchtools.tools.scan.classify",
                return_value=None,
            ),
        ):
            mock_config.return_value.has_api_key = False
            mock_config.return_value.max_content = 100000

            result = await scan(url="https://example.com")

            assert result["source_type"] == "url"
            assert result["source"] == "https://example.com"
            assert result["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_scan_file(self) -> None:
        """File scan uses _validate_file."""
        with (
            patch("mcp_airlock_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_airlock_crunchtools.tools.scan._validate_file",
                return_value="/tmp/test.txt",
            ),
            patch(
                "builtins.open",
                MagicMock(
                    return_value=MagicMock(
                        __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value="file content"))),
                        __exit__=MagicMock(return_value=False),
                    )
                ),
            ),
            patch(
                "mcp_airlock_crunchtools.tools.scan.classify",
                return_value=None,
            ),
            patch(
                "mcp_airlock_crunchtools.tools.scan.looks_like_html",
                return_value=False,
            ),
        ):
            mock_config.return_value.has_api_key = False
            mock_config.return_value.max_content = 100000

            result = await scan(path="/tmp/test.txt")

            assert result["source_type"] == "file"

    @pytest.mark.asyncio
    async def test_scan_content(self) -> None:
        """Inline content scan uses hash for source."""
        with (
            patch("mcp_airlock_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_airlock_crunchtools.tools.scan.classify",
                return_value=None,
            ),
        ):
            mock_config.return_value.has_api_key = False
            mock_config.return_value.max_content = 100000

            result = await scan(content="test content")

            assert result["source_type"] == "content"
            assert result["source"].startswith("sha256:")

    @pytest.mark.asyncio
    async def test_scan_with_qagent(self) -> None:
        """Q-Agent detection runs when API key available."""
        with (
            patch("mcp_airlock_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_airlock_crunchtools.tools.scan.fetch_url",
                new_callable=AsyncMock,
                return_value=("content", "text/plain"),
            ),
            patch(
                "mcp_airlock_crunchtools.tools.scan.classify",
                return_value=None,
            ),
            patch(
                "mcp_airlock_crunchtools.tools.scan.quarantine_detect",
                new_callable=AsyncMock,
            ) as mock_detect,
        ):
            mock_config.return_value.has_api_key = True
            mock_config.return_value.max_content = 100000

            mock_detect.return_value = {
                "injection_detected": False,
                "risk_level": "low",
                "summary": "Clean",
            }

            result = await scan(url="https://example.com")

            mock_detect.assert_called_once()
            assert result["qagent"]["available"] is True

    @pytest.mark.asyncio
    async def test_scan_no_qagent_without_api_key(self) -> None:
        """Q-Agent detection skipped without API key."""
        with (
            patch("mcp_airlock_crunchtools.tools.scan.get_config") as mock_config,
            patch(
                "mcp_airlock_crunchtools.tools.scan.fetch_url",
                new_callable=AsyncMock,
                return_value=("content", "text/plain"),
            ),
            patch(
                "mcp_airlock_crunchtools.tools.scan.classify",
                return_value=None,
            ),
            patch(
                "mcp_airlock_crunchtools.tools.scan.quarantine_detect",
                new_callable=AsyncMock,
            ) as mock_detect,
        ):
            mock_config.return_value.has_api_key = False
            mock_config.return_value.max_content = 100000

            result = await scan(url="https://example.com")

            mock_detect.assert_not_called()
            assert result["qagent"]["available"] is False
