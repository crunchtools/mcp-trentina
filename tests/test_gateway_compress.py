"""Tests for gateway/compress.py — tool description compression."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcp_trentina_crunchtools.gateway import compress as compress_mod
from mcp_trentina_crunchtools.gateway.compress import (
    _cache,
    _call_compress_model,
    _hash_description,
    _precompress_backend,
    compress_tools,
    maybe_trigger_compression,
    set_profiles,
)


def _tool(name: str, description: str, schema: dict | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": schema or {"type": "object", "properties": {}},
    }


class TestCompressTools:
    """Sync cache-lookup tests for compress_tools()."""

    def setup_method(self) -> None:
        _cache.clear()

    def test_cache_hit_replaces_description(self) -> None:
        original = "This is a very long verbose description that goes on and on"
        h = _hash_description(original)
        _cache[h] = "Short version."

        tools = [_tool("my_tool", original)]
        result = compress_tools(tools)

        assert result[0]["description"] == "Short version."

    def test_cache_miss_passes_through(self) -> None:
        tools = [_tool("my_tool", "Some description not in cache")]
        result = compress_tools(tools)

        assert result[0]["description"] == "Some description not in cache"

    def test_empty_cache_returns_original(self) -> None:
        tools = [_tool("a", "desc a"), _tool("b", "desc b")]
        result = compress_tools(tools)

        assert len(result) == 2
        assert result[0]["description"] == "desc a"
        assert result[1]["description"] == "desc b"

    def test_preserves_input_schema(self) -> None:
        schema = {"type": "object", "properties": {"url": {"type": "string"}}}
        original = "Fetch a URL and return content"
        h = _hash_description(original)
        _cache[h] = "Fetch URL."

        tools = [_tool("fetch", original, schema)]
        result = compress_tools(tools)

        assert result[0]["inputSchema"] == schema
        assert result[0]["name"] == "fetch"

    def test_preserves_extra_fields(self) -> None:
        original = "Some verbose description"
        h = _hash_description(original)
        _cache[h] = "Short."

        tool = _tool("t", original)
        tool["title"] = "My Title"
        tool["annotations"] = {"readOnly": True}

        result = compress_tools([tool])
        assert result[0]["title"] == "My Title"
        assert result[0]["annotations"] == {"readOnly": True}
        assert result[0]["description"] == "Short."

    def test_empty_description_passed_through(self) -> None:
        tools = [_tool("t", "")]
        result = compress_tools(tools)
        assert result[0]["description"] == ""

    def test_does_not_mutate_original_tool(self) -> None:
        original = "Long description here"
        h = _hash_description(original)
        _cache[h] = "Short."

        tool = _tool("t", original)
        compress_tools([tool])
        assert tool["description"] == original


class TestHashDescription:
    def test_deterministic(self) -> None:
        assert _hash_description("hello") == _hash_description("hello")

    def test_different_inputs_different_hashes(self) -> None:
        assert _hash_description("a") != _hash_description("b")

    def test_sha256(self) -> None:
        expected = hashlib.sha256(b"test").hexdigest()
        assert _hash_description("test") == expected


class TestDatabaseRoundTrip:
    """Test save/load cycle through SQLite."""

    def test_save_and_load(self, tmp_path: Any) -> None:
        from mcp_trentina_crunchtools import database as db_module
        from mcp_trentina_crunchtools.database import (
            get_all_compressions,
            get_db,
            save_compression,
        )

        db_path = str(tmp_path / "test.db")
        db_module._db = None
        get_db(db_path)

        save_compression("hash1", "original text", "short", "gemini-2.5-flash-lite")
        save_compression("hash2", "another original", "brief", "gemini-2.5-flash-lite")

        result = get_all_compressions()
        assert result["hash1"] == "short"
        assert result["hash2"] == "brief"

        db_module._db = None

    def test_compression_stats(self, tmp_path: Any) -> None:
        from mcp_trentina_crunchtools import database as db_module
        from mcp_trentina_crunchtools.database import (
            get_compression_stats,
            get_db,
            save_compression,
        )

        db_path = str(tmp_path / "test.db")
        db_module._db = None
        get_db(db_path)

        save_compression("h1", "a" * 200, "a" * 100, "model")
        save_compression("h2", "b" * 300, "b" * 150, "model")

        stats = get_compression_stats()
        assert stats["tools_compressed"] == 2
        assert stats["original_chars"] == 500
        assert stats["compressed_chars"] == 250
        assert stats["savings_percent"] == 50
        assert stats["estimated_tokens_saved"] == 62

        db_module._db = None


class TestCallCompressModel:
    """Test the Gemini API call with mocked httpx."""

    @pytest.mark.asyncio
    async def test_successful_compression(self) -> None:
        mock_response = {
            "candidates": [{
                "content": {
                    "parts": [{"text": json.dumps({
                        "compressed": [
                            {"id": "abc123", "text": "Short description."},
                        ]
                    })}]
                }
            }]
        }

        with patch("mcp_trentina_crunchtools.gateway.compress.get_config") as mock_config:
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "test-key"

            with patch("mcp_trentina_crunchtools.gateway.compress.httpx") as mock_httpx:
                mock_resp = MagicMock()
                mock_resp.json.return_value = mock_response
                mock_resp.raise_for_status.return_value = None

                mock_client = AsyncMock()
                mock_client.post.return_value = mock_resp

                mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client
                mock_httpx.Timeout = httpx.Timeout

                result = await _call_compress_model([("abc123", "Long verbose description")])

        assert len(result) == 1
        assert result[0] == ("abc123", "Short description.")

    @pytest.mark.asyncio
    async def test_no_api_key_returns_empty(self) -> None:
        with patch("mcp_trentina_crunchtools.gateway.compress.get_config") as mock_config:
            mock_config.return_value.has_api_key = False
            result = await _call_compress_model([("h1", "desc")])
        assert result == []

    @pytest.mark.asyncio
    async def test_api_failure_returns_empty(self) -> None:
        with patch("mcp_trentina_crunchtools.gateway.compress.get_config") as mock_config:
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "key"

            with patch("mcp_trentina_crunchtools.gateway.compress.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.post.side_effect = httpx.HTTPError("timeout")
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_cls.return_value = mock_client

                result = await _call_compress_model([("h1", "desc")])
        assert result == []


class TestPrecompressBackend:
    """Test the backend pre-compression flow."""

    @pytest.mark.asyncio
    async def test_skips_already_cached(self) -> None:
        _cache.clear()
        desc = "Already cached description"
        h = _hash_description(desc)
        _cache[h] = "Cached."

        mock_tools = [_tool("t1", desc)]

        with patch(
            "mcp_trentina_crunchtools.gateway.backend.list_backend_tools",
            new_callable=AsyncMock,
            return_value=mock_tools,
        ):
            from mcp_trentina_crunchtools.gateway.profile import Backend

            backend = Backend(url="http://test:8000/mcp")
            count = await _precompress_backend("test", backend)

        assert count == 0

    @pytest.mark.asyncio
    async def test_model_returns_longer_discarded(self) -> None:
        _cache.clear()
        original = "Short."

        mock_tools = [_tool("t1", original)]

        longer_result = [
            (_hash_description(original), "This is actually longer than the original text")
        ]

        with (
            patch(
                "mcp_trentina_crunchtools.gateway.backend.list_backend_tools",
                new_callable=AsyncMock,
                return_value=mock_tools,
            ),
            patch(
                "mcp_trentina_crunchtools.gateway.compress._call_compress_model",
                new_callable=AsyncMock,
                return_value=longer_result,
            ),
            patch("mcp_trentina_crunchtools.gateway.compress.save_compression"),
        ):
            from mcp_trentina_crunchtools.gateway.profile import Backend

            backend = Backend(url="http://test:8000/mcp")
            count = await _precompress_backend("test", backend)

        assert count == 0
        assert _hash_description(original) not in _cache


class TestMaybeTriggerCompression:
    """Tests for the lazy compression trigger."""

    def setup_method(self) -> None:
        _cache.clear()
        compress_mod._compress_triggered = False
        compress_mod._compress_task = None
        compress_mod._profiles = None

    @pytest.mark.asyncio
    async def test_triggers_once_only(self) -> None:
        from mcp_trentina_crunchtools.gateway.profile import AuthConfig, Backend, Profile

        auth = AuthConfig(bearer_token_env="TEST_TOKEN")
        profile = Profile(
            name="test",
            auth=auth,
            backends={"b": Backend(url="http://x:8000/mcp", compress_descriptions=True)},
        )
        set_profiles({"test": profile})

        with patch(
            "mcp_trentina_crunchtools.gateway.compress.precompress_all",
            new_callable=AsyncMock,
            return_value={},
        ) as mock_precompress:
            await maybe_trigger_compression()
            await maybe_trigger_compression()

        mock_precompress.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_profiles_is_noop(self) -> None:
        compress_mod._profiles = None
        with patch(
            "mcp_trentina_crunchtools.gateway.compress.precompress_all",
            new_callable=AsyncMock,
        ) as mock_precompress:
            await maybe_trigger_compression()

        mock_precompress.assert_not_called()
        assert not compress_mod._compress_triggered

    @pytest.mark.asyncio
    async def test_creates_background_task(self) -> None:
        from mcp_trentina_crunchtools.gateway.profile import AuthConfig, Backend, Profile

        auth = AuthConfig(bearer_token_env="TEST_TOKEN")
        profile = Profile(
            name="test",
            auth=auth,
            backends={"b": Backend(url="http://x:8000/mcp", compress_descriptions=True)},
        )
        set_profiles({"test": profile})

        with patch(
            "mcp_trentina_crunchtools.gateway.compress.precompress_all",
            new_callable=AsyncMock,
            return_value={},
        ):
            await maybe_trigger_compression()

        assert compress_mod._compress_task is not None
        assert compress_mod._compress_triggered is True


class TestRetryLogic:
    """Tests for Gemini API retry on 429/503."""

    def _gemini_response(self, items: list[tuple[str, str]]) -> dict[str, Any]:
        compressed = [{"id": h, "text": text} for h, text in items]
        return {
            "candidates": [{
                "content": {
                    "parts": [{"text": json.dumps({"compressed": compressed})}]
                }
            }]
        }

    @pytest.mark.asyncio
    async def test_retries_on_503(self) -> None:
        success_resp = MagicMock()
        success_resp.json.return_value = self._gemini_response([("h1", "Short.")])
        success_resp.raise_for_status.return_value = None

        error_resp = MagicMock()
        error_resp.status_code = 503
        error_503 = httpx.HTTPStatusError("503", request=MagicMock(), response=error_resp)

        with patch("mcp_trentina_crunchtools.gateway.compress.get_config") as mock_config:
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "key"

            with patch("mcp_trentina_crunchtools.gateway.compress.httpx") as mock_httpx:
                mock_client = AsyncMock()
                mock_client.post.side_effect = [error_503, success_resp]

                mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client
                mock_httpx.Timeout = httpx.Timeout
                mock_httpx.HTTPStatusError = httpx.HTTPStatusError

                with patch("mcp_trentina_crunchtools.gateway.compress.RETRY_BASE_DELAY", 0.01):
                    result = await _call_compress_model([("h1", "Long description")])

        assert len(result) == 1
        assert result[0] == ("h1", "Short.")
        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_429(self) -> None:
        success_resp = MagicMock()
        success_resp.json.return_value = self._gemini_response([("h1", "Short.")])
        success_resp.raise_for_status.return_value = None

        error_resp = MagicMock()
        error_resp.status_code = 429
        error_429 = httpx.HTTPStatusError("429", request=MagicMock(), response=error_resp)

        with patch("mcp_trentina_crunchtools.gateway.compress.get_config") as mock_config:
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "key"

            with patch("mcp_trentina_crunchtools.gateway.compress.httpx") as mock_httpx:
                mock_client = AsyncMock()
                mock_client.post.side_effect = [error_429, success_resp]

                mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client
                mock_httpx.Timeout = httpx.Timeout
                mock_httpx.HTTPStatusError = httpx.HTTPStatusError

                with patch("mcp_trentina_crunchtools.gateway.compress.RETRY_BASE_DELAY", 0.01):
                    result = await _call_compress_model([("h1", "Long description")])

        assert len(result) == 1
        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries(self) -> None:
        error_resp = MagicMock()
        error_resp.status_code = 503
        error_503 = httpx.HTTPStatusError("503", request=MagicMock(), response=error_resp)

        with patch("mcp_trentina_crunchtools.gateway.compress.get_config") as mock_config:
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "key"

            with patch("mcp_trentina_crunchtools.gateway.compress.httpx") as mock_httpx:
                mock_client = AsyncMock()
                mock_client.post.side_effect = error_503

                mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client
                mock_httpx.Timeout = httpx.Timeout
                mock_httpx.HTTPStatusError = httpx.HTTPStatusError

                with patch("mcp_trentina_crunchtools.gateway.compress.RETRY_BASE_DELAY", 0.01):
                    result = await _call_compress_model([("h1", "desc")])

        assert result == []
        assert mock_client.post.call_count == 3

    @pytest.mark.asyncio
    async def test_no_retry_on_400(self) -> None:
        error_resp = MagicMock()
        error_resp.status_code = 400
        error_400 = httpx.HTTPStatusError("400", request=MagicMock(), response=error_resp)

        with patch("mcp_trentina_crunchtools.gateway.compress.get_config") as mock_config:
            mock_config.return_value.has_api_key = True
            mock_config.return_value.api_key.get_secret_value.return_value = "key"

            with patch("mcp_trentina_crunchtools.gateway.compress.httpx") as mock_httpx:
                mock_client = AsyncMock()
                mock_client.post.side_effect = error_400

                mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client
                mock_httpx.Timeout = httpx.Timeout
                mock_httpx.HTTPStatusError = httpx.HTTPStatusError

                result = await _call_compress_model([("h1", "desc")])

        assert result == []
        assert mock_client.post.call_count == 1
