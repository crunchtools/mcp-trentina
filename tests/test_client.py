"""Fetch client guards: content-type allowlist and streamed size cap.

The 2026-08-22 incident started here. fetch_url had no content-type check, so
an application/pdf body went through resp.text, decoded into 39% replacement
characters, and was handed to the sanitizer and classifier as if it were
prose.
"""

from __future__ import annotations

import functools

import httpx
import pytest

from mcp_trentina_crunchtools.client import (
    MAX_RESPONSE_SIZE,
    _is_text_content_type,
    fetch_url,
)
from mcp_trentina_crunchtools.errors import FetchError, UnsupportedContentTypeError


def mock_http(
    monkeypatch: pytest.MonkeyPatch,
    *,
    content_type: str | None,
    body: bytes = b"hello",
    content_length: str | None = None,
) -> dict[str, bool]:
    """Route fetch_url through a MockTransport serving one canned response.

    Returns a dict whose ``body_read`` flag records whether the response body
    was actually pulled, so tests can prove a rejection happened on headers.
    """
    state = {"body_read": False}

    def handler(_request: httpx.Request) -> httpx.Response:
        headers = {}
        if content_type is not None:
            headers["content-type"] = content_type
        if content_length is not None:
            headers["content-length"] = content_length

        async def stream() -> object:
            state["body_read"] = True
            yield body

        return httpx.Response(200, headers=headers, content=stream())

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "mcp_trentina_crunchtools.client.httpx.AsyncClient",
        functools.partial(real_client, transport=httpx.MockTransport(handler)),
    )
    return state


class TestContentTypeAllowlist:
    """Only text-shaped bodies reach the sanitization pipeline."""

    @pytest.mark.asyncio
    async def test_pdf_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The exact shape that took the host down."""
        state = mock_http(monkeypatch, content_type="application/pdf", body=b"%PDF-1.7")

        with pytest.raises(UnsupportedContentTypeError) as exc:
            await fetch_url("https://example.com/report.pdf")

        assert "application/pdf" in str(exc.value)
        assert state["body_read"] is False, "PDF body should never be downloaded"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "content_type",
        [
            "image/png",
            "application/zip",
            "application/octet-stream",
            "video/mp4",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ],
    )
    async def test_binary_types_rejected(
        self, monkeypatch: pytest.MonkeyPatch, content_type: str
    ) -> None:
        mock_http(monkeypatch, content_type=content_type)

        with pytest.raises(UnsupportedContentTypeError):
            await fetch_url("https://example.com/thing")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "content_type",
        [
            "text/html",
            "text/plain; charset=utf-8",
            "TEXT/HTML",
            "application/json",
            "application/xml",
            "application/ld+json",
            "application/atom+xml",
            "application/vnd.api+json",
        ],
    )
    async def test_text_types_allowed(
        self, monkeypatch: pytest.MonkeyPatch, content_type: str
    ) -> None:
        mock_http(monkeypatch, content_type=content_type, body=b"body text")

        content, returned_type = await fetch_url("https://example.com/thing")

        assert content == "body text"
        assert returned_type == content_type

    @pytest.mark.asyncio
    async def test_missing_content_type_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An absent header is common on plain files; don't break those."""
        mock_http(monkeypatch, content_type=None, body=b"plain")

        content, _ = await fetch_url("https://example.com/README")

        assert content == "plain"

    def test_predicate_handles_parameters_and_case(self) -> None:
        assert _is_text_content_type("text/html;charset=ISO-8859-1")
        assert _is_text_content_type("  Application/JSON  ")
        assert _is_text_content_type("")
        assert not _is_text_content_type("application/pdf; version=1.7")


class TestSizeCap:
    """Oversized bodies are refused, ideally before they are downloaded."""

    @pytest.mark.asyncio
    async def test_declared_oversize_rejected_without_download(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = mock_http(
            monkeypatch,
            content_type="text/html",
            content_length=str(MAX_RESPONSE_SIZE + 1),
        )

        with pytest.raises(FetchError, match="too large"):
            await fetch_url("https://example.com/big")

        assert state["body_read"] is False

    @pytest.mark.asyncio
    async def test_undeclared_oversize_rejected_while_streaming(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Servers omit or lie about content-length, so recheck as bytes land."""
        mock_http(
            monkeypatch,
            content_type="text/plain",
            body=b"x" * (MAX_RESPONSE_SIZE + 10),
        )

        with pytest.raises(FetchError, match="too large"):
            await fetch_url("https://example.com/big")

    @pytest.mark.asyncio
    async def test_body_at_the_limit_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_http(monkeypatch, content_type="text/plain", body=b"y" * 1000)

        content, _ = await fetch_url("https://example.com/ok")

        assert len(content) == 1000
