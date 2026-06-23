"""Tests for Pydantic input validation models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_trentina_crunchtools.models import FetchInput, ReadInput, ScanInput


class TestFetchInput:
    """Test URL fetch input validation."""

    def test_valid_https_url(self) -> None:
        inp = FetchInput(url="https://example.com")
        assert inp.url == "https://example.com"

    def test_valid_http_url(self) -> None:
        inp = FetchInput(url="http://example.com")
        assert inp.url == "http://example.com"

    def test_rejects_ftp_url(self) -> None:
        with pytest.raises(ValidationError):
            FetchInput(url="ftp://example.com/file")

    def test_rejects_empty_url(self) -> None:
        with pytest.raises(ValidationError):
            FetchInput(url="")

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            FetchInput(url="https://example.com", evil="payload")  # type: ignore[call-arg]

    def test_custom_prompt(self) -> None:
        inp = FetchInput(url="https://example.com", prompt="Summarize this page")
        assert inp.prompt == "Summarize this page"

    def test_default_prompt(self) -> None:
        inp = FetchInput(url="https://example.com")
        assert "Extract" in inp.prompt


class TestReadInput:
    """Test file read input validation."""

    def test_valid_path(self) -> None:
        inp = ReadInput(path="/home/user/docs/readme.md")
        assert inp.path == "/home/user/docs/readme.md"

    def test_rejects_path_traversal(self) -> None:
        with pytest.raises(ValidationError):
            ReadInput(path="/home/user/../../etc/passwd")

    def test_rejects_empty_path(self) -> None:
        with pytest.raises(ValidationError):
            ReadInput(path="")

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            ReadInput(path="/tmp/test.md", evil="payload")  # type: ignore[call-arg]


class TestScanInput:
    """Test scan input validation."""

    def test_valid_url(self) -> None:
        inp = ScanInput(url="https://example.com")
        assert inp.url == "https://example.com"

    def test_valid_path(self) -> None:
        inp = ScanInput(path="/tmp/test.md")
        assert inp.path == "/tmp/test.md"

    def test_rejects_ftp_url(self) -> None:
        with pytest.raises(ValidationError):
            ScanInput(url="ftp://evil.com")

    def test_rejects_path_traversal(self) -> None:
        with pytest.raises(ValidationError):
            ScanInput(path="../../../etc/passwd")

    def test_both_none_allowed(self) -> None:
        inp = ScanInput()
        assert inp.url is None
        assert inp.path is None
