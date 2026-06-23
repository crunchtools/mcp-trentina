"""Tests for unicode sanitization module."""

from __future__ import annotations

from mcp_trentina_crunchtools.sanitize.unicode import sanitize_unicode


class TestUnicodeSanitization:
    """Test zero-width chars, bidi overrides, control chars, NFKC."""

    def test_strips_zero_width_chars(self) -> None:
        text = "h\u200be\u200cl\u200dl\u200eo"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "hello"
        assert stats.zero_width_chars == 4

    def test_strips_bidi_overrides(self) -> None:
        text = "hello\u202aworld\u202e"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "helloworld"
        assert stats.bidi_overrides == 2

    def test_strips_variation_selectors(self) -> None:
        text = "text\ufe0f\ufe01"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "text"
        assert stats.variation_selectors == 2

    def test_strips_unicode_tags(self) -> None:
        text = "normal\U000e0001\U000e0041text"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "normaltext"
        assert stats.unicode_tags == 2

    def test_strips_control_chars(self) -> None:
        text = "hello\x00\x01\x08world"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "helloworld"
        assert stats.control_chars == 3

    def test_preserves_newline_tab_cr(self) -> None:
        text = "hello\n\tworld\r"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "hello\n\tworld\r"
        assert stats.control_chars == 0

    def test_nfkc_normalization(self) -> None:
        text = "\uff28\uff45\uff4c\uff4c\uff4f"
        cleaned, _ = sanitize_unicode(text)
        assert cleaned == "Hello"

    def test_clean_text_unchanged(self) -> None:
        text = "This is perfectly normal text with no special chars."
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == text
        assert stats.zero_width_chars == 0
        assert stats.control_chars == 0

    def test_combined_invisible_chars(self) -> None:
        text = "i\u200bg\u200bn\u200bo\u200br\u200be"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "ignore"
        assert stats.zero_width_chars == 5

    def test_soft_hyphen_stripped(self) -> None:
        text = "in\u00adstruc\u00adtion"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "instruction"
        assert stats.zero_width_chars == 2

    def test_word_joiner_stripped(self) -> None:
        text = "hello\u2060world"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "helloworld"
        assert stats.zero_width_chars == 1

    def test_feff_bom_stripped(self) -> None:
        text = "\ufeffhello"
        cleaned, stats = sanitize_unicode(text)
        assert cleaned == "hello"
        assert stats.zero_width_chars == 1
