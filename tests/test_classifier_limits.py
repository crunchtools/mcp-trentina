"""Bounds on Layer 2 scanning.

Regression cover for the 2026-08-22 incident: safe_fetch pulled an 855 KB
PDF, decoded the binary as text, and handed ~462k tokens to classify().  The
unbounded sliding-window loop turned that into ~1,800 ONNX inference passes
that pegged every core for roughly 90 minutes and wedged the event loop.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from mcp_trentina_crunchtools.errors import UnscannableContentError
from mcp_trentina_crunchtools.quarantine.classifier import (
    classifier_status,
    classify,
    classify_async,
    classify_guarded,
    truncation_warning,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_TOKENS = 32_768
WINDOW = 512
STRIDE = 256


@contextmanager
def mocked_model(token_count: int, max_tokens: int = MAX_TOKENS) -> Iterator[MagicMock]:
    """Patch in a tokenizer/session pair that reports ``token_count`` tokens."""
    import numpy as np

    full_ids = list(range(token_count))

    def tokenize(_text: str, **kwargs: object) -> dict[str, list[int]]:
        """Mirror the real tokenizer: padded calls return one window."""
        if kwargs.get("padding") == "max_length":
            return {"input_ids": list(range(WINDOW)), "attention_mask": [1] * WINDOW}
        return {"input_ids": full_ids, "attention_mask": [1] * token_count}

    tokenizer = MagicMock(side_effect=tokenize)
    tokenizer.decode.return_value = "decoded segment"

    session = MagicMock()
    session.run.return_value = [np.array([[5.0, -5.0, -5.0]])]

    config = MagicMock()
    config.classifier_max_tokens = max_tokens
    config.classifier_threshold = 0.5

    with (
        patch("mcp_trentina_crunchtools.quarantine.classifier._tokenizer", tokenizer),
        patch("mcp_trentina_crunchtools.quarantine.classifier._session", session),
        patch("mcp_trentina_crunchtools.quarantine.classifier._loaded", True),
        patch("mcp_trentina_crunchtools.quarantine.classifier._load_attempted", True),
        patch(
            "mcp_trentina_crunchtools.quarantine.classifier.get_config",
            return_value=config,
        ),
    ):
        yield session


class TestSegmentCap:
    """The segment loop must be bounded by CLASSIFIER_MAX_TOKENS."""

    def test_oversized_input_is_truncated(self) -> None:
        """A PDF-sized token count is capped instead of scanned in full.

        Unbounded this was ~1,800 inference passes; capped it is ~128.
        """
        with mocked_model(token_count=462_000) as session:
            result = classify("x" * 855_551)

        assert result is not None
        assert result.truncated is True
        assert result.tokens == 462_000

        expected_max = MAX_TOKENS // STRIDE + 1
        assert session.run.call_count <= expected_max
        assert session.run.call_count < 200

    def test_normal_content_is_not_truncated(self) -> None:
        """Content within the cap keeps a full scan and no truncated flag."""
        with mocked_model(token_count=4_000) as session:
            result = classify("a normal article")

        assert result is not None
        assert result.truncated is False
        assert result.tokens == 4_000
        assert session.run.call_count == pytest.approx(4_000 // STRIDE, abs=2)

    def test_max_content_worth_of_prose_fits_under_the_cap(self) -> None:
        """QUARANTINE_MAX_CONTENT-sized prose must not trip truncation.

        100k chars of ordinary text is roughly 28k tokens. If the classifier
        cap sat below that, every large-but-legitimate inline document would
        fail closed.
        """
        with mocked_model(token_count=28_000):
            result = classify("prose")

        assert result is not None
        assert result.truncated is False

    def test_cap_disabled_when_zero(self) -> None:
        """CLASSIFIER_MAX_TOKENS=0 restores unbounded scanning."""
        with mocked_model(token_count=2_000, max_tokens=0):
            result = classify("x")

        assert result is not None
        assert result.truncated is False


class TestFailClosed:
    """Untrusted content that cannot be fully scanned must not read as clean."""

    @pytest.mark.asyncio
    async def test_untrusted_truncated_raises(self) -> None:
        with (
            mocked_model(token_count=462_000),
            pytest.raises(UnscannableContentError) as exc,
        ):
            await classify_guarded(
                "x" * 855_551, "https://example.com/big.pdf", is_trusted=False
            )

        assert "462000" in str(exc.value)
        assert "example.com/big.pdf" in str(exc.value)

    @pytest.mark.asyncio
    async def test_untrusted_bails_before_running_any_inference(self) -> None:
        """The verdict is known at the token count; scanning first is wasted CPU.

        Letting the ~128 capped passes run before raising gave an attacker a
        cheap way to burn ~112s of CPU per request.
        """
        with (
            mocked_model(token_count=462_000) as session,
            pytest.raises(UnscannableContentError),
        ):
            await classify_guarded("x", "https://evil.test/big", is_trusted=False)

        assert session.run.call_count == 0

    @pytest.mark.asyncio
    async def test_trusted_still_scans(self) -> None:
        """Only the untrusted path short-circuits; trusted content is scanned."""
        with mocked_model(token_count=462_000) as session:
            await classify_guarded("x", "/srv/trusted/doc", is_trusted=True)

        assert session.run.call_count > 0

    @pytest.mark.asyncio
    async def test_trusted_truncated_passes_with_flag(self) -> None:
        """A trusted source is allowed through, but the partial scan is visible."""
        with mocked_model(token_count=462_000):
            result = await classify_guarded(
                "x" * 855_551, "/srv/trusted/doc.txt", is_trusted=True
            )

        assert result is not None
        assert result.truncated is True

    @pytest.mark.asyncio
    async def test_untrusted_within_cap_passes(self) -> None:
        with mocked_model(token_count=4_000):
            result = await classify_guarded(
                "normal", "https://example.com/", is_trusted=False
            )

        assert result is not None
        assert result.truncated is False


class TestTruncationWarning:
    """quarantine_* and scan_* tools surface truncation instead of raising."""

    def test_warning_text_when_truncated(self) -> None:
        with mocked_model(token_count=462_000):
            result = classify("x")
            warning = truncation_warning(result)

        assert warning is not None
        assert "462000" in warning

    def test_no_warning_when_complete(self) -> None:
        with mocked_model(token_count=100):
            assert truncation_warning(classify("x")) is None

    def test_no_warning_when_classifier_unavailable(self) -> None:
        assert truncation_warning(None) is None


class TestAsyncOffload:
    """classify_async must not run inference on the event loop."""

    @pytest.mark.asyncio
    async def test_runs_on_a_worker_thread(self) -> None:
        import threading

        loop_thread = threading.get_ident()
        seen: list[int] = []

        def record(_text: str) -> None:
            seen.append(threading.get_ident())

        with patch(
            "mcp_trentina_crunchtools.quarantine.classifier.classify",
            side_effect=record,
        ):
            await classify_async("anything")

        assert seen and seen[0] != loop_thread


class TestClassifierStatus:
    """Health probes must not trigger the lazy model load."""

    def test_status_does_not_load(self) -> None:
        with patch(
            "mcp_trentina_crunchtools.quarantine.classifier.is_classifier_available"
        ) as loader:
            status = classifier_status()

        loader.assert_not_called()
        assert status in {"loaded", "not-loaded", "failed"}


class TestTelemetryDisabled:
    """onnxruntime telemetry must be off before the library is imported.

    With it live, importing onnxruntime reads /etc/machine-id and
    /proc/cpuinfo, writes /tmp/mat-debug-1.log and creates a session file
    at /tmp/.ses — none of which belongs in a container built to handle
    untrusted content.
    """

    def test_env_var_set_at_import(self) -> None:
        import os

        from mcp_trentina_crunchtools.quarantine.classifier import TELEMETRY_ENV

        assert os.environ[TELEMETRY_ENV] == "1"

    def test_operator_can_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """setdefault, not assignment — an explicit opt-in must survive."""
        import importlib
        import os

        import mcp_trentina_crunchtools.quarantine.classifier as mod

        monkeypatch.setenv(mod.TELEMETRY_ENV, "0")
        importlib.reload(mod)
        assert os.environ[mod.TELEMETRY_ENV] == "0"
