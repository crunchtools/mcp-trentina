"""Error hierarchy for mcp-trentina-crunchtools.

All errors scrub credentials from messages before surfacing to users.
"""

from __future__ import annotations

import re


def _scrub_credentials(message: str) -> str:
    """Remove API keys and tokens from error messages."""
    return re.sub(
        r"(key|token|secret|password|authorization)[=:\s]+\S+",
        r"\1=[REDACTED]",
        message,
        flags=re.IGNORECASE,
    )


class AirlockError(Exception):
    """Base error for all trentina operations."""

    def __init__(self, message: str) -> None:
        super().__init__(_scrub_credentials(message))


class FetchError(AirlockError):
    """Raised when fetching a URL fails."""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"Failed to fetch {url}: {reason}")


class SanitizationError(AirlockError):
    """Raised when the sanitization pipeline encounters an unrecoverable error."""


class QuarantineAgentError(AirlockError):
    """Raised when the Q-Agent (Gemini) call fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Q-Agent error: {reason}")


class BlockedSourceError(AirlockError):
    """Raised when a source is in the SQLite blocklist."""

    def __init__(self, source: str, detected_at: str) -> None:
        super().__init__(
            f"Source blocked: {source} (detected at {detected_at}). "
            "Use quarantine_fetch to bypass blocklist."
        )


class FileReadError(AirlockError):
    """Raised when reading a local file fails."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"Cannot read {path}: {reason}")


class ContentSizeError(AirlockError):
    """Raised when inline content exceeds the maximum allowed size."""

    def __init__(self, size: int, max_size: int) -> None:
        super().__init__(
            f"Content too large: {size} chars (max {max_size}). "
            "Split content into smaller chunks."
        )


class ConfigError(AirlockError):
    """Raised for configuration problems."""
