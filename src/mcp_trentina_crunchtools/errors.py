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

    def __init__(
        self,
        url: str,
        reason: str,
        *,
        status_code: int | None = None,
        error_body: str | None = None,
    ) -> None:
        super().__init__(f"Failed to fetch {url}: {reason}")
        self.status_code = status_code
        self.error_body = error_body


class SanitizationError(AirlockError):
    """Raised when the sanitization pipeline encounters an unrecoverable error."""


class QuarantineAgentError(AirlockError):
    """Raised when the Q-Agent (Gemini) call fails."""

    def __init__(self, reason: str, status_code: int | None = None) -> None:
        super().__init__(f"Q-Agent error: {reason}")
        self.status_code = status_code


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


class UnscannableContentError(AirlockError):
    """Raised when untrusted content is too large for Layer 2 to scan in full.

    Failing closed here is deliberate.  A partial scan that returns BENIGN is
    worse than no scan, because it lets an attacker hide an injection past the
    token cap and still collect a clean bill of health.
    """

    def __init__(self, source: str, tokens: int, max_tokens: int) -> None:
        super().__init__(
            f"Cannot fully scan {source}: {tokens} tokens exceeds the "
            f"classifier limit of {max_tokens}. Untrusted content must be "
            "scanned in full. Split the content, or add the source to the "
            "trust allowlist if you vouch for it."
        )


class UnsupportedContentTypeError(AirlockError):
    """Raised when a fetched body is not text the pipeline can reason about."""

    def __init__(
        self,
        url: str,
        content_type: str,
        *,
        redirect_chain: list[dict[str, object]] | None = None,
    ) -> None:
        parts = [
            (
                f"Refusing to fetch {url}: content-type {content_type!r} is not "
                "text. Binary bodies decode into garbage that wastes the "
                "sanitization and classification pipeline."
            ),
        ]
        if redirect_chain:
            hops = " -> ".join(
                f"{hop['url']} ({hop['status']} {hop.get('content_type', '')})"
                for hop in redirect_chain
            )
            parts.append(
                f"Redirect chain: {hops}. "
                "A page that redirects to a binary download (ZIP, PDF, etc.) "
                "is a known prompt-injection vector — the attacker wants the "
                "agent to curl/wget the archive directly and extract it."
            )
        super().__init__(" ".join(parts))
        self.redirect_chain = redirect_chain


class ConfigError(AirlockError):
    """Raised for configuration problems."""
