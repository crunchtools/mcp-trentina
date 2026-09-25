"""Provider ABC and result type for pluggable LLM backends."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any

from ...errors import QuarantineAgentError

if TYPE_CHECKING:
    import httpx


@dataclass(frozen=True)
class ProviderResult:
    """Result from a provider generate() call."""

    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class Provider(ABC):
    """Abstract base for LLM provider drivers.

    Each driver maps the common interface to a provider's REST API
    using raw httpx (no SDKs, per constitution §I.2).

    ``judge`` is the (provider, model) this instance actually calls, stamped
    by ``get_provider``. It keys the L3 concurrency limiter, which has to
    name the model a fallback really used, not the profile's primary.
    """

    judge: tuple[str, str] = ("unknown", "unknown")
    _model: str

    @property
    def model(self) -> str:
        """The model this driver sends requests to."""
        return self._model

    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_content: str,
        response_schema: dict[str, Any] | None = None,
        temperature: float = 0.1,
        max_output_tokens: int = 4096,
    ) -> ProviderResult:
        """Generate a completion and return the response text.

        Args:
            system_prompt: System-level instructions.
            user_content: User message content.
            response_schema: JSON Schema for structured output (optional).
            temperature: Sampling temperature.
            max_output_tokens: Maximum tokens in the response.

        Returns:
            ProviderResult with the model's text output and token counts.
        """


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Seconds to wait from a Retry-After header: delta-seconds or an HTTP-date."""
    if not value:
        return None
    value = value.strip()
    if value.replace(".", "", 1).isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, when.timestamp() - (time.time() if now is None else now))


def status_error(exc: httpx.HTTPStatusError) -> QuarantineAgentError:
    """The Q-Agent error for a non-2xx response, keeping how long to wait.

    Retry-After when the provider sends one. Gemini does not: it puts the wait
    in the body, as a ``google.rpc.RetryInfo`` detail ("retryDelay": "50s").
    """
    code = exc.response.status_code
    retry_after = parse_retry_after(exc.response.headers.get("retry-after"))
    if retry_after is None:
        retry_after = _google_retry_delay(exc.response)
    return QuarantineAgentError(f"HTTP {code}", status_code=code, retry_after=retry_after)


def _google_retry_delay(response: httpx.Response) -> float | None:
    """The retryDelay of a Google RetryInfo error detail, in seconds."""
    try:
        body = response.json()
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    details = error.get("details") if isinstance(error, dict) else None
    for detail in details if isinstance(details, list) else []:
        if not isinstance(detail, dict) or not str(detail.get("@type", "")).endswith(
            "google.rpc.RetryInfo"
        ):
            continue
        delay = str(detail.get("retryDelay", "")).removesuffix("s")
        return parse_retry_after(delay)
    return None
