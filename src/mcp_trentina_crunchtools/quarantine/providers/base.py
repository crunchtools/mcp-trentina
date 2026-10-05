"""Provider ABC and result type for pluggable LLM backends."""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any

from ...errors import MalformedResponseError, QuarantineAgentError

if TYPE_CHECKING:
    import httpx


@dataclass(frozen=True)
class ProviderResult:
    """Result from a provider generate() call."""

    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    truncated: bool = False
    """The provider stopped because it reached ``max_output_tokens`` (#358)."""


class Provider(ABC):
    """Abstract base for LLM provider drivers.

    Each driver maps the common interface to a provider's REST API
    using raw httpx (no SDKs, per constitution §I.2).

    ``judge`` is the (provider, model) this instance actually calls, stamped
    by ``get_provider``. It keys the L3 concurrency limiter, which has to
    name the model a fallback really used, not the profile's primary.
    """

    judge: tuple[str, str] = ("unknown", "unknown")
    key_ordinal: str = "global"
    """Which API key this instance sends: ``global`` for the env key, else
    ``key<n>`` numbered by ``get_provider``, derived from nothing in the key.
    It keys the limiter with ``judge``: a provider throttles per key (#291)."""
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


# Every key, across the four request shapes the drivers speak, that would let
# the provider call something on the model's behalf: function/tool calling,
# OpenRouter plugins (its `web` plugin fetches pages), provider-run search and
# MCP. L3 reads hostile content by design; what keeps that safe is that its
# answer can do nothing, so no request may carry one of these (#318).
TOOL_KEYS = frozenset(
    {
        "tools",
        "tool_choice",
        "functionDeclarations",
        "functions",
        "function_call",
        "plugins",
        "web_search_options",
        "mcp_servers",
    }
)


def enforce_no_tools(request_body: dict[str, Any]) -> None:
    """Refuse a request body that gives the model a way to act.

    A security invariant, not a debug assertion: it survives ``python -O``.
    Every driver calls it immediately before posting.
    """
    found = TOOL_KEYS.intersection(request_body)
    if found:
        raise QuarantineAgentError(f"SECURITY: {', '.join(sorted(found))} in provider request")


def json_object(raw: bytes | str) -> dict[str, Any]:
    """*raw* as a JSON object, or MalformedResponseError: never a parser exception.

    An upstream that answers 200 with something else is a provider failure
    like any other (#294), and the Q-Agent's fallback handles it as one.
    """
    try:
        body = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise MalformedResponseError("is not JSON") from exc
    if not isinstance(body, dict):
        raise MalformedResponseError("is not a JSON object")
    return body


def envelope(resp: httpx.Response) -> dict[str, Any]:
    """A provider's response body as a JSON object. See ``json_object``."""
    return json_object(resp.content)


def dig(value: Any, *path: str | int) -> Any:
    """``value[p0][p1]...``, or None the moment a step is the wrong shape."""
    for step in path:
        if isinstance(step, int):
            if not isinstance(value, list) or not -len(value) <= step < len(value):
                return None
        elif not isinstance(value, dict):
            return None
        value = value[step] if isinstance(step, int) else value.get(step)
    return value


def count(value: Any) -> int:
    """A token count from a usage block: an int, or 0."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


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
