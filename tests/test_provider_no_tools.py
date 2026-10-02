"""L3's no-tools invariant holds for every provider driver (#318).

L3 reads hostile content by design. What makes that safe is that its answer
can do nothing: no request it sends may give the model a tool, a plugin, a
provider-run search or an MCP server. Until #318 only the Gemini driver
refused such a body; the others merely never built one.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_trentina_crunchtools.errors import QuarantineAgentError
from mcp_trentina_crunchtools.quarantine.providers import (
    anthropic,
    gemini,
    ollama,
    openai,
)
from mcp_trentina_crunchtools.quarantine.providers.base import TOOL_KEYS, enforce_no_tools


@pytest.mark.parametrize("key", sorted(TOOL_KEYS))
def test_every_tool_key_is_refused(key: str) -> None:
    with pytest.raises(QuarantineAgentError, match="SECURITY"):
        enforce_no_tools({"model": "m", "messages": [], key: []})


class _CheckedError(Exception):
    """Raised by the spy so no request is ever sent."""


DRIVERS = [
    pytest.param(gemini, lambda: gemini.GeminiProvider(api_key="k", model="m"), id="gemini"),
    pytest.param(openai, lambda: openai.OpenAIProvider(api_key="k", model="m"), id="openai"),
    pytest.param(
        anthropic, lambda: anthropic.AnthropicProvider(api_key="k", model="m"), id="anthropic"
    ),
    pytest.param(ollama, lambda: ollama.OllamaProvider(model="m"), id="ollama"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("module", "make"), DRIVERS)
async def test_every_driver_checks_the_body_it_sends(
    module: Any, make: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []

    def spy(body: dict[str, Any]) -> None:
        seen.append(body)
        raise _CheckedError

    monkeypatch.setattr(module, "enforce_no_tools", spy)
    with pytest.raises(_CheckedError):
        await make().generate("system", "content", response_schema={"type": "object"})
    assert len(seen) == 1
    assert "content" in str(seen[0])
    # What each driver really sends passes the guard: it refuses tools, not L3.
    assert TOOL_KEYS.isdisjoint(seen[0])
