"""Results carry what the agent reads once (0.38.0).

FastMCP returns a tool's value as a text block AND as structuredContent, and
the agent pays for both. The copy goes when it repeats the text, before the
transform and the scan, so the perimeter still judges exactly what is
delivered.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from mcp_trentina_crunchtools.gateway.backend import BackendCall
from mcp_trentina_crunchtools.gateway.ingress_defense import IngressDecision
from mcp_trentina_crunchtools.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    PreProcessConfig,
    Profile,
)
from mcp_trentina_crunchtools.gateway.router import NAMESPACE_SEP, route_jsonrpc

ROUTER = "mcp_trentina_crunchtools.gateway.router"
DOC = {"issues": [{"key": "RT-1", "summary": "disk full"}], "total": 1}


def _profile() -> Profile:
    p = Profile(
        name="agent",
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(enforcement="flag", modes=["flag"]),
        backends={"rt": Backend(url="http://rt:8000/mcp")},
        preprocess=PreProcessConfig(enabled=False),
    )
    assert p.auth is not None
    p.auth.bearer_token = SecretStr("x")
    return p


async def _call(blocks: list[dict[str, Any]], structured: Any) -> tuple[dict[str, Any], AsyncMock]:
    reply = BackendCall(content=blocks, is_error=False, structured_content=structured)
    scan = AsyncMock(return_value=IngressDecision(warning=None))
    with (
        patch(f"{ROUTER}.call_backend_tool", AsyncMock(return_value=reply)),
        patch(f"{ROUTER}.scan_tool_response", scan),
        patch(f"{ROUTER}._audit", MagicMock()),
    ):
        resp = await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": f"rt{NAMESPACE_SEP}search", "arguments": {}},
            },
        )
    return resp["result"], scan


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "structured"),
    [
        (json.dumps(DOC), DOC),
        (json.dumps(DOC, indent=2), DOC),
        (json.dumps(DOC), {"result": DOC}),
        ("plain words", {"result": "plain words"}),
    ],
)
async def test_a_copy_of_the_text_is_dropped_before_the_scan(text: str, structured: Any) -> None:
    result, scan = await _call([{"type": "text", "text": text}], structured)
    assert "structuredContent" not in result
    assert result["content"][0]["text"] == text
    assert scan.call_args.kwargs["structured_content"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("blocks", "structured"),
    [
        ([{"type": "text", "text": json.dumps(DOC)}], {**DOC, "total": 2}),
        ([{"type": "text", "text": "a summary"}], DOC),
        (
            [{"type": "text", "text": json.dumps(DOC)}, {"type": "text", "text": "more"}],
            DOC,
        ),
        ([], DOC),
        ([{"type": "text", "text": '{"ok": 1}'}], {"ok": True}),
        ([{"type": "text", "text": "not json"}], {"result": None}),
    ],
)
async def test_structured_content_that_adds_anything_is_kept_and_judged(
    blocks: list[dict[str, Any]], structured: Any
) -> None:
    result, scan = await _call(blocks, structured)
    assert result["structuredContent"] == structured
    assert scan.call_args.kwargs["structured_content"] == structured
