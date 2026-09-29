"""Perimeter scan of a proxied backend's tool response.

Every remote backend's response is judged by L2 (Prompt Guard 2, local ONNX)
before it reaches the agent. The gateway serves every profile from one
asyncio event loop.
"""

from __future__ import annotations

from typing import Any

from mcp_trentina_crunchtools.quarantine.classifier import classify

MALICIOUS_THRESHOLD = 0.5


def _text_of(content_blocks: list[dict[str, Any]]) -> str:
    return "\n".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")


async def scan_tool_response(
    *, profile: Any, backend_name: str, tool_name: str, content_blocks: list[dict[str, Any]]
) -> dict[str, Any]:
    """Judge a backend response with L2 and return the decision.

    ``classify`` slides a 512-token window at stride 446 over the whole text,
    so a large response costs one ONNX pass per window.
    """
    text = _text_of(content_blocks)
    if not text.strip():
        return {"blocked": False, "warning": None}

    result = classify(text, fail_on_truncate=True, source=f"{backend_name}/{tool_name}")
    flagged = result.label == "MALICIOUS" or result.score >= MALICIOUS_THRESHOLD
    if flagged:
        return {
            "blocked": profile.defense.enforcement == "block",
            "warning": {"flagged_by": "l2", "risk_level": "high", "l2_score": result.score},
        }
    return {"blocked": False, "warning": None}
