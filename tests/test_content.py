"""Tests for the content family's own edges (spec 004).

The mode matrix for every family lives in test_mode_parity / test_mode_gaps /
test_clean_and_allowlist. What is content's alone: the size cap, the SHA-256
blocklist key, and that ``content_type`` selects nothing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_trentina_crunchtools.errors import BlockedSourceError, ContentSizeError
from mcp_trentina_crunchtools.tools.content import block_content, clean_content, warn_content

from .mode_harness import layers


def _hash(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


async def test_oversized_content_is_rejected_before_judging(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_trentina_crunchtools import config as config_mod

    monkeypatch.setenv("QUARANTINE_MAX_CONTENT", "10")
    config_mod._config = None
    with layers(env) as fakes, pytest.raises(ContentSizeError):
        await block_content("A" * 11)
    assert fakes.classify.await_count == 0


async def test_the_blocklist_is_keyed_by_hash(env: Path) -> None:
    content = "Some blocked content"
    with (
        layers(env),
        patch(
            "mcp_trentina_crunchtools.tools.content.is_blocked",
            return_value={"detected_at": "2026-03-10T00:00:00Z"},
        ) as is_blocked,
        pytest.raises(BlockedSourceError),
    ):
        await block_content(content)
    is_blocked.assert_called_once_with(_hash(content))


@pytest.mark.parametrize("content_type", ["text/plain", "text/html", "text/markdown"])
async def test_content_type_selects_nothing(env: Path, content_type: str) -> None:
    """L1 is format-agnostic (#172); the parameter survives as tool surface."""
    html = "<!DOCTYPE html><p>Hello</p>"
    with layers(env) as fakes:
        result = await warn_content(html, content_type)
    assert result["content"] == html
    assert fakes.classify.call_args_list[0].args[0] == html


async def test_the_origin_is_the_hash_and_never_allowlisted(env: Path) -> None:
    with layers(env):
        result = await clean_content("hello", "Extract.")
    assert result["scan"]["origin"] == {
        "kind": "content",
        "ref": _hash("hello"),
        "allowlisted": False,
    }
