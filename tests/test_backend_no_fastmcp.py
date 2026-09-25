"""The serializers must be correct without fastmcp loaded.

MCP SDK 2.x renamed every model field to snake_case. fastmcp re-attaches the
old camelCase spellings as deprecated properties *when it is imported*, so
``tool.inputSchema`` keeps working in any process that happens to import
fastmcp first -- which trentina always does.

That is a trap rather than compatibility, for three reasons:

* it is explicitly deprecated (reading one emits FastMCPDeprecationWarning),
  so it will be removed;
* it depends on import order, not on the object;
* it makes the whole suite green while ``gateway/backend.py`` reads fields
  that do not exist on the objects it is handed.

This module runs the serializers in a subprocess with ``fastmcp`` blocked at
import, against raw SDK models. If anything in the serialization path starts
depending on the alias shim, it fails here instead of in production.

A subprocess is required: ``fastmcp`` is already in ``sys.modules`` by the time
this file is collected, and the monkeypatch is applied at class level, so it
cannot be undone in-process.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import warnings
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_BLOCK_FASTMCP = """
import sys

class _Blocked:
    '''Make `import fastmcp` fail, so nothing can lean on its alias shim.'''

    def find_module(self, name, path=None):
        return self.find_spec(name, path)

    def find_spec(self, name, path=None, target=None):
        if name == "fastmcp" or name.startswith("fastmcp."):
            raise AssertionError(
                "the MCP serialization path imported fastmcp; it must work on "
                "raw SDK objects, not on fastmcp's deprecated camelCase aliases"
            )
        return None

sys.meta_path.insert(0, _Blocked())
"""


def _run_without_fastmcp(body: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _BLOCK_FASTMCP + textwrap.dedent(body)],
        check=False,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _assert_ok(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, (
        f"subprocess failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


class TestSerializersWithoutFastmcp:
    def test_fastmcp_really_is_blocked(self) -> None:
        """Guard the guard: prove the block works, or this file proves nothing."""
        result = _run_without_fastmcp(
            """
            try:
                import fastmcp
            except AssertionError:
                print("blocked")
            else:
                raise SystemExit("fastmcp import was NOT blocked")
            """
        )
        _assert_ok(result)
        assert "blocked" in result.stdout

    def test_tool_serialization_needs_no_alias_shim(self) -> None:
        result = _run_without_fastmcp(
            """
            from mcp.types import Tool
            from mcp_trentina_crunchtools.gateway.backend import _serialize_tool

            tool = Tool(
                name="probe",
                description="d",
                input_schema={"type": "object", "properties": {"a": {"type": "string"}}},
                output_schema={"type": "object"},
            )
            out = _serialize_tool(tool)

            assert out["name"] == "probe"
            assert out["description"] == "d"
            # Wire keys stay camelCase; the rename was Python-side only.
            assert out["inputSchema"]["properties"]["a"]["type"] == "string", out
            assert out["outputSchema"] == {"type": "object"}, out
            assert "input_schema" not in out, out
            print("ok")
            """
        )
        _assert_ok(result)
        assert "ok" in result.stdout

    def test_content_block_serialization_needs_no_alias_shim(self) -> None:
        result = _run_without_fastmcp(
            """
            from mcp.types import ImageContent, TextContent
            from mcp_trentina_crunchtools.gateway.backend import (
                _serialize_content_block,
            )

            text = _serialize_content_block(TextContent(type="text", text="hi"))
            assert text == {"type": "text", "text": "hi"}, text

            image = _serialize_content_block(
                ImageContent(type="image", data="Zm9v", mime_type="image/png")
            )
            assert image["mimeType"] == "image/png", image
            print("ok")
            """
        )
        _assert_ok(result)
        assert "ok" in result.stdout

    def test_call_result_fields_need_no_alias_shim(self) -> None:
        """is_error read through the shim would silently report False.

        A failed backend call would then audit as a success, which is the
        quietest possible way for this to go wrong.
        """
        result = _run_without_fastmcp(
            """
            from mcp.types import CallToolResult, TextContent
            from mcp_trentina_crunchtools.gateway.backend import _field

            failed = CallToolResult(
                content=[TextContent(type="text", text="boom")],
                is_error=True,
                structured_content={"detail": "boom"},
            )

            assert _field(failed, "is_error", "isError", False) is True
            assert _field(failed, "structured_content", "structuredContent") == {
                "detail": "boom"
            }
            print("ok")
            """
        )
        _assert_ok(result)
        assert "ok" in result.stdout


class TestAliasShimIsRealAndDeprecated:
    """Documents why the guard above exists, and fails if upstream changes it.

    If fastmcp ever stops attaching the aliases, this test fails and the guard
    becomes unnecessary. If it starts attaching them silently (no warning), the
    trap gets quieter and the guard becomes more important. Either way we want
    to be told.
    """

    def test_fastmcp_attaches_deprecated_camelcase_aliases(self) -> None:
        import fastmcp
        from mcp.types import Tool

        # Importing fastmcp IS the precondition under test -- the aliases are
        # attached as a side effect of it, not by anything on the object.
        assert fastmcp.__version__

        tool = Tool(name="probe", description="d", input_schema={"type": "object"})

        assert hasattr(tool, "input_schema"), "SDK field name must exist"

        # "always", because reading the alias warns from inside fastmcp and the
        # default filter shows it once per location -- any earlier read in this
        # process would otherwise swallow it and make this test lie.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                _ = tool.inputSchema
            except AttributeError:
                pytest.skip(
                    "fastmcp no longer attaches camelCase aliases; the "
                    "no-fastmcp guard is now redundant but harmless"
                )

        assert any(issubclass(w.category, DeprecationWarning) for w in caught), (
            "fastmcp still serves Tool.inputSchema but no longer deprecates it. "
            "The alias shim just got quieter, so the no-fastmcp guard in this "
            "module matters more, not less."
        )
