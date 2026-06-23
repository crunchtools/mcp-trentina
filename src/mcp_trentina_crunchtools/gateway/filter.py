"""Tool-allowlist filter for `tools/list` responses.

Applied to the aggregated backend tool list before returning to the consumer.
Tool definitions excluded by the filter never reach the consumer's prompt
context — this is where actual token savings come from versus settings.json
deny lists which keep definitions in context.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .profile import Backend


def filter_tools(tools: list[dict[str, Any]], backend: Backend) -> list[dict[str, Any]]:
    """Filter a backend's tool list against the backend's allow/deny patterns.

    A tool is kept iff its name matches any allow pattern AND does not match
    any deny pattern. Patterns use shell-style globs validated at profile
    load time (see profile.GLOB_PATTERN_RE).

    Args:
        tools: List of MCP tool definitions (each a dict with at least "name").
        backend: Backend config carrying `tools_allow` + `tools_deny` glob lists.

    Returns:
        Filtered tool list. Empty `tools_allow` results in an empty output —
        the default model value is `["*"]` (allow all), so a profile must
        explicitly opt out of that to reach the empty-allow case.
    """
    allow = backend.tools_allow
    deny = backend.tools_deny

    kept: list[dict[str, Any]] = []
    for tool in tools:
        name = str(tool.get("name", ""))
        if not name:
            continue
        if not any(fnmatchcase(name, pat) for pat in allow):
            continue
        if deny and any(fnmatchcase(name, pat) for pat in deny):
            continue
        kept.append(tool)
    return kept
