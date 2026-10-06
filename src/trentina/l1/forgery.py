"""Forgery: text that impersonates the gateway's verdicts or a tool call (#363).

Two things an agent trusts because of where they come from, written into
content instead:

* **A gateway verdict.** ``_trentina_warning`` and its siblings are keys only
  the gateway writes (``reserved.py`` strips them from someone else's JSON).
  Written as a key in prose, or as a claim that Trentina cleared what follows,
  they are aimed at this gateway in particular. Naming a marker is not forging
  one: ``the _trentina_warning field`` is documentation and does not count.
* **A tool call.** The markup a model emits to call a tool, or the JSON a
  provider wraps one in, placed where the agent reads it as its own turn.
  ``directives.py`` covers bare ``<tool>`` role tags; this covers the call.

Counts only, like every L1 stage. One count per line for verdicts; one per
opening tag or object for tool calls, so a forged call is not multiplied by
its closing tags.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_RESERVED_KEY = re.compile(r"""(?<![\w])["']?_trentina_[a-z_]{2,40}["']?[ \t]*[:=]""")
_CLEARED = re.compile(
    r"\b(?:verified|scanned|judged|cleared|approved|pre-?approved|marked|certified|validated)"
    r"\s+(?:as\s+)?(?:clean|safe|benign|trusted)\s+by\s+(?:the\s+)?trentina\b"
    r"|\btrentina\s+(?:gateway\s+)?(?:has\s+)?(?:already\s+)?"
    r"(?:verified|cleared|approved|pre-?approved|allowlisted|whitelisted|certified)\s+"
    r"(?:this|these|the\s+following)\b"
    r"|\btrentina[\s_-]{0,3}(?:verdict|status|scan(?:\s+result)?|result)\s*[:=]\s*[\"']?"
    r"(?:clean|safe|benign|pass(?:ed)?|trusted|allow(?:ed)?)\b",
    re.IGNORECASE,
)

# Opening tags only. The attribute run is bounded and cannot cross a tag or a
# line, so an unclosed `<invoke ` repeated is not rescanned from each one.
_CALL_MARKUP = re.compile(
    r"<\s*(?:antml:)?(?:function_calls|tool_calls?|tool_use|invoke)\b[^<>\n]{0,200}>"
    r"|<\|(?:tool_calls?|function_call|python_tag)\|>",
    re.IGNORECASE,
)
# A provider's wrapper, or a bare call object. Only where it interrupts prose:
# a line that is itself JSON (a document, a log record's body on its own line)
# opens with a brace, a bracket or a quote, and is somebody's data.
_CALL_JSON = re.compile(
    r"""["']tool_calls["']\s*:\s*\["""
    r"""|["']function_call["']\s*:\s*\{"""
    r"""|\{\s*["']name["']\s*:\s*["'][\w.\-]{1,64}["']\s*,\s*"""
    r"""["'](?:arguments|parameters|input)["']\s*:\s*[{"']"""
)
_JSON_LINE = re.compile(r"\s*[{\[\"']")


@dataclass
class ForgeryStats:
    """Counts of forged gateway verdicts and forged tool calls."""

    gateway_verdicts: int = 0
    tool_calls: int = 0


def detect_forgery(text: str) -> ForgeryStats:
    """Count forged verdicts by line and forged tool calls by opening."""
    stats = ForgeryStats()
    for line in text.split("\n"):
        if _RESERVED_KEY.search(line) or _CLEARED.search(line):
            stats.gateway_verdicts += 1
        stats.tool_calls += len(_CALL_MARKUP.findall(line))
        if not _JSON_LINE.match(line):
            stats.tool_calls += len(_CALL_JSON.findall(line))
    return stats
