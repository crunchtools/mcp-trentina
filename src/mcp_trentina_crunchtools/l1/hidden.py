"""Hidden-markup fingerprints — the tier-2 backstop, format-agnostic.

Conversion to Markdown (``preprocess/html.py``) is tier 1 and removes this
attack class rather than detecting it: Markdown has no ``style`` attribute, no
``display:none``, no foreground/background pair. Once a payload has been
converted, hidden content is not expressible — the category is absent, not
mitigated.

This stage catches the payloads conversion never saw: the agent asked for raw
bytes, the converter declined, or the text merely embeds markup without being
a document. It makes no decision about whether a payload "is HTML", because
there is no such decision to get wrong. It assumes any payload MAY carry
markup, scans for the fingerprints that hide content, and counts them.

Until 0.28.0 this ran only behind a ``looks_like_html`` sniffer keyed on a
leading ``<!DOCTYPE`` or ``<html>``. An HTML FRAGMENT — the shape most MCP
tool output actually carries — matched neither, so it was never checked at
all: a same-colour span in one scored ``low`` and was delivered intact, while
the identical bytes with a doctype in front scored ``medium`` and were
stripped. Same payload, two security behaviours, chosen by the first few
characters. Removing the sniffer is what this module is for.

COUNTS ONLY; the scan view passes through untouched. The hidden text's WORDS
are exactly what L2 should still read — what this stage adds is the
structural signal that those words were not meant to be seen, which is the
part no amount of reading the text can recover.

The predicate table lives here and ``preprocess/html.py`` imports it, so the
converter that STRIPS an element and the stage that COUNTS one decide by one
rule. Two hand-maintained copies of a detection table is the bug ``jsonwalk``
was written to end (#167).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

RGB_BYTE_MASK = 0xFF

# Bounded so a pathological payload cannot buy unbounded regex work. Well
# above what any real document carries, and far above the >10 that already
# saturates `risk_level_for_count` at "critical", so the cap can only cost
# precision in a count that is already maxed out.
_MAX_STYLE_ATTRS = 5_000


@dataclass
class HiddenStats:
    """Counts of content-hiding fingerprints.

    All three are SUSPICIOUS and feed ``PipelineStats.suspicious_detections``,
    flattening to ``hidden_elements``, ``hidden_off_screen`` and
    ``hidden_same_color``.
    The tag-hygiene counters that used to sit beside them (``script_tags``,
    ``style_tags``, ``meta_tags``, ``noscript_tags``, ``html_comments``) moved
    to the converter's sidecar in 0.28.0: they were never suspicious, they
    never fed risk, and counting them here only made the dataclass look like
    it was about HTML rather than about hiding.
    """

    elements: int = field(default=0)
    off_screen: int = field(default=0)
    same_color: int = field(default=0)


_NAMED_COLORS: dict[str, str] = {
    "white": "#ffffff",
    "black": "#000000",
    "red": "#ff0000",
    "green": "#008000",
    "blue": "#0000ff",
    "yellow": "#ffff00",
    "cyan": "#00ffff",
    "magenta": "#ff00ff",
    "gray": "#808080",
    "grey": "#808080",
    "silver": "#c0c0c0",
    "maroon": "#800000",
    "olive": "#808000",
    "lime": "#00ff00",
    "aqua": "#00ffff",
    "teal": "#008080",
    "navy": "#000080",
    "fuchsia": "#ff00ff",
    "purple": "#800080",
    "orange": "#ffa500",
}

_HIDDEN_STYLE_PATTERNS = (
    "display:none",
    "display: none",
    "visibility:hidden",
    "visibility: hidden",
    "opacity:0",
    "opacity: 0",
)

_OFFSCREEN_PATTERNS = (
    "clip:rect(0",
    "clip: rect(0",
    "clip-path:inset(100",
    "clip-path: inset(100",
    "font-size:0",
    "font-size: 0",
)

_POSITION_PATTERNS = (
    "position:absolute",
    "position: absolute",
    "position:fixed",
    "position: fixed",
)

_NEGATIVE_OFFSET_PATTERNS = (
    "left:-",
    "left: -",
    "top:-",
    "top: -",
)

# `style="..."` / `style='...'`. Both alternatives are `[^quote]*`, which
# cannot backtrack catastrophically on hostile input.
_STYLE_ATTR_RE = re.compile(
    r"""style\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE
)

# The bare `hidden` boolean attribute: `<div hidden>`, `<div hidden="">`,
# `<div hidden/>`. Requires a preceding tag open so the English word "hidden"
# in prose does not count.
_HIDDEN_ATTR_RE = re.compile(
    r"<[a-zA-Z][^>]*?\shidden(?=[\s/>=])", re.IGNORECASE
)

_COLOR_RE = re.compile(r"(?:^|;)\s*color\s*:\s*([^;!]+)")
_BACKGROUND_RE = re.compile(r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;!]+)")


def normalize_color(value: str) -> str | None:
    """Normalize a CSS color value to lowercase hex, or None if unparseable."""
    val = value.strip().lower()

    if val in _NAMED_COLORS:
        return _NAMED_COLORS[val]

    hex3 = re.match(r"^#([0-9a-f])([0-9a-f])([0-9a-f])$", val)
    if hex3:
        return f"#{hex3.group(1) * 2}{hex3.group(2) * 2}{hex3.group(3) * 2}"

    if re.match(r"^#[0-9a-f]{6}$", val):
        return val

    rgb = re.match(r"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", val)
    if rgb:
        r_hex = int(rgb.group(1)) & RGB_BYTE_MASK
        g_hex = int(rgb.group(2)) & RGB_BYTE_MASK
        b_hex = int(rgb.group(3)) & RGB_BYTE_MASK
        return f"#{r_hex:02x}{g_hex:02x}{b_hex:02x}"

    return None


def style_is_hidden(style_lower: str) -> bool:
    """Inline style that hides the element outright."""
    return any(p in style_lower for p in _HIDDEN_STYLE_PATTERNS)


def style_is_off_screen(style_lower: str) -> bool:
    """Inline style that moves the element out of the viewport."""
    if "text-indent" in style_lower and "-999" in style_lower:
        return True

    has_position = any(p in style_lower for p in _POSITION_PATTERNS)
    has_negative = any(p in style_lower for p in _NEGATIVE_OFFSET_PATTERNS)
    if has_position and has_negative:
        return True

    return any(p in style_lower for p in _OFFSCREEN_PATTERNS)


def style_has_same_color(style_lower: str) -> bool:
    """Foreground colour equal to background colour — text written in ink the
    colour of the paper."""
    color_match = _COLOR_RE.search(style_lower)
    bg_match = _BACKGROUND_RE.search(style_lower)
    if not (color_match and bg_match):
        return False
    fg = normalize_color(color_match.group(1))
    bg = normalize_color(bg_match.group(1))
    return bool(fg and bg and fg == bg)


def classify_style(style_lower: str) -> str | None:
    """Which hiding CONCEPT a style attribute matches: ``hidden``,
    ``off_screen``, ``same_color``, or None.

    Concepts rather than field names, so the two callers can name their own
    fields for their own audiences — the risk score wants terse keys, the
    operator sidecar wants descriptive ones — while precedence and patterns
    stay in one place. The checks are ordered and the first match wins, which
    is what the converter's per-element ``break`` has always done.
    """
    if style_is_hidden(style_lower):
        return "hidden"
    if style_is_off_screen(style_lower):
        return "off_screen"
    if style_has_same_color(style_lower):
        return "same_color"
    return None


def detect_hidden_markup(text: str) -> tuple[str, HiddenStats]:
    """Count content-hiding fingerprints in whatever we were handed.

    Returns the text unchanged. This is a counting stage, not a stripping one
    — see the module docstring for why the hidden words must survive into the
    scan view.
    """
    stats = HiddenStats()
    concept_field = {
        "hidden": "elements",
        "off_screen": "off_screen",
        "same_color": "same_color",
    }

    for seen, match in enumerate(_STYLE_ATTR_RE.finditer(text)):
        if seen >= _MAX_STYLE_ATTRS:
            break
        style = (match.group(1) or match.group(2) or "").lower()
        if not style:
            continue
        concept = classify_style(style)
        if concept is not None:
            name = concept_field[concept]
            setattr(stats, name, getattr(stats, name) + 1)

    stats.elements += len(_HIDDEN_ATTR_RE.findall(text))
    return text, stats
