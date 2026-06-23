"""HTML sanitization — parse HTML, strip hidden elements, convert to markdown."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment, Tag
from markdownify import markdownify

RGB_BYTE_MASK = 0xFF


@dataclass
class HtmlStats:
    """Counts of stripped HTML elements."""

    hidden_elements: int = field(default=0)
    html_comments: int = field(default=0)
    script_tags: int = field(default=0)
    style_tags: int = field(default=0)
    noscript_tags: int = field(default=0)
    meta_tags: int = field(default=0)
    off_screen_elements: int = field(default=0)
    same_color_text: int = field(default=0)


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

_STRIP_TAGS = ("script", "style", "noscript", "meta", "link")

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

_TAG_STAT_MAP = {
    "script": "script_tags",
    "style": "style_tags",
    "noscript": "noscript_tags",
}

_CLASSIFICATION_CHECKS: list[tuple[str, str]] = [
    ("_is_hidden", "hidden_elements"),
    ("_is_off_screen", "off_screen_elements"),
    ("_has_same_color_text", "same_color_text"),
]


def _normalize_color(value: str) -> str | None:
    """Normalize a CSS color value to lowercase hex."""
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


def _get_style_lower(tag: Tag) -> str | None:
    """Extract lowercased style attribute, or None if missing/invalid."""
    style = tag.get("style", "")
    if not isinstance(style, str) or not style:
        return None
    return style.lower()


def _is_hidden(tag: Tag) -> bool:
    """Check if an element has inline styles that hide it."""
    style_lower = _get_style_lower(tag)
    if style_lower and any(p in style_lower for p in _HIDDEN_STYLE_PATTERNS):
        return True
    return tag.get("hidden") is not None


def _is_off_screen(tag: Tag) -> bool:
    """Check if an element is positioned off-screen."""
    style_lower = _get_style_lower(tag)
    if not style_lower:
        return False

    if "text-indent" in style_lower and "-999" in style_lower:
        return True

    has_position = any(p in style_lower for p in _POSITION_PATTERNS)
    has_negative = any(p in style_lower for p in _NEGATIVE_OFFSET_PATTERNS)
    if has_position and has_negative:
        return True

    return any(p in style_lower for p in _OFFSCREEN_PATTERNS)


def _has_same_color_text(tag: Tag) -> bool:
    """Check if foreground color matches background color."""
    style = tag.get("style", "")
    if not isinstance(style, str):
        return False

    color_match = re.search(r"(?:^|;)\s*color\s*:\s*([^;!]+)", style, re.IGNORECASE)
    bg_match = re.search(
        r"(?:^|;)\s*background(?:-color)?\s*:\s*([^;!]+)",
        style,
        re.IGNORECASE,
    )

    if color_match and bg_match:
        fg = _normalize_color(color_match.group(1))
        bg = _normalize_color(bg_match.group(1))
        return bool(fg and bg and fg == bg)

    return False


_CHECK_FUNCTIONS = {
    "hidden_elements": _is_hidden,
    "off_screen_elements": _is_off_screen,
    "same_color_text": _has_same_color_text,
}


def _classify_and_remove(soup: BeautifulSoup, stats: HtmlStats) -> None:
    """Classify and remove hidden/off-screen/same-color elements."""
    for tag in list(soup.find_all(True)):
        if not isinstance(tag, Tag):
            continue
        if tag.attrs is None:
            continue
        for stat_attr, check_fn in _CHECK_FUNCTIONS.items():
            if check_fn(tag):
                setattr(stats, stat_attr, getattr(stats, stat_attr) + 1)
                tag.decompose()
                break


def _strip_dangerous_tags(soup: BeautifulSoup, stats: HtmlStats) -> None:
    """Remove script, style, noscript, meta, link tags."""
    for tag_name in _STRIP_TAGS:
        found = soup.find_all(tag_name)
        count = len(found)
        match tag_name:
            case "script":
                stats.script_tags = count
            case "style":
                stats.style_tags = count
            case "noscript":
                stats.noscript_tags = count
            case "meta" | "link":
                stats.meta_tags += count
        for tag in found:
            tag.decompose()


def sanitize_html(html_content: str) -> tuple[str, HtmlStats]:
    """Parse HTML, strip hidden/dangerous elements, convert to markdown."""
    stats = HtmlStats()
    soup = BeautifulSoup(html_content, "html.parser")

    _classify_and_remove(soup, stats)
    _strip_dangerous_tags(soup, stats)

    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    stats.html_comments = len(comments)
    for comment in comments:
        comment.extract()

    markdown_content: str = markdownify(str(soup), heading_style="ATX", strip=["img"])
    return markdown_content, stats
