"""Exfiltration URL detection — strip suspicious images used for data theft.

Markdown ``![](url)`` and, since #201, HTML ``<img src=url>`` (OWASP's
example). Either one renders as a request to the attacker's server with the
stolen data in the query string, and neither needs the reader to click.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_EXFIL_PARAM_NAMES = frozenset(
    {
        "exfil",
        "data",
        "payload",
        "stolen",
        "leak",
        "extract",
        "dump",
    }
)

# Every `src=` in an <img> tag is judged, any suspicious one counting: a
# decoy in another attribute's value (`alt="x src=/safe.png"`) cannot stand
# in for the real source. `src` follows whitespace or a slash (`<img/src=`
# is fetched) but never a hyphen (`data-src` is not).
_SRC_ATTR = re.compile(
    r"""[\s/]src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
    re.IGNORECASE,
)


def _markdown_images(text: str) -> list[tuple[int, int, str, str]]:
    """``(start, end, alt, url)`` for every ``![alt](url)``, in one pass.

    The same matches ``!\\[([^\\]]*)\\]\\(([^)]+)\\)`` found, without its cost: that
    regex rescanned the rest of the payload from every unclosed ``![``, and
    90k characters of them took seven seconds (#210). Every ``![`` before a
    given ``]`` shares that ``]``, so when it is not followed by ``(url)``
    none of them match and the scan moves past it; a missing ``]`` or ``)``
    ends the scan, since no later start could find one either.
    """
    images: list[tuple[int, int, str, str]] = []
    pos = 0
    while (start := text.find("![", pos)) >= 0:
        close = text.find("]", start + 2)
        if close < 0:
            break
        if text.startswith("(", close + 1):
            paren = text.find(")", close + 2)
            if paren < 0:
                break
            if paren > close + 2:
                images.append((start, paren + 1, text[start + 2 : close], text[close + 2 : paren]))
                pos = paren + 1
                continue
        pos = close + 1
    return images


_IMG_OPEN = re.compile(r"<img\b", re.IGNORECASE)


def _img_tags(text: str) -> list[tuple[int, int]]:
    """The ``(start, end)`` span of every complete <img> tag, in linear time.

    Each ``<img`` owns the text up to the next one, and its tag ends at the
    first ``>`` outside quotes there, or at the first ``>`` if a quote never
    closes. So every ``src=`` in the payload is judged by exactly one tag,
    and a decoy unclosed quote cannot swallow a real tag that follows it. A
    scanner rather than a regex because the regex rescanned the rest of the
    payload from every unclosed ``<img``: 4,000 of them took over a second
    (#210). Here each character is read at most twice.
    """
    starts = [m.start() for m in _IMG_OPEN.finditer(text)]
    spans: list[tuple[int, int]] = []
    for n, start in enumerate(starts):
        limit = starts[n + 1] if n + 1 < len(starts) else len(text)
        quote = ""
        close = -1
        for i in range(start + 4, limit):
            char = text[i]
            if quote:
                quote = "" if char == quote else quote
            elif char in "\"'":
                quote = char
            elif char == ">":
                close = i
                break
        if close < 0:
            close = text.find(">", start + 4, limit)
        if close >= 0:
            spans.append((start, close + 1))
    return spans


MAX_SUSPICIOUS_URL_LENGTH = 500
MAX_QUERY_VALUE_LENGTH = 100


@dataclass
class ExfiltrationStats:
    """Counts of detected exfiltration URLs."""

    exfiltration_urls: int = field(default=0)


def _is_suspicious_url(url: str) -> bool:
    """Check if a URL looks like a data exfiltration attempt."""
    try:
        parsed = urlparse(url.strip())
        query = parsed.query

        if query:
            for param_pair in query.split("&"):
                if "=" in param_pair:
                    _, value = param_pair.split("=", 1)
                    if len(value) > MAX_QUERY_VALUE_LENGTH:
                        return True
                    if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", value):
                        return True

        if query:
            param_names = {p.split("=", 1)[0].lower() for p in query.split("&") if "=" in p}
            if param_names & _EXFIL_PARAM_NAMES:
                return True

        if len(url) > MAX_SUSPICIOUS_URL_LENGTH:
            return True

    except ValueError:
        return False

    return False


def strip_exfiltration(text: str) -> tuple[str, ExfiltrationStats]:
    """Detect and remove markdown and HTML images with suspicious exfiltration URLs."""
    stats = ExfiltrationStats()

    pieces: list[str] = []
    last = 0
    for start, end, alt, url in _markdown_images(text):
        if _is_suspicious_url(url):
            stats.exfiltration_urls += 1
            pieces += [text[last:start], f"[image: {alt}]" if alt else "[image removed]"]
            last = end
    cleaned = "".join([*pieces, text[last:]])

    pieces = []
    last = 0
    for start, end in _img_tags(cleaned):
        tag = cleaned[start:end]
        urls = (m.group(1) or m.group(2) or m.group(3) or "" for m in _SRC_ATTR.finditer(tag))
        # Judged as the browser will fetch it: `&#x64;ata=` is `data=` once
        # character references are decoded, and a browser decodes them.
        if any(_is_suspicious_url(html.unescape(url)) for url in urls):
            stats.exfiltration_urls += 1
            pieces += [cleaned[last:start], "[image removed]"]
            last = end
    cleaned = "".join([*pieces, cleaned[last:]])
    return cleaned, stats
