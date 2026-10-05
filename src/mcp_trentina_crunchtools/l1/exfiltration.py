"""Exfiltration URL detection — strip suspicious images used for data theft.

Markdown ``![](url)`` and, since #201, HTML ``<img src=url>`` (OWASP's
example). Either one renders as a request to the attacker's server with the
stolen data in the query string, and neither needs the reader to click.

Links are counted too (#363), by a narrower rule, because a link is ordinary
where a data-carrying image is not: a newsletter's every link has a long
signed query. A link counts when its query is built to be FILLED IN, with a
parameter named for what it carries (``?data=``) or a placeholder where the
value goes (``?q={conversation}``). A link whose text shows one site's URL
and whose target is another's is counted apart and is informational: mail
trackers do it on every message.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse

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
_A_OPEN = re.compile(r"<a(?=[\s/])", re.IGNORECASE)
_HREF_ATTR = re.compile(
    r"""[\s/]href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
    re.IGNORECASE,
)
MAX_LINK_TEXT = 500
MAX_LINK_URL = 4096
# A value left to be filled in: `{x}`, `{{x}}`, `<x>`, `[X]`, `$X`, `${x}`.
_PLACEHOLDER = re.compile(
    r"\{\{?[A-Za-z_][^{}]{0,80}\}\}?|<[A-Za-z_][^<>]{1,80}>|\[[A-Z][^\]]{1,80}\]"
    r"|\$\{?[A-Za-z_]{3,}\}?"
)
_SHOWN_URL = re.compile(r"[\s*_`]*https?://([^/\s?#]+)", re.IGNORECASE)


def _markdown_links(text: str) -> list[tuple[str, str]]:
    """``(label, url)`` for every ``[label](url)`` that is not an image.

    Anchored on ``](``, with the label and the URL each looked for inside a
    bounded window, so repeated unclosed halves cost the window and no more.
    """
    links: list[tuple[str, str]] = []
    pos = 0
    while (close := text.find("](", pos)) >= 0:
        pos = close + 2
        paren = text.find(")", pos, pos + MAX_LINK_URL)
        start = text.rfind("[", max(0, close - MAX_LINK_TEXT), close)
        if paren < 0 or start < 0 or (start and text[start - 1] == "!"):
            continue
        target = text[pos:paren].split()
        if target:
            links.append((text[start + 1 : close], target[0].strip("<>")))
    return links


def _html_links(text: str) -> list[tuple[str, str]]:
    """``(label, url)`` for every ``<a href=url>label</a>``."""
    links: list[tuple[str, str]] = []
    for start, end in _tags(text, _A_OPEN, 2):
        href = _HREF_ATTR.search(text, start, end)
        if href is None:
            continue
        close = text.find("</", end, end + MAX_LINK_TEXT)
        label = text[end:close] if close >= 0 else ""
        links.append((label, html.unescape(href.group(1) or href.group(2) or href.group(3) or "")))
    return links


def _site(host: str) -> str:
    """The last two labels of ``host``: near enough to "the same site"."""
    return ".".join(host.lower().rstrip(".").split(":")[0].split(".")[-2:])


def _is_fill_in_link(url: str) -> bool:
    """Whether ``url``'s query is built to carry data out: see the module docstring."""
    try:
        query = urlparse(url.strip()).query
    except ValueError:
        return False
    for pair in query.split("&"):
        name, _, value = pair.partition("=")
        if name.lower() in _EXFIL_PARAM_NAMES or _PLACEHOLDER.search(unquote(value)):
            return True
    return False


def _is_mismatched(label: str, url: str) -> bool:
    """Whether ``label`` shows a URL on one site and ``url`` goes to another."""
    shown = _SHOWN_URL.match(label)
    if shown is None:
        return False
    try:
        host = urlparse(url.strip()).hostname
    except ValueError:
        return False
    return bool(host) and _site(shown.group(1)) != _site(host or "")


def _tags(text: str, opener: re.Pattern[str], skip: int) -> list[tuple[int, int]]:
    """The ``(start, end)`` span of every complete tag ``opener`` starts, in linear time.

    Written for ``<img``; ``skip`` is the opener's length. Each ``<img`` owns
    the text up to the next one, and its tag ends at the
    first ``>`` outside quotes there, or at the first ``>`` if a quote never
    closes. So every ``src=`` in the payload is judged by exactly one tag,
    and a decoy unclosed quote cannot swallow a real tag that follows it. A
    scanner rather than a regex because the regex rescanned the rest of the
    payload from every unclosed ``<img``: 4,000 of them took over a second
    (#210). Here each character is read at most twice.
    """
    starts = [m.start() for m in opener.finditer(text)]
    spans: list[tuple[int, int]] = []
    for n, start in enumerate(starts):
        limit = starts[n + 1] if n + 1 < len(starts) else len(text)
        quote = ""
        close = -1
        for i in range(start + skip, limit):
            char = text[i]
            if quote:
                quote = "" if char == quote else quote
            elif char in "\"'":
                quote = char
            elif char == ">":
                close = i
                break
        if close < 0:
            close = text.find(">", start + skip, limit)
        if close >= 0:
            spans.append((start, close + 1))
    return spans


MAX_SUSPICIOUS_URL_LENGTH = 500
MAX_QUERY_VALUE_LENGTH = 100


@dataclass
class ExfiltrationStats:
    """Counts of detected exfiltration URLs.

    ``mismatched_links`` is informational: it reaches L3's briefing and stays
    out of ``PipelineStats.suspicious_detections``.
    """

    exfiltration_urls: int = field(default=0)
    exfiltration_links: int = field(default=0)
    mismatched_links: int = field(default=0)


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
    for label, url in (*_markdown_links(text), *_html_links(text)):
        stats.exfiltration_links += _is_fill_in_link(url)
        stats.mismatched_links += _is_mismatched(label, url)

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
    for start, end in _tags(cleaned, _IMG_OPEN, 4):
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
