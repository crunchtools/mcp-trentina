"""Exfiltration URL detection — strip suspicious images used for data theft.

Markdown ``![](url)`` and, since #201, HTML ``<img src=url>`` (OWASP's
example). Either one renders as a request to the attacker's server with the
stolen data in the query string, and neither needs the reader to click.
"""

from __future__ import annotations

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

_MD_IMAGE_PATTERN = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
# Each alternative is a negated class up to its own delimiter, so hostile
# markup cannot make this backtrack.
_HTML_IMAGE_PATTERN = re.compile(
    r"""<img\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>""",
    re.IGNORECASE,
)

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

    def _replace_image(match: re.Match[str]) -> str:
        alt = match.group(1)
        url = match.group(2)
        if _is_suspicious_url(url):
            stats.exfiltration_urls += 1
            return f"[image: {alt}]" if alt else "[image removed]"
        return match.group(0)

    def _replace_html_image(match: re.Match[str]) -> str:
        url = match.group(1) or match.group(2) or match.group(3) or ""
        if _is_suspicious_url(url):
            stats.exfiltration_urls += 1
            return "[image removed]"
        return match.group(0)

    cleaned = _MD_IMAGE_PATTERN.sub(_replace_image, text)
    cleaned = _HTML_IMAGE_PATTERN.sub(_replace_html_image, cleaned)
    return cleaned, stats
