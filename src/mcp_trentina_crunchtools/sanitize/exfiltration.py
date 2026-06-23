"""Exfiltration URL detection — strip suspicious markdown images used for data theft."""

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


def sanitize_exfiltration(text: str) -> tuple[str, ExfiltrationStats]:
    """Detect and remove markdown images with suspicious exfiltration URLs."""
    stats = ExfiltrationStats()

    def _replace_image(match: re.Match[str]) -> str:
        alt = match.group(1)
        url = match.group(2)
        if _is_suspicious_url(url):
            stats.exfiltration_urls += 1
            return f"[image: {alt}]" if alt else "[image removed]"
        return match.group(0)

    cleaned = _MD_IMAGE_PATTERN.sub(_replace_image, text)
    return cleaned, stats
