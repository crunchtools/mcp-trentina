"""Security advisories for suspicious fetch failures.

The gateway's journal is also readable by agents through the podman and
systemd backends' container_logs and journal_query tools.
"""

from __future__ import annotations

import logging
from typing import Any

from trentina.client import fetch_url
from trentina.errors import FetchError, UnsupportedContentTypeError

log = logging.getLogger(__name__)


def _advisory(pattern: str) -> dict[str, Any]:
    return {"content": None, "security_advisory": {"level": "critical", "pattern": pattern}}


async def fetch_with_advisories(url: str) -> dict[str, Any]:
    """Fetch ``url``; turn a 415/406 or a redirect-to-binary into an advisory."""
    try:
        content, content_type = await fetch_url(url)
    except FetchError as exc:
        if exc.status_code in {406, 415}:
            log.warning("security advisory for %s: %s", url, exc)
            return _advisory(f"suspicious_http_{exc.status_code}")
        log.exception("fetch failed")
        raise
    except UnsupportedContentTypeError as exc:
        log.warning("redirect-to-binary advisory for %s: %s", url, exc)
        return _advisory("redirect_to_binary")
    return {"content": content, "content_type": content_type}
