"""Where a call went, for the audit row (#266).

The audit said which profile called which tool and how it ended, never where
the call was pointed. After an incident that left 17,600 actions to
reconstruct, "which hosts did it fetch, who did it message" was the one
question the database could not answer.

Three kinds, each stored beside the call in ``gateway_calls``:

- ``fetch``: the URL's host, then ``#`` and ``sha256[:16]`` of the whole URL.
  The host is what fan-out counts; the hash tells two URLs on one host apart
  without keeping a path or query that may carry a token.
- ``search``: ``q#`` and ``sha256[:16]`` of the query. Repeats are visible,
  the words are not.
- ``param``: for a proxied tool its backend declares in ``destination_params``,
  that argument's value — the channel, recipient, repo or queue — truncated.

The value is caller-chosen, so it lives in the audit database only, which no
tool reads raw. It never goes to the log (#262), and ``quarantine_stats``
shows it only to the agent that chose it; the operator gets its fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .profile import Backend

#: Longest value recorded; a recipient list or channel id fits, an essay does not.
MAX_DESTINATION_CHARS = 256
#: Room left for ``#`` and the hash after a fetch host.
_MAX_HOST_CHARS = MAX_DESTINATION_CHARS - 17

FETCH_TOOL = "fetch_tool"
SEARCH_TOOL = "search_tool"


class DestinationKind(StrEnum):
    """What a destination row counts as. Stored in ``destination_kind``."""

    FETCH = "fetch"
    SEARCH = "search"
    PARAM = "param"


@dataclass(frozen=True)
class Destination:
    """One call's destination, as the audit row stores it."""

    value: str
    kind: DestinationKind


def fingerprint(text: str) -> str:
    """``sha256[:16]`` of *text*."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _fetch(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        host = ""
    return f"{host[:_MAX_HOST_CHARS]}#{fingerprint(url)}"


def _param(value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return text[:MAX_DESTINATION_CHARS]


def destination_of(backend: Backend, tool: str, arguments: dict[str, Any]) -> Destination | None:
    """The destination one call names, or None when it names none we record.

    Internal ``fetch_tool`` and ``search_tool`` are recognized by name on the
    internal backend only: a proxied tool that happens to share the name is
    not ours, and is recorded only if its backend declares it.
    """
    if backend.is_internal:
        if tool == FETCH_TOOL and isinstance(url := arguments.get("url"), str):
            return Destination(_fetch(url), DestinationKind.FETCH)
        if tool == SEARCH_TOOL and isinstance(query := arguments.get("query"), str):
            return Destination(f"q#{fingerprint(query)}", DestinationKind.SEARCH)
        return None
    param = backend.destination_params.get(tool)
    if param is None:
        return None
    value = _param(arguments.get(param))
    return Destination(value, DestinationKind.PARAM) if value is not None else None
