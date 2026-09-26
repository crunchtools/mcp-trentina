"""Argument hygiene before a call is forwarded to a backend.

Some clients fill every optional parameter with an empty value — ``""`` for
a string, ``null`` for anything — instead of leaving it out. A backend that
validates strictly rejects ``published_after: ""`` as a malformed date, where
omitting it means "no filter". So an empty optional is dropped here, which is
what the client meant (RT #1505).

Only ``""`` and ``None``. ``0`` and ``false`` are values a caller can mean;
they are the backend's to interpret. A parameter the schema marks required is
always forwarded as given, so the backend, not the gateway, says it is empty.
"""

from __future__ import annotations

from typing import Any


def drop_empty_optional(
    arguments: dict[str, Any], schema: dict[str, Any] | None
) -> tuple[dict[str, Any], list[str]]:
    """*arguments* without its empty optional values, and the names dropped.

    With no schema to say what is required, nothing is dropped: an unknown
    parameter may be required, and forwarding it unchanged is the old
    behaviour.
    """
    if schema is None:
        return arguments, []
    required = schema.get("required")
    keep = set(required) if isinstance(required, list) else set()
    dropped = [k for k, v in arguments.items() if k not in keep and (v is None or v == "")]
    if not dropped:
        return arguments, []
    return {k: v for k, v in arguments.items() if k not in dropped}, dropped
