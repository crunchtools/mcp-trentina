"""The one JSON walk both extractors share.

Iterative, not recursive: a 4KB "[[[[..." depth bomb against a recursive walk
is an attacker-triggerable RecursionError, and an exception inside an
extractor becomes a degraded scan. The same reasoning is written out at
``defense.sanitize_json_value``, which this mirrors on purpose — if the two
walks ever disagree about what counts as a leaf, the accounting in S3 stops
meaning anything.
"""

from __future__ import annotations

from typing import Any


def iter_leaves(payload: Any) -> list[str]:
    """Every non-empty string in the document, keys included, in source order.

    Keys are leaves because a model reads ``{"IGNORE ALL PREVIOUS": true}``
    the same way it reads a value; keys used to be a scan-free channel and
    that was a bug, not an optimisation.
    """
    out: list[str] = []
    stack: list[Any] = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if node:
                out.append(node)
        elif isinstance(node, dict):
            for key, value in reversed(list(node.items())):
                stack.append(value)
                stack.append(key)
        elif isinstance(node, list):
            stack.extend(reversed(node))
    return out
