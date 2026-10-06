"""The one JSON walk. There used to be two.

Every place that asks "what strings are in this document?" comes here. That
was not true until issue #167: this walk and ``defense.run_l1_json``
were separate implementations of the same traversal, maintained by hand,
and the old docstring here said so — it warned that "if the two walks ever
disagree about what counts as a leaf, the accounting stops meaning anything"
and then left both copies in place.

They agreed. ``tests/test_full_is_defend_json.py`` proves it across the whole
adversarial corpus, and that test is what made it safe to delete one. It is
kept, because the property it checks is the reason this module exists.

Iterative, not recursive: a 4KB "[[[[..." depth bomb against a recursive walk
is an attacker-triggerable RecursionError, and an exception raised mid-scan
is a fail-open.
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
