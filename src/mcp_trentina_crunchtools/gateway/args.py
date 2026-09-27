"""Argument normalization before a call is forwarded to a backend (#241).

Some clients send every optional parameter instead of leaving it out, filling
it with a placeholder: ``""``, ``null``, ``0``. A backend that validates
strictly rejects ``published_after: ""`` or ``feed_id: 0``, where omitting the
argument means "no filter", and each rejection is a tool error an agent's
client may count against the whole server (RT #1505).

What the schema proves decides, never a list of "dumb values": ``offset: 0``
and ``unread_only: false`` are legitimate. For each argument, the first rule
that matches:

1. optional and ``""`` or ``null``        -> dropped
2. optional and equal to its ``default``  -> dropped
3. optional and provably invalid          -> dropped
4. required and provably invalid          -> reported; the router refuses

Dropping an optional cannot widen a call. The result is the call the agent
would have made by omitting it, and omitting an optional is always permitted.

"Provably" is the point. :func:`_violation` answers only what it can check,
and anything it does not understand counts as valid, so a value is never
dropped on a guess. That makes it more lenient than JSON Schema on purpose:
``oneOf`` passes when two branches match, as ``anyOf`` does, and the formats
accept what ``fromisoformat`` accepts, which is what the backends parse.
``pattern`` is skipped: the regex is the backend's, and running a backend's
regex here is a ReDoS on the gateway.

A reason names the rule, never the value. Reasons are logged, audited and
returned, and an argument may carry anything.
"""

from __future__ import annotations

import json
import math
import operator
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, TypeGuard

_MAX_DEPTH = 8
# Schema nodes visited per argument. Depth alone does not bound the work: a
# wide anyOf nested a few levels multiplies. Out of budget, nothing is proven.
_MAX_VISITS = 128

_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "number": (int, float),
    "integer": (int, float),
    "boolean": (bool,),
    "null": (type(None),),
    "array": (list,),
    "object": (dict,),
}


@dataclass
class Normalized:
    """What to forward, what was dropped and why, and what the router refuses."""

    arguments: dict[str, Any]
    dropped: dict[str, str] = field(default_factory=dict)
    invalid_required: dict[str, str] = field(default_factory=dict)


@dataclass
class _Walk:
    """One argument's traversal: the local ``$ref`` targets and the budget left."""

    defs: dict[str, Any]
    visits: int = _MAX_VISITS


def normalize_arguments(arguments: dict[str, Any], schema: dict[str, Any] | None) -> Normalized:
    """Apply the module's four rules to *arguments*, a tools/call's, under *schema*.

    *schema* is the tool's ``inputSchema`` as the backend listed it. The result
    carries ``arguments``, what to forward; ``dropped``, each removed optional
    and the rule that removed it; and ``invalid_required``, each required
    argument that fails its schema, for the router to refuse. A required
    argument is always left in ``arguments``.

    With no schema nothing changes: an unknown parameter may be required, and
    forwarding it unchanged is the old behaviour. The caller's dict is never
    mutated.
    """
    if schema is None:
        return Normalized(arguments)
    required_list = schema.get("required")
    required = set(required_list) if isinstance(required_list, list) else set()
    properties = schema.get("properties")
    properties = properties if isinstance(properties, dict) else {}
    # Local references only, keyed as a ``$ref`` spells them. Anything else
    # (a URL, a missing name) resolves to nothing and so judges nothing.
    defs = {
        f"#/{section}/{name}": target
        for section in ("$defs", "definitions")
        if isinstance(schema.get(section), dict)
        for name, target in schema[section].items()
        if isinstance(target, dict)
    }

    result = Normalized({})
    for key, value in arguments.items():
        prop = properties.get(key)
        prop = prop if isinstance(prop, dict) else {}
        if key in required:
            reason = _violation(value, prop, _Walk(defs), 0)
            if reason is not None:
                result.invalid_required[key] = reason
            result.arguments[key] = value
            continue
        drop = "empty" if value is None or value == "" else _drop_reason(value, prop, defs)
        if drop is None:
            result.arguments[key] = value
        else:
            result.dropped[key] = f"dropped: {drop}"
    if not result.dropped:
        result.arguments = arguments
    return result


def _drop_reason(value: Any, prop: dict[str, Any], defs: dict[str, Any]) -> str | None:
    reason = _violation(value, prop, _Walk(defs), 0)
    if "default" in prop and _same(value, prop["default"]):
        return "equals default"
    return reason


def _same(a: Any, b: Any) -> bool:
    """JSON equality: ``true`` is not ``1``, but ``1`` is ``1.0``."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if isinstance(a, int | float) and isinstance(b, int | float):
        return a == b
    try:
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    except (TypeError, ValueError):
        return False


def _violation(value: Any, prop: dict[str, Any], walk: _Walk, depth: int) -> str | None:
    """Why *value* fails *prop*, or None when it passes or cannot be judged."""
    walk.visits -= 1
    if depth > _MAX_DEPTH or walk.visits < 0:
        return None
    if "$ref" in prop:
        ref = prop["$ref"]
        target = walk.defs.get(ref) if isinstance(ref, str) else None
        if target is None:
            return None
        reason = _violation(value, target, walk, depth + 1)
        if reason is not None:
            return reason
    return _composed_violation(value, prop, walk, depth) or _local_violation(value, prop)


def _composed_violation(value: Any, prop: dict[str, Any], walk: _Walk, depth: int) -> str | None:
    """``anyOf``/``oneOf`` fail only when every branch fails; ``allOf`` when any does."""
    for key in ("anyOf", "oneOf"):
        branches = prop.get(key)
        if isinstance(branches, list) and branches:
            reasons = [
                _violation(value, b, walk, depth + 1) if isinstance(b, dict) else None
                for b in branches
            ]
            if all(r is not None for r in reasons):
                return _branch_reason(value, branches, reasons)
    branches = prop.get("allOf")
    for b in branches if isinstance(branches, list) else ():
        reason = _violation(value, b, walk, depth + 1) if isinstance(b, dict) else None
        if reason is not None:
            return reason
    return None


def _branch_reason(value: Any, branches: list[Any], reasons: list[str | None]) -> str:
    """The reason from the one branch *value*'s type fits, else a generic one.

    ``int | None`` with ``ge=1`` fails 0 on both branches; "below minimum 1" is
    what a model can learn from, "is not null" is not.
    """
    fitting = [
        reason
        for branch, reason in zip(branches, reasons, strict=True)
        if isinstance(branch, dict) and _type_violation(value, branch.get("type")) is None
    ]
    if len(fitting) == 1 and fitting[0] is not None:
        return fitting[0]
    return "matches no allowed form"


def _local_violation(value: Any, prop: dict[str, Any]) -> str | None:
    """The keywords that apply to *value* directly, no composition."""
    reason = _type_violation(value, prop.get("type")) or _value_violation(value, prop)
    if reason is not None:
        return reason
    if isinstance(value, str):
        return _string_violation(value, prop)
    if isinstance(value, int | float) and not isinstance(value, bool):
        return _number_violation(value, prop)
    if isinstance(value, list):
        return _bounds(len(value), prop, "minItems", "maxItems", "items")
    return None


def _value_violation(value: Any, prop: dict[str, Any]) -> str | None:
    if "const" in prop and not _same(value, prop["const"]):
        return "is not the allowed value"
    enum = prop.get("enum")
    if isinstance(enum, list) and not any(_same(value, e) for e in enum):
        return "is not an allowed value"
    return None


def _type_violation(value: Any, declared: Any) -> str | None:
    names = declared if isinstance(declared, list) else [declared]
    known = [n for n in names if isinstance(n, str) and n in _TYPES]
    if not known or len(known) != len(names):
        return None
    for name in known:
        if isinstance(value, bool) and name not in ("boolean",):
            continue
        if not isinstance(value, _TYPES[name]):
            continue
        if name == "integer" and isinstance(value, float) and not value.is_integer():
            continue
        return None
    return f"is not {' or '.join(known)}"


def _string_violation(value: str, prop: dict[str, Any]) -> str | None:
    reason = _bounds(len(value), prop, "minLength", "maxLength", "characters")
    if reason is not None:
        return reason
    fmt = prop.get("format")
    if fmt == "date-time" and not _parses(datetime.fromisoformat, value):
        return "is not a date-time"
    if fmt == "date" and not _parses(date.fromisoformat, value):
        return "is not a date"
    return None


def _parses(parse: Any, value: str) -> bool:
    try:
        parse(value)
    except ValueError:
        return False
    return True


def _number_violation(value: float, prop: dict[str, Any]) -> str | None:
    if not math.isfinite(value):
        return None
    checks = (
        ("minimum", operator.lt, "below"),
        ("exclusiveMinimum", operator.le, "not above"),
        ("maximum", operator.gt, "above"),
        ("exclusiveMaximum", operator.ge, "not below"),
    )
    for keyword, fails, relation in checks:
        bound = prop.get(keyword)
        if _is_number(bound) and fails(value, bound):
            return f"{relation} {keyword} {bound}"
    return None


def _bounds(size: int, prop: dict[str, Any], low: str, high: str, unit: str) -> str | None:
    minimum, maximum = prop.get(low), prop.get(high)
    if _is_number(minimum) and size < minimum:
        return f"has fewer than {low} {minimum} {unit}"
    if _is_number(maximum) and size > maximum:
        return f"has more than {high} {maximum} {unit}"
    return None


def _is_number(bound: Any) -> TypeGuard[int | float]:
    return isinstance(bound, int | float) and not isinstance(bound, bool)
