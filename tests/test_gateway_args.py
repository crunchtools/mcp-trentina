"""Tests for gateway/args.py — schema-driven argument normalization (#241, RT #1505)."""

from __future__ import annotations

from typing import Any

import pytest

from trentina.gateway.args import normalize_arguments

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "feed_id": {"anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]},
        "published_after": {"type": "string", "format": "date-time"},
        "query": {"type": "string"},
        "run_id": {"type": "string"},
        "limit": {"type": "integer", "default": 20, "maximum": 100},
        "offset": {"type": "integer"},
        "unread_only": {"type": "boolean", "default": False},
        "state": {"type": "string", "enum": ["open", "closed"]},
        "name": {"type": "string", "minLength": 1},
        "id": {"type": "integer", "minimum": 1},
        "code": {"type": "string", "minLength": 3, "maxLength": 3},
        "tags": {"type": "array", "minItems": 1, "maxItems": 2},
    },
    "required": ["query", "id"],
}


def _read(arguments: dict[str, Any], schema: dict[str, Any] | None) -> Any:
    """As for a read-only tool, where every provable failure is a drop.

    Most tests here are about what the validator proves, and ``dropped`` is
    where a read-only tool shows it.
    """
    return normalize_arguments(arguments, schema, read_only=True)


def _norm(**args: Any) -> Any:
    return _read({"query": "q", "id": 1, **args}, SCHEMA)


def _norm_write(**args: Any) -> Any:
    """The same call on a tool that did not say it only reads."""
    return normalize_arguments({"query": "q", "id": 1, **args}, SCHEMA)


def test_empty_optionals_are_dropped_and_named() -> None:
    result = _norm(published_after="", run_id=None)

    assert result.arguments == {"query": "q", "id": 1}
    assert result.dropped == {"published_after": "dropped: empty", "run_id": "dropped: empty"}


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("offset", 0),
        ("unread_only", True),
        ("run_id", " "),
        ("limit", 50),
        ("feed_id", 7),
        ("code", "abc"),
        ("tags", ["a", "b"]),
        ("published_after", "2026-09-24T00:00:00Z"),
    ],
)
def test_values_the_schema_allows_are_kept(key: str, value: Any) -> None:
    """0 with no minimum, and anything else the schema permits, is the backend's."""
    result = _norm(**{key: value})

    assert result.arguments[key] == value
    assert result.dropped == {}


def test_a_value_equal_to_the_default_is_forwarded() -> None:
    """``default`` is an annotation; the backend may not apply it on omission."""
    result = _norm(limit=20, unread_only=False)

    assert result.arguments["limit"] == 20
    assert result.arguments["unread_only"] is False
    assert result.dropped == {}


@pytest.mark.parametrize(
    ("allowed", "value", "dropped"),
    [(True, 1, True), (True, True, False), (20, 20.0, False), ({"a": 1}, {"a": 1}, False)],
)
def test_enum_membership_is_json_equality(allowed: Any, value: Any, dropped: bool) -> None:
    """``true`` is not ``1``; ``20.0`` is ``20``."""
    schema = {"properties": {"x": {"enum": [allowed]}}}

    assert ("x" in _read({"x": value}, schema).dropped) is dropped


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("feed_id", 0, "dropped: below minimum 1"),
        ("feed_id", "x", "dropped: matches no allowed form"),
        ("published_after", "yesterday", "dropped: is not a date-time"),
        ("state", "all", "dropped: is not an allowed value"),
        ("limit", 500, "dropped: above maximum 100"),
        ("limit", "ten", "dropped: is not integer"),
        ("offset", True, "dropped: is not integer"),
        ("offset", 1.5, "dropped: is not integer"),
        ("name", "", "dropped: empty"),
        ("code", "abcd", "dropped: has more than maxLength 3 characters"),
        ("code", "ab", "dropped: has fewer than minLength 3 characters"),
        ("tags", [], "dropped: has fewer than minItems 1 items"),
        ("tags", ["a", "b", "c"], "dropped: has more than maxItems 2 items"),
    ],
)
def test_an_optional_that_fails_its_schema_is_dropped(key: str, value: Any, reason: str) -> None:
    result = _norm(**{key: value})

    assert key not in result.arguments
    assert result.dropped == {key: reason}


@pytest.mark.parametrize(
    ("prop", "bad", "good", "reason"),
    [
        ({"const": "v1"}, "v2", "v1", "is not the allowed value"),
        ({"type": "string", "format": "date"}, "soon", "2026-09-24", "is not a date"),
        ({"type": "number", "exclusiveMinimum": 0}, 0, 0.5, "not above exclusiveMinimum 0"),
        ({"type": "number", "exclusiveMaximum": 1}, 1, 0.5, "not below exclusiveMaximum 1"),
    ],
)
def test_the_remaining_keywords(prop: dict[str, Any], bad: Any, good: Any, reason: str) -> None:
    schema = {"properties": {"x": prop}}

    assert _read({"x": bad}, schema).dropped == {"x": f"dropped: {reason}"}
    assert _read({"x": good}, schema).dropped == {}


@pytest.mark.parametrize(
    ("declared", "value", "dropped"),
    [
        (["integer", "null"], 3, False),
        (["integer", "null"], "3", True),
        (["integer", "string"], "3", False),
        (["integer", "string"], True, True),
        (["integer", "widget"], "3", False),
    ],
)
def test_a_type_list(declared: list[str], value: Any, dropped: bool) -> None:
    """Any listed type passes; bool is not integer; an unknown name judges nothing."""
    result = _read({"x": value}, {"properties": {"x": {"type": declared}}})

    assert ("x" in result.dropped) is dropped


def test_a_huge_integer_is_judged_not_crashed() -> None:
    schema = {"properties": {"n": {"type": "integer", "maximum": 100}}}

    assert _read({"n": 10**400}, schema).dropped == {"n": "dropped: above maximum 100"}


def test_a_single_branch_reports_its_own_reason() -> None:
    schema = {"properties": {"id": {"anyOf": [{"type": "integer", "minimum": 1}]}}}

    assert _read({"id": 0}, schema).dropped == {"id": "dropped: below minimum 1"}


def test_a_local_ref_is_followed() -> None:
    schema = {
        "properties": {"kind": {"$ref": "#/$defs/Kind"}},
        "$defs": {"Kind": {"type": "string", "enum": ["a", "b"]}},
    }

    assert "kind" in _read({"kind": "c"}, schema).dropped


@pytest.mark.parametrize(
    "prop",
    [
        {"type": "string", "pattern": "^[a-z]+$"},
        {"$ref": "https://example.com/schema.json"},
        {"$ref": "#/$defs/Missing"},
        {"type": "string", "format": "email"},
        {"type": "widget"},
        {"anyOf": [{"type": "integer"}, "not-a-schema"]},
    ],
)
def test_what_the_validator_cannot_judge_is_kept(prop: dict[str, Any]) -> None:
    """Never drop on a guess. ``pattern`` is skipped: a backend's regex is a ReDoS."""
    result = _read({"x": "NOT valid 123"}, {"properties": {"x": prop}})

    assert result.arguments == {"x": "NOT valid 123"}
    assert result.dropped == {}


def test_deep_nesting_is_bounded() -> None:
    prop: dict[str, Any] = {"type": "integer", "minimum": 1}
    for _ in range(50):
        prop = {"anyOf": [prop]}

    assert _read({"x": 0}, {"properties": {"x": prop}}).dropped == {}


def test_an_unresolved_ref_leaves_its_siblings_in_force() -> None:
    schema = {"properties": {"n": {"$ref": "https://x/y.json", "type": "integer", "minimum": 1}}}

    assert _read({"n": 0}, schema).dropped == {"n": "dropped: below minimum 1"}


def test_a_wide_all_of_stops_at_the_budget() -> None:
    parts: list[Any] = [{"type": "integer"}] * 500 + [{"minimum": 1}]

    assert _read({"n": 0}, {"properties": {"n": {"allOf": parts}}}).dropped == {}


def test_a_wide_schema_exhausts_the_budget_and_proves_nothing() -> None:
    """Width multiplies across levels; past the visit budget nothing is dropped."""
    prop: dict[str, Any] = {"type": "integer", "minimum": 1}
    for _ in range(4):
        prop = {"anyOf": [prop] * 8}

    assert _read({"x": 0}, {"properties": {"x": prop}}).dropped == {}


def test_a_required_argument_that_fails_is_reported_not_dropped() -> None:
    result = _read({"query": "q", "id": 0}, SCHEMA)

    assert result.arguments == {"query": "q", "id": 0}
    assert result.invalid_required == {"id": "below minimum 1"}


def test_a_missing_required_argument_is_reported() -> None:
    result = _read({"query": "q"}, SCHEMA)

    assert result.invalid_required == {"id": "is missing"}


@pytest.mark.parametrize(
    "prop",
    [{"anyOf": [{"type": "integer"}, {"type": "null"}]}, {"type": ["integer", "null"]}],
)
def test_a_required_null_the_schema_allows_is_forwarded(prop: dict[str, Any]) -> None:
    result = _read({"n": None}, {"properties": {"n": prop}, "required": ["n"]})

    assert result.arguments == {"n": None}
    assert result.invalid_required == {}


def test_a_required_empty_string_the_schema_allows_is_forwarded() -> None:
    """The backend, not the gateway, says whether an allowed value is missing."""
    result = _read({"query": "", "id": 1}, SCHEMA)

    assert result.arguments == {"query": "", "id": 1}
    assert result.invalid_required == {}


def test_no_schema_means_nothing_changes() -> None:
    args = {"published_after": "", "feed_id": 0}

    result = _read(args, None)

    assert result.arguments is args
    assert result.dropped == {}


def test_a_reason_never_carries_the_value() -> None:
    """Reasons are logged and audited; an argument may carry anything."""
    result = _norm(state="hunter2-secret", limit=10**9)

    assert "hunter2" not in str(result.dropped)
    assert "1000000000" not in str(result.dropped)


def test_all_of_fails_when_any_part_fails() -> None:
    schema = {"properties": {"n": {"allOf": [{"type": "integer"}, {"maximum": 5}]}}}

    assert _read({"n": 9}, schema).dropped == {"n": "dropped: above maximum 5"}
    assert _read({"n": 3}, schema).dropped == {}


def test_one_of_is_as_lenient_as_any_of() -> None:
    """Two matching branches are not proof of anything we can check; keep it."""
    schema = {"properties": {"n": {"oneOf": [{"type": "integer"}, {"minimum": 0}]}}}

    assert _read({"n": 3}, schema).dropped == {}
    assert _read({"n": "x"}, schema).dropped == {}
    assert "n" in _read({"n": -1.5}, schema).dropped


def test_the_callers_dict_is_not_mutated() -> None:
    args = {"query": "q", "id": 1, "run_id": "", "feed_id": 0}
    _read(args, SCHEMA)

    assert args == {"query": "q", "id": 1, "run_id": "", "feed_id": 0}


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("feed_id", "x", "matches no allowed form"),
        ("feed_id", 0, "below minimum 1"),
        ("published_after", "yesterday", "is not a date-time"),
        ("state", "all", "is not an allowed value"),
        ("limit", 500, "above maximum 100"),
        ("unread_only", "true", "is not boolean"),
        ("tags", [], "has fewer than minItems 1 items"),
    ],
)
def test_a_value_that_says_something_is_reported_not_dropped(
    key: str, value: Any, reason: str
) -> None:
    """Without it the call is not the one asked for (#335), so the router refuses."""
    result = _norm_write(**{key: value})

    assert result.invalid_optional == {key: reason}
    assert result.dropped == {}
    assert result.arguments[key] == value


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("run_id", "", "dropped: empty"),
        ("run_id", None, "dropped: empty"),
        ("feed_id", None, "dropped: empty"),
    ],
)
def test_an_empty_optional_is_dropped_whatever_the_tool(key: str, value: Any, reason: str) -> None:
    """A client that sends every optional said nothing by it (RT #1505)."""
    result = _norm_write(**{key: value})

    assert result.dropped == {key: reason}
    assert result.invalid_optional == {}
    assert key not in result.arguments


def test_a_reported_optional_reason_never_carries_the_value() -> None:
    result = _norm_write(state="hunter2-secret", limit=10**9)

    assert set(result.invalid_optional) == {"state", "limit"}
    assert "hunter2" not in str(result.invalid_optional)
    assert "1000000000" not in str(result.invalid_optional)
