"""Tests for gateway/args.py — empty optional arguments are dropped (RT #1505)."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_trentina_crunchtools.gateway.args import drop_empty_optional

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "feed_id": {"type": "integer"},
        "published_after": {"type": "string"},
        "query": {"type": "string"},
        "run_id": {"type": "string"},
    },
    "required": ["query"],
}


def test_empty_optionals_are_dropped_and_named() -> None:
    args = {"query": "rhel", "published_after": "", "run_id": None}

    cleaned, dropped = drop_empty_optional(args, SCHEMA)

    assert cleaned == {"query": "rhel"}
    assert sorted(dropped) == ["published_after", "run_id"]


@pytest.mark.parametrize("value", [0, False, [], {}, " "])
def test_values_a_caller_can_mean_are_kept(value: Any) -> None:
    """0 and false are the backend's to interpret; only "" and null are empty."""
    cleaned, dropped = drop_empty_optional({"query": "q", "feed_id": value}, SCHEMA)

    assert cleaned["feed_id"] == value
    assert dropped == []


def test_a_required_parameter_is_forwarded_even_when_empty() -> None:
    """The backend, not the gateway, says a required value is missing."""
    cleaned, _ = drop_empty_optional({"query": ""}, SCHEMA)

    assert cleaned == {"query": ""}


def test_no_schema_means_nothing_is_dropped() -> None:
    """Without a schema a parameter may be required; forward it unchanged."""
    args = {"published_after": ""}

    assert drop_empty_optional(args, None) == (args, [])


def test_the_callers_dict_is_not_mutated() -> None:
    args = {"query": "q", "run_id": ""}
    drop_empty_optional(args, SCHEMA)

    assert args == {"query": "q", "run_id": ""}
