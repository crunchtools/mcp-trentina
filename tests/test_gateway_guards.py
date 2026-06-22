"""Tests for gateway/guards.py — parameter value validation."""

from __future__ import annotations

from mcp_airlock_crunchtools.gateway.guards import check_parameter_guards
from mcp_airlock_crunchtools.gateway.profile import Backend, ParameterConstraint


def _backend(
    guards: dict[str, dict[str, ParameterConstraint]] | None = None,
) -> Backend:
    return Backend(
        url="http://x/mcp",
        tools_allow=["*"],
        parameter_guards=guards or {},
    )


class TestParameterGuards:
    """check_parameter_guards behaviour across allow, deny, and edge cases."""

    def test_no_guards_configured_passes(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message", {"to": "evil@example.com"}, _backend()
        )
        assert result is None

    def test_no_guard_for_this_tool_passes(self) -> None:
        result = check_parameter_guards(
            "other_tool",
            {"to": "evil@example.com"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["ok@x.com"])}}),
        )
        assert result is None

    def test_exact_allow_match_passes(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": "scott@gmail.com"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["scott@gmail.com"])}}),
        )
        assert result is None

    def test_glob_allow_match_passes(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": "smccarty@redhat.com"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["*@redhat.com"])}}),
        )
        assert result is None

    def test_value_not_in_allow_list_rejected(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": "evil@example.com"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["scott@gmail.com"])}}),
        )
        assert result is not None
        assert "not in allow list" in result

    def test_deny_wins_over_allow(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": "banned@redhat.com"},
            _backend({
                "send_gmail_message": {
                    "to": ParameterConstraint(
                        allow=["*@redhat.com"],
                        deny=["banned@redhat.com"],
                    )
                }
            }),
        )
        assert result is not None
        assert "deny" in result

    def test_missing_parameter_passes(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {"subject": "hello"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["scott@gmail.com"])}}),
        )
        assert result is None

    def test_none_parameter_passes(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": None},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["scott@gmail.com"])}}),
        )
        assert result is None

    def test_multiple_params_first_failure_reported(self) -> None:
        guards = {
            "send_gmail_message": {
                "to": ParameterConstraint(allow=["scott@gmail.com"]),
                "cc": ParameterConstraint(allow=["scott@gmail.com"]),
            }
        }
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": "scott@gmail.com", "cc": "evil@example.com"},
            _backend(guards),
        )
        assert result is not None
        assert "cc" in result

    def test_wildcard_allow_passes_anything(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": "anyone@anywhere.com"},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["*"])}}),
        )
        assert result is None

    def test_empty_arguments_passes(self) -> None:
        result = check_parameter_guards(
            "send_gmail_message",
            {},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["scott@gmail.com"])}}),
        )
        assert result is None

    def test_error_message_does_not_leak_value(self) -> None:
        secret = "secret-address@evil.com"
        result = check_parameter_guards(
            "send_gmail_message",
            {"to": secret},
            _backend({"send_gmail_message": {"to": ParameterConstraint(allow=["scott@gmail.com"])}}),
        )
        assert result is not None
        assert secret not in result
