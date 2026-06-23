"""Parameter guards — per-tool argument validation at the gateway.

Applied after the tool-name allowlist check and before the backend call.
A guarded parameter's value must match at least one ``allow`` pattern and
must not match any ``deny`` pattern (same semantics as tools_allow/tools_deny).
Missing or None parameters are not checked.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .profile import Backend


def check_parameter_guards(
    tool_name: str,
    arguments: dict[str, Any],
    backend: Backend,
) -> str | None:
    """Validate tool arguments against the backend's parameter guards.

    Args:
        tool_name: The un-namespaced tool name (e.g. ``send_gmail_message``).
        arguments: The arguments dict from the JSON-RPC ``tools/call`` params.
        backend: Backend config carrying ``parameter_guards``.

    Returns:
        ``None`` if all checks pass, or a terse error message on the first
        violation. Error messages never include the rejected value.
    """
    tool_guards = backend.parameter_guards.get(tool_name)
    if not tool_guards:
        return None

    for param_name, constraint in tool_guards.items():
        value = arguments.get(param_name)
        if value is None:
            continue

        str_value = str(value)

        if not any(fnmatchcase(str_value, pat) for pat in constraint.allow):
            return f"Parameter {param_name!r} value not in allow list"

        if constraint.deny and any(
            fnmatchcase(str_value, pat) for pat in constraint.deny
        ):
            return f"Parameter {param_name!r} value matches deny pattern"

    return None
