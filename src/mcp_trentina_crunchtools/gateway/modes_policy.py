"""The per-call mode, inserted into every tool the gateway serves (#193).

A profile's `defense.modes` is the policy: which of block, warn and clean its
agent may choose, on every tool of every backend. The gateway puts that choice
where the agent can make it, and nowhere else:

* **tools/list** — `strip_params` removes any `trentina_*` property a backend
  declared (ours included) BEFORE the perimeter scan, and `insert_params` adds
  the gateway's own AFTER it. The inserted text is gateway-authored, so it is
  neither judged nor compressed as if a backend wrote it. A tool whose policy
  leaves one mode gets no parameter: there is nothing to choose.
* **tools/call** — `resolve_call` pops both arguments, resolves an omitted mode
  to the default, and only then checks the policy. Checking first would let an
  omitted mode skip the check, the way a parameter guard skips an argument
  that is absent. Remote backends never see either argument.

`Backend.modes` and a `parameter_guards` entry on `trentina_mode` narrow the
policy for one backend or one tool. Neither is needed for the base policy.
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any

from ..modes import Mode, ModePolicy
from .guards import evaluate_constraint

if TYPE_CHECKING:
    from .profile import Backend, Profile

MODE_PARAM = "trentina_mode"
PROMPT_PARAM = "trentina_prompt"
INSERTED_PARAMS = (MODE_PARAM, PROMPT_PARAM)

_MODE_TEXT = {
    Mode.BLOCK: "block refuses flagged content",
    Mode.CLEAN: "clean returns a verified extraction instead (set trentina_prompt)",
    Mode.WARN: "warn returns it verbatim with a warning attached",
}


def policy_for(profile: Profile, backend: Backend, tool_name: str) -> ModePolicy:
    """The modes this profile may use on this tool, and its default."""
    names = backend.modes if backend.modes is not None else (profile.defense.modes or [])
    guard = backend.parameter_guards.get(tool_name, {}).get(MODE_PARAM)
    allowed = [n for n in names if guard is None or evaluate_constraint(n, guard) is None]
    return ModePolicy.of(allowed, profile.defense.enforcement)


def strip_params(tool: dict[str, Any]) -> dict[str, Any]:
    """The tool without any backend-declared `trentina_*` parameter."""
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return tool
    props = schema.get("properties")
    if not isinstance(props, dict) or not any(p in props for p in INSERTED_PARAMS):
        return tool
    stripped = dict(tool)
    stripped["inputSchema"] = new_schema = dict(schema)
    new_schema["properties"] = {k: v for k, v in props.items() if k not in INSERTED_PARAMS}
    required = schema.get("required")
    if isinstance(required, list):
        new_schema["required"] = [r for r in required if r not in INSERTED_PARAMS]
    return stripped


def insert_params(tool: dict[str, Any], policy: ModePolicy) -> dict[str, Any]:
    """The tool with the modes its policy offers, or unchanged if there is no choice.

    When a per-tool guard excludes the default, an omitted mode would be
    refused; the parameter is then REQUIRED, so the schema says so.
    """
    default_ok = policy.default in policy.allowed
    if not policy.allowed or (len(policy.allowed) == 1 and default_ok):
        return tool
    original = tool.get("inputSchema")
    schema: dict[str, Any] = (
        copy.deepcopy(original) if isinstance(original, dict) else {"type": "object"}
    )
    schema.setdefault("properties", {}).update(_inserted_properties(policy, default_ok))
    if not default_ok:
        schema["required"] = [*schema.get("required", []), MODE_PARAM]
    return {**tool, "inputSchema": schema}


def _inserted_properties(policy: ModePolicy, default_ok: bool) -> dict[str, Any]:
    """The gateway-authored schema text: short, and nothing a backend wrote."""
    mode_prop: dict[str, Any] = {
        "type": "string",
        "enum": [m.value for m in policy.allowed],
        "description": f"Trentina delivery: {'; '.join(_MODE_TEXT[m] for m in policy.allowed)}.",
    }
    if default_ok:
        mode_prop["default"] = policy.default.value
    props = {MODE_PARAM: mode_prop}
    if Mode.CLEAN in policy.allowed:
        props[PROMPT_PARAM] = {
            "type": "string",
            "description": "What to extract, when trentina_mode is clean.",
        }
    return props


def resolve_call(
    profile: Profile, backend: Backend, tool_name: str, arguments: dict[str, Any]
) -> tuple[ModePolicy, Mode, str | None, dict[str, Any]]:
    """Resolve the call's mode and return the arguments without ours.

    Raises:
        ModeNotPermittedError: the resolved mode is outside the policy.
    """
    forwarded = dict(arguments)
    requested = forwarded.pop(MODE_PARAM, None)
    prompt = forwarded.pop(PROMPT_PARAM, None)
    policy = policy_for(profile, backend, tool_name)
    mode = policy.resolve(requested)
    return policy, mode, prompt if isinstance(prompt, str) and prompt.strip() else None, forwarded
