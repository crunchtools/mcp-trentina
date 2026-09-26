"""Which pre-processors a call runs: the agent's pick, inside the operator's bounds (#183).

The agent chooses its transformation per call with ``trentina_preprocess``,
the way it chooses its disposition with ``trentina_mode``. The profile sets
both bounds:

* ``processors`` is the CEILING. The argument selects within it and cannot
  extend it.
* ``required`` is the FLOOR. Those run on every call, first, and the argument
  cannot remove them. That is what makes HTML conversion mandatory for a
  profile that considers markup hostile enough.

What the argument can never do is touch ``defend()``. Transformation runs
before the perimeter (``base.py`` invariant 2), so the choice changes what is
scanned only in the sense that it changes what is delivered: the two are
always the same bytes. ``trentina_preprocess=[]`` is not unscanned, it is
unconverted, and ``l1/hidden.py`` still counts what conversion would have
removed.

An omitted argument resolves to the tool's default BEFORE anything is
checked, the same rule ``ModePolicy.resolve`` follows, so absence is never a
way around the policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..errors import PreProcessNotPermittedError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

PREPROCESS_PARAM = "trentina_preprocess"

#: Declines that mean a processor did not do its job, rather than that the
#: payload was not its shape. A processor the call DEPENDS on — the profile's
#: floor, or anything an internal tool was asked to run — that reports one
#: refuses the call. ``too_large`` is here because padding a payload past the
#: parse cap must not be a way around a converter someone asked for.
FAILED_DECLINES = frozenset(
    {"error", "petit_error", "worker_error", "no_api_key", "empty_summary", "too_large"}
)

#: What each internal tool runs when the argument is omitted, at most. The
#: tool narrows it by what arrived — fetch converts only a page its server
#: calls HTML — and these names are offered even when the profile's ceiling
#: leaves them out, so a petit-only profile does not silently lose fetch's
#: conversion. `read` defaults to nothing: agents edit the files they read.
INTERNAL_DEFAULTS: dict[str, tuple[str, ...]] = {
    "fetch_tool": ("html",),
    "content_tool": ("html",),
    "read_tool": (),
}


@dataclass(frozen=True)
class PreProcessPolicy:
    """What a call may select, and what it runs regardless.

    ``offered``: the names the agent may pick, in the order they run — the
    tool's enum. Never contains a ``required`` name: there is nothing to
    choose about a processor that always runs.
    ``required``: the floor, run first on every call.
    ``selectable``: False means the tool does not take the argument at all,
    so even ``[]`` is refused: it would switch off the operator's default.
    """

    offered: tuple[str, ...]
    required: tuple[str, ...] = ()
    selectable: bool = True

    @classmethod
    def of(
        cls,
        ceiling: Iterable[str],
        required: Iterable[str] = (),
        *,
        defaults: Iterable[str] = (),
        permits: Callable[[str], bool] | None = None,
    ) -> PreProcessPolicy:
        """Build a selectable policy.

        Args:
            ceiling: the profile's ``processors``, in the order they run.
            required: the floor; removed from what is offered.
            defaults: the tool's own default, offered even when the ceiling
                omits it, and ordered ahead of it.
            permits: a parameter guard, ``permits(name) -> bool``; it narrows
                what is offered and nothing else.
        """
        floor = tuple(dict.fromkeys(required))
        offered = tuple(
            n
            for n in dict.fromkeys([*defaults, *ceiling])
            if n not in floor and (permits is None or permits(n))
        )
        return cls(offered, floor)

    def check(self, requested: Any) -> set[str]:
        """The optional names an explicit request picks, or refuse it.

        Raises:
            PreProcessNotPermittedError: the tool offers no selection, a name
                is outside ``offered``, or the value is not a list of names.
        """
        # Not offered — not selectable, or a guard emptied the enum — means
        # not accepted, [] included: it would switch the default off.
        if (
            not self.selectable
            or not self.offered
            or isinstance(requested, str)
            or not isinstance(requested, (list, tuple))
        ):
            raise PreProcessNotPermittedError(list(self.offered))
        chosen = {str(n) for n in requested} - set(self.required)
        if not chosen <= set(self.offered):
            raise PreProcessNotPermittedError(list(self.offered))
        return chosen

    def resolve(self, requested: Any, default: Sequence[str] = ()) -> tuple[str, ...]:
        """The processors this call runs, in order: required, then the pick.

        The pick runs in the policy's order, never the agent's: order changes
        what a chain produces, and the operator configured it.

        Raises:
            PreProcessNotPermittedError: see ``check``.
        """
        if requested is None:
            # The tool's default, in the tool's order. A guard narrows what
            # the agent may pick; it never edits what the operator runs.
            return self.required + tuple(n for n in default if n not in self.required)
        chosen = self.check(requested)
        return self.required + tuple(n for n in self.offered if n in chosen)


def standalone_policy() -> PreProcessPolicy:
    """No gateway: the profile default's ceiling, and no floor."""
    from ..gateway.profile import PreProcessConfig

    return PreProcessPolicy.of(
        PreProcessConfig().processors,
        defaults=[n for names in INTERNAL_DEFAULTS.values() for n in names],
    )


def current_preprocess_policy() -> PreProcessPolicy:
    """The policy the gateway bound for this call, else the standalone one."""
    from ..gateway.context import get_current_preprocess_policy

    bound = get_current_preprocess_policy()
    return bound if bound is not None else standalone_policy()
