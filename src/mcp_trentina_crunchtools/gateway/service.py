"""The gateway's service identity: the operator profile (#138).

Some model calls belong to no tenant. Compressing a shared tool description
and judging it at the perimeter are the gateway's own work, done once for
every profile that lists the tool. Until #138 that work ran as whoever was
nearby: compression took the FIRST profile's provider for a shared backend
URL, so reordering ``profiles.yaml`` changed the model, and the ``tools/list``
path had no profile bound at all, so L3 fell through to the env-global key.
Neither was a decision; both were fall-through.

The rule now: centralized work runs AS the ``role: operator`` profile — its
provider, its model, its ``llm_keys``, its bill. The operator is the seat the
Operator agent holds (``docs/operator.md``), so the identity that installs and
configures Trentina is also the one its own overhead runs under.

Binding the operator into ``context._current_profile`` is the whole mechanism
for L3: the Q-Agent already resolves provider, model, key and fallback chain
from the bound profile, and already refuses to fall back to someone else's
key. Compression resolves through the same rule (``resolve_profile_llm``).

No operator declared keeps the env-global path, which is where every call
went before — logged at startup so the fallback is a stated fact rather than
an inherited one. ``load_profiles`` refuses a second operator and an operator
with no key for its own provider.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from enum import Enum
from typing import TYPE_CHECKING

from ..config import get_config
from .context import _current_profile

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .profile import Profile

logger = logging.getLogger(__name__)


def find_operator(profiles: Mapping[str, Profile]) -> Profile | None:
    """The one ``role: operator`` profile in ``profiles``, or None.

    ``load_profiles`` guarantees there is at most one, so the first is the
    only one.
    """
    return next((p for p in profiles.values() if p.role == "operator"), None)


def service_profile() -> Profile | None:
    """The running gateway's operator, or None (no operator, or no gateway).

    Read from the active config on every call rather than cached: a reload
    refills that dict in place, and a promoted or demoted operator has to take
    effect on the next centralized call, not the next restart.
    """
    from .loader import get_active_config

    active = get_active_config()
    return find_operator(active.config.profiles) if active is not None else None


class _Unresolved(Enum):
    """``service_context``'s default: "resolve the operator yourself"."""

    TOKEN = 0


@contextmanager
def service_context(
    operator: Profile | _Unresolved | None = _Unresolved.TOKEN,
) -> Iterator[Profile | None]:
    """Run the enclosed model calls as the service identity.

    Binds the operator profile for the block and yields it. With no operator
    it binds NOTHING — explicitly None, so a tenant bound further up the stack
    cannot leak into the gateway's own work — and the env-global path applies.

    A caller that already resolved the operator passes it in. That caller has
    usually keyed something on ``judge_of(operator)``, and resolving again here
    would let a reload between the two file a verdict under one judge that
    another one reached.
    """
    if isinstance(operator, _Unresolved):
        operator = service_profile()
    token = _current_profile.set(operator)
    try:
        yield operator
    finally:
        _current_profile.reset(token)


def judge_of(profile: Profile | None) -> tuple[str, str]:
    """The (provider, model) that L3 runs on for ``profile``.

    The same resolution the Q-Agent applies: the profile's override, else the
    env default. None is the env default itself.
    """
    config = get_config()
    if profile is None:
        return config.provider, config.model
    return (
        profile.defense.provider or config.provider,
        profile.defense.model or config.model,
    )


def log_service_identity(profiles: Mapping[str, Profile]) -> None:
    """Say, once, whose identity the gateway's own model calls run under.

    WARNING for the same reason as the startup cache line: production logs at
    WARNING, and this is the line that answers "who pays for compression".
    """
    operator = find_operator(profiles)
    if operator is None:
        provider, model = judge_of(None)
        logger.warning(
            "service identity: no operator profile declared — centralized model "
            "calls (compression, perimeter L3 on tool descriptions) use the "
            "env-global key, provider=%s model=%s",
            provider,
            model,
        )
        return
    provider, model = judge_of(operator)
    logger.warning(
        "service identity: centralized model calls run as operator profile=%s provider=%s model=%s",
        operator.name,
        provider,
        model,
    )
