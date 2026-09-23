"""The one registry: a configured name becomes a driver, per role.

Trentina has two driver roles and this module is the only place either one is
resolved from configuration. It answers one question for both — "the profile
asked for the driver called X on the Y channel; give me it, or fail the
load" — and it is deliberately the same code for both roles, because the
failure it prevents is the same failure:

* **Pre-processors** transform the payload outside the perimeter. Their
  output is scanned and delivered; see ``preprocess/base.py``.
* **Guard read policies** (``scanview/``) choose which strings the scanner
  reads out of a payload that is delivered whole. See ``scanview/base.py``
  for why that privilege is a guard's and never a pre-processor's.

There were two registries here until issue #160, one per role, each with its
own parity test and only one of them with a channel lock. Different roles do
not need different wiring, and the second copy is how the pre-processor
registry came to have no channel lock at all. One mechanism, two tables.

**Channel locking.** A driver declares the ingresses it understands and
selecting one elsewhere is a ``ProfileConfigError`` at config load, not a
runtime surprise. The Matrix case is the loud one — a Matrix extractor
pointed at alert-ingress JSON would find no Matrix event shape, fall through
to generic rules, and produce a perimeter nobody had checked against that
payload. The pre-processor case is quiet and just as wrong: a reducer tuned
for one payload shape, pointed at another, declines forever and looks like it
is working.

**Parity.** Each table is declared twice — once here, once as a ``Literal`` in
``profile.py`` that makes pydantic reject an unknown name at YAML load. A
single parity test (``tests/test_gateway_drivers.py``) keeps both tables in
step with both Literals. A driver registered but not in its Literal is dead on
arrival: wired in, passing its own tests, and nameable by no profile.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..channels import Channel
from ..preprocess import (
    EmailProcessor,
    PetitProcessor,
    PreProcessor,
    StructuredProcessor,
    SummarizeProcessor,
)
from ..scanview import (
    FullExtractor,
    GenericExtractor,
    MatrixExtractor,
    ScanViewExtractor,
)
from .errors import ProfileConfigError
from .profile import ScanViewConfig

if TYPE_CHECKING:
    from collections.abc import Callable

    from .profile import PreProcessConfig

# Pre-processors. Stateless by contract (the ``PreProcessor`` protocol), so
# one instance each for the process.
PREPROCESSORS: dict[str, PreProcessor] = {
    "email": EmailProcessor(),
    "petit": PetitProcessor(),
    "structured": StructuredProcessor(),
    "summarize": SummarizeProcessor(),
}

# Guard read policies. Factories rather than singletons: an extractor may own
# per-profile state (the Matrix one owns a key cache), so one instance per
# configured profile rather than one per process.
SCAN_POLICIES: dict[str, Callable[[ScanViewConfig, Any], ScanViewExtractor]] = {
    "full": lambda _cfg, _keys: FullExtractor(),
    "generic": lambda cfg, _keys: GenericExtractor(
        skip_sample_bytes=cfg.skip_sample_bytes
    ),
    "matrix": lambda cfg, keys: MatrixExtractor(
        generic=GenericExtractor(skip_sample_bytes=cfg.skip_sample_bytes),
        keys=keys,
    ),
}


def _lock_channel(driver: Any, *, channel: Channel, profile_name: str, role: str) -> None:
    """Refuse a driver on a channel it has not declared it understands."""
    if channel not in driver.channels:
        raise ProfileConfigError(
            f"Profile {profile_name!r}: {role} {driver.name!r} is not valid on "
            f"the {channel.value} channel "
            f"(valid: {sorted(c.value for c in driver.channels)})"
        )


def build_preprocessors(
    cfg: PreProcessConfig,
    *,
    channel: Channel = Channel.TOOL,
    profile_name: str = "",
) -> list[PreProcessor]:
    """Resolve the configured processor names, in the configured order.

    An unknown name is a load error rather than a silent skip. Dropping it
    quietly is how a typo becomes a profile that looks reduced and is not —
    and the same typo in ``tools_allow`` would be caught, so this should be.
    """
    processors: list[PreProcessor] = []
    for name in cfg.processors:
        processor = PREPROCESSORS.get(name)
        if processor is None:  # pragma: no cover - the Literal blocks this
            raise ProfileConfigError(
                f"Profile {profile_name!r}: unknown pre-processor {name!r}; "
                f"known: {sorted(PREPROCESSORS)}"
            )
        _lock_channel(
            processor, channel=channel, profile_name=profile_name, role="pre-processor"
        )
        processors.append(processor)
    return processors


def build_extractor(
    cfg: ScanViewConfig | None,
    *,
    channel: Channel,
    profile_name: str = "",
    keys: Any = None,
) -> ScanViewExtractor:
    """Construct the configured guard read policy, or fail closed at load.

    ``None`` means "no scan_view block", which is the same thing as the
    default: read everything.
    """
    cfg = cfg or ScanViewConfig()
    factory = SCAN_POLICIES.get(cfg.extractor)
    if factory is None:  # pragma: no cover - the Literal makes this unreachable
        raise ProfileConfigError(
            f"Profile {profile_name!r}: unknown scan_view extractor "
            f"{cfg.extractor!r}; known: {sorted(SCAN_POLICIES)}"
        )
    extractor = factory(cfg, keys)
    _lock_channel(
        extractor, channel=channel, profile_name=profile_name, role="scan_view extractor"
    )
    return extractor
