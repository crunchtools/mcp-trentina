"""The one driver registry: parity with config, and the channel lock.

Trentina has two driver roles and one table per role, in
``gateway/drivers.py``. Until issue #160 each role also had its own registry
module and its own parity test, which is how the pre-processor table ended up
with no channel lock at all — the lock was written once, in the half nobody
copied it out of. One mechanism now, so this file covers both roles with the
same tests.

Two properties are worth the file:

REGISTRY/LITERAL PARITY. Each table is declared twice — once as a dict here,
once as a ``Literal`` in ``profile.py`` that makes pydantic reject an unknown
name at YAML load. A driver in the table but not the Literal exists, is wired
in, passes its own tests, and can be named by no profile. It is dead on
arrival and nothing else fails to say so.

THE CHANNEL LOCK. A driver declares the ingresses it understands, and
selecting one elsewhere fails at config load rather than at 3am. The failure
it prevents is silent in both roles: a Matrix extractor pointed at
alert-ingress JSON finds no Matrix event shape and falls through to generic
rules on a payload nobody checked it against; a pre-processor pointed at the
wrong shape declines forever and looks like it is working.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, get_args

import pytest

from mcp_trentina_crunchtools.channels import Channel
from mcp_trentina_crunchtools.gateway.drivers import (
    PREPROCESSORS,
    SCAN_POLICIES,
    build_extractor,
    build_preprocessors,
)
from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
from mcp_trentina_crunchtools.gateway.loader import load_profiles
from mcp_trentina_crunchtools.gateway.profile import (
    _DEFAULT_PROCESSORS,
    PreProcessConfig,
    ProcessorName,
    ScanViewConfig,
    ScanViewName,
)
from mcp_trentina_crunchtools.preprocess import Cost

if TYPE_CHECKING:
    from mcp_trentina_crunchtools.scanview import ScanViewContext, ScanViewExtractor


class TestRegistryAndConfigAgree:
    def test_every_registered_processor_is_configurable(self) -> None:
        assert set(PREPROCESSORS) == set(get_args(ProcessorName))

    def test_every_registered_scan_policy_is_configurable(self) -> None:
        assert set(SCAN_POLICIES) == set(get_args(ScanViewName))

    def test_every_default_processor_is_registered(self) -> None:
        assert set(_DEFAULT_PROCESSORS) <= set(PREPROCESSORS)
        assert set(PreProcessConfig().processors) <= set(PREPROCESSORS)

    def test_defaults_are_all_free(self) -> None:
        """A METERED processor in the defaults would spend LLM money for
        every profile that merely switched transformation on."""
        assert all(PREPROCESSORS[n].cost is Cost.FREE for n in _DEFAULT_PROCESSORS)

    def test_scan_policy_default_is_full(self) -> None:
        """A patch release must never silently narrow every deployment's scan."""
        assert ScanViewConfig().extractor == "full"

    def test_every_scan_policy_name_is_constructible(self) -> None:
        for name in SCAN_POLICIES:
            cfg = ScanViewConfig(extractor=cast("ScanViewName", name))
            assert build_extractor(cfg, channel=Channel.MATRIX).name == name

    def test_every_driver_declares_at_least_one_channel(self) -> None:
        """A driver with no channels is configurable and unreachable."""
        for processor in PREPROCESSORS.values():
            assert processor.channels, processor.name
        for name in SCAN_POLICIES:
            cfg = ScanViewConfig(extractor=cast("ScanViewName", name))
            assert build_extractor(cfg, channel=Channel.MATRIX).channels, name


class TestChannelLockingScanPolicies:
    def test_extractor_valid_on_its_channel(self) -> None:
        cfg = ScanViewConfig(extractor="generic")
        assert build_extractor(cfg, channel=Channel.ALERT).name == "generic"

    def test_extractor_rejected_on_a_channel_it_does_not_declare(self) -> None:
        class _MatrixOnly:
            name = "matrix-only"
            channels = frozenset({Channel.MATRIX})

            async def extract(self, payload: Any, ctx: ScanViewContext) -> Any:
                raise AssertionError("never called")

        SCAN_POLICIES["matrix-only"] = lambda _cfg, _keys: cast(
            "ScanViewExtractor", _MatrixOnly()
        )
        try:
            cfg = ScanViewConfig.model_construct(extractor="matrix-only")
            with pytest.raises(ProfileConfigError, match="not valid on the alert"):
                build_extractor(cfg, channel=Channel.ALERT, profile_name="p")
        finally:
            del SCAN_POLICIES["matrix-only"]


class TestChannelLockingPreProcessors:
    """The half that had no lock before the registries were collapsed."""

    def test_processors_resolve_in_configured_order(self) -> None:
        cfg = PreProcessConfig(processors=["petit", "email"])
        assert [p.name for p in build_preprocessors(cfg)] == ["petit", "email"]

    def test_every_shipped_processor_is_valid_on_the_tool_channel(self) -> None:
        cfg = PreProcessConfig(processors=list(get_args(ProcessorName)))
        assert len(build_preprocessors(cfg, channel=Channel.TOOL)) == len(PREPROCESSORS)

    def test_processor_rejected_on_a_channel_it_does_not_declare(self) -> None:
        """Today every processor is TOOL-only, so any other channel refuses.

        The lock is not decorative: the tool path is the only one that hands a
        pre-processor a string, and a processor named on the Matrix or alert
        ingress would be a profile that reads as configured and never runs.
        """
        cfg = PreProcessConfig(processors=["petit"])
        with pytest.raises(ProfileConfigError, match="not valid on the matrix"):
            build_preprocessors(cfg, channel=Channel.MATRIX, profile_name="p")

    def test_unknown_processor_name_fails_closed(self) -> None:
        cfg = PreProcessConfig.model_construct(processors=["nope"])
        with pytest.raises(ProfileConfigError, match="unknown pre-processor"):
            build_preprocessors(cfg, profile_name="p")


class TestTheLockFiresAtStartup:
    """A lock that fires on the first request to use the driver is not a lock.

    ``gateway/drivers.py`` says selecting a driver on a channel it does not
    declare is a load-time error. That is only true because ``loader.py``
    builds every driver a profile names and throws the result away. Without
    that call the refusal moves to whenever traffic first happens to hit the
    path — a latent outage rather than a refused start.

    Nothing in the shipped registry can trigger it: the ``Literal`` blocks
    unknown names, every processor declares TOOL, and every scan policy
    declares MATRIX. So a registered name is swapped for a driver with the
    wrong channels — a name pydantic accepts, so the refusal can only come
    from the lock. That is the regression this guards: the next driver added
    with channels that do not match where it is wired.
    """

    def test_a_profile_naming_a_wrong_channel_processor_refuses_to_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _MatrixOnly:
            name = "petit"
            cost = Cost.FREE
            channels = frozenset({Channel.MATRIX})

            async def run(self, payload: str, ctx: Any) -> Any:
                raise AssertionError("never called")

        monkeypatch.setitem(PREPROCESSORS, "petit", cast("Any", _MatrixOnly()))
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  josui:
    auth:
      bearer_token_env: TRENTINA_TEST_TOKEN
    preprocess:
      enabled: true
      processors: ["petit"]
    backends:
      mcp-slack:
        url: http://mcp-slack:8005/mcp
        tools_allow: ["*"]
"""
        )
        monkeypatch.setenv("TRENTINA_TEST_TOKEN", "tok")
        with pytest.raises(ProfileConfigError, match="not valid on the tool"):
            load_profiles(cfg)
