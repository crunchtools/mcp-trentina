"""A profile's own judge is what its internal tools ask (#407).

A gateway whose environment holds no provider key, and a profile that brings
its own ``defense.provider`` and ``llm_keys``: the model proxy judged that
profile's completions, and every ``fetch``, ``read``, ``content`` and
``search`` call reported ``l3_unavailable`` with nothing logged. These run
the real tools and ``defend()`` with only the model calls faked.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import SecretStr

from trentina import config as config_mod
from trentina import defense
from trentina.gateway.context import profile_context
from trentina.gateway.profile import AuthConfig, DefenseConfig, LlmKeyOverride, Profile
from trentina.modes import Mode

from .mode_harness import call, layers

pytestmark = pytest.mark.asyncio

FAMILIES = ("fetch", "read", "content", "search")


@pytest.fixture
def no_global_key(env: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The harness environment with every global provider key removed."""
    for name in ("GEMINI_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("TRENTINA_MODEL_PROVIDER", raising=False)
    config_mod._config = None
    defense._no_judge_logged.clear()
    assert config_mod.get_config().has_llm is False
    return env


def _profile(name: str, *, key: bool) -> Profile:
    profile = Profile(
        name=name,
        auth=AuthConfig(bearer_token_env="TEST"),
        defense=DefenseConfig(provider="openrouter", modes=["flag", "block"]),
        backends={},
    )
    assert profile.auth is not None
    profile.auth.bearer_token = SecretStr("x")
    if key:
        profile.llm_keys["openrouter"] = LlmKeyOverride(api_key=SecretStr("profile-key"))
    return profile


@pytest.mark.parametrize("family", FAMILIES)
async def test_a_profiles_own_key_reaches_l3_with_no_global_key(
    no_global_key: Path, family: str
) -> None:
    with layers(no_global_key) as fakes, profile_context(_profile("own-key", key=True)):
        response = await call(family, Mode.FLAG, fakes)

    fakes.detect.assert_called_once()
    assert "_trentina_warning" not in response


@pytest.mark.parametrize("family", FAMILIES)
async def test_a_profile_without_its_key_is_unavailable_never_clean(
    no_global_key: Path, family: str
) -> None:
    with layers(no_global_key) as fakes, profile_context(_profile("keyless", key=False)):
        response = await call(family, Mode.FLAG, fakes)

    fakes.detect.assert_not_called()
    assert response["_trentina_warning"]["l3_unavailable"] is True


async def test_a_global_key_does_not_stand_in_for_the_profiles(env: Path) -> None:
    """The check answers as the call resolves: a bound profile is never
    judged on the gateway's key, so the gateway holding one changes nothing."""
    defense._no_judge_logged.clear()
    assert config_mod.get_config().has_llm is True
    with layers(env) as fakes, profile_context(_profile("keyless", key=False)):
        response = await call("content", Mode.FLAG, fakes)

    fakes.detect.assert_not_called()
    assert response["_trentina_warning"]["l3_unavailable"] is True


async def test_the_missing_judge_is_logged_once_per_profile(
    no_global_key: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="trentina.defense")
    for name in ("keyless", "keyless", "other"):
        with layers(no_global_key) as fakes, profile_context(_profile(name, key=False)):
            await call("content", Mode.FLAG, fakes)

    lines = [r.getMessage() for r in caplog.records if "no provider to ask" in r.getMessage()]
    assert len(lines) == 2
    assert "'keyless'" in lines[0] and "'openrouter'" in lines[0]
    assert "'other'" in lines[1]
    assert fakes.payload not in "".join(lines)
