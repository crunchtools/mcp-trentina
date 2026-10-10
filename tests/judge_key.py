"""A test profile that holds a key for the provider its L3 runs on.

Since #407 a bound profile's L3 is available only as the call itself resolves
it: its own provider and its own key (``agent.resolve_profile_llm``). A test
that binds a profile and expects L3 to run gives it one here.
"""

from __future__ import annotations

from pydantic import SecretStr

from trentina.config import get_config
from trentina.gateway.profile import LlmKeyOverride, Profile


def with_judge_key(profile: Profile) -> Profile:
    """``profile``, holding a key for the judge provider in force."""
    provider = profile.defense.provider or get_config().provider
    profile.llm_keys[provider] = LlmKeyOverride(api_key=SecretStr("test-judge-key"))
    return profile
