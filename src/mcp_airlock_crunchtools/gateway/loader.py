"""YAML profile loader with env-var token resolution.

Fails closed: any missing env var, schema violation, or YAML parse error
raises `ProfileConfigError` at load time. The server refuses to expose
gateway routes if loading fails.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr, ValidationError

from .errors import ProfileConfigError
from .profile import Profile

logger = logging.getLogger(__name__)


def load_profiles(path: Path | str) -> dict[str, Profile]:
    """Load profile registry from YAML.

    Args:
        path: Path to the profiles YAML file.

    Returns:
        Mapping from profile name to fully-populated `Profile` (bearer tokens
        resolved from env vars and stored as `SecretStr`).

    Raises:
        ProfileConfigError: file missing, YAML invalid, schema violated, or
            an env var named in `auth.bearer_token_env` is unset.
    """
    config_path = Path(path)
    if not config_path.is_file():
        raise ProfileConfigError(f"Profiles file not found: {config_path}")

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileConfigError(f"Cannot read profiles file {config_path}: {exc}") from exc

    try:
        cfg_data: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ProfileConfigError(f"Invalid YAML in {config_path}: {exc}") from exc

    if not isinstance(cfg_data, dict):
        raise ProfileConfigError(
            f"Profiles file {config_path} must contain a top-level mapping"
        )

    profiles_section = cfg_data.get("profiles")
    if not isinstance(profiles_section, dict) or not profiles_section:
        raise ProfileConfigError(
            f"Profiles file {config_path} must contain a non-empty 'profiles' mapping"
        )

    registry: dict[str, Profile] = {}
    for name, body in profiles_section.items():
        if not isinstance(body, dict):
            raise ProfileConfigError(
                f"Profile {name!r}: body must be a mapping, got {type(body).__name__}"
            )
        try:
            profile = Profile(name=name, **body)
        except ValidationError as exc:
            raise ProfileConfigError(f"Profile {name!r}: {exc}") from exc

        env_name = profile.auth.bearer_token_env
        token_value = os.environ.get(env_name, "")
        if not token_value:
            raise ProfileConfigError(
                f"Profile {name!r}: env var {env_name} not set or empty"
            )
        profile.auth.bearer_token = SecretStr(token_value)
        registry[name] = profile

    logger.info(
        "gateway: loaded %d profile(s): %s",
        len(registry),
        ", ".join(sorted(registry)),
    )
    return registry
