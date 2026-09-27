"""The bridge process's configuration, from its own environment.

Deliberately NOT profiles.yaml. The bridge holds the upstream Matrix identity
and nothing else; the gateway holds the agent's homeserver and nothing of the
upstream one. Two processes, two environments, and neither can read the
other's (spec 015). Every secret accepts the ``_FILE`` form.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from ..gateway.errors import ProfileConfigError
from ..gateway.loader import read_secret_env

DEFAULT_HOMESERVER = "https://matrix-client.matrix.org"
DEFAULT_PORT = 8471


class SettingsError(RuntimeError):
    """A required setting is missing. Fatal at startup."""


def _secret(name: str) -> str:
    """A secret from ``NAME`` or ``NAME_FILE``, with one error type for every
    way it can be unusable."""
    try:
        return read_secret_env(name)
    except ProfileConfigError as exc:
        raise SettingsError(str(exc)) from exc


def _http_url(name: str, value: str) -> str:
    """An http(s) URL with a host, trailing slash dropped."""
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SettingsError(f"{name} must be an http(s) URL with a host, got {value!r}")
    return value.rstrip("/")


def _required(name: str) -> str:
    value = _secret(name)
    if not value:
        raise SettingsError(f"{name} (or {name}_FILE) is required")
    return value


@dataclass(frozen=True)
class BridgeSettings:
    """Everything the bridge needs to run."""

    profile: str
    homeserver: str
    user_id: str
    store_dir: Path
    pickle_key: str
    gateway_url: str
    ingress_token: str
    bridge_token: str
    listen_host: str
    listen_port: int
    device_name: str
    # Exactly one way in: a saved session, an adopted device, or a password.
    device_id: str
    access_token: str
    password: str

    @classmethod
    def from_env(cls) -> BridgeSettings:
        return cls(
            profile=_required("BRIDGE_PROFILE"),
            homeserver=_http_url(
                "BRIDGE_HOMESERVER", os.environ.get("BRIDGE_HOMESERVER", DEFAULT_HOMESERVER)
            ),
            user_id=_required("BRIDGE_USER_ID"),
            store_dir=Path(os.environ.get("BRIDGE_STORE_DIR", "/data")),
            pickle_key=_required("BRIDGE_PICKLE_KEY"),
            gateway_url=_http_url("BRIDGE_GATEWAY_URL", _required("BRIDGE_GATEWAY_URL")),
            ingress_token=_required("BRIDGE_INGRESS_TOKEN"),
            bridge_token=_required("BRIDGE_TOKEN"),
            listen_host=os.environ.get("BRIDGE_LISTEN_HOST", "127.0.0.1"),
            listen_port=int(os.environ.get("BRIDGE_LISTEN_PORT", str(DEFAULT_PORT))),
            device_name=os.environ.get("BRIDGE_DEVICE_NAME", "Trentina bridge"),
            device_id=os.environ.get("BRIDGE_DEVICE_ID", ""),
            access_token=_secret("BRIDGE_ACCESS_TOKEN"),
            password=_secret("BRIDGE_PASSWORD"),
        )
