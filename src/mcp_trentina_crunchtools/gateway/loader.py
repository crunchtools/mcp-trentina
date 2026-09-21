"""YAML profile loader with env-var token resolution.

Fails closed: any missing env var, schema violation, or YAML parse error
raises `ProfileConfigError` at load time. The server refuses to expose
gateway routes if loading fails.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import SecretStr, ValidationError

from .errors import ProfileConfigError
from .profile import AlertIngressConfig, MatrixIngressConfig, Profile


@dataclass(frozen=True)
class GatewayConfig:
    """Parsed gateway configuration with typed accessors."""

    profiles: dict[str, Profile]
    llm_providers: dict[str, Any] = field(default_factory=dict)
    matrix: dict[str, Any] = field(default_factory=dict)
    session_ttl_seconds: float = 300.0
    max_sessions_per_profile: int = 10

logger = logging.getLogger(__name__)

_ENV_REF_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


def _expand_env_refs(value: str, *, context: str) -> str:
    """Substitute ${VAR} references in a header value from os.environ.

    Fails closed (raises ProfileConfigError) if a referenced var is unset or
    empty — a missing auth secret must not silently become an unauthenticated
    backend call.
    """

    def _replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        resolved = _read_secret_env(var_name)
        if not resolved:
            raise ProfileConfigError(
                f"{context}: env var {var_name} (or {var_name}"
                f"{_ENV_FILE_SUFFIX}) referenced but not set or empty"
            )
        return resolved

    return _ENV_REF_RE.sub(_replace, value)


def _build_profile(name: str, body: Any) -> Profile:
    """Validate one profile entry and resolve its secrets from the environment.

    Resolves the bearer token from `auth.bearer_token_env`, the provisioned
    OAuth client secret from `oauth.client_secret_env`, and expands any
    ${VAR} references in backend headers. All fail closed on a missing env var.

    Each `llm_keys` entry supplies its secret one of two ways: `api_key`
    inline in the YAML, or `api_key_env` naming an environment variable.
    An inline key is taken as-is; otherwise the env var is required and an
    entry providing neither is a configuration error.
    """
    if not isinstance(body, dict):
        raise ProfileConfigError(
            f"Profile {name!r}: body must be a mapping, got {type(body).__name__}"
        )
    try:
        profile = Profile(name=name, **body)
    except ValidationError as exc:
        raise ProfileConfigError(f"Profile {name!r}: {exc}") from exc

    _warn_deprecated_defense_keys(name, body)
    _resolve_bearer_token(name, profile)
    _resolve_oauth_client_secret(name, profile)
    _resolve_llm_key_secrets(name, profile)
    _expand_backend_headers(name, profile)
    if profile.alert_ingress is not None:
        _resolve_alert_ingress_secrets(name, profile.alert_ingress)

    if profile.matrix_ingress is not None:
        _resolve_matrix_ingress_secrets(name, profile.matrix_ingress)

    return profile


def _warn_deprecated_defense_keys(name: str, body: dict[str, Any]) -> None:
    """Say so when a profile sets a key that no longer does anything.

    `l3_threshold` gated whether L3 ran. It does not any more — L3 runs on
    every input the gateway scans — and a config key that silently stopped
    mattering is exactly what an operator should be told about rather than
    discover. Retained for one release so `extra="forbid"` does not reject
    profiles written for 0.9.x; removed in 0.12.0.
    """
    defense = body.get("defense")
    if isinstance(defense, dict) and "l3_threshold" in defense:
        logger.warning(
            "Profile %r sets defense.l3_threshold, which is ignored — L3 "
            "runs on every scanned input. Remove the key; it is rejected "
            "from 0.12.0.",
            name,
        )


def _resolve_bearer_token(name: str, profile: Profile) -> None:
    profile.auth.bearer_token = _require_env(
        name, profile.auth.bearer_token_env, "bearer token",
    )


def _resolve_oauth_client_secret(name: str, profile: Profile) -> None:
    """Resolve a provisioned OAuth client's secret from the environment.

    OAuthConfig already refuses a half-declared client, so reaching here with a
    client_secret_env means client_id and the redirect URIs are present too.
    Fails closed on an unset var: a provisioned client whose secret resolved to
    empty would be stored with no secret, and the SDK's ClientAuthenticator
    rejects exactly that as misconfigured — better to say so at load.
    """
    oauth = profile.oauth
    if oauth is None or oauth.client_secret_env is None:
        return
    oauth.client_secret = _require_env(
        name, oauth.client_secret_env, "OAuth client secret",
    )


def _resolve_llm_key_secrets(name: str, profile: Profile) -> None:
    for provider_name, override in profile.llm_keys.items():
        if override.api_key.get_secret_value():
            continue
        if not override.api_key_env:
            raise ProfileConfigError(
                f"Profile {name!r} llm_keys.{provider_name}: must provide "
                f"either 'api_key' or 'api_key_env'"
            )
        key_value = _read_secret_env(override.api_key_env)
        if not key_value:
            raise ProfileConfigError(
                f"Profile {name!r} llm_keys.{provider_name}: env var "
                f"{override.api_key_env} not set or empty"
            )
        override.api_key = SecretStr(key_value)


def _expand_backend_headers(name: str, profile: Profile) -> None:
    for backend_name, backend in profile.backends.items():
        if backend.headers:
            backend.headers = {
                key: _expand_env_refs(
                    val,
                    context=f"Profile {name!r} backend {backend_name!r} header {key!r}",
                )
                for key, val in backend.headers.items()
            }


_ENV_FILE_SUFFIX = "_FILE"


def _warn_on_loose_mode(path: Path, file_var: str) -> None:
    """Warn, never fail, when a secret file is group- or world-readable.

    Constitution Section X: a runtime warning, not a hard error. Refusing to
    start over a permission bit would brick a deploy for something the
    operator can fix in place while the service keeps running.
    """
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        # The env var NAME and the mode, never the path. An operator can
        # resolve the path from the name, and a log line that points at where
        # the secrets live is a small disclosure that travels to the
        # centralized collector and sits there for 90 days. CodeQL flags the
        # path form as clear-text logging of sensitive data, and on this one
        # it is right for the right reason.
        logger.warning(
            "%s names a secret file whose mode is %04o — more permissive "
            "than 0600",
            file_var, mode,
        )


def _read_secret_env(env_var: str) -> str:
    """Resolve a secret from ``FOO``, or from the file named by ``FOO_FILE``.

    The ``_FILE`` indirection is the preferred shape for container
    deployments — podman secrets, Kubernetes secret volumes, systemd
    ``LoadCredential=`` — because the value lands in a mode-0600 file instead
    of in ``/proc/<pid>/environ``, which anything that can inspect the
    container can read.

    ``_FILE`` takes precedence when both are set, per the crunchtools
    mcp-server profile. That direction is deliberate: a mounted secret is the
    explicit, deployment-time answer, and an env var inherited from a shell or
    a stale unit file must not quietly outrank it.

    Returns "" when neither is set, leaving "is this required?" to the caller.
    Raises only when the operator named a file we cannot use — a secret
    pointed at a missing file is a broken deployment, not an absent secret.
    """
    file_var = f"{env_var}{_ENV_FILE_SUFFIX}"
    path_value = os.environ.get(file_var, "").strip()
    if path_value:
        path = Path(path_value)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProfileConfigError(
                f"{file_var}: cannot read the secret file it names "
                f"({exc.strerror or exc})"
            ) from exc
        _warn_on_loose_mode(path, file_var)
        return raw.strip()
    return os.environ.get(env_var, "")


def _require_env(name: str, env_var: str, what: str) -> SecretStr:
    """Read a required secret from the environment, failing closed if absent.

    Shared by every ingress that authenticates by a token-in-env: a missing
    or empty var is a fatal config error, not a silent None.
    """
    value = _read_secret_env(env_var)
    if not value:
        raise ProfileConfigError(
            f"Profile {name!r}: {what} env var {env_var} (or "
            f"{env_var}{_ENV_FILE_SUFFIX}) not set or empty"
        )
    return SecretStr(value)


def _resolve_matrix_ingress_secrets(name: str, matrix_ingress: MatrixIngressConfig) -> None:
    matrix_ingress.token = _require_env(name, matrix_ingress.token_env, "matrix_ingress")


def _resolve_alert_ingress_secrets(name: str, alert_ingress: AlertIngressConfig) -> None:
    alert_ingress.token = _require_env(name, alert_ingress.token_env, "alert_ingress")

    if alert_ingress.forward_secret_env:
        fwd_secret = _read_secret_env(alert_ingress.forward_secret_env)
        if not fwd_secret:
            raise ProfileConfigError(
                f"Profile {name!r}: alert_ingress forward_secret_env "
                f"{alert_ingress.forward_secret_env} not set or empty"
            )
        alert_ingress.forward_secret = SecretStr(fwd_secret)


def load_profiles(path: Path | str) -> GatewayConfig:
    """Load gateway configuration from YAML.

    Returns a ``GatewayConfig`` with typed accessors for profiles,
    llm_providers, and matrix configuration sections.

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

    registry: dict[str, Profile] = {
        name: _build_profile(name, body) for name, body in profiles_section.items()
    }

    logger.info(
        "gateway: loaded %d profile(s): %s",
        len(registry),
        ", ".join(sorted(registry)),
    )

    llm_section = cfg_data.get("llm_providers", {})
    matrix_section = cfg_data.get("matrix", {})
    gateway_section = cfg_data.get("gateway", {})
    if not isinstance(gateway_section, dict):
        gateway_section = {}

    return GatewayConfig(
        profiles=registry,
        llm_providers=llm_section if isinstance(llm_section, dict) else {},
        matrix=matrix_section if isinstance(matrix_section, dict) else {},
        session_ttl_seconds=float(gateway_section.get("session_ttl_seconds", 300.0)),
        max_sessions_per_profile=int(
            gateway_section.get("max_sessions_per_profile", 10)
        ),
    )


@dataclass(frozen=True)
class ActiveConfig:
    """What the running gateway loaded, and what it wired at startup.

    ``config.profiles`` is the SAME dict object every route handler, the
    compression module and the circuit-breaker wiring were handed at startup,
    and each of them reads it per request. Mutating that dict in place is
    therefore the whole swap — nothing has to be re-registered. Replacing it
    with a new dict would leave every holder pointing at the old one, which is
    exactly the silent no-op this machinery exists to prevent.

    The remaining fields record what CANNOT be changed by a reload, because
    they were bound into closures when the routes were registered: the LLM
    provider set, and whether the alert, matrix and OAuth routes exist at all.
    A reload compares against them so it can say what it did not apply, instead
    of reporting success over a change that went nowhere. OAuth is in this set
    because the provider and its authorization-server routes bind at startup —
    turning ``oauth.enabled`` on for a profile in the YAML and reloading cannot
    conjure a provider that boot did not build.
    """

    path: Path
    config: GatewayConfig
    llm_providers: dict[str, Any]
    alert_route_registered: bool
    matrix_route_registered: bool
    oauth_route_registered: bool


_active: ActiveConfig | None = None


def register_active_config(
    path: Path,
    config: GatewayConfig,
    llm_providers: dict[str, Any] | None = None,
    oauth_route_registered: bool = False,
) -> None:
    """Record the running configuration so it can be reloaded in place.

    Called once at startup, after the routes are registered, and again by
    each successful reload.
    """
    global _active
    _active = ActiveConfig(
        path=path,
        config=config,
        llm_providers=llm_providers if llm_providers is not None else {},
        alert_route_registered=any(
            p.alert_ingress is not None for p in config.profiles.values()
        ),
        matrix_route_registered=bool(config.matrix.get("enabled")),
        oauth_route_registered=oauth_route_registered,
    )


def get_active_config() -> ActiveConfig | None:
    """Return the running configuration, or None if the gateway is not up."""
    return _active


def replace_active_config(config: GatewayConfig) -> None:
    """Swap the scalar config after a reload, keeping the startup wiring facts.

    Raises:
        RuntimeError: no active config; a reload cannot precede startup.
    """
    global _active
    if _active is None:
        raise RuntimeError("replace_active_config called before register_active_config")
    _active = ActiveConfig(
        path=_active.path,
        config=config,
        llm_providers=_active.llm_providers,
        alert_route_registered=_active.alert_route_registered,
        matrix_route_registered=_active.matrix_route_registered,
        oauth_route_registered=_active.oauth_route_registered,
    )


def reset_active_config() -> None:
    """Forget the running configuration (for testing)."""
    global _active
    _active = None
