"""Pydantic v2 models for gateway profile configuration.

Profiles are loaded from YAML and define which backend MCP servers a consumer
can reach, which tools per backend are allowed, and which defense layers
apply to responses. Phase 1 stores the defense flags but does not apply
them — Phase 2 wires the defense pipeline in.

All models use `extra="forbid"` per the constitution; unrecognized keys in
profile YAML are a hard error at load time.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
)

from ..config import SUPPORTED_PROVIDERS

PROFILE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
BACKEND_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
GLOB_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_*][a-zA-Z0-9_*-]*$")
GUARD_VALUE_RE = re.compile(r"^[a-zA-Z0-9_*@.\-+/ ]+$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

INTERNAL_SCHEME = "internal://"

MAX_BACKEND_TIMEOUT_SECONDS = 300.0
MAX_LIST_TIMEOUT_SECONDS = 60.0


class AuthConfig(BaseModel):
    """Per-profile bearer-token auth config.

    `bearer_token_env` is the env var name holding the actual token value;
    `bearer_token` is resolved at load time and never serialized.
    """

    model_config = ConfigDict(extra="forbid")

    bearer_token_env: str = Field(
        ..., description="Env var name whose value is the profile's bearer token"
    )
    bearer_token: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved token (load-time only)"
    )

    @field_validator("bearer_token_env")
    @classmethod
    def env_name_is_uppercase_identifier(cls, v: str) -> str:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if not ENV_NAME_RE.match(v):
            raise ValueError(
                f"bearer_token_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v


class LlmKeyOverride(BaseModel):
    """Per-profile provider API key for the LLM reverse proxy.

    Provide EITHER `api_key` (direct value, for bind-mounted configs) OR
    `api_key_env` (env var reference). The `api_key` field holds the resolved
    key at load time and is never serialized to logs/JSON.
    """

    model_config = ConfigDict(extra="forbid")

    api_key_env: str | None = Field(
        default=None,
        description="Env var name whose value is this profile's provider API key",
    )
    api_key: SecretStr = Field(
        default=SecretStr(""),
        description=(
            "Direct API key value (for bind-mounted configs) or resolved from "
            "api_key_env at load time. Never serialized."
        ),
    )

    @field_validator("api_key_env")
    @classmethod
    def env_name_is_uppercase_identifier(cls, v: str | None) -> str | None:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError(
                f"api_key_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("api_key", mode="before")
    @classmethod
    def coerce_to_secret_str(cls, v: str | SecretStr) -> SecretStr:
        """Accept plain strings from YAML and wrap in SecretStr."""
        if isinstance(v, str):
            return SecretStr(v)
        return v


class ParameterConstraint(BaseModel):
    """Allow/deny constraint on a single tool parameter's value."""

    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Value glob patterns to allow (default: all)",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Value glob patterns to deny (wins over allow)",
    )

    @field_validator("allow", "deny")
    @classmethod
    def guard_values_valid(cls, v: list[str]) -> list[str]:
        for pat in v:
            if not GUARD_VALUE_RE.match(pat):
                raise ValueError(
                    f"Invalid guard value {pat!r}: allowed characters are "
                    "alphanumerics, underscore, hyphen, dot, at-sign, plus, "
                    "forward-slash, space, and '*'"
                )
        return v


class PreProcessConfig(BaseModel):
    """Token reduction applied to tool responses before the perimeter scan.

    Reduction is not defense (see ``preprocess/base.py``, invariant 1). What
    this configures is how hard to try to make a payload smaller; what comes
    out is exactly as untrusted as what went in, and the caller scans the
    reduced artifact before delivering it.

    Resolution is two-level and least-surprise: a tool's entry in the
    backend's ``preprocess_tools`` wins over the profile default, and any
    field it leaves unset inherits. Profile answers "how aggressive is this
    agent"; tool answers "is this payload shape worth it".
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Master switch. Off means the response is untouched.",
    )
    strategy: Literal["none", "chain", "best_of", "auto"] = Field(
        default="auto",
        description=(
            "How processors compose. auto runs FREE ones always and "
            "escalates to METERED only while the payload exceeds "
            "target_bytes; chain feeds each the previous output; best_of "
            "keeps whichever came out smallest."
        ),
    )
    processors: list[Literal["petit", "summarize"]] = Field(
        default_factory=lambda: ["petit"],
        description=(
            "Which processors may run, in order. 'summarize' is METERED: it "
            "spends an LLM call AND forces its output to MODEL_OUTPUT "
            "provenance, which draws unconditional L3 — two model calls per "
            "response, not one. Default is the FREE set."
        ),
    )
    target_bytes: int = Field(
        default=20_000,
        ge=0,
        description=(
            "Size the reducer is trying to get under. Only 'auto' binds on "
            "it, as the ceiling above which METERED processors are allowed."
        ),
    )
    min_bytes: int = Field(
        default=4_096,
        ge=0,
        description=(
            "Floor below which the response is passed through untouched. "
            "Reduction has a fixed cost and small payloads cannot repay it."
        ),
    )


class ToolPreProcess(BaseModel):
    """Per-tool override. Every field is optional; unset inherits the profile."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    strategy: Literal["none", "chain", "best_of", "auto"] | None = None
    processors: list[Literal["petit", "summarize"]] | None = None
    target_bytes: int | None = Field(default=None, ge=0)
    min_bytes: int | None = Field(default=None, ge=0)


class Backend(BaseModel):
    """Per-profile backend MCP server config."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(
        ...,
        description=(
            "Backend location. Either a streamable-http URL (http(s)://) or "
            "internal://<label> for trentina's own in-process tool surface."
        ),
    )
    tools_allow: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Tool-name glob patterns to allow (default: all)",
    )
    tools_deny: list[str] = Field(
        default_factory=list,
        description="Tool-name glob patterns to deny (wins over tools_allow)",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Extra HTTP headers to send to the backend",
    )
    timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=MAX_BACKEND_TIMEOUT_SECONDS,
        description="Per-call backend timeout",
    )
    list_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=MAX_LIST_TIMEOUT_SECONDS,
        description=(
            "Timeout for tools/list metadata fetch "
            "(streamable-HTTP handshake needs headroom)"
        ),
    )
    parameter_guards: dict[str, dict[str, ParameterConstraint]] = Field(
        default_factory=dict,
        description=(
            "Tool name -> parameter name -> value constraint. "
            "Validated at call time before the backend is contacted."
        ),
    )
    validate_output_schema: bool = Field(
        default=True,
        description=(
            "Validate tool results against the backend's outputSchema "
            "(disable for buggy backends)"
        ),
    )
    compress_descriptions: bool = Field(
        default=False,
        description="Compress verbose tool descriptions via LLM at gateway startup",
    )
    preprocess_tools: dict[str, ToolPreProcess] = Field(
        default_factory=dict,
        description=(
            "Per-tool response-reduction overrides, keyed by tool name "
            "(same shape as parameter_guards). Whether reduction helps is a "
            "property of the tool's OUTPUT SHAPE, not of who called it: "
            "syslog_tail_tool is log-shaped for every profile. Unset tools "
            "use the profile default."
        ),
    )

    @field_validator("url")
    @classmethod
    def url_scheme_supported(cls, v: str) -> str:
        """Allow http(s):// (remote MCP) or internal://<label> (trentina's own tools).

        SSE and stdio are not supported. An internal:// URL must carry a
        URL-safe slug label after the scheme (cosmetic, but required so the
        namespace stays well-formed).
        """
        if v.startswith(("http://", "https://")):
            return v
        if v.startswith(INTERNAL_SCHEME):
            label = v[len(INTERNAL_SCHEME) :]
            if not BACKEND_NAME_RE.match(label):
                raise ValueError(
                    f"internal:// URL must carry a slug label "
                    f"(^[a-z][a-z0-9-]*$): {v!r}"
                )
            return v
        raise ValueError(
            f"Backend URL must start with http://, https://, or internal://: {v!r}"
        )

    @property
    def is_internal(self) -> bool:
        """True when this backend resolves to trentina's in-process tool surface."""
        return self.url.startswith(INTERNAL_SCHEME)

    @field_validator("tools_allow", "tools_deny")
    @classmethod
    def glob_patterns_valid(cls, v: list[str]) -> list[str]:
        """Each glob must match GLOB_PATTERN_RE — restricted character set, no regex metachars."""
        for pat in v:
            if not GLOB_PATTERN_RE.match(pat):
                raise ValueError(
                    f"Invalid glob pattern {pat!r}: allowed characters are "
                    "alphanumerics, underscore, hyphen, and '*'; first character "
                    "may not be a hyphen"
                )
        return v


class AlertIngressConfig(BaseModel):
    """Per-profile alert webhook ingress.

    Receives external alert POSTs (e.g. from Nagios) at ``/alert/{token}``
    and forwards the JSON payload to ``forward_url`` (e.g. a Hermes webhook).
    The token embedded in the URL is the sole authentication mechanism.
    """

    model_config = ConfigDict(extra="forbid")

    token_env: str = Field(
        ..., description="Env var name whose value is the alert ingress token",
    )
    token: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved token (load-time only)",
    )
    forward_url: str = Field(
        ..., description="URL to forward alert payloads to",
    )
    forward_secret_env: str | None = Field(
        default=None,
        description="Env var for HMAC secret used to sign forwarded payloads",
    )
    forward_secret: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved HMAC secret (load-time only)",
    )

    @field_validator("forward_secret_env")
    @classmethod
    def forward_secret_env_is_uppercase(cls, v: str | None) -> str | None:
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError(
                f"forward_secret_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("token_env")
    @classmethod
    def env_name_is_uppercase_identifier(cls, v: str) -> str:
        if not ENV_NAME_RE.match(v):
            raise ValueError(
                f"token_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @field_validator("forward_url")
    @classmethod
    def url_must_be_http(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                f"forward_url must start with http:// or https://: {v!r}"
            )
        return v


class DefenseConfig(BaseModel):
    """Per-profile defense policy, read by the shared pipeline.

    There are deliberately NO on/off switches for the layers (owner's call,
    2026-09-13): the earlier schema had `sanitize`/`classify`/`quarantine`
    booleans, and production ran `quarantine: false` for months without the
    owner knowing — partly because none of it was wired, partly because
    three unrelated words hid what they controlled. A profile behind
    Trentina gets all three layers, full stop; what a profile controls is
    THRESHOLDS (how suspicious before a layer flags or escalates) and the
    ENFORCEMENT consequence. A layer that is genuinely unavailable at
    runtime (no ONNX model, provider down) is a degraded state that /health
    reports and block-mode refuses on — never a config option that fails
    silent.

    Cost control for L3 lives in `l3_threshold`, not in an off switch: L3
    fires on model-output provenance, on any suspicious L1 detection, or on
    an L2 score at/above the threshold — so clean traffic costs nothing and
    an operator who wants L3 rarer raises the threshold in daylight instead
    of turning the layer off in the dark.
    """

    model_config = ConfigDict(extra="forbid")

    enforcement: Literal["annotate", "extract", "block"] = Field(
        default="annotate",
        description=(
            "What a flagged tool response becomes. annotate: delivered "
            "intact with a _trentina_warning (the calibration mode). "
            "block: refused outright — autonomous agents (kagetora, "
            "takeda). extract: replaced by a Q-Agent extraction — "
            "interactive profiles (josui). "
            "TRENTINA_ENFORCEMENT_OVERRIDE=annotate is the kill switch: it "
            "forces annotate everywhere for the night block misfires."
        ),
    )
    l2_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "L2 (Prompt Guard) score at or above which the content is "
            "flagged, in addition to the model's own MALICIOUS label"
        ),
    )
    l3_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description=(
            "L2 score at or above which L3 (the Q-Agent) reviews the "
            "content. L3 also always fires on model-output provenance and "
            "on any suspicious L1 detection; this threshold only adds the "
            "score trigger. Raise it to spend less on L3, in daylight."
        ),
    )
    audit: bool = Field(default=True, description="Write detection rows to SQLite")
    provider: str | None = Field(
        default=None,
        description=(
            "LLM provider override for this profile "
            "(falls back to TRENTINA_MODEL_PROVIDER)"
        ),
    )
    model: str | None = Field(
        default=None,
        description=(
            "LLM model override for this profile "
            "(falls back to QUARANTINE_MODEL)"
        ),
    )

    @field_validator("provider")
    @classmethod
    def provider_is_supported(cls, v: str | None) -> str | None:
        """If set, must be a known provider name."""
        if v is not None and v not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unknown provider {v!r}. Supported: {', '.join(SUPPORTED_PROVIDERS)}"
            )
        return v


class MatrixIngressConfig(BaseModel):
    """Per-profile access to the Matrix reverse proxy.

    The proxy at ``/matrix/{token}/{path}`` forwards to the homeserver only
    for a token that resolves to a profile. Before this existed the proxy
    was an open relay: anything that could reach the port could use
    Trentina as a Matrix client proxy, unauthenticated and unattributed.
    Token-in-path mirrors the alert ingress and costs the Matrix client
    nothing — the homeserver URL configured in the agent simply includes
    the token as a path prefix.
    """

    model_config = ConfigDict(extra="forbid")

    token_env: str = Field(
        ..., description="Env var name whose value is the Matrix proxy token",
    )
    token: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved token (load-time only)",
    )


class Profile(BaseModel):
    """One consumer profile: name, auth, backends, defense config."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Profile name (URL-safe slug)")
    auth: AuthConfig
    backends: dict[str, Backend] = Field(
        default_factory=dict,
        description="Backend MCP servers reachable from this profile",
    )
    llm_keys: dict[str, LlmKeyOverride] = Field(
        default_factory=dict,
        description=(
            "Per-provider API key overrides for the LLM proxy, keyed by "
            "provider name (must match a configured llm_providers entry)."
        ),
    )
    defense: DefenseConfig = Field(default_factory=DefenseConfig)
    preprocess: PreProcessConfig = Field(
        default_factory=PreProcessConfig,
        description=(
            "Profile-level response reduction policy. Off by default: a "
            "gateway that starts quietly rewriting payloads is not a "
            "default anyone opted into."
        ),
    )
    alert_ingress: AlertIngressConfig | None = Field(
        default=None,
        description="Alert webhook ingress configuration (optional)",
    )
    matrix_ingress: MatrixIngressConfig | None = Field(
        default=None,
        description="Matrix reverse-proxy access for this profile (optional)",
    )

    @field_validator("name")
    @classmethod
    def name_matches_re(cls, v: str) -> str:
        """Profile name must be a URL-safe slug (matches PROFILE_NAME_RE)."""
        if not PROFILE_NAME_RE.match(v):
            raise ValueError(f"Profile name {v!r} must match ^[a-z][a-z0-9-]*$")
        return v

    @field_validator("backends")
    @classmethod
    def backend_names_match_re(cls, v: dict[str, Backend]) -> dict[str, Backend]:
        """Each backend dict key must be a URL-safe slug (matches BACKEND_NAME_RE)."""
        for name in v:
            if not BACKEND_NAME_RE.match(name):
                raise ValueError(f"Backend name {name!r} must match ^[a-z][a-z0-9-]*$")
        return v

    @field_validator("llm_keys")
    @classmethod
    def llm_key_names_match_re(
        cls, v: dict[str, LlmKeyOverride]
    ) -> dict[str, LlmKeyOverride]:
        """Each llm_keys dict key must be a provider slug (matches PROVIDER_NAME_RE).

        Cross-validation against configured llm_providers happens at wiring time
        in register_llm_routes (the provider list is not available here).
        """
        for name in v:
            if not PROVIDER_NAME_RE.match(name):
                raise ValueError(f"Provider name {name!r} must match ^[a-z][a-z0-9-]*$")
        return v
