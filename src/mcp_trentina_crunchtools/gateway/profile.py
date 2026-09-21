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
    model_validator,
)

from ..config import SUPPORTED_PROVIDERS

PROFILE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
BACKEND_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
GLOB_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_*][a-zA-Z0-9_*-]*$")
GUARD_VALUE_RE = re.compile(r"^[a-zA-Z0-9_*@.\-+/ ]+$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

INTERNAL_SCHEME = "internal://"

# What a profile may reach through the gateway's own admin tools. Two values,
# because the only distinction that matters is "my slice" versus "the whole
# gateway" — an agent profile sees and acts on itself, the operator seat holds
# the box. See gateway/scope.py, which is the only place this is interpreted.
ProfileRole = Literal["agent", "operator"]

# Registered pre-processors. Adding one means adding it here, to
# gateway.reduce._REGISTRY, and nowhere else.
ProcessorName = Literal["petit", "structured", "email", "summarize"]
# FREE only, and ordered by how cheaply each one can decline: structured
# and email reject a payload of the wrong shape on their first check, so
# petit — which has to group every line before it knows — goes last.
# summarize is selectable but never a default: it is METERED and its output
# draws unconditional L3, so it costs two model calls.
_DEFAULT_PROCESSORS: list[ProcessorName] = ["structured", "email", "petit"]

# Registered scan-view extractors. Adding one means adding it here, to
# gateway.scanview._REGISTRY, and nowhere else. Declared twice on purpose:
# this Literal is what makes pydantic reject an unknown name at YAML load,
# and a parity test keeps the two in step.
ScanViewName = Literal["full", "generic"]

# Fields of ScanViewConfig an AGENT may change by reloading its own profile.
# Everything else in that block decides how much of the payload is read at
# all -- an agent may retune its own performance, it may not reshape its own
# perimeter. Enforced in tools/reload.py.
SCAN_VIEW_AGENT_FIELDS: frozenset[str] = frozenset(
    {"skip_sample_bytes", "min_coverage", "deadline_seconds"}
)

# 64 KiB of sampled openings is already ~36 L2 windows, which costs more than
# the extraction saved. A ceiling, not a recommendation.
_MAX_SKIP_SAMPLE_BYTES = 65536

# Reduction budget, in bytes of a single tool response.
#
# ~20 KB is roughly 5K tokens: large enough that ordinary responses pass
# through untouched, small enough that the handful of replies which
# dominate a transcript get attention. Only the `auto` strategy binds on
# it, as the ceiling above which METERED processors are allowed.
DEFAULT_TARGET_BYTES = 20_000

# Floor below which a response is passed through untouched. Reduction has
# a fixed cost — a parse, a walk, and for METERED a model call — and a
# payload this small cannot repay it however well it compresses.
DEFAULT_MIN_BYTES = 4_096

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
    processors: list[ProcessorName] = Field(
        default_factory=lambda: list(_DEFAULT_PROCESSORS),
        description=(
            "Which processors may run, in order. 'summarize' is METERED: it "
            "spends an LLM call AND forces its output to MODEL_OUTPUT "
            "provenance, which draws unconditional L3 — two model calls per "
            "response, not one. Default is the FREE set."
        ),
    )
    target_bytes: int = Field(
        default=DEFAULT_TARGET_BYTES,
        ge=0,
        description=(
            "Size the reducer is trying to get under. Only 'auto' binds on "
            "it, as the ceiling above which METERED processors are allowed."
        ),
    )
    min_bytes: int = Field(
        default=DEFAULT_MIN_BYTES,
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
    processors: list[ProcessorName] | None = None
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

    There is no cost control for L3 any more, and that is the point. It used
    to live in `l3_threshold`, which meant clean traffic never reached the
    judge — and since L2 FLAGS at `l2_threshold` while escalation needed
    `l3_threshold`, there was a band L2 flagged that L3 never reviewed.

    That was read as satisfying "all three layers, full stop" because it
    removed the per-layer booleans. It did not: a threshold deciding whether
    a layer executes is an off switch with a dial on it. The mandate is that
    L1, L2 and L3 run on every input to the gateway. They do, and
    `l3_threshold` is ignored.

    What a profile still controls is `l2_threshold` — how suspicious L2 must
    be before it FLAGS, which is a consequence and not an execution — and
    `enforcement`, which is what a flag costs.
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
            "DEPRECATED and ignored. L3 runs on every input the gateway "
            "scans, with no score gate. The field is retained for one "
            "release so profiles written for 0.9.x keep loading "
            "(extra=forbid would otherwise reject them); it is removed in "
            "0.11.0. Setting it has no effect."
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


class ScanViewConfig(BaseModel):
    """What the defense pipeline is allowed to read, and how it reports gaps.

    The default is ``full`` -- scan every string leaf, which is what shipped
    before extractors existed. That default is load-bearing: merging this
    changes no deployment's behaviour until an operator opts in, and a
    defense change whose default narrows the perimeter is one that lands by
    accident.
    """

    model_config = ConfigDict(extra="forbid")

    extractor: ScanViewName = Field(
        default="full",
        description=(
            "Which extractor selects the scanned subset. full: every leaf, "
            "no selection. generic: skip only what is structurally incapable "
            "of carrying language -- ciphertext, identifiers, enum "
            "constants, numbers, and exact duplicates."
        ),
    )
    skip_sample_bytes: int = Field(
        default=1024,
        ge=0,
        le=_MAX_SKIP_SAMPLE_BYTES,
        description=(
            "Budget for sampling the opening of skipped strings, so a "
            "payload hidden in a declined field still reaches L1/L2. Zero "
            "disables the backstop -- do that only with a reason."
        ),
    )
    min_coverage: float = Field(
        default=0.02,
        ge=0.0,
        le=1.0,
        description=(
            "Below this fraction of characters read, the response carries a "
            "low_scan_coverage warning. Not a block: an observable, on the "
            "same channel as l2_truncated."
        ),
    )
    deadline_seconds: float = Field(
        default=20.0,
        gt=0.0,
        le=120.0,
        description=(
            "How long extraction plus judgement may take before the response "
            "forwards anyway, annotated scan_timeout."
        ),
    )


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
    scan_view: ScanViewConfig = Field(
        default_factory=ScanViewConfig,
        description=(
            "How much of a Matrix response the defense pipeline reads. "
            "Defaults to scanning everything, so adopting this is an "
            "explicit operator decision rather than a silent narrowing."
        ),
    )


class OAuthConfig(BaseModel):
    """Per-profile Google-backed OAuth access, opt-in on top of static bearer.

    A profile always carries a static bearer (``auth``). When ``oauth.enabled``
    is set it ALSO accepts a Google-backed OAuth token whose verified email is
    in ``allowed_emails`` — the seat for a client that cannot send a static
    ``Authorization`` header (gemini.google.com Custom Apps, which offers only
    "no auth" or OAuth). The static token keeps working for every other client.

    There is no secret in this block: the UPSTREAM Google client credentials are
    a gateway-wide setting (``TRENTINA_OAUTH_GOOGLE_CLIENT_ID`` /
    ``_CLIENT_SECRET``), not per-profile, and the DOWNSTREAM client secret is
    named here by env var rather than written here. What a profile holds is the
    authorization decision — who may use it — which is not a secret and belongs
    in the config the operator reads.

    ``client_id``/``client_secret_env``/``client_redirect_uris`` declare a
    statically provisioned CONFIDENTIAL client: one whose credentials the
    operator types into a third-party console rather than one that registers
    itself through DCR. gemini.google.com Custom Apps is the motivating case —
    its connector offers only an MCP server URL, a Client ID and a Client
    Secret, so it discovers our authorization server from the URL and then
    authenticates to it with those credentials. A proxy that advertises only
    ``token_endpoint_auth_method=none`` tells such a client the credentials it
    holds are unusable, and it abandons the flow before ever calling ``/token``.
    See CHANGELOG 0.9.0 and RT #1502.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=False,
        description="Accept Google-backed OAuth tokens for this profile",
    )
    allowed_emails: list[str] = Field(
        default_factory=list,
        description=(
            "Verified Google account emails permitted through this profile. "
            "Compared case-insensitively. Empty while enabled is a hard error "
            "— an OAuth seat open to any Google account is never intended."
        ),
    )
    client_id: str | None = Field(
        default=None,
        description=(
            "Client ID of a statically provisioned confidential OAuth client, "
            "as typed into the third-party console. Requires "
            "client_secret_env and client_redirect_uris."
        ),
    )
    client_secret_env: str | None = Field(
        default=None,
        description=(
            "Env var name whose value is that client's secret. The secret "
            "itself is never written in this file."
        ),
    )
    client_secret: SecretStr | None = Field(
        default=None,
        exclude=True,
        description="Resolved client secret (load-time only)",
    )
    client_redirect_uris: list[str] = Field(
        default_factory=list,
        description=(
            "Exact redirect URIs the provisioned client may use. Matched "
            "verbatim — a provisioned client gets no pattern matching."
        ),
    )

    @field_validator("client_secret_env")
    @classmethod
    def client_secret_env_is_uppercase_identifier(cls, v: str | None) -> str | None:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if v is not None and not ENV_NAME_RE.match(v):
            raise ValueError(
                f"client_secret_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v

    @model_validator(mode="after")
    def provisioned_client_is_all_or_nothing(self) -> OAuthConfig:
        """A half-declared confidential client must not start.

        Each piece is useless alone and a missing piece fails in a way that is
        hard to read from the outside: no client_id and the secret is never
        consulted; no redirect URI and every /authorize is rejected as an
        unregistered redirect. Refuse at load instead.
        """
        declared = {
            "client_id": self.client_id is not None,
            "client_secret_env": self.client_secret_env is not None,
            "client_redirect_uris": bool(self.client_redirect_uris),
        }
        if any(declared.values()) and not all(declared.values()):
            missing = sorted(k for k, present in declared.items() if not present)
            raise ValueError(
                "a provisioned OAuth client needs client_id, client_secret_env "
                f"and client_redirect_uris together — missing {', '.join(missing)}"
            )
        if self.client_id is not None and not self.enabled:
            raise ValueError(
                "a provisioned OAuth client requires oauth.enabled — a client "
                "that can authenticate but reaches a profile with OAuth off is "
                "a misconfiguration, not a degraded mode"
            )
        return self

    @field_validator("allowed_emails")
    @classmethod
    def emails_normalized(cls, v: list[str]) -> list[str]:
        """Lower-case each entry and reject anything that is not an email."""
        normalized: list[str] = []
        for raw in v:
            email = raw.strip().lower()
            local, sep, domain = email.partition("@")
            if not sep or not local or "." not in domain:
                raise ValueError(
                    f"allowed_emails entry {raw!r} is not an email address"
                )
            normalized.append(email)
        return normalized

    @model_validator(mode="after")
    def allowlist_required_when_enabled(self) -> OAuthConfig:
        """A profile that turns OAuth on must name who may use it."""
        if self.enabled and not self.allowed_emails:
            raise ValueError(
                "oauth.enabled is true but allowed_emails is empty — refusing "
                "to expose an OAuth seat open to any Google account"
            )
        return self


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
    role: ProfileRole = Field(
        default="agent",
        description=(
            "What this profile may see and act on through the gateway's own "
            "admin tools. 'agent' (the default) is self-scope: its own audit "
            "rows, its own backends, its own section of profiles.yaml. "
            "'operator' is the seat that holds the whole gateway."
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
    oauth: OAuthConfig | None = Field(
        default=None,
        description="Google-backed OAuth access for this profile (optional)",
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
